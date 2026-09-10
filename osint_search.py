from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parent
TOOLS_ROOT = Path(os.getenv("OSINT_TOOLS_DIR", ROOT / "tools")).resolve()
_local_python = ROOT / ("venv\\Scripts\\python.exe" if os.name == "nt" else "venv/bin/python")
PYTHON_EXECUTABLE = str(_local_python) if _local_python.is_file() else sys.executable
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,31}$")
ALLOWED_TOOLS = {"blackbird", "maigret", "sherlock"}
MAX_ACTIVE_JOBS = 2
JOB_TIMEOUT = max(20, min(int(os.getenv("OSINT_JOB_TIMEOUT", "120")), 120))
REQUEST_TIMEOUT = max(4, min(int(os.getenv("OSINT_REQUEST_TIMEOUT", "6")), 20))
JOB_TTL = 30 * 60
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()
EXECUTOR = ThreadPoolExecutor(max_workers=MAX_ACTIVE_JOBS, thread_name_prefix="osint-search")
TOOL_EXECUTOR = ThreadPoolExecutor(max_workers=3, thread_name_prefix="osint-tool")
ANSI_RE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def _repo(name: str) -> Path:
    return TOOLS_ROOT / name


def tool_status() -> dict[str, dict]:
    return {
        "blackbird": {
            "label": "Blackbird",
            "available": (_repo("blackbird") / "blackbird.py").is_file(),
            "source": "https://github.com/antoniaci/blackbird",
        },
        "maigret": {
            "label": "Maigret",
            "available": (_repo("maigret") / "maigret" / "maigret.py").is_file(),
            "source": "https://github.com/soxoj/maigret",
        },
        "sherlock": {
            "label": "Sherlock",
            "available": (_repo("sherlock") / "sherlock_project" / "__main__.py").is_file(),
            "source": "https://github.com/sherlock-project/sherlock",
        },
    }


def _validate(username: str, tools: list[str], ai: bool) -> tuple[str, list[str], bool]:
    username = username.strip().lstrip("@")
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("Username должен содержать 2–32 символа: латиница, цифры, _, ., -.")
    selected = list(dict.fromkeys(tools))
    if not selected or any(tool not in ALLOWED_TOOLS for tool in selected):
        raise ValueError("Выберите хотя бы один разрешённый инструмент.")
    return username, selected, bool(ai)


def _collect_files(folder: Path) -> list[dict]:
    results = []
    for path in folder.rglob("*.json"):
        if path.stat().st_size > 2_000_000:
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        results.append({"file": path.name, "data": value})
    return results


def _normalise(tool: str, stdout: str, files: list[dict]) -> list[dict]:
    stdout = ANSI_RE.sub("", stdout)
    found = []
    seen = set()

    def add(url: str, site: str = ""):
        url = url.rstrip(").,;")
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc or url in seen:
            return
        seen.add(url)
        found.append({"site": site or parsed.netloc, "url": url, "status": "found"})

    for match in re.findall(r"https?://[^\s<>'\"]+", stdout):
        add(match)
    for report in files:
        stack = [report["data"]]
        while stack:
            value = stack.pop()
            if isinstance(value, dict):
                for key, item in value.items():
                    if isinstance(item, str) and item.startswith(("http://", "https://")):
                        add(item, str(key))
                    else:
                        stack.append(item)
            elif isinstance(value, list):
                stack.extend(value)
    return found[:500]


def _run_tool(tool: str, username: str, workdir: Path) -> dict:
    python = PYTHON_EXECUTABLE
    if tool == "blackbird":
        repo = _repo("blackbird")
        bootstrap = (
            "import runpy,sys,types; "
            "sys.argv[0]='blackbird.py'; "
            "sys.path.insert(0,'src'); sys.path.insert(0,'src/modules'); "
            "utils=types.ModuleType('utils'); utils.__path__=['src/modules/utils']; sys.modules['utils']=utils; "
            "runpy.run_path('blackbird.py', run_name='__main__')"
        )
        command = [
            python, "-c", bootstrap,
            "--username", username, "--json", "--no-nsfw",
            "--timeout", str(REQUEST_TIMEOUT),
        ]
    elif tool == "maigret":
        repo = _repo("maigret")
        command = [
            python, "-m", "maigret.maigret", username, "--json", "simple",
            "--folderoutput", str(workdir),
            "--timeout", str(REQUEST_TIMEOUT),
            "--no-progressbar",
        ]
    else:
        repo = _repo("sherlock")
        command = [
            python, "-m", "sherlock_project", username, "--print-found",
            "--no-color", "--timeout", str(REQUEST_TIMEOUT),
        ]
    if not repo.is_dir():
        return {"tool": tool, "status": "unavailable", "error": "Инструмент не скачан."}
    if tool == "maigret":
        settings_source = ROOT / "maigret_settings.json"
        settings_target = repo / "maigret" / "resources" / "settings.json"
        try:
            settings_target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(settings_source, settings_target)
        except OSError as exc:
            logging.exception("Unable to prepare Maigret settings")
            return {
                "tool": tool,
                "status": "error",
                "error": f"Не удалось подготовить настройки Maigret: {exc}",
            }
    env = {
        **os.environ,
        "PYTHONUNBUFFERED": "1",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    }
    if tool == "blackbird":
        env["PYTHONPATH"] = os.pathsep.join(
            [str(repo / "src"), str(repo / "src" / "modules"), env.get("PYTHONPATH", "")]
        )
    try:
        completed = subprocess.run(
            command,
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=JOB_TIMEOUT,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {"tool": tool, "status": "timeout", "error": f"Превышен таймаут {JOB_TIMEOUT} секунд."}
    except OSError as exc:
        logging.exception("Unable to start OSINT tool %s", tool)
        return {"tool": tool, "status": "error", "error": str(exc)[:300]}
    output = (completed.stdout + "\n" + completed.stderr)[-100_000:]
    return {
        "tool": tool,
        "status": "ok" if completed.returncode == 0 else "error",
        "exit_code": completed.returncode,
        "results": _normalise(tool, output, _collect_files(workdir)),
        "log": output[-4000:],
        "error": "" if completed.returncode == 0 else (
            output.strip().splitlines()[-1][:500]
            if output.strip() else "Инструмент завершился с ошибкой."
        ),
    }


def _cleanup() -> None:
    cutoff = time.time() - JOB_TTL
    with JOBS_LOCK:
        for job_id in list(JOBS):
            if JOBS[job_id].get("updated_at", 0) < cutoff:
                JOBS.pop(job_id, None)


def _worker(job_id: str, username: str, tools: list[str], ai: bool) -> None:
    try:
        with tempfile.TemporaryDirectory(prefix="podslushka-osint-") as temp:
            workdir = Path(temp)
            futures = {
                TOOL_EXECUTOR.submit(_run_tool, tool, username, workdir): index
                for index, tool in enumerate(tools)
            }
            completed = {}
            for future in as_completed(futures):
                index = futures[future]
                try:
                    completed[index] = future.result()
                except Exception as exc:
                    tool = tools[index]
                    logging.exception("OSINT tool %s failed in job %s", tool, job_id)
                    completed[index] = {
                        "tool": tool,
                        "status": "error",
                        "results": [],
                        "error": str(exc)[:300],
                    }
                with JOBS_LOCK:
                    JOBS[job_id].update(
                        results=[completed[item] for item in sorted(completed)],
                        completed_tools=len(completed),
                        updated_at=time.time(),
                    )
            results = [completed[index] for index in range(len(tools))]
        summary = summarize_results(username, results) if ai else ""
        with JOBS_LOCK:
            JOBS[job_id].update(
                status="completed",
                results=results,
                ai_summary=summary,
                ai_requested=ai,
                updated_at=time.time(),
            )
    except Exception:
        logging.exception("OSINT job %s failed", job_id)
        with JOBS_LOCK:
            JOBS[job_id].update(
                status="failed",
                error="Поиск завершился внутренней ошибкой.",
                updated_at=time.time(),
            )


def start_job(username: str, tools: list[str], ai: bool = False) -> dict:
    _cleanup()
    username, tools, ai = _validate(username, tools, ai)
    with JOBS_LOCK:
        active = sum(item["status"] == "running" for item in JOBS.values())
        if active >= MAX_ACTIVE_JOBS:
            raise RuntimeError("Сейчас выполняются два поиска. Повторите через минуту.")
        job_id = uuid.uuid4().hex
        JOBS[job_id] = {
            "id": job_id,
            "username": username,
            "tools": tools,
            "ai_requested": ai,
            "status": "running",
            "created_at": time.time(),
            "updated_at": time.time(),
            "results": [],
        }
    EXECUTOR.submit(_worker, job_id, username, tools, ai)
    return get_job(job_id)


def get_job(job_id: str) -> dict:
    with JOBS_LOCK:
        job = JOBS.get(job_id)
        if not job:
            raise KeyError(job_id)
        return json.loads(json.dumps(job))


def summarize_results(username: str, results: list[dict]) -> str:
    """Summarize only the public URLs returned by the selected tools."""
    provider = os.getenv("AI_PROVIDER", "gemini").strip().lower()
    urls = [
        item["url"]
        for result in results
        for item in result.get("results", [])
        if item.get("url")
    ][:200]
    if not urls:
        return "ИИ не нашёл публичных ссылок для краткого резюме."
    prompt = (
        "Сделай краткое резюме проверки публичного username. Не устанавливай личность "
        "человека и не делай выводов за пределами данных. Укажи число найденных ссылок "
        "и повторяющиеся домены. Ответ на русском, максимум 500 символов.\n"
        f"Username: {username}\nСсылки:\n" + "\n".join(urls)
    )
    try:
        if provider in {"qwen", "huggingface", "hf", "deepseek", "glm"} and os.getenv("HF_TOKEN"):
            model = os.getenv(
                "DEEPSEEK_MODEL" if provider == "deepseek" else (
                    "GLM_MODEL" if provider == "glm" else "HF_MODEL"
                ),
                "zai-org/GLM-5.3" if provider == "glm" else "Qwen/Qwen3.8-27B",
            )
            payload = json.dumps({
                "model": model,
                "messages": [
                    {"role": "system", "content": "Ты безопасный аналитик публичных результатов."},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.2,
                "max_tokens": 300,
            }).encode("utf-8")
            request = urllib.request.Request(
                "https://router.huggingface.co/v1/chat/completions",
                data=payload,
                method="POST",
                headers={
                    "Authorization": "Bearer " + os.environ["HF_TOKEN"],
                    "Content-Type": "application/json",
                },
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                data = json.loads(response.read().decode("utf-8"))
            return str(data["choices"][0]["message"]["content"]).strip()[:1000]
        if os.getenv("GEMINI_API_KEY"):
            payload = json.dumps({
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "maxOutputTokens": 300},
            }).encode("utf-8")
            endpoint = (
                "https://generativelanguage.googleapis.com/v1beta/models/"
                + os.getenv("GEMINI_MODEL", "gemini-3-flash-preview")
                + ":generateContent?key=" + os.environ["GEMINI_API_KEY"]
            )
            request = urllib.request.Request(
                endpoint,
                data=payload,
                method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                data = json.loads(response.read().decode("utf-8"))
            return str(data["candidates"][0]["content"]["parts"][0]["text"]).strip()[:1000]
    except (KeyError, TypeError, ValueError, json.JSONDecodeError,
            urllib.error.URLError, urllib.error.HTTPError, OSError, TimeoutError):
        logging.warning("OSINT AI summary failed")
    return "ИИ-резюме недоступно: проверьте настройки выбранного провайдера."
