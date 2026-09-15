# Contributing

## Before you start

Read the project README and choose a focused change. Do not include generated
virtual-environment files, downloaded third-party repositories, database dumps,
tokens or screenshots containing private data.

## Local setup

```powershell
python -m venv venv
.\venv\Scripts\python.exe -m pip install -r requirements.txt
```

## Validation

Run:

```powershell
.\venv\Scripts\python.exe -m py_compile db_viewer.py osint_search.py site_monitor.py
git diff --check
```

For UI changes, verify both a desktop viewport and a narrow mobile viewport.
For OSINT changes, verify partial results, source timeout handling and the
history endpoints.

## Pull requests

Keep pull requests small and describe:

1. what changed;
2. why it changed;
3. how it was tested;
4. any configuration or migration impact.

Never commit secrets or real user data.
