# Security policy

## Reporting a vulnerability

Please do not open a public issue for a security vulnerability.

Send a private report to the repository maintainers with:

- a short description of the issue;
- affected file or endpoint;
- reproduction steps;
- impact assessment;
- a suggested fix, if available.

Do not include live tokens, passwords, personal data or production database
contents in a report.

## Operational guidance

- Keep `.env` and production credentials outside Git.
- Rotate exposed Telegram, Google, Gemini and Hugging Face credentials
  immediately.
- Use PostgreSQL and HTTPS for production deployments.
- Keep `DASHBOARD_SYNC_SECRET` and `MULTIBOT_ENCRYPTION_KEY` private.
