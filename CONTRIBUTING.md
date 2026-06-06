# Contributing

This project is defensive and offline-only.

Contributions must preserve the safety scope:

- No live network capture
- No raw sockets
- No AF_PACKET usage
- No sudo/root requirement
- No packet injection
- No credential extraction
- No real packet captures
- No real credentials, tokens, domains, or public IP addresses

Run the local checks before submitting changes:

```bash
python -m pytest
python -m ruff check .
python -m ruff format --check .
```

