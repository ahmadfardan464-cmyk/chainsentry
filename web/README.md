# chainsentry web UI

A small Flask app that lets users paste a Solidity contract and get a
markdown report in the browser.

## Run

```bash
cd /home/user/workspace/chainsentry
python3 -m web.app
# Open http://127.0.0.1:5000
```

## Endpoints

- `GET /` — paste form
- `POST /scan` — runs the scanner on the form input, returns the rendered report
- `GET /health` — basic liveness check (returns detector count)

## Notes

- Flask is the only non-stdlib dependency. It is bundled with `pyproject.toml`'s
  `[project.optional-dependencies]` group, not `requirements.txt` (since the
  CLI is stdlib-only).
- The web UI is single-page, no JS frameworks. Runs entirely on the server.
- For production, run behind a real WSGI server (gunicorn, uwsgi) and
  rate-limit `/scan` to prevent abuse.
