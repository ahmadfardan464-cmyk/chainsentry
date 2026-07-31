"""chainsentry web UI — small Flask app that lets users paste a Solidity
contract and get a markdown report. Stdlib-only Flask (no extra deps
beyond the project's requirements.txt)."""
from __future__ import annotations

import sys
from pathlib import Path

# Make the project root importable when running `python3 web/app.py`.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from flask import Flask, render_template, request  # noqa: E402

from chainsentry.scanner import scan_source  # noqa: E402
from chainsentry.reporters import to_markdown  # noqa: E402


app = Flask(__name__, template_folder="templates", static_folder="static")


@app.route("/", methods=["GET"])
def index() -> str:
    return render_template("index.html", report=None, source="")


@app.route("/scan", methods=["POST"])
def scan() -> str:
    source = request.form.get("source", "").strip()
    if not source:
        return render_template("index.html", report="(empty input — paste a contract)", source="")
    if "pragma" not in source and "contract" not in source:
        return render_template(
            "index.html",
            report="(input doesn't look like Solidity — missing `pragma` and `contract` keywords)",
            source=source,
        )
    report = scan_source(source, filename="<pasted>")
    md = to_markdown([report])
    return render_template("index.html", report=md, source=source)


@app.route("/health", methods=["GET"])
def health() -> tuple[str, int]:
    from chainsentry.detectors import ALL_DETECTORS
    return (f"ok — {len(ALL_DETECTORS)} detectors loaded", 200)


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=False)
