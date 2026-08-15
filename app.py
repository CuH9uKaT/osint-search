import csv
import io
import os
import re
import subprocess
import sys
import time
from functools import wraps

from flask import Flask, Response, jsonify, redirect, render_template, request, session, url_for

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-secret-key")
APP_PASSWORD = os.environ.get("APP_PASSWORD", "")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
last_search = {}
RATE_SECONDS = int(os.environ.get("RATE_SECONDS", "10"))


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if APP_PASSWORD and not session.get("authenticated"):
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


@app.get("/login")
def login():
    if not APP_PASSWORD:
        return redirect(url_for("index"))
    return render_template("login.html", error=None)


@app.post("/login")
def login_post():
    if not APP_PASSWORD:
        return redirect(url_for("index"))
    if request.form.get("password", "") == APP_PASSWORD:
        session["authenticated"] = True
        return redirect(url_for("index"))
    return render_template("login.html", error="Неправильний пароль."), 401


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login" if APP_PASSWORD else "index"))


@app.get("/")
@login_required
def index():
    return render_template("index.html")


@app.post("/api/search")
@login_required
def search():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()

    if not USERNAME_RE.fullmatch(username):
        return jsonify({
            "ok": False,
            "error": "Username: 1–64 символи, лише A-Z, a-z, 0-9, крапка, дефіс або підкреслення."
        }), 400

    now = time.time()
    client = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown")
    if now - last_search.get(client, 0) < RATE_SECONDS:
        return jsonify({
            "ok": False,
            "error": f"Зачекай {RATE_SECONDS} секунд перед наступним пошуком."
        }), 429
    last_search[client] = now

    cmd = [
        sys.executable, "-m", "sherlock_project",
        username,
        "--print-found",
        "--no-color",
        "--timeout", "20",
    ]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=300,
            cwd="/tmp",
        )
    except subprocess.TimeoutExpired:
        return jsonify({"ok": False, "error": "Пошук перевищив ліміт часу."}), 504
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Не вдалося запустити Sherlock: {exc}"}), 500

    output = (proc.stdout or "") + "\n" + (proc.stderr or "")
    results = []

    for line in output.splitlines():
        m = re.match(r"^\[\+\]\s+([^:]+):\s*(https?://\S+)", line.strip())
        if m:
            site = m.group(1).strip()
            url = m.group(2).rstrip(".,);]")
            results.append({"site": site, "url": url, "status": "Знайдено"})

    # De-duplicate while preserving order.
    seen = set()
    unique = []
    for item in results:
        key = (item["site"], item["url"])
        if key not in seen:
            seen.add(key)
            unique.append(item)

    return jsonify({
        "ok": True,
        "username": username,
        "count": len(unique),
        "results": unique,
        "return_code": proc.returncode,
    })


@app.post("/api/export.csv")
@login_required
def export_csv():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "results")).strip()
    results = data.get("results", [])

    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Site", "URL", "Status"])
    for item in results:
        writer.writerow([
            item.get("site", ""),
            item.get("url", ""),
            item.get("status", ""),
        ])

    filename = re.sub(r"[^A-Za-z0-9_.-]+", "_", username) or "results"
    return Response(
        out.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}.csv"'}
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)
