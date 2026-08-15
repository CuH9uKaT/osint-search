"""
OSINT Search — Flask + Sherlock
Streaming results, real cancel, session-bound jobs, PWA-ready API.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import secrets
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from functools import wraps
from typing import Any
from pathlib import Path

import categories

from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("osint")

# ---------------------------------------------------------------------------
# Config from environment
# ---------------------------------------------------------------------------
def _env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    if v is None or str(v).strip() == "":
        return default
    return str(v).strip()


SECRET_KEY = _env("SECRET_KEY")
APP_PASSWORD = _env("APP_PASSWORD")
SITE_TIMEOUT = max(5, int(_env("SITE_TIMEOUT", "12") or "12"))
SEARCH_TIMEOUT = max(30, int(_env("SEARCH_TIMEOUT", "180") or "180"))
RATE_SECONDS = max(1, int(_env("RATE_SECONDS", "12") or "12"))
# Sherlock 0.16.0 has an internal 20-thread request pool; it does not expose a
# --workers CLI flag. Keep this env for forward compatibility, but never pass
# an unsupported flag to the pinned version. See _sherlock_workers().
SHERLOCK_WORKERS = min(40, max(1, int(_env("SHERLOCK_WORKERS", "20") or "20")))

MODE_LIMITS = {
    "social": {
        "site_timeout": max(5, int(_env("SOCIAL_SITE_TIMEOUT", "10") or "10")),
        "search_timeout": max(30, int(_env("SOCIAL_SEARCH_TIMEOUT", "120") or "120")),
    },
    "community": {
        "site_timeout": max(5, int(_env("COMMUNITY_SITE_TIMEOUT", "10") or "10")),
        "search_timeout": max(30, int(_env("COMMUNITY_SEARCH_TIMEOUT", "150") or "150")),
    },
    "gaming": {
        "site_timeout": max(5, int(_env("GAMING_SITE_TIMEOUT", "10") or "10")),
        "search_timeout": max(30, int(_env("GAMING_SEARCH_TIMEOUT", "150") or "150")),
    },
    "developer": {
        "site_timeout": max(5, int(_env("DEVELOPER_SITE_TIMEOUT", "12") or "12")),
        "search_timeout": max(30, int(_env("DEVELOPER_SEARCH_TIMEOUT", "180") or "180")),
    },
    "full": {
        "site_timeout": max(5, int(_env("FULL_SITE_TIMEOUT", "12") or "12")),
        "search_timeout": max(30, int(_env("FULL_SEARCH_TIMEOUT", "240") or "240")),
    },
}
LOGIN_MAX_FAILS = max(3, int(_env("LOGIN_MAX_FAILS", "8") or "8"))
LOGIN_LOCK_SECONDS = max(30, int(_env("LOGIN_LOCK_SECONDS", "300") or "300"))
JOB_TTL_SECONDS = 600
MAX_ACTIVE_JOBS_PER_USER = 1
MAX_ACTIVE_JOBS_GLOBAL = 1  # free Render: one Sherlock at a time
SESSION_HOURS = 12

_in_container = bool(os.environ.get("PORT") or os.path.exists("/.dockerenv"))

if not SECRET_KEY or SECRET_KEY == "change-this-secret-key":
    if _in_container:
        raise RuntimeError("SECRET_KEY must be set (Render: generateValue).")
    SECRET_KEY = secrets.token_hex(32)
    log.warning("SECRET_KEY not set — ephemeral (dev only).")

if not APP_PASSWORD:
    if _in_container:
        raise RuntimeError("APP_PASSWORD is required in production.")
    log.warning("APP_PASSWORD not set — auth disabled (dev only).")


app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=_in_container,
    PERMANENT_SESSION_LIFETIME=60 * 60 * SESSION_HOURS,
    MAX_CONTENT_LENGTH=128 * 1024,
)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

# ---------------------------------------------------------------------------
# Rate / login lock (RAM; single-worker)
# ---------------------------------------------------------------------------
_rate_lock = threading.Lock()
_rate_hits: dict[str, float] = {}
_login_fails: dict[str, list[float]] = {}

_diag = {
    "last_search_elapsed": None,
    "last_search_at": None,
    "last_search_username": None,
    "last_search_found": None,
    "started_at": time.time(),
}


def _client_ip() -> str:
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip() or "unknown"
    return request.remote_addr or "unknown"


def _session_uid() -> str:
    """Stable per-browser id stored in signed session cookie."""
    if "uid" not in session:
        session["uid"] = secrets.token_hex(16)
        session.permanent = True
    return session["uid"]


def _csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(24)
    return session["csrf"]


def _check_csrf() -> bool:
    token = (
        request.headers.get("X-CSRF-Token")
        or (request.get_json(silent=True) or {}).get("csrf")
        or request.form.get("csrf")
        or ""
    )
    expected = session.get("csrf", "")
    if not expected or not token:
        return False
    return secrets.compare_digest(str(token), str(expected))


def _rate_ok(key: str) -> str | None:
    now = time.time()
    with _rate_lock:
        last = _rate_hits.get(key, 0.0)
        if now - last < RATE_SECONDS:
            return f"Зачекай {int(RATE_SECONDS - (now - last)) + 1} с."
        if len(_rate_hits) > 2000:
            cut = now - RATE_SECONDS * 5
            for k in [k for k, t in _rate_hits.items() if t < cut]:
                del _rate_hits[k]
        _rate_hits[key] = now
    return None


def _login_locked(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        fails = [t for t in _login_fails.get(ip, []) if now - t < LOGIN_LOCK_SECONDS]
        _login_fails[ip] = fails
        return len(fails) >= LOGIN_MAX_FAILS


def _login_fail(ip: str) -> None:
    with _rate_lock:
        _login_fails.setdefault(ip, []).append(time.time())


def _login_ok(ip: str) -> None:
    with _rate_lock:
        _login_fails.pop(ip, None)


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------
_FOUND_RE = re.compile(
    r"^\s*\[\s*\+\s*\]\s+(?P<site>[^:]+?)\s*:\s*(?P<url>https?://\S+)",
    re.IGNORECASE,
)


@dataclass
class Job:
    id: str
    username: str
    owner: str  # session uid
    mode: str  # social | community | gaming | developer | full
    status: str = "queued"
    results: list[dict] = field(default_factory=list)
    error: str | None = None
    return_code: int | None = None
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    site_timeout: int = 12
    search_timeout: int = 180
    site_count: int = 0
    proc: subprocess.Popen | None = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _seen: set[tuple[str, str]] = field(default_factory=set, repr=False)

    def public(self, include_results: bool = True) -> dict[str, Any]:
        elapsed = None
        if self.started_at:
            end = self.finished_at or time.time()
            elapsed = round(end - self.started_at, 1)
        out: dict[str, Any] = {
            "job_id": self.id,
            "username": self.username,
            "mode": self.mode,
            "status": self.status,
            "count": len(self.results),
            "error": self.error,
            "return_code": self.return_code,
            "elapsed_sec": elapsed,
            "site_timeout": self.site_timeout,
            "search_timeout": self.search_timeout,
            "site_count": self.site_count,
        }
        if include_results:
            with self._lock:
                out["results"] = list(self.results)
        return out


_jobs_lock = threading.Lock()
_jobs: dict[str, Job] = {}


def _cleanup_jobs() -> None:
    now = time.time()
    with _jobs_lock:
        for jid in [j for j, x in _jobs.items() if x.finished_at and now - x.finished_at > JOB_TTL_SECONDS]:
            del _jobs[jid]


def _get_owned_job(job_id: str, owner: str) -> Job | None:
    with _jobs_lock:
        job = _jobs.get(job_id)
    if not job or job.owner != owner:
        return None
    return job


def _kill_pg(proc: subprocess.Popen | None) -> None:
    if proc is None or proc.poll() is not None:
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    except Exception as exc:
        log.warning("killpg TERM: %s", exc)
        try:
            proc.terminate()
        except Exception:
            pass
    try:
        proc.wait(timeout=4)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
        try:
            proc.wait(timeout=2)
        except Exception:
            pass


def _parse_line(line: str) -> dict | None:
    line = line.strip()
    if not line or "[+]" not in line:
        return None
    m = _FOUND_RE.match(line)
    if m:
        site = m.group("site").strip()
        url = m.group("url").rstrip(".,);]'\"")
    else:
        try:
            after = line.split("[+]", 1)[1].strip()
            if ":" not in after or "http" not in after.lower():
                return None
            site_part, url_part = after.split(":", 1)
            site = site_part.strip()
            url = url_part.strip().split()[0].rstrip(".,);]'\"")
            if not url.lower().startswith("http"):
                return None
        except Exception:
            return None
    return {"site": site, "url": url, "status": "found"}


def _append_result(job: Job, item: dict) -> None:
    key = (item["site"].lower(), item["url"])
    with job._lock:
        if key in job._seen:
            return
        job._seen.add(key)
        job.results.append(item)
    log.info("SEARCH RESULT job=%s site=%s", job.id, item["site"])


def _run_job(job: Job) -> None:
    with job._lock:
        if job.status == "cancelled":
            return
        job.status = "running"
        job.started_at = time.time()

    log.info(
        "SEARCH START job=%s username=%r mode=%s sites=%d timeout=%ss site_timeout=%ss workers=%d",
        job.id, job.username, job.mode, job.site_count, job.search_timeout,
        job.site_timeout, SHERLOCK_WORKERS,
    )

    data_json = Path(__file__).resolve().parent / "data.json"
    if not data_json.is_file():
        # fallback: package local
        data_json = None

    cmd = [
        sys.executable, "-m", "sherlock_project",
        job.username,
        "--print-found",
        "--no-color",
        "--no-txt",
        "--timeout", str(job.site_timeout),
    ]
    if data_json is not None:
        cmd.extend(["--json", str(data_json)])
    else:
        cmd.append("--local")
    site_list = categories.sites_for_mode(job.mode)
    if site_list is not None:
        if not site_list:
            with job._lock:
                job.status = "error"
                job.error = f"У категорії «{job.mode}» немає сайтів у каталозі."
                job.finished_at = time.time()
            return
        for site in site_list:
            cmd.extend(["--site", site])
        log.info("SEARCH MODE job=%s category=%s sites=%d", job.id, job.mode, len(site_list))

    proc: subprocess.Popen | None = None
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            cwd="/tmp",
            start_new_session=True,
            bufsize=1,
        )
        with job._lock:
            job.proc = proc

        deadline = time.time() + job.search_timeout
        stdout_data: list[str] = []
        stderr_data: list[str] = []

        def _read_stderr() -> None:
            try:
                assert proc and proc.stderr
                for line in proc.stderr:
                    stderr_data.append(line)
            except Exception:
                pass

        err_t = threading.Thread(target=_read_stderr, daemon=True)
        err_t.start()

        assert proc.stdout is not None
        import select

        while True:
            if time.time() > deadline:
                log.warning("SEARCH TIMEOUT job=%s", job.id)
                _kill_pg(proc)
                with job._lock:
                    if job.status != "cancelled":
                        job.status = "timeout"
                        job.error = f"Перевищено загальний ліміт {job.search_timeout} с. Часткові результати збережено."
                        job.finished_at = time.time()
                        job.proc = None
                break

            with job._lock:
                if job.status == "cancelled":
                    break

            if proc.poll() is not None:
                rest = proc.stdout.read() or ""
                for line in rest.splitlines():
                    stdout_data.append(line + "\n")
                    item = _parse_line(line)
                    if item:
                        _append_result(job, item)
                break

            ready, _, _ = select.select([proc.stdout], [], [], 0.4)
            if not ready:
                continue
            line = proc.stdout.readline()
            if line:
                stdout_data.append(line)
                item = _parse_line(line)
                if item:
                    _append_result(job, item)
            elif proc.poll() is not None:
                break

        err_t.join(timeout=2)
        rc = proc.returncode
        with job._lock:
            job.return_code = rc
            job.proc = None
            if job.status == "cancelled":
                job.finished_at = job.finished_at or time.time()
            elif job.status == "timeout":
                pass
            elif rc not in (0, None) and not job.results:
                err = "".join(stderr_data).strip() or "".join(stdout_data).strip()
                if len(err) > 400:
                    err = err[:400] + "…"
                job.status = "error"
                job.error = f"Sherlock код {rc}." + (f" {err}" if err else "")
                job.finished_at = time.time()
            else:
                job.status = "done"
                job.finished_at = time.time()

        elapsed = (job.finished_at or time.time()) - (job.started_at or time.time())
        _diag["last_search_elapsed"] = round(elapsed, 1)
        _diag["last_search_at"] = time.time()
        _diag["last_search_username"] = job.username
        _diag["last_search_found"] = len(job.results)

        log.info(
            "SEARCH FINISHED job=%s status=%s found=%d elapsed=%.1fs rc=%s",
            job.id, job.status, len(job.results), elapsed, rc,
        )

    except Exception as exc:
        log.exception("SEARCH FAILED job=%s: %s", job.id, exc)
        _kill_pg(proc)
        with job._lock:
            if job.status not in ("cancelled", "timeout"):
                job.status = "error"
                job.error = f"{type(exc).__name__}: {exc}"
            job.finished_at = time.time()
            job.proc = None


def _cancel_job(job: Job) -> bool:
    with job._lock:
        if job.status in ("done", "error", "timeout", "cancelled"):
            return False
        job.status = "cancelled"
        job.error = "Скасовано. Часткові результати збережено."
        job.finished_at = time.time()
        proc = job.proc
        job.proc = None
    _kill_pg(proc)
    log.info("SEARCH CANCELLED job=%s found=%d", job.id, len(job.results))
    return True


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if APP_PASSWORD and not session.get("authenticated"):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Потрібна авторизація."}), 401
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def csrf_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if APP_PASSWORD and not _check_csrf():
            return jsonify({"ok": False, "error": "Невірний CSRF-токен. Онови сторінку."}), 403
        return fn(*args, **kwargs)
    return wrapper


# ---------------------------------------------------------------------------
# Routes: pages
# ---------------------------------------------------------------------------
@app.get("/login")
def login():
    if not APP_PASSWORD:
        return redirect(url_for("index"))
    if session.get("authenticated"):
        return redirect(url_for("index"))
    return render_template("login.html", error=None, csrf=_csrf_token())


@app.post("/login")
def login_post():
    if not APP_PASSWORD:
        return redirect(url_for("index"))
    ip = _client_ip()
    if _login_locked(ip):
        log.warning("Login LOCKED ip=%s", ip)
        return render_template(
            "login.html",
            error=f"Забагато спроб. Спробуй через {LOGIN_LOCK_SECONDS // 60} хв.",
            csrf=_csrf_token(),
        ), 429

    if not _check_csrf():
        return render_template("login.html", error="Онови сторінку і спробуй знову.", csrf=_csrf_token()), 403

    password = request.form.get("password", "")
    if secrets.compare_digest(password, APP_PASSWORD):
        session.clear()
        session["authenticated"] = True
        session.permanent = True
        _session_uid()
        _csrf_token()
        _login_ok(ip)
        log.info("Login OK ip=%s", ip)
        return redirect(url_for("index"))

    _login_fail(ip)
    log.warning("Login FAIL ip=%s", ip)
    return render_template("login.html", error="Неправильний пароль.", csrf=_csrf_token()), 401


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("login" if APP_PASSWORD else "index"))


@app.get("/")
@login_required
def index():
    _session_uid()
    return render_template("index.html", csrf=_csrf_token())


# ---------------------------------------------------------------------------
# Health & diagnostics
# ---------------------------------------------------------------------------
@app.get("/healthz")
@app.get("/health")
def healthz():
    return jsonify({"status": "ok"}), 200


@app.get("/api/diag")
@login_required
def api_diag():
    active = 0
    with _jobs_lock:
        for j in _jobs.values():
            if j.status in ("queued", "running") and j.owner == _session_uid():
                active += 1

    sherlock_ver = "?"
    try:
        p = subprocess.run(
            [sys.executable, "-m", "sherlock_project", "--version"],
            capture_output=True, text=True, timeout=15,
        )
        sherlock_ver = (p.stdout or p.stderr or "").strip().split("\n")[0][:120] or "?"
    except Exception as exc:
        sherlock_ver = f"error: {exc}"

    cat = categories.get_status()
    with _jobs_lock:
        global_running = sum(1 for j in _jobs.values() if j.status in ("queued", "running"))

    return jsonify({
        "ok": True,
        "server": "ok",
        "python": sys.version.split()[0],
        "sherlock": sherlock_ver,
        "uptime_sec": int(time.time() - _diag["started_at"]),
        "last_search_elapsed": _diag["last_search_elapsed"],
        "last_search_at": _diag["last_search_at"],
        "last_search_username": _diag["last_search_username"],
        "last_search_found": _diag["last_search_found"],
        "active_job_user": active > 0,
        "active_jobs_global": global_running,
        "site_timeout": SITE_TIMEOUT,
        "search_timeout": SEARCH_TIMEOUT,
        "mode_limits": MODE_LIMITS,
        "sherlock_workers_requested": SHERLOCK_WORKERS,
        "sherlock_workers_effective": 20,
        "rate_seconds": RATE_SECONDS,
        "catalog": cat,
    })


# ---------------------------------------------------------------------------
# API: search
# ---------------------------------------------------------------------------
@app.get("/api/modes")
@login_required
def api_modes():
    try:
        modes = categories.modes_public()
        return jsonify({"ok": True, "modes": modes, "catalog": categories.get_status()})
    except RuntimeError as exc:
        return jsonify({"ok": False, "error": str(exc), "catalog": categories.get_status()}), 503


@app.post("/api/search")
@login_required
@csrf_required
def api_search_start():
    _cleanup_jobs()
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "")).strip()
    mode = str(data.get("mode", "social")).strip().lower()
    if mode not in ("social", "community", "gaming", "developer", "full"):
        mode = "social"

    if not USERNAME_RE.fullmatch(username):
        return jsonify({"ok": False, "error": "Username: 1–64 символи (A-Z a-z 0-9 . - _)."}), 400

    owner = _session_uid()
    ip = _client_ip()
    # Rate limit: both session and IP (new sessions cannot bypass)
    for key in (f"search:uid:{owner}", f"search:ip:{ip}"):
        err = _rate_ok(key)
        if err:
            return jsonify({"ok": False, "error": err}), 429

    # Catalog must be healthy
    try:
        categories.ensure_catalog()
    except RuntimeError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503

    with _jobs_lock:
        global_active = [j for j in _jobs.values() if j.status in ("queued", "running")]
        if len(global_active) >= MAX_ACTIVE_JOBS_GLOBAL:
            j0 = global_active[0]
            left = None
            if j0.started_at:
                left = max(0, int(j0.search_timeout - (time.time() - j0.started_at)))
            msg = "Сервер зайнятий іншим пошуком."
            if left is not None:
                msg += f" Поточний пошук завершиться орієнтовно через ~{left} с."
            else:
                msg += " Спробуй трохи пізніше."
            return jsonify({"ok": False, "error": msg}), 503

        user_active = sum(1 for j in global_active if j.owner == owner)
        if user_active >= MAX_ACTIVE_JOBS_PER_USER:
            return jsonify({"ok": False, "error": "Уже є активний пошук. Скасуй або дочекайся."}), 409

        limits = MODE_LIMITS[mode]
        mode_sites = categories.sites_for_mode(mode)
        site_count = len(mode_sites) if mode_sites is not None else int(categories.get_status().get("total_usable") or 0)
        job_id = uuid.uuid4().hex[:16]
        job = Job(
            id=job_id, username=username, owner=owner, mode=mode,
            site_timeout=limits["site_timeout"],
            search_timeout=limits["search_timeout"],
            site_count=site_count,
        )
        _jobs[job_id] = job

    threading.Thread(target=_run_job, args=(job,), daemon=True, name=f"sh-{job_id}").start()
    log.info("SEARCH QUEUED job=%s username=%r mode=%s owner=%s", job_id, username, mode, owner[:8])
    return jsonify({"ok": True, "job_id": job_id, "status": "queued", "mode": mode}), 202


@app.get("/api/search/<job_id>")
@login_required
def api_search_status(job_id: str):
    job = _get_owned_job(job_id, _session_uid())
    if not job:
        return jsonify({"ok": False, "error": "Завдання не знайдено."}), 404
    return jsonify({"ok": True, **job.public(include_results=True)})


@app.post("/api/search/<job_id>/cancel")
@login_required
@csrf_required
def api_search_cancel(job_id: str):
    job = _get_owned_job(job_id, _session_uid())
    if not job:
        return jsonify({"ok": False, "error": "Завдання не знайдено."}), 404
    cancelled = _cancel_job(job)
    return jsonify({"ok": True, "cancelled": cancelled, **job.public()})


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------
@app.post("/api/export")
@login_required
@csrf_required
def api_export():
    data = request.get_json(silent=True) or {}
    username = str(data.get("username", "results")).strip() or "results"
    results = data.get("results") or []
    fmt = str(data.get("format", "csv")).lower()
    if not isinstance(results, list):
        return jsonify({"ok": False, "error": "Невірний format results."}), 400

    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", username)[:64] or "results"

    if fmt == "json":
        payload = json.dumps(
            {"username": username, "count": len(results), "results": results},
            ensure_ascii=False, indent=2,
        )
        return Response(
            payload,
            mimetype="application/json; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="osint_{safe}.json"', "Cache-Control": "no-store"},
        )

    if fmt == "txt":
        lines = [f"# OSINT {username}", f"# found: {len(results)}", ""]
        for item in results:
            if isinstance(item, dict):
                lines.append(f"{item.get('site', '')}\t{item.get('url', '')}")
        body = "\n".join(lines) + "\n"
        return Response(
            body,
            mimetype="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="osint_{safe}.txt"', "Cache-Control": "no-store"},
        )

    # csv default
    buf = io.StringIO()
    buf.write("\ufeff")
    w = csv.writer(buf)
    w.writerow(["Site", "URL", "Status"])
    for item in results:
        if not isinstance(item, dict):
            continue
        st = item.get("status", "")
        if st == "found":
            st = "Знайдено"
        w.writerow([str(item.get("site", "")), str(item.get("url", "")), str(st)])
    return Response(
        buf.getvalue(),
        mimetype="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="osint_{safe}.csv"', "Cache-Control": "no-store"},
    )


# CSRF bootstrap for SPA-ish frontend
@app.get("/api/session")
@login_required
def api_session():
    return jsonify({"ok": True, "csrf": _csrf_token()})


# ---------------------------------------------------------------------------
# PWA static-ish routes (served from templates/static paths)
# ---------------------------------------------------------------------------
@app.get("/manifest.webmanifest")
def manifest():
    return Response(
        json.dumps({
            "name": "OSINT Search",
            "short_name": "OSINT",
            "start_url": "/",
            "display": "standalone",
            "background_color": "#0f172a",
            "theme_color": "#0f172a",
            "lang": "uk",
            "icons": [
                {"src": "/static/icon-192.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable"},
                {"src": "/static/icon-512.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable"},
            ],
        }),
        mimetype="application/manifest+json",
    )


@app.get("/sw.js")
def service_worker():
    # Minimal SW: network-first for app shell; no offline Sherlock.
    js = """
self.addEventListener('install', e => { self.skipWaiting(); });
self.addEventListener('activate', e => { e.waitUntil(clients.claim()); });
self.addEventListener('fetch', e => {
  // pass-through; presence enables "Add to Home Screen"
});
"""
    return Response(js, mimetype="application/javascript")


def _sherlock_version() -> str:
    try:
        p = subprocess.run(
            [sys.executable, "-m", "sherlock_project", "--version"],
            capture_output=True, text=True, timeout=15, cwd="/tmp",
        )
        return (p.stdout or p.stderr or "").strip().split("\n")[0][:120] or "?"
    except Exception as exc:
        return f"error: {exc}"


def _startup_smoke_test() -> None:
    cat = categories.get_status()
    version = _sherlock_version()
    log.info(
        "SMOKE OK=%s | sherlock=%s | data_json=%s | sha=%s | usable=%s | nsfw=%s | counts=%s | workers_requested=%s | workers_effective=20",
        cat.get("ok"), version, bool(cat.get("path")), cat.get("sha256_16"),
        cat.get("total_usable"), cat.get("nsfw_excluded"), cat.get("counts"), SHERLOCK_WORKERS,
    )


# Graceful SIGTERM (Render shutdown)
def _handle_sigterm(signum, frame):
    log.info("SIGTERM received — cancelling active jobs")
    with _jobs_lock:
        jobs = list(_jobs.values())
    for j in jobs:
        if j.status in ("queued", "running"):
            _cancel_job(j)
    sys.exit(0)


signal.signal(signal.SIGTERM, _handle_sigterm)

# Load Sherlock catalog once at startup and run a local smoke test.
categories.preload()
log.info("Catalog status: %s", categories.get_status())
_startup_smoke_test()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, debug=False)
