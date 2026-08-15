"""
OSINT Search — Flask + Sherlock (memory-safe for free Render ~512MB).
Batched site checks, low workers, real cancel, streaming results.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import secrets
import select
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from typing import Any

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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("osint")


def _env(name: str, default: str | None = None) -> str | None:
    v = os.environ.get(name)
    if v is None or str(v).strip() == "":
        return default
    return str(v).strip()


SECRET_KEY = _env("SECRET_KEY")
APP_PASSWORD = _env("APP_PASSWORD")

# Free Render: default workers=8 (not 20). Hard cap 24.
SHERLOCK_WORKERS = min(12, max(1, int(_env("SHERLOCK_WORKERS", "6") or "6")))
SITE_BATCH_SIZE = max(10, min(30, int(_env("SITE_BATCH_SIZE", "20") or "20")))
ALLOW_FULL_SEARCH = (_env("ALLOW_FULL_SEARCH", "0") or "0") not in ("0", "false", "False", "no")
CHILD_MEMORY_MB = max(256, min(448, int(_env("CHILD_MEMORY_MB", "384") or "384")))

SITE_TIMEOUT = max(5, int(_env("SITE_TIMEOUT", "12") or "12"))
SEARCH_TIMEOUT = max(30, int(_env("SEARCH_TIMEOUT", "180") or "180"))
RATE_SECONDS = max(1, int(_env("RATE_SECONDS", "12") or "12"))
LOGIN_MAX_FAILS = max(3, int(_env("LOGIN_MAX_FAILS", "8") or "8"))
LOGIN_LOCK_SECONDS = max(30, int(_env("LOGIN_LOCK_SECONDS", "300") or "300"))
JOB_TTL_SECONDS = 600
MAX_ACTIVE_JOBS_PER_USER = 1
MAX_ACTIVE_JOBS_GLOBAL = 1
SESSION_HOURS = 12

_MODE_TIMEOUTS = {
    "social": (10, 120),
    "community": (12, 150),
    "gaming": (12, 150),
    "developer": (12, 150),
    "full": (12, 210),
}


def timeouts_for_mode(mode: str) -> tuple[int, int]:
    mode = (mode or "social").lower()
    site_d, search_d = _MODE_TIMEOUTS.get(mode, (SITE_TIMEOUT, SEARCH_TIMEOUT))
    site = max(5, int(_env(f"SITE_TIMEOUT_{mode.upper()}", str(site_d)) or site_d))
    search = max(30, int(_env(f"SEARCH_TIMEOUT_{mode.upper()}", str(search_d)) or search_d))
    return site, search


def estimate_seconds(mode: str, n_sites: int | None) -> str:
    if mode == "full" or (n_sites and n_sites > 200):
        return "1–3 хв"
    site_t, search_t = timeouts_for_mode(mode)
    if n_sites is None:
        return f"до ~{search_t // 60} хв" if search_t >= 60 else f"до ~{search_t} с"
    waves = max(1, (n_sites + SHERLOCK_WORKERS - 1) // SHERLOCK_WORKERS)
    est = min(search_t, max(12, int(waves * min(2.5, site_t) * 0.8)))
    if est >= 60:
        return f"~{est // 60}–{(est // 60) + 1} хв"
    return f"~{max(15, est)}–{est + 25} с"


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


_FOUND_RE = re.compile(
    r"^\s*\[\s*\+\s*\]\s+(?P<site>[^:]+?)\s*:\s*(?P<url>https?://\S+)",
    re.IGNORECASE,
)


@dataclass
class Job:
    id: str
    username: str
    owner: str
    mode: str
    status: str = "queued"
    results: list[dict] = field(default_factory=list)
    error: str | None = None
    return_code: int | None = None
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    batch_info: str | None = None
    proc: subprocess.Popen | None = field(default=None, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _seen: set[tuple[str, str]] = field(default_factory=set, repr=False)

    def public(self) -> dict[str, Any]:
        elapsed = None
        if self.started_at:
            end = self.finished_at or time.time()
            elapsed = round(end - self.started_at, 1)
        with self._lock:
            results = list(self.results)
            batch_info = self.batch_info
        return {
            "job_id": self.id,
            "username": self.username,
            "mode": self.mode,
            "status": self.status,
            "count": len(results),
            "results": results,
            "error": self.error,
            "return_code": self.return_code,
            "elapsed_sec": elapsed,
            "batch_info": batch_info,
        }


_jobs_lock = threading.Lock()
_jobs: dict[str, Job] = {}


def _cleanup_jobs() -> None:
    now = time.time()
    with _jobs_lock:
        for jid in [
            j for j, x in _jobs.items()
            if x.finished_at and now - x.finished_at > JOB_TTL_SECONDS
        ]:
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
        proc.wait(timeout=3)
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
    log.info("SEARCH RESULT | job=%s | site=%s", job.id, item["site"])


def _chunked(items: list, size: int) -> list[list]:
    return [items[i : i + size] for i in range(0, len(items), size)]


def _build_cmd(username: str, site_timeout: int, sites: list[str]) -> list[str]:
    data_json = Path(__file__).resolve().parent / "data.json"
    runner = Path(__file__).resolve().parent / "run_sherlock.py"
    cmd = [
        sys.executable, str(runner),
        username,
        "--print-found",
        "--no-color",
        "--no-txt",
        "--timeout", str(site_timeout),
    ]
    if data_json.is_file():
        cmd.extend(["--json", str(data_json)])
    else:
        cmd.append("--local")
    for site in sites:
        cmd.extend(["--site", site])
    return cmd


def _run_one_batch(job: Job, cmd: list[str], deadline: float) -> int | None:
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
            env={**os.environ, "SHERLOCK_WORKERS": str(SHERLOCK_WORKERS), "SHERLOCK_CHILD_MEMORY_MB": str(CHILD_MEMORY_MB)},
            bufsize=1,
        )
        with job._lock:
            job.proc = proc

        stderr_buf: list[str] = []

        def _stderr() -> None:
            try:
                assert proc and proc.stderr
                for line in proc.stderr:
                    if len(stderr_buf) < 200:
                        stderr_buf.append(line[:1000])
            except Exception:
                pass

        threading.Thread(target=_stderr, daemon=True).start()
        assert proc.stdout is not None

        while True:
            if time.time() > deadline:
                log.warning("SEARCH TIMEOUT job=%s (batch)", job.id)
                _kill_pg(proc)
                with job._lock:
                    if job.status != "cancelled":
                        job.status = "timeout"
                        job.error = "Перевищено ліміт часу. Часткові результати збережено."
                        job.finished_at = time.time()
                    job.proc = None
                return None

            with job._lock:
                if job.status == "cancelled":
                    _kill_pg(proc)
                    job.proc = None
                    return None

            if proc.poll() is not None:
                rest = proc.stdout.read() or ""
                for line in rest.splitlines():
                    item = _parse_line(line)
                    if item:
                        _append_result(job, item)
                break

            ready, _, _ = select.select([proc.stdout], [], [], 0.3)
            if not ready:
                continue
            line = proc.stdout.readline()
            if line:
                item = _parse_line(line)
                if item:
                    _append_result(job, item)
            elif proc.poll() is not None:
                break

        rc = proc.returncode
        with job._lock:
            job.proc = None
        if rc is not None and rc < 0:
            log.error(
                "SEARCH batch signal-kill rc=%s job=%s stderr=%s",
                rc, job.id, "".join(stderr_buf)[:400],
            )
        return rc
    except Exception:
        _kill_pg(proc)
        with job._lock:
            job.proc = None
        raise


def _run_job(job: Job) -> None:
    with job._lock:
        if job.status == "cancelled":
            return
        job.status = "running"
        job.started_at = time.time()

    site_timeout, search_timeout = timeouts_for_mode(job.mode)
    site_list = categories.sites_for_mode(job.mode)

    if site_list is None:
        # full → explicit list so we can batch (never unconstrained 462 in one process wave)
        cats = categories.ensure_catalog()
        site_list = []
        seen: set[str] = set()
        for key in ("social", "community", "gaming", "developer", "other"):
            for name in cats.get(key, []):
                if name not in seen:
                    seen.add(name)
                    site_list.append(name)

    if not site_list:
        with job._lock:
            job.status = "error"
            job.error = f"У категорії «{job.mode}» немає сайтів."
            job.finished_at = time.time()
        return

    if job.mode == "full" and not ALLOW_FULL_SEARCH:
        with job._lock:
            job.status = "error"
            job.error = (
                "Повний пошук вимкнено (ліміт пам'яті free Render). "
                "Обери «Соцмережі» або іншу категорію. "
                "Або встанови ALLOW_FULL_SEARCH=1 після збільшення плану."
            )
            job.finished_at = time.time()
        return

    batches = _chunked(site_list, SITE_BATCH_SIZE)
    deadline = time.time() + search_timeout
    n_sites = len(site_list)

    log.info(
        "SEARCH START | job=%s | username=%r | mode=%s | sites=%s | batches=%s | "
        "batch_size=%s | site_timeout=%s | search_timeout=%s | workers=%s",
        job.id, job.username, job.mode, n_sites, len(batches),
        SITE_BATCH_SIZE, site_timeout, search_timeout, SHERLOCK_WORKERS,
    )
    log.info("SEARCH MEMORY GUARD | job=%s | child_limit_mb=%s", job.id, CHILD_MEMORY_MB)

    last_rc: int | None = 0
    try:
        for bi, batch in enumerate(batches, 1):
            with job._lock:
                if job.status in ("cancelled", "timeout"):
                    break
                job.batch_info = f"{bi}/{len(batches)}"

            if time.time() > deadline:
                with job._lock:
                    if job.status not in ("cancelled",):
                        job.status = "timeout"
                        job.error = f"Ліміт {search_timeout} с. Часткові результати збережено."
                        job.finished_at = time.time()
                break

            log.info(
                "SEARCH BATCH | job=%s | %s/%s | batch_sites=%s | found=%s",
                job.id, bi, len(batches), len(batch), len(job.results),
            )
            cmd = _build_cmd(job.username, site_timeout, batch)
            try:
                last_rc = _run_one_batch(job, cmd, deadline)
            except Exception as exc:
                log.exception("batch error job=%s", job.id)
                with job._lock:
                    if job.status not in ("cancelled", "timeout"):
                        job.status = "error"
                        job.error = (
                            f"Помилка Sherlock: {type(exc).__name__}: {exc}. "
                            "Ймовірний брак пам'яті — спробуй «Соцмережі»."
                        )
                        job.finished_at = time.time()
                break

            with job._lock:
                if job.status in ("cancelled", "timeout"):
                    break

            time.sleep(0.25)  # let RSS settle between batches

        elapsed = time.time() - (job.started_at or time.time())
        with job._lock:
            if job.status == "running":
                if last_rc in (-9, -15) and not job.results:
                    job.status = "error"
                    job.error = (
                        "Sherlock завершився без результатів. На free Render це може бути ліміт пам'яті; "
                        "поточні безпечні налаштування: 6 workers / 20 сайтів у пакеті."
                    )
                elif last_rc is not None and last_rc < 0 and not job.results:
                    job.status = "error"
                    job.error = f"Sherlock завершено сигналом {-last_rc}. Спробуй режим «Соцмережі»."
                elif last_rc not in (0, None) and not job.results:
                    job.status = "error"
                    job.error = f"Sherlock код {last_rc}."
                else:
                    job.status = "done"
                job.return_code = last_rc
                job.finished_at = time.time()
                job.proc = None
                job.batch_info = None

        _diag["last_search_elapsed"] = round(elapsed, 1)
        _diag["last_search_at"] = time.time()
        _diag["last_search_username"] = job.username
        _diag["last_search_found"] = len(job.results)
        log.info(
            "SEARCH FINISHED | job=%s | status=%s | found=%d | elapsed=%.1fs | rc=%s",
            job.id, job.status, len(job.results), elapsed, last_rc,
        )
    except Exception as exc:
        log.exception("SEARCH FAILED job=%s: %s", job.id, exc)
        with job._lock:
            proc = job.proc
            job.proc = None
        _kill_pg(proc)
        with job._lock:
            if job.status not in ("cancelled", "timeout"):
                job.status = "error"
                job.error = f"{type(exc).__name__}: {exc}"
            job.finished_at = time.time()


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
    log.info("SEARCH CANCELLED | job=%s | found=%d", job.id, len(job.results))
    return True


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
            return jsonify({"ok": False, "error": "Невірний CSRF. Онови сторінку."}), 403
        return fn(*args, **kwargs)
    return wrapper


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
        return render_template(
            "login.html",
            error=f"Забагато спроб. Зачекай {LOGIN_LOCK_SECONDS // 60} хв.",
            csrf=_csrf_token(),
        ), 429
    if not _check_csrf():
        return render_template("login.html", error="Онови сторінку.", csrf=_csrf_token()), 403
    if secrets.compare_digest(request.form.get("password", ""), APP_PASSWORD):
        session.clear()
        session["authenticated"] = True
        session.permanent = True
        _session_uid()
        _csrf_token()
        _login_ok(ip)
        return redirect(url_for("index"))
    _login_fail(ip)
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
        global_running = sum(1 for j in _jobs.values() if j.status in ("queued", "running"))

    sherlock_ver = "?"
    try:
        p = subprocess.run(
            [sys.executable, "-m", "sherlock_project", "--version"],
            capture_output=True, text=True, timeout=15,
        )
        sherlock_ver = (p.stdout or p.stderr or "").strip().split("\n")[0][:120] or "?"
    except Exception as exc:
        sherlock_ver = f"error: {exc}"

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
        "rate_seconds": RATE_SECONDS,
        "workers": SHERLOCK_WORKERS,
        "batch_size": SITE_BATCH_SIZE,
        "allow_full_search": ALLOW_FULL_SEARCH,
        "catalog": categories.get_status(),
    })


@app.get("/api/modes")
@login_required
def api_modes():
    try:
        modes = categories.modes_public()
        for m in modes:
            m["eta"] = estimate_seconds(m["id"], m.get("count"))
            site_t, search_t = timeouts_for_mode(m["id"])
            m["site_timeout"] = site_t
            m["search_timeout"] = search_t
            if m["id"] == "full":
                if not ALLOW_FULL_SEARCH:
                    m["warning"] = "Повний пошук вимкнено на free-плані (пам'ять)."
                    m["disabled"] = True
                else:
                    m["warning"] = "Повний пошук може зайняти 1–3 хв і навантажити free Render."
        return jsonify({
            "ok": True,
            "modes": modes,
            "catalog": categories.get_status(),
            "workers": SHERLOCK_WORKERS,
            "batch_size": SITE_BATCH_SIZE,
        })
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

    if mode == "full" and not ALLOW_FULL_SEARCH:
        return jsonify({
            "ok": False,
            "error": "Повний пошук вимкнено через ліміт пам'яті. Обери «Соцмережі».",
        }), 400

    try:
        categories.ensure_catalog()
    except RuntimeError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503

    owner = _session_uid()
    ip = _client_ip()
    for key in (f"search:uid:{owner}", f"search:ip:{ip}"):
        err = _rate_ok(key)
        if err:
            return jsonify({"ok": False, "error": err}), 429

    with _jobs_lock:
        global_active = [j for j in _jobs.values() if j.status in ("queued", "running")]
        if len(global_active) >= MAX_ACTIVE_JOBS_GLOBAL:
            j0 = global_active[0]
            _, j_search_t = timeouts_for_mode(j0.mode)
            left = None
            if j0.started_at:
                left = max(0, int(j_search_t - (time.time() - j0.started_at)))
            msg = f"Сервер виконує інший пошук (режим: {j0.mode})."
            if left is not None:
                msg += f" Ще ~{left} с."
            return jsonify({"ok": False, "error": msg}), 503

        if sum(1 for j in global_active if j.owner == owner) >= MAX_ACTIVE_JOBS_PER_USER:
            return jsonify({"ok": False, "error": "Уже є активний пошук. Натисни Стоп."}), 409

        job_id = uuid.uuid4().hex[:16]
        job = Job(id=job_id, username=username, owner=owner, mode=mode)
        _jobs[job_id] = job

    threading.Thread(target=_run_job, args=(job,), daemon=True, name=f"sh-{job_id}").start()
    log.info("SEARCH QUEUED | job=%s | username=%r | mode=%s", job_id, username, mode)
    return jsonify({"ok": True, "job_id": job_id, "status": "queued", "mode": mode}), 202


@app.get("/api/search/<job_id>")
@login_required
def api_search_status(job_id: str):
    job = _get_owned_job(job_id, _session_uid())
    if not job:
        return jsonify({"ok": False, "error": "Завдання не знайдено."}), 404
    return jsonify({"ok": True, **job.public()})


@app.post("/api/search/<job_id>/cancel")
@login_required
@csrf_required
def api_search_cancel(job_id: str):
    job = _get_owned_job(job_id, _session_uid())
    if not job:
        return jsonify({"ok": False, "error": "Завдання не знайдено."}), 404
    cancelled = _cancel_job(job)
    return jsonify({"ok": True, "cancelled": cancelled, **job.public()})


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
        return Response(
            "\n".join(lines) + "\n",
            mimetype="text/plain; charset=utf-8",
            headers={"Content-Disposition": f'attachment; filename="osint_{safe}.txt"', "Cache-Control": "no-store"},
        )

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


@app.get("/api/session")
@login_required
def api_session():
    return jsonify({"ok": True, "csrf": _csrf_token()})


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
    return Response(
        "self.addEventListener('install',e=>self.skipWaiting());"
        "self.addEventListener('activate',e=>e.waitUntil(clients.claim()));",
        mimetype="application/javascript",
    )


def _handle_sigterm(signum, frame):
    log.info("SIGTERM — cancelling jobs")
    with _jobs_lock:
        jobs = list(_jobs.values())
    for j in jobs:
        if j.status in ("queued", "running"):
            _cancel_job(j)
    sys.exit(0)


signal.signal(signal.SIGTERM, _handle_sigterm)

categories.preload()
_st = categories.get_status()
if _st.get("ok"):
    _c = _st.get("counts") or {}
    log.info(
        "CATALOG OK | total=%s | social=%s | community=%s | gaming=%s | developer=%s | other=%s | sha=%s | workers=%s | batch=%s",
        _st.get("total_usable"), _c.get("social"), _c.get("community"),
        _c.get("gaming"), _c.get("developer"), _c.get("other"),
        _st.get("sha256_16"), SHERLOCK_WORKERS, SITE_BATCH_SIZE,
    )
else:
    log.error("CATALOG FAIL | %s", _st.get("error"))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "10000"))
    app.run(host="0.0.0.0", port=port, debug=False)
