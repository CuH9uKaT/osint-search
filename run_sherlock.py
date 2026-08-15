"""Memory-safe launcher for Sherlock 0.16.x.

The upstream CLI hard-codes up to 20 request workers. This wrapper patches
that value inside the Sherlock child process itself, which is the process
that actually consumes the Render memory budget.
"""
from __future__ import annotations

import os


def _limit_memory() -> None:
    try:
        import resource
        mb = max(256, min(448, int(os.environ.get("SHERLOCK_CHILD_MEMORY_MB", "384"))))
        limit = mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (limit, limit))
    except Exception:
        pass


def main() -> None:
    _limit_memory()
    import sherlock_project.sherlock as sh

    workers = min(12, max(1, int(os.environ.get("SHERLOCK_WORKERS", "6"))))
    base = sh.SherlockFuturesSession

    class PatchedSession(base):
        def __init__(self, *args, max_workers=2, **kwargs):
            max_workers = min(workers, max(1, max_workers))
            super().__init__(*args, max_workers=max_workers, **kwargs)

    sh.SherlockFuturesSession = PatchedSession
    sh.main()


if __name__ == "__main__":
    main()
