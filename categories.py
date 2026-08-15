"""
Sherlock catalog categories.

Social / community / gaming / developer lists are curated allowlists.
At runtime every name is intersected with the installed data.json so we never
pass a --site that Sherlock does not know. NSFW (isNSFW) is always excluded.
"""

from __future__ import annotations

import json
import logging
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any

log = logging.getLogger("osint.categories")

CATEGORIES_META = {
    "social": {
        "label": "Соцмережі",
        "emoji": "📱",
        "desc": "Соціальні мережі та профілі",
    },
    "community": {
        "label": "Спільноти",
        "emoji": "💬",
        "desc": "Форуми, спільноти, Q&A",
    },
    "gaming": {
        "label": "Ігри",
        "emoji": "🎮",
        "desc": "Ігрові платформи та трекери",
    },
    "developer": {
        "label": "Розробка",
        "emoji": "💻",
        "desc": "Код, DevOps, CTF, tech",
    },
    "full": {
        "label": "Повний",
        "emoji": "🌐",
        "desc": "Увесь каталог Sherlock (без NSFW)",
    },
}

# ---------------------------------------------------------------------------
# Curated allowlists (names MUST match data.json keys when present).
# Unknown names are silently dropped after intersection with the catalog.
# ---------------------------------------------------------------------------

SOCIAL_ALLOWLIST = [
    # Major social networks
    "Instagram", "Twitter", "LinkedIn", "VK", "Snapchat", "YouTube",
    "TikTok", "Pinterest", "tumblr", "Myspace", "Bluesky", "threads",
    "Clubhouse", "Vero", "Plurk", "Naver",

    # Messaging / social identity platforms
    "Telegram", "Discord", "Kik", "Discord.bio",

    # Fediverse / decentralized social
    "mastodon.social", "mastodon.cloud", "mastodon.xyz", "Fosstodon",
    "Framapiaf", "Mamot", "mstdn.io", "chaos.social", "social.tchncs.de",
    "pixelfed.social", "minds",

    # Photo / video / creator social platforms
    "Flickr", "Imgur", "VSCO", "EyeEm", "YouPic", "SmugMug", "Blipfoto",
    "Clapper", "YouNow", "Periscope", "Rumble", "Vimeo", "DailyMotion",
    "Giphy", "Tenor",

    # Blogging / microblogging / public journals
    "LiveJournal", "Blogger", "Medium", "write.as", "note", "HubPages",

    # Public people / interest networks
    "couchsurfing", "interpals", "datingRU", "Tellonym.me",
    "IRC-Galleria", "Polarsteps", "Trawelling", "Strava", "Untappd",
    "last.fm", "MixCloud", "SoundCloud", "Spotify", "Smule",
    "ReverbNation", "Bandcamp", "YandexMusic",
]


COMMUNITY_ALLOWLIST = [
    "Chatujme.cz",
    "Reddit", "HackerNews", "Lobsters", "Slashdot", "Disqus", "Hubski",
    "LessWrong", "SoylentNews", "dailykos", "Wykop", "pikabu", "pr0gramm",
    "kaskus", "nairaland.com", "jbzd.com.pl", "9GAG", "ShitpostBot5000",
    "Warrior Forum", "DigitalSpy", "BuzzFeed", "CNET", "Slant",
    "Apple Discussions", "Ask Fedora", "Bitwarden Forum", "BraveCommunity",
    "Caddy Community", "Car Talk Community", "Choice Community",
    "CloudflareCommunity", "Cryptomator Forum", "Discuss.Elastic.co",
    "Eintracht Frankfurt Forum", "Envato Forum", "Icons8 Community",
    "Ionic Forum", "Joplin Forum", "LinuxFR.org", "LOR", "MMORPG Forum",
    "Nextcloud Forum", "NICommunityForum", "OurDJTalk", "Rclone Forum",
    "SublimeForum", "WICG Forum", "WolframalphaForum", "forum_guns",
    "Gutefrage", "Autofrage", "Finanzfrage", "Gesundheitsfrage",
    "Motorradfrage", "Reisefrage", "Sportlerfrage", "Bezuzyteczna",
    "Tweakers", "Dealabs", "PepperNL", "PepperPL", "NationStates Nation",
    "NationStates Region", "programming.dev", "DEV Community",
    "habr", "toster", "opennet", "phpRU", "d3RU", "nnRU", "satsisRU",
    "TrashboxRU", "babyblogRU", "spletnik", "irecommend", "drive2",
    "Velomania", "hunting", "geocaching", "BiggerPockets", "leasehackr",
]

GAMING_ALLOWLIST = [
    "Steam Community (User)", "Steam Community (Group)", "Roblox",
    "Xbox Gamertag", "PSNProfiles.com", "Twitch", "Kick", "Chess",
    "Lichess", "Pychess", "Minecraft", "FortniteTracker", "Speedrun.com",
    "osu!", "RuneScape", "Kongregate", "Newgrounds", "Itch.io",
    "Ninja Kiwi", "NintendoLife", "Pokemon Showdown", "TETR.IO",
    "Star Citizen", "Giant Bomb", "Gamespot", "PCGamer", "Polygon",
    "BoardGameGeek", "igromania", "exophase", "NitroType", "Typeracer",
    "Monkeytype", "Blitz Tactics", "Playstrategy", "GaiaOnline",
    "Outgress", "MMORPG Forum", "Scratch", "Clozemaster", "Duolingo",
    "Memrise", "Sporcle", "Football", "Championat", "SportsRU", "VLR",
    "jeuxvideo", "Nightbot", "Splits.io",
]

DEVELOPER_ALLOWLIST = [
    "GitHub", "GitLab", "BitBucket", "Codeberg", "Gitea", "Gitee",
    "NotABug.org", "SourceForge", "Launchpad", "GNOME VCS", "Docker Hub",
    "PyPi", "npm", "Packagist", "RubyGems", "Gradle", "CTAN",
    "Replit.com", "Codepen", "Codewars", "LeetCode", "HackerRank",
    "HackerEarth", "Codeforces", "Codechef", "Atcoder", "Topcoder",
    "Kaggle", "Hugging Face", "Hashnode", "devRant", "freecodecamp",
    "GeeksforGeeks", "Codecademy", "Platzi", "CSSBattle", "DMOJ",
    "Coders Rank", "Coderwall", "Code Snippet Wiki", "Asciinema",
    "GitBook", "Pastebin", "Keybase", "HackerOne", "BugCrowd",
    "HackTheBox", "TryHackMe", "Intigriti", "HackenProof (Hackers)",
    "CyberDefenders", "PentesterLab", "Holopin", "Apple Developer",
    "ProductHunt", "DEV Community", "habr", "Career.habr",
    "toster", "opennet", "prog.hu", "Velog", "sessionize", "Hackaday",
    "hackster", "Instructables", "Opensource", "Weblate", "Jellyfin Weblate",
    "Crowdin", "VirusTotal", "HudsonRock", "BioHacking", "eGPU",
    "Needrom", "fl", "kwork", "Freelancer", "Contently", "Coroflot",
    "Behance", "Dribbble", "ArtStation", "Carbonmade", "Crevado",
    "SpeakerDeck", "SlideShare", "Slides", "LottieFiles", "Sketchfab",
    "CGTrader", "Cults3D", "MyMiniFactory", "Polymart", "BOOTH",
    "ThemeForest", "Audiojungle", "Envato Forum",
]

_ALLOWLISTS = {
    "social": SOCIAL_ALLOWLIST,
    "community": COMMUNITY_ALLOWLIST,
    "gaming": GAMING_ALLOWLIST,
    "developer": DEVELOPER_ALLOWLIST,
}

# ---------------------------------------------------------------------------
# Catalog load + status
# ---------------------------------------------------------------------------

_status_lock = threading.Lock()
_status: dict[str, Any] = {
    "ok": False,
    "error": "not loaded",
    "path": None,
    "total_raw": 0,
    "total_usable": 0,  # non-NSFW
    "counts": {},
    "loaded_at": None,
}


def get_status() -> dict[str, Any]:
    with _status_lock:
        return dict(_status)


def _find_data_json() -> Path | None:
    local = Path(__file__).resolve().parent / "data.json"
    if local.is_file():
        return local
    try:
        import sherlock_project

        path = Path(sherlock_project.__file__).resolve().parent / "resources" / "data.json"
        if path.is_file():
            return path
    except Exception as exc:
        log.warning("sherlock_project import failed: %s", exc)
    return None


def _load_raw() -> tuple[dict, Path]:
    path = _find_data_json()
    if path is None:
        raise FileNotFoundError(
            "Sherlock data.json not found (package resources or ./data.json)."
        )
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or len(data) < 10:
        raise ValueError("data.json looks empty or invalid")
    return data, path


@lru_cache(maxsize=1)
def catalog() -> dict[str, list[str]]:
    """
    {category: [site_name, ...]} intersected with installed data.json.
    Raises on failure; caller should use ensure_catalog().
    """
    data, path = _load_raw()
    usable: dict[str, dict] = {}
    nsfw = 0
    for name, meta in data.items():
        if name.startswith("$") or not isinstance(meta, dict):
            continue
        if meta.get("isNSFW"):
            nsfw += 1
            continue
        usable[name] = meta

    by_cat: dict[str, list[str]] = {k: [] for k in _ALLOWLISTS}
    assigned: set[str] = set()

    for cat, allow in _ALLOWLISTS.items():
        for name in allow:
            if name in usable and name not in assigned:
                by_cat[cat].append(name)
                assigned.add(name)
        by_cat[cat] = sorted(by_cat[cat], key=str.lower)

    other = sorted((n for n in usable if n not in assigned), key=str.lower)
    by_cat["other"] = other

    import time

    import hashlib
    raw_bytes = path.read_bytes()
    digest = hashlib.sha256(raw_bytes).hexdigest()[:16]

    with _status_lock:
        _status.update({
            "ok": True,
            "error": None,
            "path": str(path),
            "sha256_16": digest,
            "total_raw": len(usable) + nsfw,
            "total_usable": len(usable),
            "nsfw_excluded": nsfw,
            "counts": {k: len(v) for k, v in by_cat.items()},
            "loaded_at": time.time(),
        })

    log.info(
        "Catalog OK path=%s usable=%d nsfw=%d counts=%s",
        path, len(usable), nsfw, _status["counts"],
    )
    return by_cat


def ensure_catalog() -> dict[str, list[str]]:
    """Load catalog or raise RuntimeError with a clear message."""
    try:
        return catalog()
    except Exception as exc:
        with _status_lock:
            _status.update({"ok": False, "error": str(exc), "counts": {}})
        log.error("Catalog load failed: %s", exc)
        raise RuntimeError(f"Каталог Sherlock недоступний: {exc}") from exc


def sites_for_mode(mode: str) -> list[str] | None:
    """
    None → full catalog (omit --site flags).
    list → pass each as --site.
    """
    cats = ensure_catalog()
    mode = (mode or "social").lower().strip()
    if mode in ("full", "all"):
        return None
    if mode not in _ALLOWLISTS:
        mode = "social"
    return list(cats.get(mode, []))


def modes_public() -> list[dict]:
    cats = ensure_catalog()
    st = get_status()
    out = []
    for key, meta in CATEGORIES_META.items():
        if key == "full":
            count = st.get("total_usable") or sum(len(v) for v in cats.values())
        else:
            count = len(cats.get(key, []))
        out.append({
            "id": key,
            "label": meta["label"],
            "emoji": meta["emoji"],
            "desc": meta["desc"],
            "count": count,
        })
    return out


def preload() -> None:
    """Call at app startup."""
    try:
        ensure_catalog()
    except Exception:
        pass  # status already recorded; search will refuse
