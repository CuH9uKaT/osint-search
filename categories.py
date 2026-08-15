"""
Sherlock catalog categories.

Allowlists are curated and intersected with the bundled data.json at runtime.
NSFW (isNSFW) is always excluded. Unknown names in allowlists are dropped.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from functools import lru_cache
from pathlib import Path
from typing import Any

log = logging.getLogger("osint.categories")

# UI exposes only these two modes (internal allowlists still used for catalog stats)
CATEGORIES_META = {
    "social": {
        "label": "Соцмережі",
        "emoji": "📱",
        "desc": "Тільки соціальні мережі та профілі",
    },
    "full": {
        "label": "Повний пошук",
        "emoji": "🌐",
        "desc": "Усі доступні категорії (без NSFW)",
    },
}

# ---------------------------------------------------------------------------
# Strict social: identity / network profiles (not academic, not donations)
# ---------------------------------------------------------------------------
SOCIAL_ALLOWLIST = [
    # Core networks
    "Instagram", "Twitter", "LinkedIn", "VK", "Snapchat", "YouTube",
    "TikTok", "Pinterest", "tumblr", "Myspace", "Bluesky", "threads",
    "Clubhouse", "Vero", "Plurk", "Naver",
    # Messaging with profiles
    "Telegram", "Discord", "Signal", "Slack", "Kik", "Chatujme.cz",
    # Fediverse
    "mastodon.social", "mastodon.cloud", "mastodon.xyz", "Fosstodon",
    "Framapiaf", "Mamot", "mstdn.io", "chaos.social", "social.tchncs.de",
    "pixelfed.social", "minds",
    # Link-in-bio / about
    "About.me", "Linktree", "AllMyLinks", "Gravatar", "omg.lol", "F3.cool", "Listed",
    # Photo / video social
    "Flickr", "Imgur", "VSCO", "EyeEm", "YouPic", "SmugMug", "Blipfoto",
    "Clapper", "YouNow", "Periscope", "Rumble", "Vimeo", "DailyMotion",
    "Giphy", "Tenor",
    # Personal microblog / journal
    "LiveJournal", "Blogger",
    # People / social discovery
    "couchsurfing", "interpals", "datingRU", "Tellonym.me", "IRC-Galleria",
    # Music profiles (common OSINT identity)
    "last.fm", "MixCloud", "SoundCloud", "Spotify", "Smule", "ReverbNation",
    "Bandcamp", "YandexMusic",
    # Crypto-adjacent identity still used as social handle
    "Keybase", "IFTTT",
]

COMMUNITY_ALLOWLIST = [
    # Forums / discussion
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
    "Tweakers", "Dealabs", "PepperNL", "PepperPL",
    "NationStates Nation", "NationStates Region",
    "programming.dev", "DEV Community",
    "habr", "toster", "opennet", "phpRU", "d3RU", "nnRU", "satsisRU",
    "TrashboxRU", "babyblogRU", "spletnik", "irecommend", "drive2",
    "Velomania", "hunting", "geocaching", "BiggerPockets", "leasehackr",
    # Reading / fandom / media communities
    "GoodReads", "Letterboxd", "Trakt", "LibraryThing", "Rate Your Music",
    "Discogs", "Bookcrossing", "Wattpad", "Archive of Our Own",
    "MyAnimeList", "Anilist", "Mydramalist", "Fandom", "Fanpop",
    "Medium", "write.as", "note", "HubPages", "Scribd", "Issuu",
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
    "Outgress", "Scratch", "Clozemaster", "Duolingo", "Memrise",
    "Sporcle", "Football", "Championat", "SportsRU", "VLR",
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
    "GitBook", "Pastebin", "HackerOne", "BugCrowd",
    "HackTheBox", "TryHackMe", "Intigriti", "HackenProof (Hackers)",
    "CyberDefenders", "PentesterLab", "Holopin", "Apple Developer",
    "ProductHunt", "Career.habr",
    "sessionize", "Hackaday", "hackster", "Instructables", "Opensource",
    "Weblate", "Jellyfin Weblate", "Crowdin", "VirusTotal", "HudsonRock",
    "BioHacking", "eGPU", "Needrom", "fl", "kwork", "Freelancer",
    "Contently", "Coroflot", "Behance", "Dribbble", "ArtStation",
    "Carbonmade", "Crevado", "SpeakerDeck", "SlideShare", "Slides",
    "LottieFiles", "Sketchfab", "CGTrader", "Cults3D", "MyMiniFactory",
    "Polymart", "BOOTH", "ThemeForest", "Audiojungle",
    # Academic / research profiles (not "social networks")
    "ResearchGate", "Academia.edu", "Harvard Scholar",
    # Creator monetization (not core social)
    "Open Collective", "Patreon", "BuyMeACoffee", "kofi", "Gumroad",
    "CashApp", "Venmo",
]

_ALLOWLISTS = {
    "social": SOCIAL_ALLOWLIST,
    "community": COMMUNITY_ALLOWLIST,
    "gaming": GAMING_ALLOWLIST,
    "developer": DEVELOPER_ALLOWLIST,
}

# ---------------------------------------------------------------------------
_status_lock = threading.Lock()
_status: dict[str, Any] = {
    "ok": False,
    "error": "not loaded",
    "path": None,
    "sha256_16": None,
    "total_raw": 0,
    "total_usable": 0,
    "nsfw_excluded": 0,
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
            "Sherlock data.json not found (./data.json or package resources)."
        )
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict) or len(data) < 10:
        raise ValueError("data.json looks empty or invalid")
    return data, path


@lru_cache(maxsize=1)
def catalog() -> dict[str, list[str]]:
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

    # Priority order: social first (strict), then others
    for cat in ("social", "community", "gaming", "developer"):
        for name in _ALLOWLISTS[cat]:
            if name in usable and name not in assigned:
                by_cat[cat].append(name)
                assigned.add(name)
        by_cat[cat] = sorted(by_cat[cat], key=str.lower)

    by_cat["other"] = sorted((n for n in usable if n not in assigned), key=str.lower)

    digest = hashlib.sha256(path.read_bytes()).hexdigest()[:16]
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
        "Catalog OK path=%s usable=%d nsfw=%d counts=%s sha=%s",
        path, len(usable), nsfw, _status["counts"], digest,
    )
    return by_cat


def ensure_catalog() -> dict[str, list[str]]:
    try:
        return catalog()
    except Exception as exc:
        with _status_lock:
            _status.update({"ok": False, "error": str(exc), "counts": {}})
        log.error("Catalog load failed: %s", exc)
        raise RuntimeError(f"Каталог Sherlock недоступний: {exc}") from exc


def sites_for_mode(mode: str) -> list[str] | None:
    cats = ensure_catalog()
    mode = (mode or "social").lower().strip()
    if mode in ("full", "all"):
        return None
    if mode not in _ALLOWLISTS:
        mode = "social"
    return list(cats.get(mode, []))


def modes_public() -> list[dict]:
    """Only Social + Full for the UI."""
    cats = ensure_catalog()
    st = get_status()
    out = []
    for key, meta in CATEGORIES_META.items():
        if key == "full":
            count = int(st.get("total_usable") or 0)
        elif key == "social":
            count = len(cats.get("social", []))
        else:
            continue
        out.append({
            "id": key,
            "label": meta["label"],
            "emoji": meta["emoji"],
            "desc": meta["desc"],
            "count": count,
        })
    return out


def preload() -> None:
    try:
        ensure_catalog()
    except Exception:
        pass
