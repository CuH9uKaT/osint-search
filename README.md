# OSINT Search (final)

Веб-обгортка над [Sherlock](https://github.com/sherlock-project/sherlock) 0.16.0:

- фоновий job, live-результати, реальний **STOP**
- pinned **`data.json`** (`--json`), NSFW виключено
- категорії: Соцмережі / Спільноти / Ігри / Розробка / Повний
- mode-specific timeouts + memory-safe `SHERLOCK_WORKERS` (default 6)
- auth, CSRF, 1 глобальний пошук, rate limit IP+session
- PWA, mobile UI, CSV/JSON/TXT, `/healthz`, діагностика

Деплой: див. **[DEPLOY.md](DEPLOY.md)**.

## Локально

```bash
export SECRET_KEY=$(python -c 'import secrets;print(secrets.token_hex(32))')
export APP_PASSWORD=devpass
export SHERLOCK_WORKERS=6
pip install -r requirements.txt
python app.py
```

## Режими (типові counts з bundled data.json)

| Режим | ~N | Timeout site / total |
|--------|-----|----------------------|
| 📱 Соцмережі | 72 | 10 / 120 с |
| 💬 Спільноти | 101 | 12 / 150 с |
| 🎮 Ігри | 49 | 12 / 150 с |
| 💻 Розробка | 100 | 12 / 150 с |
| 🌐 Повний | 462 | 12 / 210 с |

Точні числа — у UI та `/api/modes` після старту.

## Налаштування пам'яті

- `SHERLOCK_WORKERS=6` — кількість паралельних HTTP-запитів усередині Sherlock.
- `SITE_BATCH_SIZE=20` — скільки сайтів передається одному дочірньому запуску.
- `CHILD_MEMORY_MB=384` — жорсткий ліміт адресного простору Sherlock-процесу на Linux; батьківський Flask/Gunicorn не обмежується цим значенням.
- `ALLOW_FULL_SEARCH=0` — безпечне значення для free Render. Повний пошук можна ввімкнути лише після збільшення ресурсів і тесту.

## API (скорочено)

- `GET /api/modes` — режими, eta, warning
- `POST /api/search` `{username, mode}` → `job_id`
- `GET /api/search/<id>` — статус + results
- `POST /api/search/<id>/cancel`
- `POST /api/export` `{format: csv|json|txt}`
- `GET /api/diag` · `GET /healthz`

Mutating requests: header `X-CSRF-Token`.


### Memory-safe Sherlock launcher
`run_sherlock.py` запускає Sherlock у дочірньому процесі та застосовує `SHERLOCK_WORKERS` саме всередині цього процесу. Це важливо: патч класу у Flask-процесі не впливає на окремий `python -m sherlock_project`. Для free Render базові значення — 6 workers, 20 сайтів у пакеті, ліміт дочірнього процесу 384 MB.
