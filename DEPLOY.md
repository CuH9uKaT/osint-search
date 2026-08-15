# Deploy на Render

## 1. Репозиторій

1. Розпакуй `osint-search-web-final.zip` у Git-репозиторій.
2. GitHub Desktop → **Commit** → **Push**.

## 2. Web Service

- **Runtime:** Docker  
- **Branch:** main (або твоя)  
- **Auto-Deploy:** Yes  

## 3. Environment Variables (обов’язково)

| Key | Value | Примітка |
|-----|--------|----------|
| `APP_PASSWORD` | *сильний пароль* | **Обов’язково** |
| `SECRET_KEY` | generateValue або випадковий | У `render.yaml` вже generateValue |

### Рекомендовані (вже в render.yaml)

| Key | Default | Опис |
|-----|---------|------|
| `SHERLOCK_WORKERS` | `20` | Паралельні HTTP-запити (max 40) |
| `SITE_TIMEOUT` | `12` | Fallback per-site; режими мають свої значення |
| `SEARCH_TIMEOUT` | `180` | Fallback overall |
| `RATE_SECONDS` | `12` | Пауза між пошуками (IP+session) |

### Mode-specific (опційно)

| Key | Default |
|-----|---------|
| `SITE_TIMEOUT_SOCIAL` | 10 |
| `SEARCH_TIMEOUT_SOCIAL` | 120 |
| `SITE_TIMEOUT_COMMUNITY` | 12 |
| `SEARCH_TIMEOUT_COMMUNITY` | 150 |
| `SITE_TIMEOUT_GAMING` | 12 |
| `SEARCH_TIMEOUT_GAMING` | 150 |
| `SITE_TIMEOUT_DEVELOPER` | 12 |
| `SEARCH_TIMEOUT_DEVELOPER` | 150 |
| `SITE_TIMEOUT_FULL` | 12 |
| `SEARCH_TIMEOUT_FULL` | 210 |

## 4. Health check

Path: **`/healthz`**

## 5. Після деплою — checklist

1. Відкрий сайт → увійди з `APP_PASSWORD`.
2. ⚙️ Діагностика → `catalog.ok: true`, `workers`, counts.
3. Логи Render мають містити:
   ```
   CATALOG OK | total=462 | social=72 | ...
   SMOKE | sherlock=...
   ```
4. **Перший пошук:** режим **📱 Соцмережі**, свій username.
5. **Тест STOP (обов’язково):**
   - режим **Повний**
   - ПОШУК → зачекай ~15 с (мають з’явитись результати)
   - **СТОП**
   - статус «Скасовано», часткові результати лишились
   - новий пошук можна запустити

## 6. Який режим першим

| Мета | Режим | Орієнтовний час |
|------|--------|-----------------|
| Швидко перевірити людину | 📱 Соцмережі | десятки секунд |
| Форуми / читання | 💬 Спільноти | ~1–2 хв |
| Максимум покриття | 🌐 Повний | **1–3 хв** (free Render) |

На free tier **не запускай Full без потреби**. На сервері одночасно лише **один** Sherlock.

## 7. Типові проблеми

| Симптом | Дія |
|---------|-----|
| `APP_PASSWORD is required` | Додай env і Redeploy |
| `Каталог недоступний` | Переконайся, що `data.json` у корені образу |
| `Сервер зараз виконує інший пошук` | Зачекай або STOP з іншої вкладки того ж користувача |
| Пошук дуже довгий | Використовуй «Соцмережі»; не підвищуй workers на free Render. |


## Free Render (512MB) — важливо

- Default: `SHERLOCK_WORKERS=6`, `SITE_BATCH_SIZE=20` (сайти пакетами, не всі одразу).
- Перший тест: **лише 📱 Соцмережі**.
- Якщо знову `Ran out of memory` / 502:
  - `SHERLOCK_WORKERS=6`
  - `SITE_BATCH_SIZE=20`
  - `ALLOW_FULL_SEARCH=0`
- Не натискай ПОШУК повторно, поки йде активний job.


### Memory-safe Sherlock launcher
`run_sherlock.py` запускає Sherlock у дочірньому процесі та застосовує `SHERLOCK_WORKERS` саме всередині цього процесу. Це важливо: патч класу у Flask-процесі не впливає на окремий `python -m sherlock_project`. Для free Render базові значення — 6 workers, 20 сайтів у пакеті, ліміт дочірнього процесу 384 MB.
