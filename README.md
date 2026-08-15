# OSINT Search — Free Render safe

Вебінтерфейс для перевірки username через Sherlock на публічних сервісах.

## Режими

- **📱 Соцмережі** — основний режим, 72 сайти з поточного pinned `data.json`.
- **🌐 Повний** — вимкнений за замовчуванням на Free Render (`ALLOW_FULL_SEARCH=0`), бо 462 сайти можуть перевищити ліміт пам’яті 512 MB.

## Free Render safety

- Gunicorn: 1 worker / 2 threads
- `SHERLOCK_WORKERS=1`
- `SITE_BATCH_SIZE=5`
- `CHILD_MEMORY_MB=300`
- Social: `SITE_TIMEOUT_SOCIAL=15`, `SEARCH_TIMEOUT_SOCIAL=300`
- `MALLOC_ARENA_MAX=2`
- Один активний пошук на весь сервіс
- Пошук виконується пакетами; часткові результати зберігаються
- STOP завершує process group Sherlock

## Render Environment Variables

Обов’язково:

- `APP_PASSWORD` — задай власний сильний пароль у Render
- `SECRET_KEY` — Render генерує автоматично через `render.yaml`

Основні:

| Змінна | Значення |
|---|---:|
| `SHERLOCK_WORKERS` | `2` |
| `SITE_BATCH_SIZE` | `10` |
| `CHILD_MEMORY_MB` | `300` |
| `ALLOW_FULL_SEARCH` | `0` |
| `RATE_SECONDS` | `20` |
| `SITE_TIMEOUT_SOCIAL` | `15` |
| `SEARCH_TIMEOUT_SOCIAL` | `300` |

## Після деплою

1. Дочекайся `Live`.
2. Відкрий сайт.
3. Увійди за `APP_PASSWORD`.
4. Обери **📱 Соцмережі**.
5. Для першого тесту використай вигаданий username, наприклад `testuser123456`.
6. Натисни **ПОШУК один раз**.
7. Під час пошуку UI показує пакет `X/Y`; не запускай другий пошук.

Очікувано: Social перевіряється пакетами по 5 сайтів. На Free Render перший запуск після cold start може бути повільнішим.

## Важливо

Результат Sherlock означає лише те, що публічна сторінка пройшла його перевірку username. Це не доводить, що профіль належить конкретній особі. Будь-які збіги потрібно перевіряти незалежно та використовувати лише законно доступну публічну інформацію.
