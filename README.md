# VFS Italy Notify

Скрипт следит за страницей записи italyvms.com и пишет в Telegram, когда
ответ от `get_nearest.htm` отличается от «На ближайшие 2 недели записи нет».

Капча reCAPTCHA v2 решается через [RuCaptcha](https://rucaptcha.com/)
(совместимо с 2captcha — достаточно поменять `RUCAPTCHA_HOST`).

## Как это работает

1. Скрипт запрашивает HTML формы и достаёт `data-sitekey` reCAPTCHA и токен
   сессии из параметра `t=` в URL.
2. Отправляет sitekey + URL формы в RuCaptcha и ждёт `g-recaptcha-response`.
3. Раз в `CHECK_INTERVAL_SECONDS` (по умолчанию 30 сек) дёргает
   `https://italyvms.com/vcs/get_nearest.htm` с этим токеном.
4. Если ответ отличается от строки `NO_SLOTS_TEXT` — отправляет текст ответа
   в Telegram.
5. Раз в `CAPTCHA_TTL_SECONDS` (по умолчанию 600 сек = 10 минут) перезаходит
   на страницу и заново решает капчу.

## Установка

Требуется Python 3.9+.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Настройка

1. Скопируйте `.env.example` в `.env` и заполните:
   - `URL` — полный URL формы записи (с актуальным `t=…&lang=ru`).
   - `RUCAPTCHA_API_KEY` — ключ из [личного кабинета RuCaptcha](https://rucaptcha.com/setting).
   - `TELEGRAM_BOT_TOKEN` — токен бота от [@BotFather](https://t.me/BotFather).
   - `TELEGRAM_CHAT_ID` — ваш chat_id (бот должен быть запущен; узнать id
     можно через [@userinfobot](https://t.me/userinfobot) или по
     `https://api.telegram.org/bot<TOKEN>/getUpdates` после `/start`).

2. (Опционально) Подкорректируйте интервалы и параметры запроса.

## Запуск

```powershell
python monitor.py
```

Скрипт пишет лог в stdout. Остановить — Ctrl+C.

### Запуск как сервис

На Windows проще всего использовать [NSSM](https://nssm.cc/) или Планировщик
заданий: запускать `python monitor.py` в каталоге проекта.

На Linux — systemd unit, при необходимости с `Restart=on-failure` и
`EnvironmentFile=/path/to/.env`.

## Полезные мелочи

- `DEDUPE_NOTIFICATIONS=true` (по умолчанию) — дублирующие подряд ответы не
  спамят в Telegram, новое сообщение уйдёт только при изменении ответа.
- Если RuCaptcha падает по балансу/таймауту, скрипт делает паузу 60 секунд и
  пробует заново.
- В случае пустого ответа или ответа, похожего на ошибку капчи, скрипт
  немедленно решает новую капчу, не дожидаясь окончания 10-минутного окна.
- Для других центров/категорий измените `CENTER`, `PERSONS`, `URGENT`, `LANG`.

## Файлы

- `monitor.py` — скрипт мониторинга.
- `requirements.txt` — зависимости.
- `.env.example` — шаблон конфигурации.
