"""Monitor italyvms.com for available appointment slots.

Workflow:
  1. Fetch the booking page and extract reCAPTCHA sitekey + session token.
  2. Submit the captcha to RuCaptcha (or 2captcha) and wait for the solved
     g-recaptcha-response token.
  3. Every CHECK_INTERVAL_SECONDS query /vcs/get_nearest.htm. If the response
     differs from the "no slots" sentinel, push it to Telegram.
  4. Every CAPTCHA_TTL_SECONDS reload the page and re-solve the captcha.
"""

from __future__ import annotations

import html
import logging
import os
import re
import signal
import sys
import time
from typing import Tuple
from urllib.parse import parse_qs, urlparse

import requests
from dotenv import load_dotenv

load_dotenv()


URL = (os.getenv("URL") or "").strip()
RUCAPTCHA_KEY = (os.getenv("RUCAPTCHA_API_KEY") or "").strip()
TG_TOKEN = (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()
TG_CHAT = (os.getenv("TELEGRAM_CHAT_ID") or "").strip()

CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL_SECONDS", "30"))
CAPTCHA_TTL = int(os.getenv("CAPTCHA_TTL_SECONDS", "600"))
NO_SLOTS_TEXT = os.getenv("NO_SLOTS_TEXT", "На ближайшие 2 недели записи нет").strip()
RUCAPTCHA_HOST = os.getenv("RUCAPTCHA_HOST", "https://rucaptcha.com").rstrip("/")
DEDUPE = (os.getenv("DEDUPE_NOTIFICATIONS", "true").strip().lower()
          in ("1", "true", "yes", "on"))

CENTER = os.getenv("CENTER", "11")
PERSONS = os.getenv("PERSONS", "1")
URGENT = os.getenv("URGENT", "0")
LANG = os.getenv("LANG", "ru")

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

REQUEST_TIMEOUT = 30
RUCAPTCHA_POLL_INTERVAL = 5
RUCAPTCHA_FIRST_WAIT = 15
RUCAPTCHA_MAX_WAIT = 180

NEAREST_URL = "https://italyvms.com/vcs/get_nearest.htm"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("italyvms")


class CaptchaError(Exception):
    pass


class PageError(Exception):
    pass


_stop = False


def _handle_signal(signum, _frame):
    global _stop
    log.info("Получен сигнал %s — останавливаюсь после текущего цикла…", signum)
    _stop = True


def require_env() -> None:
    missing = [
        name for name, val in (
            ("URL", URL),
            ("RUCAPTCHA_API_KEY", RUCAPTCHA_KEY),
            ("TELEGRAM_BOT_TOKEN", TG_TOKEN),
            ("TELEGRAM_CHAT_ID", TG_CHAT),
        ) if not val
    ]
    if missing:
        log.error("Не заполнены переменные окружения: %s", ", ".join(missing))
        log.error("Скопируйте .env.example в .env и заполните значения.")
        sys.exit(1)


def fetch_page(session: requests.Session) -> Tuple[str, str]:
    """Загружает страницу и возвращает (sitekey, session_token)."""
    log.info("Загружаю страницу: %s", URL)
    resp = session.get(URL, timeout=REQUEST_TIMEOUT)
    resp.raise_for_status()
    text = resp.text

    sitekey_match = re.search(r'data-sitekey="([^"]+)"', text)
    if not sitekey_match:
        raise PageError("Не удалось найти data-sitekey reCAPTCHA на странице")
    sitekey = sitekey_match.group(1)

    parsed = urlparse(URL)
    qs = parse_qs(parsed.query)
    token = (qs.get("t", [""])[0] or "").strip()
    if not token:
        token_match = re.search(r"'token'\s*:\s*'([^']+)'", text)
        if not token_match:
            raise PageError("Не удалось найти токен сессии (параметр t)")
        token = token_match.group(1)

    log.info("Sitekey: %s; токен сессии: %s…", sitekey, token[:24])
    return sitekey, token


def solve_recaptcha(sitekey: str, page_url: str) -> str:
    """Отправляет капчу в RuCaptcha и возвращает решённый токен."""
    log.info("Отправляю reCAPTCHA в RuCaptcha…")
    in_resp = requests.post(
        f"{RUCAPTCHA_HOST}/in.php",
        data={
            "key": RUCAPTCHA_KEY,
            "method": "userrecaptcha",
            "googlekey": sitekey,
            "pageurl": page_url,
            "json": 1,
        },
        timeout=REQUEST_TIMEOUT,
    )
    in_resp.raise_for_status()
    in_data = in_resp.json()
    if in_data.get("status") != 1:
        raise CaptchaError(f"RuCaptcha отклонила задание: {in_data.get('request')}")

    captcha_id = in_data["request"]
    log.info("Задача RuCaptcha id=%s, ждём решения…", captcha_id)

    time.sleep(RUCAPTCHA_FIRST_WAIT)
    deadline = time.time() + RUCAPTCHA_MAX_WAIT
    while time.time() < deadline:
        if _stop:
            raise CaptchaError("Остановлено пользователем во время ожидания капчи")
        try:
            res_resp = requests.get(
                f"{RUCAPTCHA_HOST}/res.php",
                params={
                    "key": RUCAPTCHA_KEY,
                    "action": "get",
                    "id": captcha_id,
                    "json": 1,
                },
                timeout=REQUEST_TIMEOUT,
            )
            res_resp.raise_for_status()
            data = res_resp.json()
        except (ValueError, requests.RequestException) as exc:
            log.warning("Ошибка опроса RuCaptcha: %s", exc)
            time.sleep(RUCAPTCHA_POLL_INTERVAL)
            continue

        if data.get("status") == 1:
            log.info("Капча решена RuCaptcha.")
            return data["request"]

        request = (data.get("request") or "").upper()
        if request == "CAPCHA_NOT_READY":
            time.sleep(RUCAPTCHA_POLL_INTERVAL)
            continue
        raise CaptchaError(f"Ошибка RuCaptcha: {request}")

    raise CaptchaError("Истёк таймаут ожидания решения капчи")


def report_bad_captcha(captcha_id: str) -> None:
    """Сообщить RuCaptcha, что токен не сработал — обычно частичный возврат средств."""
    try:
        requests.get(
            f"{RUCAPTCHA_HOST}/res.php",
            params={
                "key": RUCAPTCHA_KEY,
                "action": "reportbad",
                "id": captcha_id,
                "json": 1,
            },
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        pass


def strip_html(s: str) -> str:
    """Снимаем теги и нормализуем пробелы."""
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def check_nearest(session: requests.Session, token: str, captcha_token: str) -> str:
    """Запрашиваем get_nearest.htm и возвращаем тело ответа."""
    params = {
        "center": CENTER,
        "persons": PERSONS,
        "urgent": URGENT,
        "token": token,
        "g-recaptcha-response": captcha_token,
        "lang": LANG,
    }
    headers = {
        "Referer": URL,
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "*/*",
    }
    resp = session.get(
        NEAREST_URL,
        params=params,
        headers=headers,
        timeout=REQUEST_TIMEOUT,
    )
    resp.raise_for_status()
    return resp.text


def notify_telegram(text: str) -> bool:
    """Отправить сообщение в Telegram. Возвращает True при успехе."""
    api = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    try:
        resp = requests.post(
            api,
            data={
                "chat_id": TG_CHAT,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        log.error("Не удалось отправить сообщение в Telegram: %s", exc)
        return False

    if resp.status_code != 200:
        log.error("Telegram API вернул %s: %s", resp.status_code, resp.text)
        return False
    log.info("Уведомление отправлено в Telegram.")
    return True


def looks_like_captcha_failure(stripped: str) -> bool:
    """Эвристика: ответ говорит о провале капчи — нужна новая."""
    if not stripped:
        return True
    needle = stripped.lower()
    keywords = ("captcha", "recaptcha", "капча", "капчу", "капчи")
    return any(k in needle for k in keywords)


def sleep_interruptible(seconds: float) -> None:
    """time.sleep, но ломается, если прилетает SIGINT/SIGTERM."""
    end = time.time() + seconds
    while not _stop and time.time() < end:
        time.sleep(min(1.0, end - time.time()))


def build_message(stripped: str) -> str:
    return (
        "<b>Italy VMS — есть изменение по записи!</b>\n"
        f"<b>Ответ:</b> {html.escape(stripped)}\n"
        f'<a href="{html.escape(URL, quote=True)}">Открыть форму</a>'
    )


def cycle(session: requests.Session) -> None:
    """Один цикл: страница + капча + опросы в течение CAPTCHA_TTL."""
    sitekey, token = fetch_page(session)
    captcha_token = solve_recaptcha(sitekey, URL)

    captcha_deadline = time.time() + CAPTCHA_TTL
    last_notified: str | None = None
    first_check = True
    consecutive_failures = 0

    while not _stop and time.time() < captcha_deadline:
        if not first_check:
            sleep_interruptible(CHECK_INTERVAL)
            if _stop:
                return
        first_check = False

        try:
            raw = check_nearest(session, token, captcha_token)
        except requests.RequestException as exc:
            log.warning("Ошибка запроса get_nearest.htm: %s", exc)
            consecutive_failures += 1
            if consecutive_failures >= 5:
                log.warning("Слишком много сетевых ошибок — обновляю капчу.")
                return
            continue

        consecutive_failures = 0
        stripped = strip_html(raw)
        preview = stripped if len(stripped) <= 300 else stripped[:300] + "…"
        log.info("Ответ get_nearest: %s", preview or "<пусто>")

        if stripped == NO_SLOTS_TEXT:
            last_notified = NO_SLOTS_TEXT
            continue

        if looks_like_captcha_failure(stripped):
            log.warning("Похоже на ошибку капчи — пересолвлю.")
            return

        if DEDUPE and stripped == last_notified:
            log.info("Тот же ответ, что и в прошлый раз — уведомление не дублирую.")
            continue

        if notify_telegram(build_message(stripped)):
            last_notified = stripped

    if not _stop:
        log.info("Прошло %s сек — обновляю страницу и капчу.", CAPTCHA_TTL)


def main() -> None:
    require_env()
    signal.signal(signal.SIGINT, _handle_signal)
    try:
        signal.signal(signal.SIGTERM, _handle_signal)
    except (AttributeError, ValueError):
        pass

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    log.info(
        "Старт: проверка раз в %s сек; капча обновляется каждые %s сек.",
        CHECK_INTERVAL, CAPTCHA_TTL,
    )

    while not _stop:
        try:
            cycle(session)
        except (PageError, CaptchaError) as exc:
            log.error("Ошибка цикла: %s. Пауза 60 сек и пробуем заново.", exc)
            sleep_interruptible(60)
        except requests.RequestException as exc:
            log.error("Сетевая ошибка: %s. Пауза 60 сек.", exc)
            sleep_interruptible(60)
        except Exception:
            log.exception("Неожиданная ошибка в цикле — пауза 60 сек.")
            sleep_interruptible(60)

    log.info("Скрипт остановлен.")


if __name__ == "__main__":
    main()
