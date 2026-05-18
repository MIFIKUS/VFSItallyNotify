"""Monitor italyvms.com for appointment time slots via get_times.htm.

Workflow:
  1. Fetch the booking page and extract reCAPTCHA sitekey, session token,
     and fdate (параметр последней возможной даты из JS на странице).
     Requests use optional proxies from ITALYVMS_PROXY_FILE and/or
     ITALYVMS_PROXIES (URL or host:port:user:pass per line; same Session).
  2. Submit the captcha to RuCaptcha (or 2captcha) and wait for the solved
     g-recaptcha-response token (без прокси — напрямую к RuCaptcha).
  3. Every CHECK_INTERVAL_SECONDS, for each weekday from today through the
     lookahead window, request /vcs/get_times.htm sequentially with a pause
     between dates (rate limiting).
     Если ответ «слишком много запросов» — смена прокси и повтор запроса.
     Responses that only indicate an invalid past date are ignored; captcha
     failures trigger an immediate re-solve; other non-empty responses go to
     Telegram.
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
from datetime import date, timedelta
from urllib.parse import parse_qs, quote, urlparse

import requests
from dotenv import load_dotenv

load_dotenv()


URL = (os.getenv("URL") or "").strip()
RUCAPTCHA_KEY = (os.getenv("RUCAPTCHA_API_KEY") or "").strip()
TG_TOKEN = (os.getenv("TELEGRAM_BOT_TOKEN") or "").strip()
TG_CHAT = (os.getenv("TELEGRAM_CHAT_ID") or "").strip()

CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL_SECONDS", "30"))
CAPTCHA_TTL = int(os.getenv("CAPTCHA_TTL_SECONDS", "600"))
RUCAPTCHA_HOST = os.getenv("RUCAPTCHA_HOST", "https://rucaptcha.com").rstrip("/")
DEDUPE = (os.getenv("DEDUPE_NOTIFICATIONS", "true").strip().lower()
          in ("1", "true", "yes", "on"))

CENTER = os.getenv("CENTER", "11")
PERSONS = os.getenv("PERSONS", "1")
LANG = os.getenv("LANG", "ru")

VTYPE = os.getenv("VTYPE", "13")
CATEGORY = os.getenv("CATEGORY", "C")
URGENT_ALLOWED = os.getenv("URGENT_ALLOWED", "1").strip()
# Запасной fdate, если на странице не удалось распознать (обычно не нужен).
FDATE_ENV = (os.getenv("FDATE") or "").strip()
LOOKAHEAD_DAYS = int(os.getenv("LOOKAHEAD_DAYS", "62"))
GET_TIMES_DELAY_SECONDS = max(0.0, float(os.getenv("GET_TIMES_DELAY_SECONDS", "1")))

INVALID_DATE_PHRASE = (
    "неверная дата - должна быть больше или равна текущей"
)
NO_SUITABLE_INTERVALS_PHRASE = "нет подходящих временных интервалов"
HOLIDAY_DATE_PHRASE = "неверная дата - дата в списке праздников"
RATE_LIMIT_PHRASE = "слишком много запросов"

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)

REQUEST_TIMEOUT = 30
RUCAPTCHA_POLL_INTERVAL = 5
RUCAPTCHA_FIRST_WAIT = 15
RUCAPTCHA_MAX_WAIT = 180

TIMES_URL = "https://italyvms.com/vcs/get_times.htm"
CONFIGURED_PROXY_FILE = (os.getenv("ITALYVMS_PROXY_FILE") or "").strip()
PROXY_SCHEME = (os.getenv("ITALYVMS_PROXY_SCHEME") or "http").strip().rstrip("://")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("italyvms")


def _resolve_proxy_file(path: str) -> str:
    """Путь к файлу прокси: абсолютный, cwd или каталог monitor.py."""
    expanded = os.path.expanduser(os.path.expandvars(path.strip()))
    if os.path.isfile(expanded):
        return os.path.abspath(expanded)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(script_dir, expanded)
    if os.path.isfile(candidate):
        return candidate
    return expanded


def _normalize_proxy_line(line: str) -> str | None:
    """Строка прокси → URL для requests (http/socks или host:port:user:pass)."""
    u = line.strip()
    if not u or u.startswith("#"):
        return None
    lower = u.lower()
    if lower.startswith(("http://", "https://", "socks4://", "socks5://")):
        return u
    if "@" in u and "://" not in u:
        return f"{PROXY_SCHEME}://{u}"
    parts = u.split(":")
    if len(parts) == 4:
        if parts[1].isdigit():
            host, port, user, password = parts
        elif parts[-1].isdigit():
            user, password, host, port = parts
        else:
            log.warning("Неизвестный формат прокси, пропуск: %s", parts[0])
            return None
        return (
            f"{PROXY_SCHEME}://{quote(user, safe='')}:{quote(password, safe='')}"
            f"@{host}:{port}"
        )
    if len(parts) == 2 and parts[1].isdigit():
        return f"{PROXY_SCHEME}://{parts[0]}:{parts[1]}"
    log.warning("Неизвестный формат прокси, пропуск: %s", parts[0] if parts else u)
    return None


def _read_proxy_urls_from_file(path: str) -> list[str]:
    """Читает прокси из файла (URL или host:port:user:pass на строку)."""
    resolved = _resolve_proxy_file(path)
    try:
        with open(resolved, encoding="utf-8-sig") as fh:
            lines = fh.readlines()
    except OSError as exc:
        log.error("Не удалось прочитать файл прокси %s: %s", resolved, exc)
        sys.exit(1)
    urls: list[str] = []
    for line in lines:
        url = _normalize_proxy_line(line)
        if url:
            urls.append(url)
    return urls


def _parse_proxy_urls() -> list[str]:
    """Прокси из ITALYVMS_PROXY_FILE (приоритетно), затем из ITALYVMS_PROXIES."""
    urls: list[str] = []
    if CONFIGURED_PROXY_FILE:
        urls.extend(_read_proxy_urls_from_file(CONFIGURED_PROXY_FILE))
    raw = (os.getenv("ITALYVMS_PROXIES") or "").strip()
    if raw:
        for chunk in raw.replace(",", "\n").splitlines():
            url = _normalize_proxy_line(chunk)
            if url:
                urls.append(url)
    return urls


PROXY_URLS = _parse_proxy_urls()
_proxy_index = 0


class CaptchaError(Exception):
    pass


class PageError(Exception):
    pass


_stop = False


def _handle_signal(signum, _frame):
    global _stop
    log.info("Получен сигнал %s — останавливаюсь после текущего цикла…", signum)
    _stop = True


def apply_proxy_to_session(session: requests.Session) -> None:
    """Задаёт session.proxies по текущему индексу или отключает прокси."""
    if not PROXY_URLS:
        session.proxies.clear()
        return
    idx = _proxy_index % len(PROXY_URLS)
    url = PROXY_URLS[idx]
    session.proxies = {"http": url, "https": url}


def rate_limit_max_attempts() -> int:
    """Сколько раз пробовать get_times при ответе о лимите (со сменой прокси)."""
    n = len(PROXY_URLS)
    if n >= 2:
        return n
    return 2


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
        log.error("Скопируйте шаблон .env и заполните значения.")
        sys.exit(1)


def _parse_dd_mm_yyyy(value: str) -> date | None:
    """Проверка и разбор даты в формате ДД.ММ.ГГГГ (как на сайте)."""
    parts = value.strip().split(".")
    if len(parts) != 3:
        return None
    try:
        d, m, y = (int(parts[0]), int(parts[1]), int(parts[2]))
    except ValueError:
        return None
    try:
        return date(y, m, d)
    except ValueError:
        return None


def extract_fdate_from_page(page_html: str) -> str | None:
    """Достаёт значение fdate из inline JS формы.

    На странице встречается вид `'fdate': '01.10.2026'` (между именем ключа и «:»
    стоит закрывающая кавычка), поэтому нужен паттерн вида fdate'?: …
    """
    patterns = (
        r"fdate['\"]?\s*:\s*['\"](\d{2}\.\d{2}\.\d{4})['\"]",
        r"['\"]fdate['\"]?\s*:\s*['\"](\d{2}\.\d{2}\.\d{4})['\"]",
        r"fdate\s*=\s*['\"](\d{2}\.\d{2}\.\d{4})['\"]",
        r'"fdate"\s*:\s*"(\d{2}\.\d{2}\.\d{4})"',
    )
    for pat in patterns:
        m = re.search(pat, page_html, flags=re.I)
        if not m:
            continue
        cand = m.group(1)
        parsed = _parse_dd_mm_yyyy(cand)
        if parsed is None:
            continue
        # Заглушка в разметке сайта
        if cand == "99.99.9999":
            continue
        return cand
    return None


def fetch_page(session: requests.Session) -> tuple[str, str, str]:
    """Загружает страницу и возвращает (sitekey, session_token, fdate)."""
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

    fdate_val = extract_fdate_from_page(text)
    if not fdate_val and FDATE_ENV:
        if _parse_dd_mm_yyyy(FDATE_ENV):
            fdate_val = FDATE_ENV
            log.info("fdate из переменной окружения FDATE: %s", fdate_val)
    if not fdate_val:
        raise PageError(
            "Не удалось извлечь fdate со страницы формы; при необходимости задайте FDATE в .env"
        )

    log.info(
        "Sitekey: %s; токен сессии: %s…; fdate: %s",
        sitekey,
        token[:24],
        fdate_val,
    )
    return sitekey, token, fdate_val


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


def strip_html(s: str) -> str:
    """Снимаем теги и нормализуем пробелы."""
    s = re.sub(r"<[^>]+>", " ", s)
    s = html.unescape(s)
    s = re.sub(r"\s+", " ", s).strip()
    return s


def weekday_dates_in_window(last_day: date) -> list[date]:
    """Все дни с сегодня (локальный календарь) по last_day включительно, без Сб–Вс."""
    today = date.today()
    out: list[date] = []
    d = today
    while d <= last_day:
        if d.weekday() < 5:
            out.append(d)
        d += timedelta(days=1)
    return out


def is_rate_limited_response(stripped: str) -> bool:
    return RATE_LIMIT_PHRASE in stripped.lower()


def query_times_for_date(
    session: requests.Session,
    app_day: date,
    token: str,
    captcha_token: str,
    fdate_val: str,
) -> tuple[str, str]:
    """Запрос get_times.htm через session (cookies + прокси); при лимите — смена прокси и повтор."""
    appdate_str = app_day.strftime("%d.%m.%Y")
    params = {
        "vtype": VTYPE,
        "category": CATEGORY,
        "center": CENTER,
        "persons": PERSONS,
        "appdate": appdate_str,
        "urgent_allowed": URGENT_ALLOWED,
        "fdate": fdate_val,
        "token": token,
        "g-recaptcha-response": captcha_token,
        "lang": LANG,
    }
    headers = {
        "Referer": URL,
        "X-Requested-With": "XMLHttpRequest",
        "Accept": "*/*",
    }
    max_attempts = rate_limit_max_attempts()
    last_raw = ""
    for attempt in range(max_attempts):
        resp = session.get(
            TIMES_URL,
            params=params,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        last_raw = resp.text
        st = strip_html(last_raw)
        if not is_rate_limited_response(st):
            return appdate_str, last_raw
        log.warning(
            "Ответ лимита запросов для %s (попытка %s/%s).",
            appdate_str,
            attempt + 1,
            max_attempts,
        )
        if attempt + 1 >= max_attempts:
            return appdate_str, last_raw
        rotate_proxy(session)
    return appdate_str, last_raw


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


def is_ignored_times_response(stripped: str) -> bool:
    """Ответы, на которые не шлём уведомление в Telegram."""
    low = stripped.lower()
    if INVALID_DATE_PHRASE in low:
        return True
    if NO_SUITABLE_INTERVALS_PHRASE in low:
        return True
    if HOLIDAY_DATE_PHRASE in low:
        return True
    if RATE_LIMIT_PHRASE in low:
        return True
    return False


def sleep_interruptible(seconds: float) -> None:
    """time.sleep, но ломается, если прилетает SIGINT/SIGTERM."""
    end = time.time() + seconds
    while not _stop and time.time() < end:
        time.sleep(min(1.0, end - time.time()))


def rotate_proxy(session: requests.Session) -> None:
    """Следующий прокси из списка или пауза, если прокси не заданы."""
    global _proxy_index
    if PROXY_URLS:
        _proxy_index = (_proxy_index + 1) % len(PROXY_URLS)
        apply_proxy_to_session(session)
        log.info(
            "Прокси: #%s из %s",
            (_proxy_index % len(PROXY_URLS)) + 1,
            len(PROXY_URLS),
        )
        if len(PROXY_URLS) == 1:
            sleep_interruptible(5)
        return
    log.warning(
        "Лимит запросов: не задан ITALYVMS_PROXY_FILE и ITALYVMS_PROXIES — пауза 3 с перед повтором."
    )
    sleep_interruptible(3)


def build_times_message(appdate_str: str, stripped: str) -> str:
    return (
        "<b>Italy VMS — ответ get_times</b>\n"
        f"<b>Дата записи:</b> {html.escape(appdate_str)}\n"
        f"<b>Ответ:</b> {html.escape(stripped)}\n"
        f'<a href="{html.escape(URL, quote=True)}">Открыть форму</a>'
    )


def scan_all_dates(
    session: requests.Session,
    token: str,
    captcha_token: str,
    fdate_val: str,
    last_notified_by_date: dict[str, str],
) -> tuple[bool, int, int]:
    """Опрашивает все целевые даты по одному запросу с паузой между датами.

    Возвращает (captcha_bad, net_errors, total_dates).
    """
    last_day = date.today() + timedelta(days=LOOKAHEAD_DAYS)
    dates = weekday_dates_in_window(last_day)
    log.info(
        "Опрос get_times: %s будних дней с %s по %s (окно %s дн.), пауза %s с между запросами",
        len(dates),
        dates[0].strftime("%d.%m.%Y") if dates else "—",
        last_day.strftime("%d.%m.%Y"),
        LOOKAHEAD_DAYS,
        GET_TIMES_DELAY_SECONDS,
    )

    captcha_bad = False
    net_errors = 0

    first_date = True
    for d in dates:
        if _stop:
            break
        if not first_date and GET_TIMES_DELAY_SECONDS > 0:
            sleep_interruptible(GET_TIMES_DELAY_SECONDS)
        first_date = False

        try:
            appdate_str, raw = query_times_for_date(
                session,
                d,
                token,
                captcha_token,
                fdate_val,
            )
        except requests.RequestException as exc:
            log.warning("Ошибка запроса get_times: %s", exc)
            net_errors += 1
            continue

        stripped = strip_html(raw)
        preview = stripped if len(stripped) <= 200 else stripped[:200] + "…"
        log.info("[%s] %s", appdate_str, preview or "<пусто>")

        if is_rate_limited_response(stripped):
            log.warning("[%s] Лимит запросов после всех попыток смены прокси.", appdate_str)
            net_errors += 1
            continue

        if is_ignored_times_response(stripped):
            continue

        if looks_like_captcha_failure(stripped):
            log.warning("[%s] Похоже на ошибку капчи — пересолвлю.", appdate_str)
            captcha_bad = True
            break

        if not stripped:
            continue

        if DEDUPE and last_notified_by_date.get(appdate_str) == stripped:
            log.info("[%s] Тот же ответ — пропуск дубликата.", appdate_str)
            continue

        if notify_telegram(build_times_message(appdate_str, stripped)):
            last_notified_by_date[appdate_str] = stripped

    return captcha_bad, net_errors, len(dates)


def cycle(session: requests.Session) -> None:
    """Один цикл: страница + капча + опросы в течение CAPTCHA_TTL."""
    sitekey, token, fdate_val = fetch_page(session)
    captcha_token = solve_recaptcha(sitekey, URL)

    captcha_deadline = time.time() + CAPTCHA_TTL
    last_notified_by_date: dict[str, str] = {}
    first_check = True
    consecutive_failures = 0

    while not _stop and time.time() < captcha_deadline:
        if not first_check:
            sleep_interruptible(CHECK_INTERVAL)
            if _stop:
                return
        first_check = False

        try:
            captcha_bad, errs, n_dates = scan_all_dates(
                session, token, captcha_token, fdate_val, last_notified_by_date
            )
        except requests.RequestException as exc:
            log.warning("Сетевая ошибка при сканировании дат: %s", exc)
            consecutive_failures += 1
            if consecutive_failures >= 5:
                log.warning("Много сетевых ошибок — обновляю страницу и капчу.")
                return
            continue

        consecutive_failures = 0
        if n_dates and errs >= max(5, n_dates // 2):
            log.warning(
                "Большая доля запросов get_times завершилась ошибкой (%s) — "
                "обновляю страницу и капчу.",
                errs,
            )
            return

        if captcha_bad:
            return

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
    apply_proxy_to_session(session)
    if PROXY_URLS:
        parts: list[str] = []
        if CONFIGURED_PROXY_FILE:
            parts.append(f"файл {CONFIGURED_PROXY_FILE}")
        if (os.getenv("ITALYVMS_PROXIES") or "").strip():
            parts.append("ITALYVMS_PROXIES")
        log.info(
            "Прокси для italyvms: %s адрес(ов) [%s].",
            len(PROXY_URLS),
            "; ".join(parts) if parts else "?",
        )
    else:
        log.info(
            "Прокси не заданы (пусты ITALYVMS_PROXY_FILE и ITALYVMS_PROXIES) — прямое подключение."
        )

    log.info(
        "Старт: get_times по будням на %s дней вперёд; пауза между датами %s с; "
        "пауза между полными проходами %s сек; капча каждые %s сек.",
        LOOKAHEAD_DAYS,
        GET_TIMES_DELAY_SECONDS,
        CHECK_INTERVAL,
        CAPTCHA_TTL,
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
