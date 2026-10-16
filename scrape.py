#!/usr/bin/env python3
"""Senate eFD relay scraper — in-house Congressional Alpha Hunter infrastructure.

Scrapes U.S. Senate Electronic Financial Disclosure (eFD) Periodic Transaction
Reports (STOCK Act) and publishes them as clean JSON. Runs on GitHub Actions
(the Senate's Akamai edge blocks datacenter IPs; Actions runners are not
blocked). Output is consumed by the Congressional Alpha Hunter research
pipeline via raw.githubusercontent.com.

NON-COMMERCIAL RESEARCH USE ONLY (5 U.S.C. 13107(c) / EIGA: no commercial use
of disclosure data). Rows are normalized facts; no conclusions about any
member are drawn here.

Flow
----
1. Polite session handshake: GET /search/home/, accept the per-session EULA
   click-through, retain session cookies + CSRF token.
2. POST /search/report/data/ (DataTables server-side protocol,
   report_types=[11] = Periodic Transaction Reports), paginated.
3. For each electronically-filed PTR UUID: GET /search/view/ptr/{uuid}/
   and parse the structured transaction table.
4. Write data/latest.json + data/snapshots/ptr_<timestamp>.json.

Politeness
----------
- >=2s between every request.
- Exponential backoff with jitter on transient network errors / HTTP 5xx.
- HARD STOP on HTTP 403 / 429 or Akamai challenge pages: one clear log line,
  no retry, no evasion. Run aborts; the previous good snapshot is kept.

Normalization is byte-identical to ingest/senate_efd.py in the main pipeline
repo (helpers copied verbatim) so relay JSON matches pipeline expectations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import random
import re
import sys
import time
from datetime import date, datetime, timedelta, timezone

import requests
from bs4 import BeautifulSoup

# ---------------------------------------------------------------- SITE
BASE = "https://efdsearch.senate.gov"
HOME_PATH = "/search/home/"
DATA_PATH = "/search/report/data/"
PTR_VIEW_PATH = "/search/view/ptr/{uuid}/"

PTR_REPORT_TYPE = 11  # eFD report-type id for Periodic Transaction Reports

DT_FIELDS = {
    "draw": "draw",
    "start": "start",
    "length": "length",
    "report_types": "report_types",
    "from_date": "from_date",
    "to_date": "to_date",
    "filer_name": "filer_name",
}
DT_PAGE_LENGTH = 100

EXPECTED_HEADERS = [
    "transaction date", "owner", "ticker", "asset description",
    "asset type", "type", "amount", "comment",
]

CHALLENGE_MARKERS = (
    "_abck", "sensor_data", "akamai", "bot manager", "access denied",
    "request denied", "reference #", "please verify you are a human",
    "are you a robot", "perimeterx", "datadome",
)

USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
MIN_INTERVAL = 2.0
BACKOFF_BASE = 3.0
BACKOFF_ATTEMPTS = 4

# ---------------------------------------------------------------- helpers (verbatim from pipeline ingest/db.py)


def _canon_value(v):
    if v is None:
        return None
    if isinstance(v, float) and math.isnan(v):
        return None
    if isinstance(v, (datetime,)):
        return v.isoformat()
    if isinstance(v, (date,)):
        return v.isoformat()
    if isinstance(v, float) and v.is_integer():
        return int(v)
    if hasattr(v, "item"):
        try:
            return _canon_value(v.item())
        except Exception:
            return str(v)
    return v


def canonical_json(obj) -> str:
    if isinstance(obj, dict):
        obj = {k: _canon_value(v) for k, v in obj.items()}
    elif isinstance(obj, (list, tuple)):
        obj = [_canon_value(v) for v in obj]
    else:
        obj = _canon_value(obj)
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(",", ":"))


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def now_utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


_ASSET_TYPE_BY_CODE = {
    "ST": "stock", "GS": "bond", "CS": "bond", "OP": "option", "PS": "stock",
}

_RE_OPTION_WORD = re.compile(r"\boptions?\b", re.I)
_RE_CALL_PUT = re.compile(r"\b(call|put)\b", re.I)
_RE_BOND = re.compile(r"\b(bonds?|treasury|treasuries|municipal|debentures?)\b", re.I)
_RE_NOTE = re.compile(r"\bnotes?\b", re.I)
_RE_MF = re.compile(r"\bmutual fund\b", re.I)

_RE_STRIKE1 = re.compile(r"strike\s*price\s*\$?\s*([\d,]+(?:\.\d+)?)", re.I)
_RE_STRIKE2 = re.compile(r"\b(?:call|put)\s+options?,?\s*\$([\d,]+(?:\.\d+)?)", re.I)
_RE_EXPIRY1 = re.compile(r"exp(?:ires?|\.)?\s*(\d{1,2}/\d{1,2}/\d{2,4})", re.I)
_RE_EXPIRY2 = re.compile(
    r"\b(JAN|FEB|MAR|APR|MAY|JUN|JUL|AUG|SEP|OCT|NOV|DEC)[a-z]*\s+(\d{1,2})"
    r"(?:\s*,?\s*(\d{2}|\d{4}))?\s+([\d.]+)\s+(call|put)\b", re.I)
_MONTHS = {m: i + 1 for i, m in enumerate(
    ["JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC"])}


def map_asset_type(asset_type_code, asset_description, comment, ticker):
    code = (asset_type_code or "").strip().upper() or None
    if code in _ASSET_TYPE_BY_CODE:
        return _ASSET_TYPE_BY_CODE[code]
    text = " ".join(x for x in [asset_description, comment] if x)
    if _RE_OPTION_WORD.search(text) or (_RE_CALL_PUT.search(text)
                                        and ("strike" in text.lower() or "expir" in text.lower())):
        return "option"
    if _RE_BOND.search(text) or _RE_NOTE.search(text):
        return "bond"
    if _RE_MF.search(text):
        return "mutual fund"
    if ticker:
        return "stock"
    return "other"


def parse_option_fields(asset_description, comment, trade_date_iso):
    text = " ".join(x for x in [asset_description, comment] if x)
    if not text:
        return None, None, None
    m = _RE_CALL_PUT.search(text)
    otype = m.group(1).lower() if m else None
    strike = None
    m = _RE_STRIKE1.search(text) or _RE_STRIKE2.search(text)
    if m:
        try:
            strike = float(m.group(1).replace(",", ""))
        except ValueError:
            strike = None
    expiry = None
    m = _RE_EXPIRY1.search(text)
    if m:
        parts = m.group(1).split("/")
        try:
            mm, dd, yy = int(parts[0]), int(parts[1]), int(parts[2])
            if yy < 100:
                yy += 2000
            expiry = date(yy, mm, dd).isoformat()
        except ValueError:
            expiry = None
    else:
        m = _RE_EXPIRY2.search(text)
        if m:
            mon, day, yr, k, cp = m.group(1).upper(), int(m.group(2)), m.group(3), m.group(4), m.group(5)
            if otype is None:
                otype = cp.lower()
            if strike is None:
                try:
                    strike = float(k)
                except ValueError:
                    pass
            try:
                if yr is None:
                    yr = int((trade_date_iso or "2000")[:4])
                else:
                    yr = int(yr)
                    if yr < 100:
                        yr += 2000
                expiry = date(yr, _MONTHS[mon], day).isoformat()
            except (ValueError, KeyError):
                expiry = None
    return strike, expiry, otype


def parse_amount_range(text):
    if not text:
        return None, None
    t = text.replace("*", "").replace(",", "").strip()
    t = re.sub(r"[a-g]{2,}", "", t).strip()
    t = re.sub(r"\s+", " ", t)
    m = re.match(r"^\$?\s*([\d.]+)\s*-\s*\$?\s*([\d.]+)$", t)
    if m:
        return int(float(m.group(1))), int(float(m.group(2)))
    m = re.match(r"^[Oo]ver\s*\$?\s*([\d.]+)$", t)
    if m:
        return int(float(m.group(1))), None
    m = re.match(r"^[^$]*?\b[Oo]ver\s*\$?\s*([\d.]+)$", t)
    if m:
        return int(float(m.group(1))), None
    m = re.match(r"^[A-J]\s*\$?\s*([\d.]+)\s*-\s*\$?\s*([\d.]+)$", t)
    if m:
        return int(float(m.group(1))), int(float(m.group(2)))
    return None, None


def dedupe_content_hash(member_name, trade_date, ticker, transaction_type, amount_low, amount_high):
    return sha256_hex(canonical_json(
        [member_name, trade_date, ticker, transaction_type, amount_low, amount_high]))

# ---------------------------------------------------------------- errors


class EFDBlocked(RuntimeError):
    """Hard stop: 403 / 429 / challenge page. No retry, no evasion."""


class EFDFetchError(RuntimeError):
    """Transient failure that survived backoff (timeouts, 5xx)."""


def looks_like_challenge(status, body_text):
    if status in (403, 429):
        return True
    t = (body_text or "").lower()
    return any(m in t for m in CHALLENGE_MARKERS)

# ---------------------------------------------------------------- session


class EFDSession:
    def __init__(self):
        self.s = requests.Session()
        self.s.headers.update({
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            "Referer": BASE + HOME_PATH,
        })
        self.last_req = 0.0
        self.csrf = None
        self.request_count = 0

    def _throttle(self):
        dt = time.time() - self.last_req
        if dt < MIN_INTERVAL:
            time.sleep(MIN_INTERVAL - dt)

    def _request(self, method, url, **kw):
        self._throttle()
        delay = BACKOFF_BASE
        last_exc = None
        for _ in range(BACKOFF_ATTEMPTS):
            try:
                r = self.s.request(method, url, timeout=60, **kw)
            except (requests.Timeout, requests.ConnectionError) as e:
                last_exc = e
                time.sleep(delay + random.uniform(0, 1.0))
                delay *= 2
                continue
            self.last_req = time.time()
            self.request_count += 1
            body = r.text or ""
            if looks_like_challenge(r.status_code, body):
                print(f"HARD STOP: eFD blocked this session "
                      f"(status={r.status_code}). No retry, no evasion.",
                      flush=True)
                raise EFDBlocked(f"blocked at {url}: HTTP {r.status_code}")
            if 500 <= r.status_code < 600:
                last_exc = EFDFetchError(f"HTTP {r.status_code} at {url}")
                time.sleep(delay + random.uniform(0, 1.0))
                delay *= 2
                continue
            r.raise_for_status()
            return r
        raise EFDFetchError(f"transient failure at {url} after "
                            f"{BACKOFF_ATTEMPTS} attempts: {last_exc}")

    def get(self, url, **kw):
        return self._request("GET", url, **kw)

    def post(self, url, **kw):
        return self._request("POST", url, **kw)

    def handshake(self):
        r = self.get(BASE + HOME_PATH)
        soup = BeautifulSoup(r.text, "html.parser")
        self.csrf = self.s.cookies.get("csrftoken") or self.s.cookies.get("csrf")
        form = None
        for f in soup.find_all("form"):
            text = f.get_text(" ", strip=True).lower()
            action = (f.get("action") or "").lower()
            if "agree" in text or "accept" in text or "agree" in action:
                form = f
                break
        if form is None:
            if self.csrf:
                print("handshake: no agree form; session already holds CSRF — proceeding",
                      flush=True)
                return
            raise EFDBlocked("handshake: no EULA agree form found (form markup changed)")
        action = form.get("action") or HOME_PATH
        agree_url = action if action.startswith("http") else BASE + action
        payload = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "").lower()
            if itype in ("submit", "button", "image") and "agree" not in (
                    inp.get("value") or "").lower():
                continue
            payload[name] = inp.get("value", "")
        if not any("agree" in str(v).lower() or "accept" in str(v).lower()
                   for v in payload.values()):
            payload.setdefault("agree", "I Agree")
        headers = {}
        if self.csrf:
            headers["X-CSRFToken"] = self.csrf
        self.post(agree_url, data=payload, headers=headers)
        self.csrf = (self.s.cookies.get("csrftoken")
                     or self.s.cookies.get("csrf") or self.csrf)
        print(f"handshake: EULA accepted; csrf={'present' if self.csrf else 'absent'}",
              flush=True)

    def search_ptrs(self, from_date=None, to_date=None, start=0,
                    length=DT_PAGE_LENGTH, draw=1):
        payload = {
            DT_FIELDS["draw"]: draw,
            DT_FIELDS["start"]: start,
            DT_FIELDS["length"]: length,
            DT_FIELDS["report_types"]: [PTR_REPORT_TYPE],
        }
        if from_date:
            payload[DT_FIELDS["from_date"]] = from_date
        if to_date:
            payload[DT_FIELDS["to_date"]] = to_date
        headers = {"X-Requested-With": "XMLHttpRequest",
                   "Accept": "application/json, */*;q=0.8"}
        if self.csrf:
            headers["X-CSRFToken"] = self.csrf
        r = self.post(BASE + DATA_PATH, data=payload, headers=headers)
        try:
            return r.json()
        except ValueError:
            raise EFDFetchError(
                f"search response was not JSON (first 200 chars: {r.text[:200]!r})")

# ---------------------------------------------------------------- parsing

_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")


def _norm_header(text):
    return re.sub(r"[^a-z ]", "", (text or "").lower()).strip()


def extract_uuid(value):
    if not value:
        return None
    m = _UUID_RE.search(str(value))
    return m.group(0).upper() if m else None


def parse_search_row(row):
    if isinstance(row, list):
        row = {f"col{i}": v for i, v in enumerate(row)}
    flat = {str(k).lower(): v for k, v in (row or {}).items()}
    blob = json.dumps(row, default=str)
    uuid = None
    for k in ("ptr_link", "link", "url", "view", "href", "uuid", "id"):
        if k in flat:
            uuid = extract_uuid(flat[k])
            if uuid:
                break
    if uuid is None:
        uuid = extract_uuid(blob)
    if uuid is None:
        return None

    def pick(*fragments):
        for k, v in flat.items():
            kl = k.replace("_", " ").replace("-", " ")
            if all(f in kl for f in fragments) and v:
                return str(v).strip()
        return None

    member = pick("filer", "name") or pick("senator") or pick("name")
    office = pick("office")
    report_type = pick("report", "type") or "Periodic Transaction Report"
    filing_date = (pick("date", "received") or pick("filing", "date") or pick("filed"))
    amended = bool(pick("amend")) or "amend" in blob.lower()
    return {"uuid": uuid, "member_name": member, "office": office,
            "report_type": report_type, "filing_date": filing_date,
            "is_amendment": 1 if amended else 0}


def parse_filing_date(raw):
    if not raw:
        return None
    raw = str(raw).strip()
    for fmt in ("%m/%d/%Y", "%m/%d/%y", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw, fmt).date().isoformat()
        except ValueError:
            pass
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", raw)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    return None


def _table_is_transaction_table(table):
    headers = [_norm_header(th.get_text(" ", strip=True)) for th in table.find_all("th")]
    if not headers:
        first = table.find("tr")
        if first:
            headers = [_norm_header(c.get_text(" ", strip=True))
                       for c in first.find_all(["td", "th"])]
    hit = sum(1 for h in EXPECTED_HEADERS if h in headers)
    return hit >= 4, headers


def parse_detail(html):
    soup = BeautifulSoup(html, "html.parser")
    text = soup.get_text(" ", strip=True)
    paper_markers = ("scanned", "image only", "paper filing", ".pdf")
    has_embed = soup.find("embed") or soup.find("iframe") or soup.find(
        "object", attrs={"data": re.compile(r"\.pdf", re.I)})
    pdf_link = soup.find("a", href=re.compile(r"\.pdf(\?|$)", re.I))

    tx_table = None
    tx_headers = None
    for table in soup.find_all("table"):
        ok, headers = _table_is_transaction_table(table)
        if ok:
            tx_table, tx_headers = table, headers
            break

    def grab(*fragments):
        for dt in soup.find_all("dt"):
            label = _norm_header(dt.get_text(" ", strip=True))
            if all(f in label for f in fragments):
                dd = dt.find_next_sibling("dd")
                if dd:
                    return dd.get_text(" ", strip=True)
        for tr in soup.find_all("tr"):
            cells = tr.find_all(["th", "td"])
            if len(cells) >= 2:
                label = _norm_header(cells[0].get_text(" ", strip=True))
                if all(f in label for f in fragments):
                    return cells[1].get_text(" ", strip=True)
        return None

    member = grab("filer", "name") or grab("senator") or grab("name")
    office = grab("office")
    filing_date = grab("date", "received") or grab("filing", "date") or grab("filed")
    amend_text = grab("amend") or ""
    is_amendment = 1 if ("amend" in amend_text.lower()
                         or "amend" in (member or "").lower()) else 0
    if re.search(r"\bamended\b", text, re.I):
        is_amendment = 1
    header = {"member_name": (member or "").strip() or None,
              "office": (office or "").strip() or None,
              "filing_date": filing_date, "is_amendment": is_amendment}

    if tx_table is None:
        if has_embed or pdf_link or any(m in text.lower() for m in paper_markers):
            return {"paper": True, "header": header, "transactions": []}
        raise ValueError("detail page has no recognizable transaction table")

    key_map = {
        "transaction date": "trade_date_raw", "owner": "owner",
        "ticker": "ticker", "asset description": "asset_name",
        "asset name": "asset_name", "asset type": "asset_type_raw",
        "type": "transaction_type_raw", "transaction type": "transaction_type_raw",
        "amount": "amount_raw", "comment": "comment", "comments": "comment",
    }
    positions = [key_map.get(h) for h in tx_headers]
    if not any(positions):
        positions = ["trade_date_raw", "owner", "ticker", "asset_name",
                     "asset_type_raw", "transaction_type_raw", "amount_raw", "comment"]

    transactions = []
    rows = tx_table.find_all("tr")
    body_rows = [r for r in rows if not r.find("th")] or rows[1:]
    for i, tr in enumerate(body_rows):
        cells = [c.get_text(" ", strip=True) for c in tr.find_all(["td", "th"])]
        if not cells or not any(cells):
            continue
        t = {}
        for pos, key in enumerate(positions):
            if key and pos < len(cells):
                t[key] = cells[pos]
        if not t:
            continue
        t["row_index"] = i
        transactions.append(t)
    return {"paper": False, "header": header, "transactions": transactions}

# ---------------------------------------------------------------- normalization

_SENATE_TTYPE = {
    "purchase": "purchase", "p": "purchase", "sale": "sale", "s": "sale",
    "sale (full)": "sale", "partial sale": "partial sale",
    "s (partial)": "partial sale", "sale (partial)": "partial sale",
    "exchange": "exchange", "e": "exchange",
}

_SENATE_ASSET = {
    "stock": "stock", "stocks": "stock", "bond": "bond", "bonds": "bond",
    "option": "option", "options": "option",
    "mutual fund": "mutual fund", "mutual funds": "mutual fund",
}


def map_senate_asset_type(asset_type_raw, asset_name, comment, ticker):
    raw = (asset_type_raw or "").strip().lower()
    for key, val in _SENATE_ASSET.items():
        if key in raw:
            return val
    return map_asset_type(None, asset_name, comment, ticker)


def normalize_row(t, header, uuid, detail_url, first_seen):
    member = header["member_name"] or "UNKNOWN"
    trade_date = parse_filing_date(t.get("trade_date_raw"))
    filing_date = parse_filing_date(header["filing_date"])
    low, high = parse_amount_range(t.get("amount_raw") or "")
    mid = (low + high) / 2.0 if (low is not None and high is not None) else None
    ticker = (t.get("ticker") or "").strip().upper() or None
    if ticker == "--":
        ticker = None
    ttype = _SENATE_TTYPE.get((t.get("transaction_type_raw") or "").strip().lower(),
                              "unmarked")
    asset_type = map_senate_asset_type(t.get("asset_type_raw"), t.get("asset_name"),
                                       t.get("comment"), ticker)
    os_, oe, ot = None, None, None
    if asset_type == "option":
        os_, oe, ot = parse_option_fields(t.get("asset_name"), t.get("comment"), trade_date)
    return {
        "member_name": member, "chamber": "senate",
        "trade_date": trade_date, "available_date": filing_date,
        "ticker": ticker, "asset_name": (t.get("asset_name") or "").strip() or None,
        "asset_type": asset_type, "transaction_type": ttype,
        "amount_low": low, "amount_high": high, "amount_midpoint": mid,
        "option_strike": os_, "option_expiry": oe, "option_type": ot,
        "filing_doc_id": uuid, "filing_date": filing_date,
        "content_hash": dedupe_content_hash(member, trade_date, ticker, ttype, low, high),
        "is_amendment": header["is_amendment"],
        "first_seen_date": first_seen, "source": "senate", "source_url": detail_url,
        "owner": (t.get("owner") or "").strip() or None,
        "comment": (t.get("comment") or "").strip() or None,
    }

# ---------------------------------------------------------------- main


def iter_ptr_filings(session, from_date=None, to_date=None, max_pages=0):
    start, draw, pages, total = 0, 1, 0, None
    while True:
        resp = session.search_ptrs(from_date=from_date, to_date=to_date,
                                   start=start, length=DT_PAGE_LENGTH, draw=draw)
        data = resp.get("data") or []
        records_total = resp.get("recordsTotal")
        records_filtered = resp.get("recordsFiltered", records_total)
        if total is None:
            total = records_total
            print(f"search: recordsTotal={records_total} "
                  f"recordsFiltered={records_filtered}", flush=True)
        for row in data:
            f = parse_search_row(row)
            if f is None:
                print("search: skipped a row with no parseable UUID", flush=True)
                continue
            yield f
        pages += 1
        start += len(data)
        draw += 1
        target = records_filtered if records_filtered is not None else total
        if not data or (target and start >= target):
            break
        if max_pages and pages >= max_pages:
            break
    yield {"__catalog__": True, "records_total": total,
           "records_filtered": records_filtered, "pages": pages}


def main():
    ap = argparse.ArgumentParser(description="Senate eFD PTR relay scraper (research-only).")
    ap.add_argument("--from-date", default="",
                    help="search start YYYY-MM-DD (default: 14 days ago)")
    ap.add_argument("--to-date", default="", help="search end YYYY-MM-DD")
    ap.add_argument("--out-dir", default="data",
                    help="output directory for latest.json + snapshots/")
    ap.add_argument("--limit", type=int, default=0, help="process at most N filings")
    ap.add_argument("--max-pages", type=int, default=0, help="stop search after N pages")
    ap.add_argument("--dry-run", action="store_true", help="search only, no detail pages")
    ap.add_argument("--handshake-only", action="store_true")
    args = ap.parse_args()

    if not args.from_date:
        args.from_date = (date.today() - timedelta(days=14)).isoformat()

    session = EFDSession()
    try:
        session.handshake()
    except EFDBlocked as e:
        print(f"ABORT: {e}", flush=True)
        return 2
    if args.handshake_only:
        print("handshake-only: OK", flush=True)
        return 0

    filings, catalog = [], None
    for item in iter_ptr_filings(session, args.from_date or None,
                                 args.to_date or None, max_pages=args.max_pages):
        if item.get("__catalog__"):
            catalog = item
        else:
            filings.append(item)
    if args.limit:
        filings = filings[:args.limit]
    print(f"filings to process: {len(filings)}", flush=True)

    if args.dry_run:
        for f in filings[:10]:
            print(f"  {f['uuid']} {f.get('member_name')} {f.get('filing_date')}", flush=True)
        print("dry-run: no detail pages fetched, nothing written", flush=True)
        return 0

    first_seen = now_utc_iso()[:10]
    out_filings = []
    stats = {"done": 0, "paper": 0, "failed": 0, "trades": 0}
    for i, f in enumerate(filings):
        uuid = f["uuid"]
        detail_url = BASE + PTR_VIEW_PATH.format(uuid=uuid)
        try:
            r = session.get(detail_url)
            parsed = parse_detail(r.text)
        except EFDBlocked as e:
            print(f"ABORT mid-run at {uuid}: {e}", flush=True)
            return 2  # no snapshot written; previous good snapshot stands
        except Exception as e:
            print(f"  {uuid}: FAILED {type(e).__name__}: {e}", flush=True)
            stats["failed"] += 1
            continue
        header = parsed["header"]
        for k in ("member_name", "filing_date", "is_amendment"):
            if not header.get(k) and f.get(k):
                header[k] = f[k]
        entry = {"uuid": uuid, "member_name": header["member_name"],
                 "office": header.get("office"), "filing_date": header["filing_date"],
                 "is_amendment": header["is_amendment"], "paper": parsed["paper"],
                 "detail_url": detail_url, "trades": []}
        if parsed["paper"]:
            stats["paper"] += 1
        else:
            normed = [normalize_row(t, header, uuid, detail_url, first_seen)
                      for t in parsed["transactions"]]
            best = {}
            for n in normed:  # amendment-wins dedupe, mirrors pipeline
                k = n["content_hash"]
                if k not in best or n["is_amendment"] > best[k]["is_amendment"]:
                    best[k] = n
            entry["trades"] = list(best.values())
            stats["done"] += 1
            stats["trades"] += len(entry["trades"])
        out_filings.append(entry)
        if (i + 1) % 10 == 0:
            print(f"[{i+1}/{len(filings)}] done={stats['done']} "
                  f"paper={stats['paper']} failed={stats['failed']} "
                  f"trades={stats['trades']}", flush=True)

    snapshot = {
        "relay": "senate-efd-relay",
        "run_at": now_utc_iso(),
        "from_date": args.from_date,
        "to_date": args.to_date or None,
        "search": {"records_total": catalog["records_total"] if catalog else None,
                   "records_filtered": catalog["records_filtered"] if catalog else None,
                   "pages": catalog["pages"] if catalog else None},
        "stats": stats,
        "filings": out_filings,
    }
    os.makedirs(args.out_dir, exist_ok=True)
    os.makedirs(os.path.join(args.out_dir, "snapshots"), exist_ok=True)
    latest_path = os.path.join(args.out_dir, "latest.json")
    snap_name = f"ptr_{datetime.now(timezone.utc).strftime('%Y-%m-%d_%H%M%S')}.json"
    snap_path = os.path.join(args.out_dir, "snapshots", snap_name)
    with open(snap_path, "w") as fh:
        json.dump(snapshot, fh, indent=1)
    with open(latest_path, "w") as fh:
        json.dump(snapshot, fh, indent=1)
    print(f"wrote {snap_path} and {latest_path}", flush=True)
    print(json.dumps(stats, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
