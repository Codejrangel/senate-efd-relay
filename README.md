# senate-efd-relay

In-house relay for U.S. Senate Electronic Financial Disclosure (eFD) Periodic
Transaction Reports (STOCK Act trades). Part of the Congressional Alpha Hunter
research stack.

## Why this exists

`efdsearch.senate.gov` publishes no bulk download or API, and its Akamai edge
blocks datacenter IP ranges (our research host gets HTTP 403). GitHub Actions
runners are not blocked, so a scheduled workflow scrapes the official portal
and commits clean JSON here. The research pipeline reads
`data/latest.json` via `raw.githubusercontent.com`. Same official data,
un-blocked egress, self-owned so it can't be abandoned by a third party.

## Use constraints

- **Non-commercial research only** (5 U.S.C. 13107(c) / Ethics in Government
  Act: obtaining or using disclosure reports for a commercial purpose is
  unlawful). Rows are normalized facts; no conclusions about any member.
- Polite scraping: ≥2s between requests, exponential backoff on 5xx,
  **hard stop on 403/429 or challenge pages — no retry, no evasion.**
  On a block the run aborts and the previous good snapshot stands.

## Layout

- `scrape.py` — the scraper. Usage: `python scrape.py --out-dir data`
  (default: rolling 14-day window). `--dry-run` searches without fetching
  detail pages; `--handshake-only` verifies connectivity.
- `.github/workflows/scrape.yml` — daily 12:00 UTC schedule + manual dispatch.
- `data/latest.json` — newest snapshot (what the pipeline ingests).
- `data/snapshots/ptr_*.json` — dated snapshots for audit history.

## Snapshot schema

```json
{
  "relay": "senate-efd-relay",
  "run_at": "2026-10-16T12:04:11+00:00",
  "from_date": "2026-10-02",
  "to_date": null,
  "search": {"records_total": 42, "records_filtered": 42, "pages": 1},
  "stats": {"done": 40, "paper": 2, "failed": 0, "trades": 138},
  "filings": [
    {
      "uuid": "B999BC0E-...",
      "member_name": "John Doe",
      "office": "Senator",
      "filing_date": "2026-10-07",
      "is_amendment": 0,
      "paper": false,
      "detail_url": "https://efdsearch.senate.gov/search/view/ptr/<uuid>/",
      "trades": [
        {
          "member_name": "John Doe", "chamber": "senate",
          "trade_date": "2026-09-30", "available_date": "2026-10-07",
          "ticker": "NVDA", "asset_name": "NVIDIA Corporation",
          "asset_type": "stock", "transaction_type": "purchase",
          "amount_low": 1001, "amount_high": 15000, "amount_midpoint": 8000.5,
          "option_strike": null, "option_expiry": null, "option_type": null,
          "filing_doc_id": "B999BC0E-...", "filing_date": "2026-10-07",
          "content_hash": "…", "is_amendment": 0,
          "first_seen_date": "2026-10-16",
          "source": "senate",
          "source_url": "https://efdsearch.senate.gov/search/view/ptr/<uuid>/",
          "owner": "Self", "comment": null
        }
      ]
    }
  ]
}
```

Paper-scan filings appear with `"paper": true` and an empty `trades` list —
they are coverage gaps, never silently skipped.
