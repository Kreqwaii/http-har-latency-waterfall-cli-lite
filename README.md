# http-har-latency-waterfall-cli-lite

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero%20(stdlib%20only)-brightgreen.svg)](https://docs.python.org/3/library/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Fast, offline HTTP Archive (`.har`) performance & regression analyzer written in **100% pure Python 3.9+ stdlib** (zero external dependencies).

Быстрый офлайн-анализатор производительности и регрессий HTTP Archive (`.har`) на **чистом Python 3.9+ stdlib** (без внешних зависимостей).

---

## Features / Возможности

- **Latency Percentiles:** Computes `p50`, `p95`, `p99` TTFB (`wait`) and total duration globally, per host, and per endpoint.
- **6 Built-in Performance Rules:** Detects 4xx/5xx errors, slow API calls (`>500ms`), large uncompressed payloads (`>50KB` without `gzip`/`br`), duplicate/N+1 identical requests, 3xx redirect chains, and missing `Cache-Control` on static assets.
- **HAR Regression Diff:** Compare `baseline.har` vs `regressed.har` to catch latency spikes and new errors in CI.
- **CI-Ready:** Outputs `Markdown` or `JSON`, with `--fail-on <severity>` exit codes.

---

## Quick Start / Быстрый старт

```bash
# Analyze a single HAR capture (Markdown)
py -m har_waterfall_lite analyze samples/regressed.har

# Analyze with JSON output and CI gate
py -m har_waterfall_lite analyze samples/regressed.har --format json --fail-on high

# Compare baseline vs regressed HAR
py -m har_waterfall_lite diff samples/baseline.har samples/regressed.har --fail-on medium
```

---

## Rules / Правила анализа

| Rule ID | Severity | Description (EN / RU) |
|---|---|---|
| `HAR001` | `high` / `critical` | HTTP 4xx/5xx errors / Ошибки HTTP 4xx/5xx |
| `HAR002` | `medium` / `high` | Slow requests (`>500ms` by default) / Медленные запросы (`>500мс`) |
| `HAR003` | `medium` | Large uncompressed payload (`>50KB` missing `gzip`/`br`/`zstd`) / Крупный несжатый ответ |
| `HAR004` | `medium` / `high` | Duplicate / N+1 identical requests / Дублирующиеся N+1 запросы |
| `HAR005` | `low` | HTTP 3xx redirect chains / Цепочки редиректов 3xx |
| `HAR006` | `low` | Missing `Cache-Control` on static assets / Отсутствует `Cache-Control` на статике |

---

## Need the full Pro Studio?

Need the full Pro Studio (interactive waterfall Web UI, baseline diff charts, SARIF 2.1.0, SLO budgets)?

👉 **Get it here:** https://funpay.com/users/20096179/
