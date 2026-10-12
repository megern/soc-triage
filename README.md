# SOC Triage

## Version 1.0.0

Persistent investigation casebook. Transactional deduplicated imports, conflicting-ID rejection, case ownership, review history and reopening closed cases on new evidence. Four states: open, investigating, closed, false_positive. Event batches <=16 MiB, casebook <=100000 events. Database and exported notes are private investigation data; the existing pseudonymized triage export remains separate. Historical cases are retained if rule settings change. No SIEM connector, blocking action or compromise certification.

See the [complete local workflow](docs/v1-workflow.md) for installation, commands, review artifacts and limits. Earlier preview notes below describe their historical tagged revisions.

## Sharing an investigation report (local development)

`--pseudonym-key-file /absolute/local/key` replaces account names, source IPs,
event IDs and evidence references with deterministic HMAC-SHA256 pseudonyms.
Supply a locally generated random secret containing at least 32 bytes; retain
it locally and never commit it. The same key preserves correlation across
reports; different keys produce different identifiers. Extra event metadata is
omitted from this export. The input events and key file cannot be overwritten
by the report destination.

This is pseudonymization, not anonymity: timestamps, event kinds and activity
patterns remain sensitive. Review the export before sharing it. The tool does
not send records or keys anywhere. The ordinary full report remains the default.

## Public preview v0.2.0

Python 3.11+; commands below use a local Mac/Linux shell. Source and reports are public; this is a research/development preview, not a production-security certification.

```sh
git clone --branch v0.2.0 https://github.com/megern/soc-triage.git
cd soc-triage
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install .
soc-triage --help
```

The installed entry point was exercised outside the checkout in a separate local environment. This revision has 12 passing local tests. No hosted CI or cloud compute is used. Report an issue with the command, Python/OS versions, sanitized input and expected/actual behavior; remove credentials and private records first. Benchmarks describe the supplied fixtures and hardware.

A small offline baseline for reviewing authentication events. It groups events by source and account, flags repeated failures and a subsequent successful login, and keeps the exact event IDs behind each finding. A privilege grant is marked for review rather than treated as proof of compromise.

```sh
python3 triage.py examples/events.jsonl --output examples/report.json
python3 -m unittest -v
```

## Input and decisions

Each JSONL event has `id`, an offset-aware ISO timestamp, `kind`, `user`, and `source_ip`. Recognized kinds are `login_failed`, `login_success`, and `privilege_granted`. Other event kinds remain in the timeline. Duplicate IDs and timestamps without an offset are rejected.

Five failures inside 300 seconds produce a medium-priority lead; a success inside that window produces a high-priority lead. The output preserves evidence and suggested investigation steps. This is a deterministic baseline intended for comparison with a later local language-model assistant. It makes no network requests and takes no response actions.

The included events are synthetic. This prototype has no production SIEM integration or measured analyst-time benefit. The test suite checks exact evidence, expired windows, separation between users, and input validation.

## العربية

أداة محلية تربط أحداث تسجيل الدخول بالحساب والمصدر، وتعرض سبب التنبيه ومعرّفات السجلات الأصلية. البيانات المرفقة اصطناعية؛ النتائج خيوط للتحقيق وليست إثباتًا على اختراق.

## Optional cross-account correlation

```sh
python3 triage.py examples/events.jsonl --spray-threshold 5 --failure-threshold 5 --output /tmp/triage.json
python3 -m unittest discover -s .
```

`--spray-threshold` opts into distinct-account failure correlation from the same source within the configured time window. Its minimum is two accounts. The default keeps the original per-account behavior. Findings include exact event IDs, affected accounts and timestamps. A shared NAT or proxy can create false positives; investigate the lead before taking action. This is a rule baseline on synthetic examples, not measured production detection.


### Window-processing study

`python3 benchmark_local.py` compares the optimized implementation with the frozen previous source under `benchmarks/`. Per-account expiry uses a deque, and cross-account windows maintain account counts as events expire. The frozen synthetic timing results are in `results/local-scaling-20261011.json`. Three repetitions alternate execution order; inputs and outputs are identical between implementations. This exercise suppresses alerts to isolate window maintenance. Large evidence-producing findings can still cost quadratic work. Timings describe this local run with shared machine activity, not production detection or isolated-system throughput.
