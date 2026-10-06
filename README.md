# SOC Triage

A small offline baseline for reviewing authentication events. It groups events by source and account, flags repeated failures and a subsequent successful login, and keeps the exact event IDs behind each finding. A privilege grant is marked for review rather than treated as proof of compromise.

```sh
python3 triage.py examples/events.jsonl --output examples/report.json
python3 -m unittest -v
```

## Input and decisions

Each JSONL event has `id`, an offset-aware ISO timestamp, `kind`, `user`, and `source_ip`. Recognized kinds are `login_failed`, `login_success`, and `privilege_granted`. Other event kinds remain in the timeline. Duplicate IDs and timestamps without an offset are rejected.

Five failures inside 300 seconds produce a medium-priority lead; a success inside that window produces a high-priority lead. The output preserves evidence and suggested investigation steps. This is a deterministic baseline intended for comparison with a later local language-model assistant. It makes no network requests and takes no response actions.

The included events are synthetic. This prototype has no production SIEM integration, cross-account correlation, or measured analyst-time benefit. The test suite checks exact evidence, expired windows, separation between users, and input validation.

## العربية

أداة محلية تربط أحداث تسجيل الدخول بالحساب والمصدر، وتعرض سبب التنبيه ومعرّفات السجلات الأصلية. البيانات المرفقة اصطناعية؛ النتائج خيوط للتحقيق وليست إثباتًا على اختراق.
