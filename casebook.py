"""Local transactional event ingestion, case ownership and review history."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
from datetime import datetime, timezone
from triage import analyze
from soc_report_bundle import write_bundle

def connect(path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    app_id = conn.execute('PRAGMA application_id').fetchone()[0]
    tables = conn.execute("SELECT count(*) FROM sqlite_master WHERE type='table'").fetchone()[0]
    if app_id not in (0, 1397703473) or (app_id == 0 and tables):
        conn.close()
        raise ValueError('Database is not a SOC casebook')
    conn.execute('PRAGMA application_id=1397703473')
    conn.execute('PRAGMA user_version=1')
    conn.execute('PRAGMA foreign_keys=ON')
    conn.executescript('CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY,payload TEXT NOT NULL); CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY,status TEXT NOT NULL,owner TEXT NOT NULL,payload TEXT NOT NULL); CREATE TABLE IF NOT EXISTS history(seq INTEGER PRIMARY KEY,case_id TEXT NOT NULL REFERENCES cases(id),timestamp TEXT NOT NULL,action TEXT NOT NULL,note TEXT NOT NULL); CREATE TABLE IF NOT EXISTS ingests(seq INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,canonical_batch_sha256 TEXT NOT NULL,event_count INTEGER NOT NULL,rules_json TEXT NOT NULL);')
    path.chmod(384)
    return conn

def stamp():
    return datetime.now(timezone.utc).isoformat()

def ingest(conn, events, window=300, threshold=5, spray=None):
    analyze(events, window, threshold, spray)
    inserted = 0
    with conn:
        for event in events:
            payload = json.dumps(event, sort_keys=True, ensure_ascii=False, allow_nan=False)
            existing = conn.execute('SELECT payload FROM events WHERE id=?', (event['id'],)).fetchone()
            if existing and existing['payload'] != payload:
                raise ValueError('Event ID collision with different content: ' + event['id'])
            if not existing:
                conn.execute('INSERT INTO events VALUES(?,?)', (event['id'], payload))
                inserted += 1
        if conn.execute('SELECT count(*) FROM events').fetchone()[0] > 100000:
            raise ValueError('Casebook limit is 100000 events')
        all_events = [json.loads(row[0]) for row in conn.execute('SELECT payload FROM events')]
        report = analyze(all_events, window, threshold, spray)
        canonical_hash = hashlib.sha256(json.dumps(events, sort_keys=True, ensure_ascii=False, allow_nan=False).encode()).hexdigest()
        rules = json.dumps({'window_seconds': window, 'failure_threshold': threshold, 'spray_threshold': spray}, sort_keys=True)
        conn.execute('INSERT INTO ingests(timestamp,canonical_batch_sha256,event_count,rules_json) VALUES(?,?,?,?)', (stamp(), canonical_hash, len(events), rules))
        for finding in report['findings']:
            identity = [finding['rule'], finding.get('user'), finding['source_ip'], finding['first_seen']]
            case_id = hashlib.sha256(json.dumps(identity).encode()).hexdigest()
            payload = json.dumps(finding, sort_keys=True)
            previous = conn.execute('SELECT * FROM cases WHERE id=?', (case_id,)).fetchone()
            if not previous:
                conn.execute('INSERT INTO cases VALUES(?,?,?,?)', (case_id, 'open', '', payload))
                conn.execute('INSERT INTO history(case_id,timestamp,action,note) VALUES(?,?,?,?)', (case_id, stamp(), 'created', 'Rule matched; analyst review required'))
            elif previous['payload'] != payload:
                new_evidence = set(finding['evidence_ids']) - set(json.loads(previous['payload'])['evidence_ids'])
                status = 'open' if new_evidence and previous['status'] in ('closed', 'false_positive') else previous['status']
                conn.execute('UPDATE cases SET payload=?,status=? WHERE id=?', (payload, status, case_id))
                conn.execute('INSERT INTO history(case_id,timestamp,action,note) VALUES(?,?,?,?)', (case_id, stamp(), 'evidence_updated', 'New evidence count: ' + str(len(new_evidence))))
    return {'new_events': inserted, 'total_events': len(all_events), 'current_rule_findings': len(report['findings'])}

def transition(conn, case_id, status, owner, note):
    if status not in ('open', 'investigating', 'closed', 'false_positive') or not isinstance(note, str) or (not note.strip()) or (len(note) > 4000) or (len(owner) > 200):
        raise ValueError('Valid status, owner <=200 chars and review note of 1..4000 chars required')
    with conn:
        row = conn.execute('SELECT id FROM cases WHERE id=?', (case_id,)).fetchone()
        if not row:
            raise ValueError('Unknown case ID')
        conn.execute('UPDATE cases SET status=?,owner=? WHERE id=?', (status, owner, case_id))
        conn.execute('INSERT INTO history(case_id,timestamp,action,note) VALUES(?,?,?,?)', (case_id, stamp(), status, json.dumps({'owner': owner, 'note': note}, ensure_ascii=False)))

def snapshot(conn, status=None):
    if status is not None and status not in ('open', 'investigating', 'closed', 'false_positive'):
        raise ValueError('Unknown case status')
    cases = conn.execute('SELECT * FROM cases WHERE status=? ORDER BY id', (status,)) if status else conn.execute('SELECT * FROM cases ORDER BY id')
    history = conn.execute('SELECT h.* FROM history h JOIN cases c ON c.id=h.case_id WHERE c.status=? ORDER BY h.seq', (status,)) if status else conn.execute('SELECT seq,case_id,timestamp,action,note FROM history ORDER BY seq')
    return {'tool': 'soc-casebook', 'events_stored': conn.execute('SELECT count(*) FROM events').fetchone()[0], 'cases': [dict(id=row['id'], status=row['status'], owner=row['owner'], finding=json.loads(row['payload'])) for row in cases], 'review_history': [dict(row) for row in history], 'ingest_history': [dict(row) for row in conn.execute('SELECT * FROM ingests ORDER BY seq')], 'scope': 'Private local investigation records. Rule leads are not proof of compromise. Cases remain historical if rule configuration changes; export contains analyst notes and identities.'}

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--db', type=Path, required=True)
    sub = parser.add_subparsers(dest='command', required=True)
    load = sub.add_parser('ingest')
    load.add_argument('events', type=Path)
    load.add_argument('--window', type=int, default=300)
    load.add_argument('--threshold', type=int, default=5)
    load.add_argument('--spray', type=int)
    review = sub.add_parser('review')
    review.add_argument('case_id')
    review.add_argument('--status', required=True)
    review.add_argument('--owner', default='')
    review.add_argument('--note', required=True)
    listing = sub.add_parser('list')
    listing.add_argument('--status', choices=('open', 'investigating', 'closed', 'false_positive'))
    export = sub.add_parser('export')
    export.add_argument('--status', choices=('open', 'investigating', 'closed', 'false_positive'))
    export.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == 'ingest' and args.db.resolve() == args.events.resolve():
            raise ValueError('Database must not overwrite event input')
        if args.command == 'ingest' and args.events.stat().st_size > 16 * 1024 * 1024:
            raise ValueError('Input batch exceeds 16 MiB')
        if args.command != 'ingest' and (not args.db.is_file()):
            raise ValueError('Casebook does not exist; ingest events first')
        conn = connect(args.db)
        try:
            if args.command == 'ingest':
                result = ingest(conn, [json.loads(line) for line in args.events.read_text().splitlines() if line.strip()], args.window, args.threshold, args.spray)
            elif args.command == 'review':
                transition(conn, args.case_id, args.status, args.owner, args.note)
                result = {'status': 'review_recorded'}
            else:
                result = snapshot(conn, args.status)
                if args.command == 'export':
                    write_bundle(args.output, result, 'SOC investigation casebook')
            print(json.dumps(result, ensure_ascii=False, indent=2))
        finally:
            conn.close()
    except (ValueError, OSError, sqlite3.Error) as error:
        parser.exit(2, str(error) + '\n')
if __name__ == '__main__':
    main()
