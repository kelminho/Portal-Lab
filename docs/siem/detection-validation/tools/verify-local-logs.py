#!/usr/bin/env python3
"""
Verifica nos logs LOCAIS do portal (logs/securecorp-*.json) se cada requisição executada por
run-pentest-cases.sh gerou os eventos esperados. Não consulta o SIEM: o resultado é só a
validação local (etapa 1). A etapa 2 (ingestão + alerta no Falcon NG-SIEM) é registrada à mão em
results/validation-results.csv.

Uso:
    python3 -I verify-local-logs.py --evidence-dir ../evidence/<RUN_ID> [--log-dir ../../../../logs]

Entrada : <evidence-dir>/expect.tsv   (test, request_id, kind, a, b, c)
Saídas  : <evidence-dir>/local-verification.tsv   uma linha por expectativa
          <evidence-dir>/local-summary.tsv        uma linha por teste (LOCAL-PASS / LOCAL-FAIL)
          <evidence-dir>/local-events/<teste>.jsonl   linhas de log correspondentes (evidência)

Tipos de expectativa (kind):
    ev           a=event_type  b=action|-  c=outcome|-    evento de auditoria/segurança existe
    http         a=status_code                              HttpRequest com esse status
    none         a=event_type                               NÃO existe evento desse tipo na requisição
    field        a=campo=valor                              campo (nível superior ou properties) no HttpRequest
    detail       a=texto                                    properties.details de algum evento contém o texto
    samesession  a=request_id de outra requisição           mesmo session_ref (não nulo)
"""
import argparse
import collections
import csv
import glob
import json
import os
import sys


def load_events(log_dir):
    by_request = collections.defaultdict(list)
    raw_lines = collections.defaultdict(list)
    files = sorted(glob.glob(os.path.join(log_dir, "securecorp-*.json")))
    if not files:
        sys.exit(f"Nenhum securecorp-*.json em {log_dir}")
    for path in files:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                request_id = event.get("request_id")
                if request_id:
                    by_request[request_id].append(event)
                    raw_lines[request_id].append(line)
    return by_request, raw_lines


def field_of(event, name):
    if name in event:
        return event[name]
    return (event.get("properties") or {}).get(name)


def describe(events):
    return "; ".join(
        f"{e.get('event_type')}:{e.get('action', '-')}"
        + (f"[{e.get('status_code')}]" if e.get("event_type") == "HttpRequest" else f"[{e.get('outcome', '-')}]")
        for e in events
    ) or "(nenhum evento com esse request_id)"


def check(kind, a, b, c, request_id, by_request):
    events = by_request.get(request_id, [])
    if kind == "ev":
        ok = any(
            e.get("event_type") == a
            and (b in ("-", "") or e.get("action") == b)
            and (c in ("-", "") or e.get("outcome") == c)
            for e in events
        )
    elif kind == "http":
        ok = any(e.get("event_type") == "HttpRequest" and str(e.get("status_code")) == a for e in events)
    elif kind == "none":
        ok = not any(e.get("event_type") == a for e in events)
    elif kind == "field":
        name, _, value = a.partition("=")
        ok = any(
            e.get("event_type") == "HttpRequest" and str(field_of(e, name)) == value for e in events
        )
    elif kind == "detail":
        ok = any(a in str((e.get("properties") or {}).get("details", "")) for e in events)
    elif kind == "samesession":
        mine = {e.get("session_ref") for e in events if e.get("session_ref")}
        other = {e.get("session_ref") for e in by_request.get(a, []) if e.get("session_ref")}
        ok = bool(mine & other)
    else:
        return "UNKNOWN-KIND", describe(events)
    return ("OK" if ok else "MISSING"), describe(events)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--log-dir", default=os.path.join(os.path.dirname(__file__), "..", "..", "..", "..", "logs"))
    args = parser.parse_args()

    by_request, raw_lines = load_events(args.log_dir)
    expect_path = os.path.join(args.evidence_dir, "expect.tsv")
    rows = []
    with open(expect_path, encoding="utf-8", newline="") as handle:
        for record in csv.reader(handle, delimiter="\t"):
            if len(record) < 6:
                record += ["-"] * (6 - len(record))
            rows.append(record[:6])

    per_test = collections.OrderedDict()
    verification = []
    for test, request_id, kind, a, b, c in rows:
        result, observed = check(kind, a, b, c, request_id, by_request)
        verification.append([test, request_id, kind, a, b, c, result, observed])
        per_test.setdefault(test, {"ok": 0, "fail": 0, "requests": set()})
        per_test[test]["ok" if result == "OK" else "fail"] += 1
        per_test[test]["requests"].add(request_id)

    with open(os.path.join(args.evidence_dir, "local-verification.tsv"), "w", encoding="utf-8", newline="") as out:
        writer = csv.writer(out, delimiter="\t")
        writer.writerow(["test", "request_id", "kind", "a", "b", "c", "result", "observed_events"])
        writer.writerows(verification)

    events_dir = os.path.join(args.evidence_dir, "local-events")
    os.makedirs(events_dir, exist_ok=True)
    with open(os.path.join(args.evidence_dir, "local-summary.tsv"), "w", encoding="utf-8", newline="") as out:
        writer = csv.writer(out, delimiter="\t")
        writer.writerow(["test", "expectations_ok", "expectations_failed", "local_status"])
        for test, data in per_test.items():
            status = "LOCAL-PASS" if data["fail"] == 0 else "LOCAL-FAIL"
            writer.writerow([test, data["ok"], data["fail"], status])
            with open(os.path.join(events_dir, f"{test}.jsonl"), "w", encoding="utf-8") as events_out:
                for request_id in sorted(data["requests"]):
                    for line in raw_lines.get(request_id, []):
                        events_out.write(line + "\n")
            print(f"{test:5} {status:11} ok={data['ok']:3} falhas={data['fail']:3}")

    failed = [v for v in verification if v[6] != "OK"]
    print(f"\n{len(verification) - len(failed)}/{len(verification)} expectativas confirmadas nos logs locais.")
    for row in failed[:40]:
        print(f"  FALHA {row[0]} {row[1]} {row[2]} {row[3]} {row[4]} {row[5]} -> {row[7]}")


if __name__ == "__main__":
    main()
