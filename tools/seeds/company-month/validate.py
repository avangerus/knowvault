#!/usr/bin/env python3
"""Validate one materialized company-month seed without changing it."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


SOURCE_ROOTS = ("documents", "repo", "relational")
CSV_COLUMNS = {
    "teams": ["team_id", "team_code", "team_name", "manager_employee_id"],
    "employees": ["employee_id", "team_id", "employee_name", "role", "email", "active_from", "active_to"],
    "customers": ["customer_id", "customer_name", "segment", "region", "primary_contact", "support_tier"],
    "services": ["service_code", "service_name", "description", "default_team_id"],
    "contracts": ["contract_id", "customer_id", "contract_no", "start_date", "end_date", "status", "sla_policy_version", "monthly_fee_rub", "renewal_date"],
    "assets": ["asset_id", "customer_id", "asset_type", "asset_name", "status", "installed_date", "last_seen_at"],
    "tickets": ["ticket_id", "customer_id", "contract_id", "asset_id", "assigned_team_id", "assigned_employee_id", "category", "priority", "subject", "created_at", "first_response_at", "resolved_at", "closed_at", "status", "sla_policy_version", "sla_due_at", "sla_breached"],
    "ticket_events": ["event_id", "ticket_id", "event_at", "from_status", "to_status", "actor_employee_id", "note"],
    "invoices": ["invoice_id", "contract_id", "invoice_date", "due_date", "subtotal_rub", "tax_rub", "total_rub", "status"],
    "payments": ["payment_id", "invoice_id", "payment_date", "amount_rub", "method", "reference"],
    "time_entries": ["entry_id", "employee_id", "ticket_id", "contract_id", "work_date", "hours", "kind"],
    "releases": ["release_id", "version", "release_date", "service_code", "status", "commit_ref", "released_by_employee_id"],
}
STATUS_TRANSITIONS = {
    "": {"new"},
    "new": {"in_progress"},
    "in_progress": {"resolved", "pending", "open"},
    "resolved": {"closed"},
}


class Checks:
    def __init__(self) -> None:
        self.errors: list[str] = []

    def require(self, condition: bool, message: str) -> None:
        if not condition:
            self.errors.append(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_csv(root: Path, table: str, checks: Checks) -> list[dict[str, str]]:
    path = root / "relational" / f"{table}.csv"
    checks.require(path.is_file(), f"missing CSV: relational/{table}.csv")
    if not path.is_file():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        checks.require(reader.fieldnames == CSV_COLUMNS[table], f"schema mismatch: {table}.csv")
        return list(reader)


def unique_ids(rows: list[dict[str, str]], field: str, checks: Checks, label: str) -> set[str]:
    values = [row.get(field, "") for row in rows]
    checks.require(all(values), f"blank {label}.{field}")
    checks.require(len(values) == len(set(values)), f"duplicate {label}.{field}")
    return set(values)


def parse_ts(value: str, checks: Checks, label: str) -> dt.datetime | None:
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        checks.errors.append(f"invalid timestamp in {label}: {value!r}")
        return None
    checks.require(parsed.utcoffset() == dt.timedelta(hours=3), f"timestamp timezone is not +03:00 in {label}: {value}")
    return parsed


def parse_date(value: str, checks: Checks, label: str) -> dt.date | None:
    try:
        return dt.date.fromisoformat(value)
    except ValueError:
        checks.errors.append(f"invalid date in {label}: {value!r}")
        return None


def compare_expected(checks: Checks, question_map: dict[str, dict[str, Any]], qid: str, value: Any) -> None:
    checks.require(qid in question_map, f"missing golden question {qid}")
    if qid in question_map:
        checks.require(question_map[qid].get("expected") == value, f"golden answer mismatch {qid}: expected {question_map[qid].get('expected')!r}, recomputed {value!r}")


def validate(root: Path) -> tuple[int, dict[str, Any]]:
    checks = Checks()
    manifest_path = root / "control" / "manifest.json"
    expected_path = root / "control" / "expected-answers.json"
    checks.require(manifest_path.is_file(), "missing control/manifest.json")
    checks.require(expected_path.is_file(), "missing control/expected-answers.json")
    if checks.errors:
        return 1, {"errors": checks.errors}
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    checks.require(manifest.get("source_roots") == list(SOURCE_ROOTS), "manifest source_roots must exclude control")
    checks.require(manifest.get("oracle_root") == "control/", "manifest oracle_root must be control/")
    checks.require(len(expected.get("questions", [])) >= 25, "expected-answers.json must contain at least 25 questions")
    question_map = {question["id"]: question for question in expected.get("questions", [])}

    actual_files: set[str] = set()
    for source_root in SOURCE_ROOTS:
        path = root / source_root
        checks.require(path.is_dir(), f"missing source root: {source_root}")
        if not path.is_dir():
            continue
        for child in path.rglob("*"):
            if child.is_file() and ".git" not in child.parts:
                actual_files.add(child.relative_to(root).as_posix())
    manifest_files = {entry.get("path", "") for entry in manifest.get("files", [])}
    checks.require(actual_files == manifest_files, "manifest file list differs from source tree")
    for entry in manifest.get("files", []):
        path = root / entry["path"]
        checks.require(path.is_file(), f"manifest path missing: {entry['path']}")
        if path.is_file():
            checks.require(path.stat().st_size == entry["bytes"], f"manifest byte count mismatch: {entry['path']}")
            checks.require(sha256_file(path) == entry["sha256"], f"manifest hash mismatch: {entry['path']}")

    tables = {table: read_csv(root, table, checks) for table in CSV_COLUMNS}
    teams = unique_ids(tables["teams"], "team_id", checks, "teams")
    employees = unique_ids(tables["employees"], "employee_id", checks, "employees")
    customers = unique_ids(tables["customers"], "customer_id", checks, "customers")
    services = unique_ids(tables["services"], "service_code", checks, "services")
    contracts = unique_ids(tables["contracts"], "contract_id", checks, "contracts")
    assets = unique_ids(tables["assets"], "asset_id", checks, "assets")
    tickets = unique_ids(tables["tickets"], "ticket_id", checks, "tickets")
    event_ids = unique_ids(tables["ticket_events"], "event_id", checks, "ticket_events")
    invoices = unique_ids(tables["invoices"], "invoice_id", checks, "invoices")
    payment_ids = unique_ids(tables["payments"], "payment_id", checks, "payments")
    entries = unique_ids(tables["time_entries"], "entry_id", checks, "time_entries")
    releases = unique_ids(tables["releases"], "release_id", checks, "releases")
    del event_ids, payment_ids, entries, releases

    employee_by_id = {row["employee_id"]: row for row in tables["employees"]}
    customer_by_id = {row["customer_id"]: row for row in tables["customers"]}
    contract_by_id = {row["contract_id"]: row for row in tables["contracts"]}
    asset_by_id = {row["asset_id"]: row for row in tables["assets"]}
    ticket_by_id = {row["ticket_id"]: row for row in tables["tickets"]}
    invoice_by_id = {row["invoice_id"]: row for row in tables["invoices"]}
    team_by_id = {row["team_id"]: row for row in tables["teams"]}
    service_by_id = {row["service_code"]: row for row in tables["services"]}

    for row in tables["employees"]:
        checks.require(row["team_id"] in teams, f"employee FK: {row['employee_id']}.team_id")
        checks.require(row["email"].endswith("@example.invalid"), f"non-example contact: {row['employee_id']}")
        parse_date(row["active_from"], checks, f"employee {row['employee_id']}.active_from")
        if row["active_to"]:
            parse_date(row["active_to"], checks, f"employee {row['employee_id']}.active_to")
    for row in tables["services"]:
        checks.require(row["default_team_id"] in teams, f"service FK: {row['service_code']}.default_team_id")
    for row in tables["customers"]:
        checks.require(row["primary_contact"].endswith("@example.invalid"), f"non-example contact: {row['customer_id']}")
    for row in tables["contracts"]:
        checks.require(row["customer_id"] in customers, f"contract FK: {row['contract_id']}.customer_id")
        start = parse_date(row["start_date"], checks, f"contract {row['contract_id']}.start_date")
        end = parse_date(row["end_date"], checks, f"contract {row['contract_id']}.end_date")
        renewal = parse_date(row["renewal_date"], checks, f"contract {row['contract_id']}.renewal_date")
        if start and end and renewal:
            checks.require(start <= end < renewal, f"contract dates: {row['contract_id']}")
        checks.require(int(row["monthly_fee_rub"]) > 0, f"contract amount: {row['contract_id']}")
        expected_status = "active" if end and end >= dt.date(2026, 8, 31) else "expired"
        checks.require(row["status"] == expected_status, f"contract status: {row['contract_id']}")
    for row in tables["assets"]:
        checks.require(row["customer_id"] in customers, f"asset FK: {row['asset_id']}.customer_id")
        installed = parse_date(row["installed_date"], checks, f"asset {row['asset_id']}.installed_date")
        seen = parse_ts(row["last_seen_at"], checks, f"asset {row['asset_id']}.last_seen_at")
        if installed and seen:
            checks.require(installed < seen.date(), f"asset dates: {row['asset_id']}")
    for row in tables["teams"]:
        checks.require(row["manager_employee_id"] in employees, f"team manager FK: {row['team_id']}")

    ticket_dates: dict[str, dt.datetime] = {}
    current_sla = {"P1": 15, "P2": 60, "P3": 240, "P4": 2880}
    for row in tables["tickets"]:
        checks.require(row["customer_id"] in customers, f"ticket FK: {row['ticket_id']}.customer_id")
        checks.require(row["contract_id"] in contracts, f"ticket FK: {row['ticket_id']}.contract_id")
        checks.require(row["asset_id"] in assets, f"ticket FK: {row['ticket_id']}.asset_id")
        checks.require(row["assigned_team_id"] in teams, f"ticket FK: {row['ticket_id']}.assigned_team_id")
        checks.require(row["assigned_employee_id"] in employees, f"ticket FK: {row['ticket_id']}.assigned_employee_id")
        checks.require(contract_by_id.get(row["contract_id"], {}).get("customer_id") == row["customer_id"], f"ticket contract/customer mismatch: {row['ticket_id']}")
        checks.require(asset_by_id.get(row["asset_id"], {}).get("customer_id") == row["customer_id"], f"ticket asset/customer mismatch: {row['ticket_id']}")
        checks.require(employee_by_id.get(row["assigned_employee_id"], {}).get("team_id") == row["assigned_team_id"], f"ticket employee/team mismatch: {row['ticket_id']}")
        created = parse_ts(row["created_at"], checks, f"ticket {row['ticket_id']}.created_at")
        response = parse_ts(row["first_response_at"], checks, f"ticket {row['ticket_id']}.first_response_at")
        due = parse_ts(row["sla_due_at"], checks, f"ticket {row['ticket_id']}.sla_due_at")
        ticket_dates[row["ticket_id"]] = created or dt.datetime.min.replace(tzinfo=dt.timezone.utc)
        if created and response and due:
            checks.require(created <= response <= due or response > due, f"ticket time order: {row['ticket_id']}")
            expected_breach = response - created > dt.timedelta(minutes=current_sla[row["priority"]])
            checks.require(row["sla_breached"] == str(expected_breach).lower(), f"ticket SLA flag: {row['ticket_id']}")
        if row["status"] in {"resolved", "closed"}:
            checks.require(bool(row["resolved_at"]), f"missing resolved_at: {row['ticket_id']}")
            parse_ts(row["resolved_at"], checks, f"ticket {row['ticket_id']}.resolved_at")
        else:
            checks.require(not row["resolved_at"], f"unexpected resolved_at: {row['ticket_id']}")
        if row["status"] == "closed":
            checks.require(bool(row["closed_at"]), f"missing closed_at: {row['ticket_id']}")
            parse_ts(row["closed_at"], checks, f"ticket {row['ticket_id']}.closed_at")
        else:
            checks.require(not row["closed_at"], f"unexpected closed_at: {row['ticket_id']}")

    events_by_ticket: dict[str, list[dict[str, str]]] = {}
    for row in tables["ticket_events"]:
        checks.require(row["ticket_id"] in tickets, f"event FK: {row['event_id']}.ticket_id")
        checks.require(row["actor_employee_id"] in employees, f"event FK: {row['event_id']}.actor_employee_id")
        parsed = parse_ts(row["event_at"], checks, f"event {row['event_id']}.event_at")
        if parsed and row["ticket_id"] in ticket_dates:
            checks.require(parsed >= ticket_dates[row["ticket_id"]], f"event before ticket creation: {row['event_id']}")
        events_by_ticket.setdefault(row["ticket_id"], []).append(row)
    for ticket_id, ticket in ticket_by_id.items():
        events = sorted(events_by_ticket.get(ticket_id, []), key=lambda row: (row["event_at"], row["event_id"]))
        checks.require(events, f"missing event history: {ticket_id}")
        if not events:
            continue
        previous = ""
        for event in events:
            checks.require(event["from_status"] == previous, f"invalid event transition source: {event['event_id']}")
            checks.require(event["to_status"] in STATUS_TRANSITIONS.get(previous, set()), f"invalid event transition: {event['event_id']}")
            previous = event["to_status"]
        checks.require(previous == ticket["status"], f"terminal event does not match ticket: {ticket_id}")

    payment_totals: dict[str, int] = {invoice_id: 0 for invoice_id in invoices}
    for row in tables["invoices"]:
        checks.require(row["contract_id"] in contracts, f"invoice FK: {row['invoice_id']}.contract_id")
        invoice_date = parse_date(row["invoice_date"], checks, f"invoice {row['invoice_id']}.invoice_date")
        due_date = parse_date(row["due_date"], checks, f"invoice {row['invoice_id']}.due_date")
        checks.require(int(row["tax_rub"]) == int(row["subtotal_rub"]) * 20 // 100, f"invoice tax arithmetic: {row['invoice_id']}")
        checks.require(int(row["total_rub"]) == int(row["subtotal_rub"]) + int(row["tax_rub"]), f"invoice total arithmetic: {row['invoice_id']}")
        checks.require(invoice_date is not None and due_date is not None and invoice_date <= due_date, f"invoice dates: {row['invoice_id']}")
    cutoff_date = dt.date(2026, 9, 1)
    for row in tables["payments"]:
        checks.require(row["invoice_id"] in invoices, f"payment FK: {row['payment_id']}.invoice_id")
        payment_date = parse_date(row["payment_date"], checks, f"payment {row['payment_id']}.payment_date")
        invoice = invoice_by_id.get(row["invoice_id"])
        if invoice and payment_date:
            checks.require(payment_date >= dt.date.fromisoformat(invoice["invoice_date"]), f"payment before invoice: {row['payment_id']}")
            checks.require(payment_date < cutoff_date, f"payment after cutoff: {row['payment_id']}")
        amount = int(row["amount_rub"])
        checks.require(amount > 0, f"nonpositive payment: {row['payment_id']}")
        payment_totals[row["invoice_id"]] += amount
    for invoice_id, paid in payment_totals.items():
        invoice = invoice_by_id[invoice_id]
        total = int(invoice["total_rub"])
        checks.require(paid <= total, f"payment exceeds invoice: {invoice_id}")
        due = dt.date.fromisoformat(invoice["due_date"])
        expected_status = "paid" if paid == total else ("partial" if paid else ("overdue" if due < cutoff_date else "issued"))
        checks.require(invoice["status"] == expected_status, f"invoice status arithmetic: {invoice_id}")

    for row in tables["time_entries"]:
        checks.require(row["employee_id"] in employees, f"time entry FK: {row['entry_id']}.employee_id")
        checks.require(row["ticket_id"] in tickets, f"time entry FK: {row['entry_id']}.ticket_id")
        checks.require(row["contract_id"] in contracts, f"time entry FK: {row['entry_id']}.contract_id")
        checks.require(ticket_by_id.get(row["ticket_id"], {}).get("contract_id") == row["contract_id"], f"time entry contract mismatch: {row['entry_id']}")
        work_date = parse_date(row["work_date"], checks, f"time entry {row['entry_id']}.work_date")
        if work_date:
            checks.require(dt.date(2026, 8, 1) <= work_date < cutoff_date, f"time entry outside month: {row['entry_id']}")
        checks.require(0 < int(row["hours"]) <= 24, f"time entry hours: {row['entry_id']}")
    for row in tables["releases"]:
        checks.require(row["service_code"] in services, f"release FK: {row['release_id']}.service_code")
        checks.require(row["released_by_employee_id"] in employees, f"release FK: {row['release_id']}.released_by_employee_id")
        checks.require(len(row["commit_ref"]) == 40 and all(character in "0123456789abcdef" for character in row["commit_ref"]), f"release commit ref: {row['release_id']}")
        parse_date(row["release_date"], checks, f"release {row['release_id']}.release_date")

    counts = manifest.get("counts", {})
    expected_counts = {
        "documents_total": sum(1 for path in actual_files if path.startswith("documents/")),
        "staff": len(tables["employees"]),
        "teams": len(tables["teams"]),
        "customers": len(tables["customers"]),
        "contracts": len(tables["contracts"]),
        "assets": len(tables["assets"]),
        "tickets": len(tables["tickets"]),
        "ticket_events": len(tables["ticket_events"]),
        "invoices": len(tables["invoices"]),
        "payments": len(tables["payments"]),
        "time_entries": len(tables["time_entries"]),
        "releases": len(tables["releases"]),
    }
    for key, value in expected_counts.items():
        checks.require(counts.get(key) == value, f"manifest count mismatch: {key}")
    checks.require(35 <= expected_counts["documents_total"] <= 60, "document count must be between 35 and 60")
    checks.require(len(tables["employees"]) == 24, "staff count must be 24")
    checks.require(len(tables["teams"]) == 4, "team count must be 4")
    checks.require(len(tables["customers"]) == 8, "customer count must be 8")
    checks.require(8 <= len(tables["contracts"]) <= 12, "contract count must be 8..12")
    checks.require(len(tables["assets"]) == 80, "asset count must be 80")
    checks.require(580 <= len(tables["tickets"]) <= 620, "ticket count must be about 600")
    checks.require(8 <= len(tables["releases"]) <= 16, "release count must be about 12")

    first = dt.date(2026, 8, 1)
    last = dt.date(2026, 8, 31)
    weekly: dict[str, list[dict[str, str]]] = {}
    for week_index in range(4):
        start = first + dt.timedelta(days=week_index * 7)
        end = last if week_index == 3 else first + dt.timedelta(days=(week_index + 1) * 7 - 1)
        weekly[f"W{week_index + 1:02d}"] = [row for row in tables["tickets"] if start <= dt.date.fromisoformat(row["created_at"][:10]) <= end]
    def week_metrics(rows: list[dict[str, str]]) -> dict[str, int]:
        return {
            "created": len(rows),
            "closed": sum(row["status"] == "closed" for row in rows),
            "p1": sum(row["priority"] == "P1" for row in rows),
        }
    weekly_numbers = {key: week_metrics(rows) for key, rows in weekly.items()}
    peak_week = max(weekly_numbers, key=lambda key: (weekly_numbers[key]["p1"], key))
    asset_status_counts = {status: sum(row["status"] == status for row in tables["assets"]) for status in ("active", "maintenance", "retired")}
    ticket_status_counts = {status: sum(row["status"] == status for row in tables["tickets"]) for status in ("closed", "resolved", "pending", "open")}
    invoice_total = sum(int(row["total_rub"]) for row in tables["invoices"])
    paid_total = sum(int(row["amount_rub"]) for row in tables["payments"])
    employee_team = {row["employee_id"]: row["team_id"] for row in tables["employees"]}
    time_by_team = {team_id: 0 for team_id in teams}
    for row in tables["time_entries"]:
        time_by_team[employee_team[row["employee_id"]]] += int(row["hours"])
    p1_current = 0
    p1_old = 0
    for row in tables["tickets"]:
        if row["priority"] != "P1":
            continue
        created = dt.datetime.fromisoformat(row["created_at"])
        response = dt.datetime.fromisoformat(row["first_response_at"])
        p1_current += response - created > dt.timedelta(minutes=15)
        p1_old += response - created > dt.timedelta(minutes=30)
    incident_candidates = [row for row in tables["tickets"]]
    priority_rank = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    incident_gateway = min(
        incident_candidates,
        key=lambda row: (
            abs((dt.date.fromisoformat(row["created_at"][:10]) - dt.date(2026, 8, 7)).days),
            priority_rank.get(row["priority"], 9),
            row["ticket_id"],
        ),
    )
    compare_expected(checks, question_map, "Q03", {"teams": len(teams), "employees": len(employees)})
    compare_expected(checks, question_map, "Q04", sum(row["team_id"] == "T02" for row in tables["employees"]))
    compare_expected(checks, question_map, "Q08", weekly_numbers["W03"]["created"])
    compare_expected(checks, question_map, "Q09", {"week": peak_week, "p1": weekly_numbers[peak_week]["p1"]})
    compare_expected(checks, question_map, "Q10", {"ticket": incident_gateway["ticket_id"], "created_at": incident_gateway["created_at"], "first_response_at": incident_gateway["first_response_at"], "status": incident_gateway["status"], "cause": "incorrect concurrent-request limit"})
    compare_expected(checks, question_map, "Q12", weekly_numbers["W04"]["closed"])
    compare_expected(checks, question_map, "Q17", {"invoice_count": len(tables["invoices"]), "total_rub": invoice_total})
    compare_expected(checks, question_map, "Q18", {"payment_count": len(tables["payments"]), "paid_rub": paid_total})
    compare_expected(checks, question_map, "Q19", invoice_total - paid_total)
    compare_expected(checks, question_map, "Q20", sum(dt.date.fromisoformat(row["start_date"]) <= last <= dt.date.fromisoformat(row["end_date"]) for row in tables["contracts"]))
    compare_expected(checks, question_map, "Q21", asset_status_counts)
    compare_expected(checks, question_map, "Q22", ticket_status_counts)
    compare_expected(checks, question_map, "Q23", time_by_team)
    compare_expected(checks, question_map, "Q24", {"policy_minutes": 15, "breached_p1": p1_current})
    compare_expected(checks, question_map, "Q25", {"policy_minutes": 30, "breached_p1": p1_old})
    compare_expected(checks, question_map, "Q28", sum(row["customer_id"] == "C003" for row in tables["tickets"]))
    compare_expected(checks, question_map, "Q29", time_by_team["T03"])
    latest_release = max(tables["releases"], key=lambda row: row["release_date"])
    compare_expected(checks, question_map, "Q30", {"count": len(tables["releases"]), "latest_version": latest_release["version"]})
    compare_expected(checks, question_map, "Q34", [row["to_status"] for row in sorted(events_by_ticket["TCK-0001"], key=lambda row: (row["event_at"], row["event_id"]))])

    repo = root / "repo"
    if repo.is_dir() and (repo / ".git").is_dir():
        git_env = os.environ.copy()
        git_env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
        result = subprocess.run(["git", "symbolic-ref", "--short", "HEAD"], cwd=repo, env=git_env, text=True, capture_output=True, check=False)
        checks.require(result.returncode == 0 and result.stdout.strip() == "main", "Git branch must be main")
        result = subprocess.run(["git", "rev-list", "--count", "main"], cwd=repo, env=git_env, text=True, capture_output=True, check=False)
        checks.require(result.returncode == 0 and result.stdout.strip() == "12", "Git history must contain 12 commits")
        for release in tables["releases"]:
            result = subprocess.run(["git", "cat-file", "-e", release["commit_ref"]], cwd=repo, env=git_env, text=True, capture_output=True, check=False)
            checks.require(result.returncode == 0, f"release commit missing: {release['release_id']}")
    else:
        checks.errors.append("missing generated Git repository")

    summary = {
        "dataset_revision": manifest.get("dataset_revision"),
        "month": manifest.get("month"),
        "seed": manifest.get("seed"),
        "documents": expected_counts["documents_total"],
        "staff": len(tables["employees"]),
        "teams": len(tables["teams"]),
        "customers": len(tables["customers"]),
        "contracts": len(tables["contracts"]),
        "assets": len(tables["assets"]),
        "tickets": len(tables["tickets"]),
        "ticket_events": len(tables["ticket_events"]),
        "invoices": len(tables["invoices"]),
        "payments": len(tables["payments"]),
        "time_entries": len(tables["time_entries"]),
        "releases": len(tables["releases"]),
        "golden_questions": len(expected.get("questions", [])),
        "errors": checks.errors,
    }
    return (1 if checks.errors else 0), summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed-dir", required=True)
    args = parser.parse_args(argv)
    code, summary = validate(Path(args.seed_dir))
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
