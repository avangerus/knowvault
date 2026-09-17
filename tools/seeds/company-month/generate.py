#!/usr/bin/env python3
"""Generate a deterministic, fictional company-month source fixture.

The generated tree is deliberately a source fixture, not KnowVault business
logic.  It contains documents, a tiny Git repository and an external SQL
source.  ``control/`` is an oracle and must stay outside connector mounts.
"""

from __future__ import annotations

import argparse
import calendar
import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Iterable


DATASET_REVISION = "company-month-seed-v2-en"
DEFAULT_MONTH = "2026-08"
DEFAULT_SEED = "company-month-v1"
TIMEZONE = "+03:00"
TIMEZONE_NAME = "Europe/Moscow"
SOURCE_ROOTS = ("documents", "repo", "relational")
TABLE_COLUMNS: dict[str, list[str]] = {
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


class StableRng:
    """Small keyed PRNG whose results do not depend on Python's random module."""

    def __init__(self, seed: str) -> None:
        self.seed = str(seed)

    def number(self, key: str) -> int:
        raw = hashlib.sha256((self.seed + "|" + key).encode("utf-8")).digest()
        return int.from_bytes(raw[:8], "big")

    def randint(self, key: str, low: int, high: int) -> int:
        return low + self.number(key) % (high - low + 1)

    def choice(self, key: str, values: list[str]) -> str:
        return values[self.number(key) % len(values)]


def fail(message: str) -> None:
    raise SystemExit("company-month seed: " + message)


def parse_month(value: str) -> tuple[dt.date, dt.date, dt.datetime]:
    if value != DEFAULT_MONTH:
        fail(f"company-month-seed-v1 supports only --month={DEFAULT_MONTH}")
    if not re.fullmatch(r"\d{4}-\d{2}", value):
        fail("--month must use YYYY-MM")
    try:
        year, month = (int(part) for part in value.split("-"))
        first = dt.date(year, month, 1)
    except ValueError as exc:
        fail(f"invalid --month: {exc}")
    last = dt.date(year, month, calendar.monthrange(year, month)[1])
    next_month = last + dt.timedelta(days=1)
    cutoff = dt.datetime(next_month.year, next_month.month, next_month.day, tzinfo=dt.timezone(dt.timedelta(hours=3)))
    return first, last, cutoff


def date_text(value: dt.date) -> str:
    return value.isoformat()


def local_dt(day: dt.date, hour: int, minute: int = 0) -> dt.datetime:
    return dt.datetime(day.year, day.month, day.day, hour, minute, tzinfo=dt.timezone(dt.timedelta(hours=3)))


def timestamp(value: dt.datetime) -> str:
    return value.isoformat(timespec="seconds")


def write_bytes(root: Path, relative: str, data: bytes) -> None:
    path = root / Path(relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def write_text(root: Path, relative: str, text: str) -> None:
    write_bytes(root, relative, (text.rstrip("\n") + "\n").encode("utf-8"))


def write_json(root: Path, relative: str, value: Any) -> None:
    write_text(root, relative, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def write_csv(root: Path, relative: str, columns: list[str], rows: Iterable[dict[str, Any]]) -> None:
    path = root / Path(relative)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=columns, lineterminator="\n", extrasaction="raise")
        writer.writeheader()
        for row in rows:
            writer.writerow({column: row.get(column, "") for column in columns})


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def make_base_data(first: dt.date, last: dt.date, seed: str) -> dict[str, list[dict[str, Any]]]:
    rng = StableRng(seed)
    teams = [
        {"team_id": "T01", "team_code": "OPS", "team_name": "Operations Center", "manager_employee_id": "E001"},
        {"team_id": "T02", "team_code": "SUP", "team_name": "Customer Support", "manager_employee_id": "E007"},
        {"team_id": "T03", "team_code": "ENG", "team_name": "Engineering Platform", "manager_employee_id": "E013"},
        {"team_id": "T04", "team_code": "FIN", "team_name": "Finance and Contracts", "manager_employee_id": "E019"},
    ]
    roles = {
        "T01": ["Coordinator", "Dispatcher", "Operations Specialist", "Senior Operator", "Operator", "Operator"],
        "T02": ["Support Lead", "Support Engineer", "Support Engineer", "Support Engineer", "SLA Coordinator", "Knowledge Base Specialist"],
        "T03": ["Platform Lead", "Backend Engineer", "Backend Engineer", "SRE Engineer", "QA Engineer", "Release Engineer"],
        "T04": ["Financial Controller", "Accountant", "Accountant", "Contract Manager", "Analyst", "Payments Specialist"],
    }
    employees: list[dict[str, Any]] = []
    for index in range(24):
        team_id = teams[index // 6]["team_id"]
        employee_number = index + 1
        active_to = "" if employee_number != 24 else date_text(last)
        employees.append(
            {
                "employee_id": f"E{employee_number:03d}",
                "team_id": team_id,
                "employee_name": f"Employee{employee_number:02d}",
                "role": roles[team_id][index % 6],
                "email": f"staff{employee_number:02d}@example.invalid",
                "active_from": "2026-01-01",
                "active_to": active_to,
            }
        )

    customers: list[dict[str, Any]] = []
    segments = ["retail", "logistics", "education", "manufacturing"]
    regions = ["North", "Central", "South", "East"]
    tiers = ["standard", "standard", "priority", "standard", "priority", "standard", "standard", "priority"]
    for index in range(8):
        number = index + 1
        customers.append(
            {
                "customer_id": f"C{number:03d}",
                "customer_name": f"Customer{number:02d} Demo",
                "segment": segments[index % len(segments)],
                "region": regions[index % len(regions)],
                "primary_contact": f"contact{number:02d}@example.invalid",
                "support_tier": tiers[index],
            }
        )

    services = [
        {"service_code": "SVC-CORE", "service_name": "Ticket Management", "description": "Ticket intake, routing and tracking", "default_team_id": "T02"},
        {"service_code": "SVC-MON", "service_name": "Monitoring", "description": "Monitoring integration availability", "default_team_id": "T03"},
        {"service_code": "SVC-DATA", "service_name": "Data Exchange", "description": "Scheduled exports and synchronization", "default_team_id": "T03"},
        {"service_code": "SVC-OPS", "service_name": "Operations", "description": "Daily operations and SLA tracking", "default_team_id": "T01"},
        {"service_code": "SVC-REPORT", "service_name": "Reporting", "description": "Monthly and weekly customer reports", "default_team_id": "T04"},
    ]

    contract_specs = [
        ("K001", "C001", "KV-2026-001", "2026-01-10", "2026-12-31"),
        ("K002", "C002", "KV-2026-002", "2026-02-01", "2026-11-30"),
        ("K003", "C003", "KV-2026-003", "2026-01-20", "2026-12-31"),
        ("K004", "C004", "KV-2026-004", "2026-03-01", "2027-02-28"),
        ("K005", "C005", "KV-2026-005", "2026-01-15", "2026-12-31"),
        ("K006", "C006", "KV-2026-006", "2026-04-01", "2027-03-31"),
        ("K007", "C007", "KV-2026-007", "2026-02-15", "2026-10-31"),
        ("K008", "C008", "KV-2026-008", "2026-05-01", "2027-04-30"),
        ("K009", "C001", "KV-2026-009", "2026-06-01", "2027-05-31"),
        ("K010", "C004", "KV-2025-010", "2025-12-01", "2026-08-21"),
    ]
    contracts: list[dict[str, Any]] = []
    for index, (contract_id, customer_id, contract_no, start_date, end_date) in enumerate(contract_specs, start=1):
        end_value = dt.date.fromisoformat(end_date)
        status = "active" if end_value >= last else "expired"
        contracts.append(
            {
                "contract_id": contract_id,
                "customer_id": customer_id,
                "contract_no": contract_no,
                "start_date": start_date,
                "end_date": end_date,
                "status": status,
                "sla_policy_version": "sla-2026-08-current",
                "monthly_fee_rub": 48000 + index * 3500,
                "renewal_date": date_text(end_value + dt.timedelta(days=1)),
            }
        )

    assets: list[dict[str, Any]] = []
    asset_types = ["gateway", "agent", "connector", "terminal"]
    asset_statuses = ["active", "active", "active", "maintenance", "retired"]
    customer_assets: dict[str, list[str]] = {customer["customer_id"]: [] for customer in customers}
    for index in range(80):
        asset_number = index + 1
        customer_id = customers[index % len(customers)]["customer_id"]
        status = "retired" if asset_number % 17 == 0 else ("maintenance" if asset_number % 13 == 0 else "active")
        asset_id = f"A{asset_number:04d}"
        installed = first - dt.timedelta(days=30 + asset_number * 3)
        last_seen = local_dt(first + dt.timedelta(days=(asset_number * 3) % 29), 8 + asset_number % 9, asset_number % 60)
        assets.append(
            {
                "asset_id": asset_id,
                "customer_id": customer_id,
                "asset_type": asset_types[index % len(asset_types)],
                "asset_name": f"Node-{asset_number:03d}",
                "status": status,
                "installed_date": date_text(installed),
                "last_seen_at": timestamp(last_seen),
            }
        )
        customer_assets[customer_id].append(asset_id)

    contracts_by_customer: dict[str, list[str]] = {customer["customer_id"]: [] for customer in customers}
    for contract in contracts:
        contracts_by_customer[contract["customer_id"]].append(contract["contract_id"])
    employees_by_team: dict[str, list[str]] = {team["team_id"]: [] for team in teams}
    for employee in employees:
        employees_by_team[employee["team_id"]].append(employee["employee_id"])

    current_sla_minutes = {"P1": 15, "P2": 60, "P3": 240, "P4": 2880}
    categories = ["access", "exchange", "data", "configuration", "reporting"]
    tickets: list[dict[str, Any]] = []
    ticket_events: list[dict[str, Any]] = []
    for index in range(600):
        ticket_number = index + 1
        ticket_id = f"TCK-{ticket_number:04d}"
        customer_id = customers[(rng.number(f"customer-{ticket_number}") + index) % len(customers)]["customer_id"]
        contract_id = contracts_by_customer[customer_id][index % len(contracts_by_customer[customer_id])]
        asset_id = customer_assets[customer_id][index % len(customer_assets[customer_id])]
        team_id = "T02" if index % 5 != 0 else ("T03" if index % 2 == 0 else "T01")
        assigned_employee_id = employees_by_team[team_id][index % len(employees_by_team[team_id])]
        category = categories[(index + rng.randint(f"category-{ticket_number}", 0, 4)) % len(categories)]
        if ticket_number % 37 == 0:
            priority = "P1"
        elif ticket_number % 5 == 0:
            priority = "P2"
        elif ticket_number % 3 == 0:
            priority = "P3"
        else:
            priority = "P4"
        status_bucket = index % 12
        if status_bucket <= 7:
            status = "closed"
        elif status_bucket <= 9:
            status = "resolved"
        elif status_bucket == 10:
            status = "pending"
        else:
            status = "open"
        day = first + dt.timedelta(days=(index * 7 + rng.randint(f"day-{ticket_number}", 0, 4)) % 29)
        created = local_dt(day, 9 + index % 9, (index * 13) % 60)
        response_delay = {
            "P1": 8 + index % 8,
            "P2": 34 + index % 25,
            "P3": 100 + index % 90,
            "P4": 180 + index % 240,
        }[priority]
        if ticket_number % 41 == 0:
            response_delay += 30
        if ticket_number % 53 == 0:
            response_delay += 75
        first_response = created + dt.timedelta(minutes=response_delay)
        terminal_at = created + dt.timedelta(hours=4 + index % 7)
        resolved_at = terminal_at if status in {"resolved", "closed"} else None
        closed_at = terminal_at + dt.timedelta(hours=2) if status == "closed" else None
        due_at = created + dt.timedelta(minutes=current_sla_minutes[priority])
        ticket = {
            "ticket_id": ticket_id,
            "customer_id": customer_id,
            "contract_id": contract_id,
            "asset_id": asset_id,
            "assigned_team_id": team_id,
            "assigned_employee_id": assigned_employee_id,
            "category": category,
            "priority": priority,
            "subject": f"Check {category}: {customer_id} / {asset_id}",
            "created_at": timestamp(created),
            "first_response_at": timestamp(first_response),
            "resolved_at": timestamp(resolved_at) if resolved_at else "",
            "closed_at": timestamp(closed_at) if closed_at else "",
            "status": status,
            "sla_policy_version": "sla-2026-08-current",
            "sla_due_at": timestamp(due_at),
            "sla_breached": "true" if response_delay > current_sla_minutes[priority] else "false",
        }
        tickets.append(ticket)
        event_times: list[tuple[dt.datetime, str, str, str]] = [
            (created, "", "new", "Ticket registered"),
            (created + dt.timedelta(minutes=2), "new", "in_progress", "Assignee selected"),
        ]
        if status == "closed":
            event_times.extend(
                [
                    (terminal_at - dt.timedelta(hours=2), "in_progress", "resolved", "Resolution confirmed"),
                    (closed_at, "resolved", "closed", "Closed after verification"),
                ]
            )
        elif status == "resolved":
            event_times.append((terminal_at, "in_progress", "resolved", "Resolution confirmed"))
        elif status == "pending":
            event_times.append((terminal_at, "in_progress", "pending", "Waiting for customer response"))
        else:
            event_times.append((terminal_at, "in_progress", "open", "Work continues"))
        for event_index, (event_at, from_status, to_status, note) in enumerate(event_times, start=1):
            ticket_events.append(
                {
                    "event_id": f"EVT-{ticket_number:04d}-{event_index:02d}",
                    "ticket_id": ticket_id,
                    "event_at": timestamp(event_at),
                    "from_status": from_status,
                    "to_status": to_status,
                    "actor_employee_id": assigned_employee_id,
                    "note": note,
                }
            )

    invoices: list[dict[str, Any]] = []
    payments: list[dict[str, Any]] = []
    cutoff_date = last + dt.timedelta(days=1)
    for index in range(40):
        number = index + 1
        contract = contracts[index % len(contracts)]
        issue_date = first + dt.timedelta(days=(index * 5) % 26)
        due_date = issue_date + dt.timedelta(days=14)
        subtotal = 38000 + (index % 10) * 4200 + (index % len(contracts)) * 1000
        tax = subtotal * 20 // 100
        total = subtotal + tax
        invoice_id = f"INV-{number:04d}"
        pattern = index % 5
        payment_parts: list[int] = []
        if pattern in {0, 3, 4}:
            payment_parts = [total] if pattern in {0, 4} else [total // 2, total - total // 2]
        elif pattern == 2:
            payment_parts = [total // 2]
        paid_total = sum(payment_parts)
        if paid_total == total:
            status = "paid"
        elif paid_total:
            status = "partial"
        elif due_date < cutoff_date:
            status = "overdue"
        else:
            status = "issued"
        invoices.append(
            {
                "invoice_id": invoice_id,
                "contract_id": contract["contract_id"],
                "invoice_date": date_text(issue_date),
                "due_date": date_text(due_date),
                "subtotal_rub": subtotal,
                "tax_rub": tax,
                "total_rub": total,
                "status": status,
            }
        )
        for payment_index, amount in enumerate(payment_parts, start=1):
            payment_date = issue_date + dt.timedelta(days=1 + payment_index)
            payments.append(
                {
                    "payment_id": f"PAY-{number:04d}-{payment_index:02d}",
                    "invoice_id": invoice_id,
                    "payment_date": date_text(payment_date),
                    "amount_rub": amount,
                    "method": "bank_transfer" if payment_index % 2 else "card",
                    "reference": f"DEMO-{number:04d}-{payment_index:02d}",
                }
            )

    time_entries: list[dict[str, Any]] = []
    work_offsets = [2, 4, 7, 9, 12, 16, 21, 26]
    for employee_index, employee in enumerate(employees):
        for entry_index, offset in enumerate(work_offsets, start=1):
            work_date = first + dt.timedelta(days=offset)
            ticket_index = (employee_index * 17 + entry_index * 11) % len(tickets)
            ticket = tickets[ticket_index]
            hours = 4 + (employee_index + entry_index) % 5
            time_entries.append(
                {
                    "entry_id": f"TE-{employee_index + 1:02d}-{entry_index:02d}",
                    "employee_id": employee["employee_id"],
                    "ticket_id": ticket["ticket_id"],
                    "contract_id": ticket["contract_id"],
                    "work_date": date_text(work_date),
                    "hours": hours,
                    "kind": "billable" if (employee_index + entry_index) % 4 else "internal",
                }
            )

    return {
        "teams": teams,
        "employees": employees,
        "customers": customers,
        "services": services,
        "contracts": contracts,
        "assets": assets,
        "tickets": tickets,
        "ticket_events": ticket_events,
        "invoices": invoices,
        "payments": payments,
        "time_entries": time_entries,
    }


def git_run(repo: Path, args: list[str], env: dict[str, str]) -> str:
    result = subprocess.run(["git", *args], cwd=repo, env=env, text=True, capture_output=True, check=False)
    if result.returncode:
        fail(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def build_repo(repo: Path, first: dt.date) -> list[dict[str, str]]:
    repo.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull})
    git_run(repo, ["init", "--quiet", "-b", "main"], env)
    commits: list[dict[str, str]] = []
    step_files: list[tuple[str, dict[str, str], str | None]] = [
        (
            "feat: initialize demo service",
            {
                ".gitattributes": "* text eol=lf\n",
                "README.md": "# KV Service Demo\n\nSynthetic service for code-reading tests.\nMain branch: `main`.\n",
                "go.mod": "module example.invalid/kv-demo\n\ngo 1.22\n",
            },
            "v0.1.0",
        ),
        (
            "feat: add command entrypoint",
            {
                "cmd/kvdemo/main.go": "package main\n\nimport \"fmt\"\n\nconst serviceName = \"kv-demo\"\n\nfunc main() {\n\tfmt.Println(serviceName)\n}\n",
            },
            "v0.2.0",
        ),
        (
            "feat: define ticket escalation window",
            {
                "internal/ticket/router.go": "package ticket\n\nconst escalationWindowMinutes = 30\n\nfunc EscalationWindowMinutes() int {\n\treturn escalationWindowMinutes\n}\n",
            },
            "v0.3.0",
        ),
        (
            "feat: add priority names",
            {
                "internal/ticket/priority.go": "package ticket\n\nconst (\n\tPriorityP1 = \"P1\"\n\tPriorityP2 = \"P2\"\n\tPriorityP3 = \"P3\"\n)\n",
            },
            None,
        ),
        (
            "docs: record initial SLA setting",
            {
                "config/sla.yaml": "policy: sla-2026-01\nfirst_response_minutes:\n  P1: 30\n  P2: 120\n",
            },
            None,
        ),
        (
            "test: cover ticket router",
            {
                "internal/ticket/router_test.go": "package ticket\n\nimport \"fmt\"\n\nfunc ExampleEscalationWindowMinutes() {\n\tfmt.Println(EscalationWindowMinutes())\n\t// Output: 30\n}\n",
            },
            None,
        ),
        (
            "fix: align escalation with August policy",
            {
                "internal/ticket/router.go": "package ticket\n\nconst escalationWindowMinutes = 15\n\nfunc EscalationWindowMinutes() int {\n\treturn escalationWindowMinutes\n}\n",
                "internal/ticket/router_test.go": "package ticket\n\nimport \"fmt\"\n\nfunc ExampleEscalationWindowMinutes() {\n\tfmt.Println(EscalationWindowMinutes())\n\t// Output: 15\n}\n",
            },
            "v0.4.0",
        ),
        (
            "feat: add assignment helper",
            {
                "internal/ticket/assignment.go": "package ticket\n\nfunc NeedsPlatform(category string) bool {\n\treturn category == \"exchange\" || category == \"data\"\n}\n",
            },
            None,
        ),
        (
            "ops: publish current SLA config",
            {
                "config/sla.yaml": "policy: sla-2026-08-current\neffective_from: 2026-08-01\nfirst_response_minutes:\n  P1: 15\n  P2: 60\n",
            },
            None,
        ),
        (
            "docs: add incident checklist",
            {
                "docs/incident-checklist.md": "# Incident checklist\n\n1. Record the detection time.\n2. Assign an owner.\n3. Add a link to the ticket.\n",
            },
            None,
        ),
        (
            "feat: add health command",
            {
                "cmd/kvdemo/health.go": "package main\n\nfunc healthy() bool {\n\treturn true\n}\n",
            },
            "v0.5.0",
        ),
        (
            "release: prepare August demo",
            {
                "CHANGELOG.md": "# Changelog\n\n## 2026-08\n\n- Added the current SLA and escalation checks.\n",
            },
            None,
        ),
    ]
    for index, (subject, files, tag) in enumerate(step_files, start=1):
        for relative, content in files.items():
            write_text(repo, relative, content)
        commit_date = dt.datetime(first.year, first.month, first.day, 9, 0, tzinfo=dt.timezone(dt.timedelta(hours=3))) + dt.timedelta(days=index * 2 - 2)
        commit_date_text = commit_date.strftime("%Y-%m-%dT%H:%M:%S+03:00")
        commit_env = dict(env)
        commit_env.update(
            {
                "GIT_AUTHOR_NAME": "KV Seed Bot",
                "GIT_AUTHOR_EMAIL": "seed-bot@example.invalid",
                "GIT_COMMITTER_NAME": "KV Seed Bot",
                "GIT_COMMITTER_EMAIL": "seed-bot@example.invalid",
                "GIT_AUTHOR_DATE": commit_date_text,
                "GIT_COMMITTER_DATE": commit_date_text,
            }
        )
        git_run(repo, ["-c", "core.autocrlf=false", "add", "-A"], commit_env)
        git_run(repo, ["-c", "core.autocrlf=false", "commit", "--quiet", "--no-gpg-sign", "-m", subject], commit_env)
        commit_hash = git_run(repo, ["rev-parse", "HEAD"], commit_env)
        if tag:
            git_run(repo, ["tag", tag, commit_hash], commit_env)
        commits.append({"index": str(index), "subject": subject, "date": commit_date_text, "hash": commit_hash, "tag": tag or ""})
    return commits


def make_releases(data: dict[str, list[dict[str, Any]]], commits: list[dict[str, str]], first: dt.date) -> None:
    services = ["SVC-CORE", "SVC-MON", "SVC-DATA", "SVC-OPS", "SVC-REPORT"]
    rows: list[dict[str, Any]] = []
    for index in range(12):
        commit = commits[index]
        release_day = first + dt.timedelta(days=index * 2)
        rows.append(
            {
                "release_id": f"REL-{index + 1:03d}",
                "version": f"v0.{index + 1}.0",
                "release_date": date_text(release_day),
                "service_code": services[index % len(services)],
                "status": "deployed",
                "commit_ref": commit["hash"],
                "released_by_employee_id": "E018",
            }
        )
    data["releases"] = rows


def metrics(data: dict[str, list[dict[str, Any]]], first: dt.date) -> dict[str, dict[str, Any]]:
    tickets = data["tickets"]
    result: dict[str, dict[str, Any]] = {}
    for week_index in range(4):
        start = first + dt.timedelta(days=week_index * 7)
        end = first + dt.timedelta(days=(week_index + 1) * 7 - 1)
        if week_index == 3:
            end = first + dt.timedelta(days=calendar.monthrange(first.year, first.month)[1] - 1)
        rows = [ticket for ticket in tickets if start <= dt.date.fromisoformat(ticket["created_at"][:10]) <= end]
        result[f"W{week_index + 1:02d}"] = {
            "start": date_text(start),
            "end": date_text(end),
            "created": len(rows),
            "closed": sum(ticket["status"] == "closed" for ticket in rows),
            "resolved": sum(ticket["status"] == "resolved" for ticket in rows),
            "pending": sum(ticket["status"] == "pending" for ticket in rows),
            "open": sum(ticket["status"] == "open" for ticket in rows),
            "p1": sum(ticket["priority"] == "P1" for ticket in rows),
            "sla_breached": sum(ticket["sla_breached"] == "true" for ticket in rows),
            "customers": len({ticket["customer_id"] for ticket in rows}),
            "top_category": max(("access", "exchange", "data", "configuration", "reporting"), key=lambda category: sum(ticket["category"] == category for ticket in rows)),
        }
    return result


def choose_incident_ticket(data: dict[str, list[dict[str, Any]]], target: dt.date, category: str | None = None) -> dict[str, Any]:
    """Choose a row-backed incident ticket, preferring an exact target date."""
    candidates = [
        ticket
        for ticket in data["tickets"]
        if category is None or ticket["category"] == category
    ]
    priority_rank = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    return min(
        candidates,
        key=lambda ticket: (
            abs((dt.date.fromisoformat(ticket["created_at"][:10]) - target).days),
            priority_rank.get(ticket["priority"], 9),
            ticket["ticket_id"],
        ),
    )


def md_document(title: str, source: str, effective: str, body: str, status: str = "working document") -> str:
    return f"# {title}\n\n- Source: {source}\n- Status: {status}\n- Effective/recorded: {effective}\n\n{body.strip()}\n"


def build_documents(root: Path, data: dict[str, list[dict[str, Any]]], commits: list[dict[str, str]], first: dt.date, last: dt.date) -> None:
    docs: dict[str, str] = {}
    customer_by_id = {row["customer_id"]: row for row in data["customers"]}
    contract_by_id = {row["contract_id"]: row for row in data["contracts"]}
    weekly = metrics(data, first)
    incident_gateway = choose_incident_ticket(data, first + dt.timedelta(days=6))
    incident_sync = choose_incident_ticket(data, first + dt.timedelta(days=17), "data")
    gateway_events = sorted([event for event in data["ticket_events"] if event["ticket_id"] == incident_gateway["ticket_id"]], key=lambda event: (event["event_at"], event["event_id"]))
    sync_events = sorted([event for event in data["ticket_events"] if event["ticket_id"] == incident_sync["ticket_id"]], key=lambda event: (event["event_at"], event["event_id"]))
    docs["documents/common/company-profile.md"] = md_document(
        "KV Service Demo: dataset profile",
        "company-register",
        "2026-08-01..2026-08-31",
        "KV Service Demo is a fictional organization for local KnowVault connector testing.\n\nMonthly snapshot: August 2026. All dates and times use Europe/Moscow (UTC+03:00). The snapshot cutoff is 2026-09-01T00:00:00+03:00. Names, addresses and contacts are synthetic; the `example.invalid` domain is not intended for mail delivery.\n\nThis dataset includes documents, a local Git repository and a separate external PostgreSQL source. The oracle in `control/` is not a knowledge source and must not be mounted by connectors.",
        "canonical fixture profile",
    )
    docs["documents/common/organization/teams-and-roles.md"] = md_document(
        "Teams and roles",
        "hr-directory-demo",
        "2026-08-01",
        "The company has four teams: T01 Operations Center, T02 Customer Support, T03 Engineering Platform and T04 Finance and Contracts. Each team has six synthetic employees. Their managers are E001, E007, E013 and E019 respectively.\n\nSupport handles tickets and tracks SLAs; the platform team owns monitoring, data exchange and releases; operations provides daily coordination; finance manages contracts, invoices and payments.",
    )
    docs["documents/common/organization/working-hours.md"] = md_document(
        "Working calendar",
        "operations-calendar",
        "2026-08-01",
        "The duty desk works weekdays 09:00–18:00 Europe/Moscow time. P1 tickets enter the queue around the clock; processing outside working hours is recorded as an event with its actual timestamp. All fixture calculations use the same data cutoff: 2026-09-01T00:00:00+03:00.",
    )
    docs["documents/common/services/catalog.md"] = md_document(
        "Service catalog",
        "service-catalog",
        "2026-08-01",
        "Service codes are used in CSV files and the release register:\n\n- SVC-CORE — ticket management and routing, owner T02.\n- SVC-MON — availability monitoring, owner T03.\n- SVC-DATA — data exchange, owner T03.\n- SVC-OPS — operations, owner T01.\n- SVC-REPORT — reporting, owner T04.\n\nThe catalog describes each service; actual ticket volumes are in the separate tabular source.",
    )
    docs["documents/common/policy/sla-2026-01-superseded.md"] = md_document(
        "SLA-2026-01 (superseded)",
        "policy-board",
        "2026-01-01..2026-07-31",
        "The old policy required a first response within 30 minutes for P1, 120 minutes for P2, 480 minutes for P3 and two working days for P4. It has been `superseded` since 2026-08-01. This version applies to questions about events before August; it is not current for the August snapshot.",
        "historical, superseded",
    )
    docs["documents/common/policy/sla-2026-08-current.md"] = md_document(
        "SLA-2026-08 (current policy)",
        "policy-board",
        "2026-08-01",
        "The current SLA has applied since 2026-08-01: first response for P1 within 15 minutes, P2 within 60 minutes, P3 within 240 minutes and P4 within two working days (represented as 2880 minutes in the tabular test sample). This document explicitly replaces `sla-2026-01-superseded.md`. Answers about August use this version; the old version is cited only for historical questions.",
        "current, effective",
    )
    docs["documents/common/policy/incident-severity.md"] = md_document(
        "Incident classification",
        "incident-board",
        "2026-08-01",
        "P1 means complete unavailability or loss of critical data exchange; P2 means noticeable degradation for several customers; P3 means a limited failure; P4 means advice or planned configuration. P1 requires a detection time, owner, ticket link, restoration time and root-cause review.",
    )
    for week_name, week in weekly.items():
        docs[f"documents/common/weekly/operations-{week_name}.md"] = md_document(
            f"Operations report {week_name}: {week['start']} — {week['end']}",
            "operations-weekly-register",
            f"{week['start']}..{week['end']}",
            f"Tickets created during the operational week: {week['created']}. Of these, closed: {week['closed']}, resolved without closure: {week['resolved']}, awaiting a response: {week['pending']}, still open: {week['open']}.\n\nP1 tickets: {week['p1']}; tickets breaching the current SLA: {week['sla_breached']}; customers affected: {week['customers']}. Most frequent category: '{week['top_category']}'. Row and event details are in `relational/tickets.csv` and `relational/ticket_events.csv`.",
        )
    docs["documents/common/meetings/2026-08-05.md"] = md_document(
        "Meeting decisions 2026-08-05",
        "management-meeting",
        "2026-08-05",
        "1. Record the transition to SLA-2026-08 for the August snapshot.\n2. Keep historical and current policies separate in reports.\n3. Include the ticket ID in SVC-DATA incident postmortems.\n\nPublication owner: E013; review due 2026-08-12.",
    )
    docs["documents/common/meetings/2026-08-19.md"] = md_document(
        "Meeting decisions 2026-08-19",
        "management-meeting",
        "2026-08-19",
        "1. Keep the nightly data-exchange check in the 02:00–03:00 window.\n2. Review overdue P1 tickets weekly for priority customers.\n3. Include the full commit ref in release notes, not just the version number.\n\nDecision review is scheduled for 2026-08-26; the release register is in the separate tabular source.",
    )
    docs["documents/common/release-train.md"] = md_document(
        "Release train policy",
        "release-board",
        "2026-08-01",
        "The release train publishes small changes every two days during the test month. Version numbers and release dates are in the `releases` table; code is verified by reading the repository at the commit ref. In the August example, releases have status `deployed`, and E018 is authorized to publish them.",
    )
    docs["documents/common/knowledge-maintenance.md"] = md_document(
        "Knowledge base maintenance",
        "knowledge-council",
        "2026-08-01",
        "Policy documents have explicit effective dates and statuses. When a rule changes, the old version remains a separate object. Weekly reports capture a snapshot and do not replace source rows. Finance documents have a separate root and access permission.",
    )

    docs["documents/support/runbooks/ticket-triage.md"] = md_document(
        "Runbook: ticket triage",
        "support-runbook",
        "2026-08-01",
        "1. Find the customer and active contract.\n2. Check the asset_id and latest events.\n3. Assign P1–P4 using the incident classification.\n4. Record a separate first-response timestamp.\n5. For P1 responses delayed more than 15 minutes, record the breach reason in a note.",
    )
    docs["documents/support/runbooks/escalation.md"] = md_document(
        "Runbook: escalation to the platform team",
        "support-runbook",
        "2026-08-01",
        "The 'exchange' and 'data' categories are routed to T03. Attach the ticket link and commit ref to the incident record. Before handing it over to the customer, the support engineer checks that the latest event has not been changed retroactively.",
    )
    docs["documents/support/runbooks/asset-linking.md"] = md_document(
        "Runbook: linking assets",
        "support-runbook",
        "2026-08-01",
        "Each ticket refers to one asset_id. Match the asset's customer_id to the ticket's customer_id; a mismatch is a data error. Status `retired` does not prevent reading history, but new operations on that asset require a support-team decision.",
    )
    docs["documents/support/runbooks/weekly-review.md"] = md_document(
        "Runbook: weekly review",
        "support-runbook",
        "2026-08-01",
        "At the end of each operational week, the team reviews P1 tickets, SLA breaches, `pending` tickets and customers with recurring categories. Counts are checked against CSV files; causes are checked against incident documents.",
    )

    customer_services = ["SVC-CORE", "SVC-MON", "SVC-DATA", "SVC-REPORT"]
    for index, customer in enumerate(data["customers"], start=1):
        customer_id = customer["customer_id"]
        contract_ids = [contract["contract_id"] for contract in data["contracts"] if contract["customer_id"] == customer_id]
        docs[f"documents/support/customers/{customer_id}.md"] = md_document(
            f"Profile: {customer['customer_name']}",
            "customer-success-register",
            "2026-08-01",
            f"Customer ID: {customer_id}. Segment: {customer['segment']}; region: {customer['region']}; support tier: {customer['support_tier']}. Contact: {customer['primary_contact']}.\n\nServices listed in the support record: {', '.join(customer_services[: 2 + index % 3])}. Contracts and amounts are not copied here: finance maintains them in `documents/finance/` and the external source. Contract IDs for navigation: {', '.join(contract_ids)}.",
        )

    docs["documents/support/incidents/INC-2026-08-07-gateway.md"] = md_document(
        "INC-2026-08-07: gateway latency",
        "incident-register",
        "2026-08-07",
        f"{incident_gateway['created_at'][11:16]} — SVC-MON monitoring detected increased response times; registered {incident_gateway['priority']} ticket {incident_gateway['ticket_id']} for {incident_gateway['customer_id']}. {incident_gateway['first_response_at'][11:16]} — first response recorded in the ticket. {gateway_events[-1]['event_at'][11:16]} — final ticket event: {incident_gateway['status']}. Cause: incorrect concurrent-request limit in the test configuration. Customer contacts and invoices are outside this review.",
        "incident review",
    )
    docs["documents/support/incidents/INC-2026-08-18-sync.md"] = md_document(
        "INC-2026-08-18: incomplete synchronization",
        "incident-register",
        "2026-08-18",
        f"{incident_sync['created_at'][11:16]} — incomplete SVC-DATA export detected; opened {incident_sync['priority']} ticket {incident_sync['ticket_id']} for {incident_sync['customer_id']}. {incident_sync['first_response_at'][11:16]} — first support response. {sync_events[-1]['event_at'][11:16]} — final ticket event: {incident_sync['status']}. Technical cause: a repeated offset in the nightly job. Temporary measure: retry a batch only after checking the latest event_id.",
        "incident review",
    )
    docs["documents/support/incidents/postmortem-2026-08-07.md"] = md_document(
        "Postmortem: gateway 2026-08-07",
        "incident-postmortem",
        "2026-08-11",
        f"Related ticket: {incident_gateway['ticket_id']}. Impact: request delays for several customers. Trigger: a configuration limit; the ticket row records the first response at {incident_gateway['first_response_at']}. Resolution: rollback, followed by a queue check. Actions: add a limit check to the release checklist; owner E013; review date 2026-08-20. Event times come from the incident register and ticket_events, not the monthly finance report.",
    )
    docs["documents/support/incidents/postmortem-2026-08-18.md"] = md_document(
        "Postmortem: synchronization 2026-08-18",
        "incident-postmortem",
        "2026-08-22",
        f"Related ticket: {incident_sync['ticket_id']}. Impact: one batch for {incident_sync['customer_id']} was incomplete. Cause: offset reuse; final ticket status: {incident_sync['status']}. Actions: block repeated offsets and check the latest event_id; owner E015; review date 2026-08-29.",
    )
    for week_name, week in weekly.items():
        rows = [ticket for ticket in data["tickets"] if week["start"] <= ticket["created_at"][:10] <= week["end"]]
        by_category = {category: sum(ticket["category"] == category for ticket in rows) for category in ("access", "exchange", "data", "configuration", "reporting")}
        docs[f"documents/support/weekly/support-{week_name}.md"] = md_document(
            f"Support report {week_name}",
            "support-weekly-register",
            f"{week['start']}..{week['end']}",
            f"Support received {week['created']} tickets. Categories: " + ", ".join(f"{key}={value}" for key, value in by_category.items()) + f". Week-end statuses in the snapshot: closed={week['closed']}, resolved={week['resolved']}, pending={week['pending']}, open={week['open']}. Questions about the cause of a specific ticket require its events and runbook, not just this report.",
        )
    docs["documents/support/decisions/2026-08-12-routing.md"] = md_document(
        "Support decision 2026-08-12",
        "support-council",
        "2026-08-12",
        "Tickets in the 'exchange' and 'data' categories require a latest-event check before escalation to T03. P1 retains an immediate path without waiting for the weekly review. This change does not alter the historical SLA policy.",
    )
    docs["documents/support/decisions/2026-08-26-maintenance.md"] = md_document(
        "Support decision 2026-08-26",
        "support-council",
        "2026-08-26",
        "The planned asset maintenance window is 2026-08-30 02:00–03:00. P1 tickets during this window count as incidents when impact is confirmed; ordinary tickets remain queued. The change log must include the asset_id.",
    )
    docs["documents/support/releases/v0.3.0.md"] = md_document(
        "Release v0.3.0: escalation window",
        "release-notes",
        "2026-08-05",
        "At repository ref `v0.3.0`, EscalationWindowMinutes returns 30 minutes. This is a historical ref; the current August policy is published in a separate release and SLA document.",
    )
    docs["documents/support/releases/v0.4.0.md"] = md_document(
        "Release v0.4.0: current SLA",
        "release-notes",
        "2026-08-13",
        "At ref `v0.4.0`, the escalation window changed to 15 minutes to match SLA-2026-08. For a reproducible check, read `internal/ticket/router.go` at that ref.",
    )
    docs["documents/support/releases/release-checklist.md"] = md_document(
        "Release checklist",
        "release-board",
        "2026-08-01",
        "Before publishing, check the SLA configuration, router test, incident checklist and commit ref. A version number without a commit ref is insufficient for code verification.",
    )
    docs["documents/support/sla-exceptions/priority-customers.md"] = md_document(
        "Exceptions for priority customers",
        "support-council",
        "2026-08-01",
        "The priority tier affects queue order and weekly review, but does not override the current SLA time limits. Any manual acceleration must be recorded as a ticket event.",
    )

    for contract in data["contracts"]:
        customer = customer_by_id[contract["customer_id"]]
        docs[f"documents/finance/contracts/{contract['contract_id']}.md"] = md_document(
            f"Contract record {contract['contract_no']}",
            "contract-register",
            f"{contract['start_date']}..{contract['end_date']}",
            f"Customer: {customer['customer_name']} ({customer['customer_id']}). Contract: {contract['contract_no']}; internal ID: {contract['contract_id']}. Monthly fee in the register: {contract['monthly_fee_rub']} RUB. SLA version: {contract['sla_policy_version']}. Status at the end of August: {contract['status']}. Renewal date from the register: {contract['renewal_date']}.",
            "finance scope source",
        )
    invoice_total = sum(int(invoice["total_rub"]) for invoice in data["invoices"])
    paid_total = sum(int(payment["amount_rub"]) for payment in data["payments"])
    outstanding = invoice_total - paid_total
    overdue = [invoice for invoice in data["invoices"] if invoice["status"] == "overdue"]
    docs["documents/finance/reports/invoice-register-2026-08.md"] = md_document(
        "Invoice register for August 2026",
        "finance-ledger",
        "2026-08-31",
        f"The register contains 40 invoices. Total invoiced: {invoice_total} RUB. Row statuses and amounts are in `relational/invoices.csv`; this report does not replace those rows.",
    )
    docs["documents/finance/reports/cash-receipts-2026-08.md"] = md_document(
        "Cash receipts for August 2026",
        "finance-ledger",
        "2026-08-31",
        f"The payment register records {len(data['payments'])} payments totaling {paid_total} RUB. The amount is the sum of rows in `relational/payments.csv`; payment references are synthetic.",
    )
    docs["documents/finance/reports/ar-aging-2026-08.md"] = md_document(
        "Accounts receivable at the snapshot cutoff",
        "finance-ledger",
        "2026-09-01T00:00:00+03:00",
        f"Outstanding register balance: {outstanding} RUB. Overdue invoices at the snapshot cutoff: {len(overdue)}. Verification uses invoice_id, due_date and payment amounts; support documents do not contain this metric.",
    )
    docs["documents/finance/reports/month-close-2026-08.md"] = md_document(
        "Month close 2026-08",
        "finance-close-board",
        "2026-09-01",
        "The August close checks invoices, payments and contracts that expired during the month. Contract K010 ends on 2026-08-21 and has status expired; other contract rows are checked against their own dates. Totals are verified against the external table.",
    )
    renewal_rows = sorted(data["contracts"], key=lambda contract: contract["renewal_date"])[:4]
    docs["documents/finance/reports/contract-renewals.md"] = md_document(
        "Upcoming renewals",
        "contract-register",
        "2026-08-31",
        "The first four renewal dates in the register: " + ", ".join(f"{row['contract_id']}={row['renewal_date']}" for row in renewal_rows) + ". For the full list, read individual contract records or the contracts table.",
    )
    for relative, text in sorted(docs.items()):
        write_text(root, relative, text)


def build_bootstrap(root: Path) -> None:
    ddl = """-- External PostgreSQL source for the fictional company-month fixture.
-- Run from the seed root with psql; this never targets the KnowVault product DB.
BEGIN;
CREATE TABLE teams (team_id text PRIMARY KEY, team_code text NOT NULL, team_name text NOT NULL, manager_employee_id text);
CREATE TABLE employees (employee_id text PRIMARY KEY, team_id text NOT NULL REFERENCES teams(team_id), employee_name text NOT NULL, role text NOT NULL, email text NOT NULL, active_from date NOT NULL, active_to date);
CREATE TABLE customers (customer_id text PRIMARY KEY, customer_name text NOT NULL, segment text NOT NULL, region text NOT NULL, primary_contact text NOT NULL, support_tier text NOT NULL);
CREATE TABLE services (service_code text PRIMARY KEY, service_name text NOT NULL, description text NOT NULL, default_team_id text NOT NULL REFERENCES teams(team_id));
CREATE TABLE contracts (contract_id text PRIMARY KEY, customer_id text NOT NULL REFERENCES customers(customer_id), contract_no text NOT NULL, start_date date NOT NULL, end_date date NOT NULL, status text NOT NULL, sla_policy_version text NOT NULL, monthly_fee_rub integer NOT NULL, renewal_date date NOT NULL);
CREATE TABLE assets (asset_id text PRIMARY KEY, customer_id text NOT NULL REFERENCES customers(customer_id), asset_type text NOT NULL, asset_name text NOT NULL, status text NOT NULL, installed_date date NOT NULL, last_seen_at timestamptz NOT NULL);
CREATE TABLE tickets (ticket_id text PRIMARY KEY, customer_id text NOT NULL REFERENCES customers(customer_id), contract_id text NOT NULL REFERENCES contracts(contract_id), asset_id text NOT NULL REFERENCES assets(asset_id), assigned_team_id text NOT NULL REFERENCES teams(team_id), assigned_employee_id text NOT NULL REFERENCES employees(employee_id), category text NOT NULL, priority text NOT NULL, subject text NOT NULL, created_at timestamptz NOT NULL, first_response_at timestamptz NOT NULL, resolved_at timestamptz, closed_at timestamptz, status text NOT NULL, sla_policy_version text NOT NULL, sla_due_at timestamptz NOT NULL, sla_breached boolean NOT NULL);
CREATE TABLE ticket_events (event_id text PRIMARY KEY, ticket_id text NOT NULL REFERENCES tickets(ticket_id), event_at timestamptz NOT NULL, from_status text, to_status text NOT NULL, actor_employee_id text NOT NULL REFERENCES employees(employee_id), note text NOT NULL);
CREATE TABLE invoices (invoice_id text PRIMARY KEY, contract_id text NOT NULL REFERENCES contracts(contract_id), invoice_date date NOT NULL, due_date date NOT NULL, subtotal_rub integer NOT NULL, tax_rub integer NOT NULL, total_rub integer NOT NULL, status text NOT NULL);
CREATE TABLE payments (payment_id text PRIMARY KEY, invoice_id text NOT NULL REFERENCES invoices(invoice_id), payment_date date NOT NULL, amount_rub integer NOT NULL, method text NOT NULL, reference text NOT NULL);
CREATE TABLE time_entries (entry_id text PRIMARY KEY, employee_id text NOT NULL REFERENCES employees(employee_id), ticket_id text NOT NULL REFERENCES tickets(ticket_id), contract_id text NOT NULL REFERENCES contracts(contract_id), work_date date NOT NULL, hours integer NOT NULL, kind text NOT NULL);
CREATE TABLE releases (release_id text PRIMARY KEY, version text NOT NULL, release_date date NOT NULL, service_code text NOT NULL REFERENCES services(service_code), status text NOT NULL, commit_ref text NOT NULL, released_by_employee_id text NOT NULL REFERENCES employees(employee_id));
"""
    copy_order = list(TABLE_COLUMNS)
    copy_lines = []
    for table in copy_order:
        columns = ", ".join(TABLE_COLUMNS[table])
        copy_lines.append(f"\\copy {table} ({columns}) FROM 'relational/{table}.csv' WITH (FORMAT csv, HEADER true, NULL '')")
    write_text(root, "relational/bootstrap.sql", ddl + "\n" + "\n".join(copy_lines) + "\nCOMMIT;\n")


def build_control(root: Path, data: dict[str, list[dict[str, Any]]], commits: list[dict[str, str]], first: dt.date, last: dt.date, cutoff: dt.datetime, month: str, seed: str) -> None:
    control = root / "control"
    control.mkdir(parents=True, exist_ok=True)
    weekly = metrics(data, first)
    ticket_status_counts = {status: sum(ticket["status"] == status for ticket in data["tickets"]) for status in ("closed", "resolved", "pending", "open")}
    asset_status_counts = {status: sum(asset["status"] == status for asset in data["assets"]) for status in ("active", "maintenance", "retired")}
    contract_active = sum(dt.date.fromisoformat(contract["start_date"]) <= last and dt.date.fromisoformat(contract["end_date"]) >= last for contract in data["contracts"])
    team_by_id = {row["team_id"]: row for row in data["teams"]}
    employee_team = {row["employee_id"]: row["team_id"] for row in data["employees"]}
    time_by_team: dict[str, int] = {team_id: 0 for team_id in team_by_id}
    for entry in data["time_entries"]:
        time_by_team[employee_team[entry["employee_id"]]] += int(entry["hours"])
    invoice_total = sum(int(invoice["total_rub"]) for invoice in data["invoices"])
    paid_total = sum(int(payment["amount_rub"]) for payment in data["payments"])
    p1_current_breach = sum(ticket["priority"] == "P1" and ticket["sla_breached"] == "true" for ticket in data["tickets"])
    p1_old_breach = 0
    for ticket in data["tickets"]:
        if ticket["priority"] != "P1":
            continue
        created = dt.datetime.fromisoformat(ticket["created_at"])
        response = dt.datetime.fromisoformat(ticket["first_response_at"])
        p1_old_breach += response - created > dt.timedelta(minutes=30)
    ticket_one_events = [event["to_status"] for event in data["ticket_events"] if event["ticket_id"] == "TCK-0001"]
    incident_gateway = choose_incident_ticket(data, first + dt.timedelta(days=6))
    latest_release = max(data["releases"], key=lambda release: release["release_date"])
    q = []

    def add(question_id: str, prompt: str, capabilities: list[str], expected: Any, sources: list[str], kind: str = "answer", sql: str | None = None, role: str | None = None, note: str | None = None) -> None:
        item: dict[str, Any] = {
            "id": question_id,
            "prompt": prompt,
            "capabilities": capabilities,
            "kind": kind,
            "expected": expected,
            "sources": sources,
        }
        if sql:
            item["sql"] = sql
        if role:
            item["role"] = role
        if note:
            item["note"] = note
        q.append(item)

    add("Q01", "What is the company's name in this dataset?", ["M1-docs"], "KV Service Demo", ["documents/common/company-profile.md"])
    add("Q02", "What timezone and cutoff does the August snapshot use?", ["M1-docs"], {"timezone": TIMEZONE_NAME, "cutoff": timestamp(cutoff)}, ["documents/common/company-profile.md", "documents/common/organization/working-hours.md"])
    add("Q03", "How many teams and employees does the company have?", ["M1-docs"], {"teams": len(data["teams"]), "employees": len(data["employees"])}, ["documents/common/organization/teams-and-roles.md"])
    add("Q04", "How many employees are in Customer Support?", ["M1-docs"], 6, ["documents/common/organization/teams-and-roles.md"])
    add("Q05", "What is the current P1 SLA and when did it take effect?", ["M1-docs"], {"minutes": 15, "effective_from": "2026-08-01", "status": "current"}, ["documents/common/policy/sla-2026-08-current.md"])
    add("Q06", "Which P1 SLA applied before August 2026?", ["M1-docs"], {"minutes": 30, "effective_from": "2026-01-01", "status": "superseded"}, ["documents/common/policy/sla-2026-01-superseded.md"])
    add("Q07", "How did the P1 rules differ on 2026-07-20 and 2026-08-20?", ["M1-docs"], {"2026-07-20": 30, "2026-08-20": 15}, ["documents/common/policy/sla-2026-01-superseded.md", "documents/common/policy/sla-2026-08-current.md"])
    add("Q08", "How many tickets were created in operational week W03?", ["M1-docs"], weekly["W03"]["created"], ["documents/common/weekly/operations-W03.md"])
    peak_week = max(weekly, key=lambda key: (weekly[key]["p1"], key))
    add("Q09", "Which operational week had the most P1 tickets?", ["M1-docs"], {"week": peak_week, "p1": weekly[peak_week]["p1"]}, [f"documents/common/weekly/operations-{week}.md" for week in weekly])
    add("Q10", "What happened in the gateway incident on August 7?", ["M1-docs"], {"ticket": incident_gateway["ticket_id"], "created_at": incident_gateway["created_at"], "first_response_at": incident_gateway["first_response_at"], "status": incident_gateway["status"], "cause": "incorrect concurrent-request limit"}, ["documents/support/incidents/INC-2026-08-07-gateway.md", "relational/tickets.csv"])
    add("Q11", "What did the August 19 meeting decide about the nightly data-exchange check?", ["M1-docs"], "keep the nightly check in the 02:00–03:00 window", ["documents/common/meetings/2026-08-19.md"])
    add("Q12", "How many tickets were closed in week W04?", ["M1-docs"], weekly["W04"]["closed"], ["documents/support/weekly/support-W04.md"], note="The user wording deliberately allows abbreviation and ellipsis.")
    add("Q13", "What support tier does Customer03 Demo have?", ["M1-docs"], next(row["support_tier"] for row in data["customers"] if row["customer_id"] == "C003"), ["documents/support/customers/C003.md"])
    add("Q14", "What does EscalationWindowMinutes return at Git ref v0.3.0?", ["M1-git"], {"path": "internal/ticket/router.go", "value": 30}, ["repo/internal/ticket/router.go"], note="Read ref v0.3.0 specifically, not the working tree.")
    add("Q15", "What does EscalationWindowMinutes return at Git ref v0.4.0?", ["M1-git"], {"path": "internal/ticket/router.go", "value": 15}, ["repo/internal/ticket/router.go"], note="Read ref v0.4.0 specifically, not the working tree.")
    add("Q16", "What is the main branch called in the synthetic repository?", ["M1-git"], "main", ["repo/README.md"], note="Check Git metadata/refs; the README records the expected branch name for navigation.")
    add("Q17", "What is the total invoiced amount across the 40 invoices?", ["M3-sql"], {"invoice_count": len(data["invoices"]), "total_rub": invoice_total}, ["relational/invoices.csv"], sql="SELECT COUNT(*) AS invoice_count, SUM(total_rub) AS total_rub FROM invoices;")
    add("Q18", "What is the total payment amount and how many payment rows are there?", ["M3-sql"], {"payment_count": len(data["payments"]), "paid_rub": paid_total}, ["relational/payments.csv"], sql="SELECT COUNT(*) AS payment_count, SUM(amount_rub) AS paid_rub FROM payments;")
    add("Q19", "What is the outstanding balance on 2026-09-01 from invoices and payments?", ["M3-sql"], invoice_total - paid_total, ["relational/invoices.csv", "relational/payments.csv"], sql="SELECT SUM(i.total_rub - COALESCE(p.paid_rub, 0)) AS outstanding_rub FROM invoices i LEFT JOIN (SELECT invoice_id, SUM(amount_rub) AS paid_rub FROM payments GROUP BY invoice_id) p USING (invoice_id);")
    add("Q20", "How many contracts are active at the end of August?", ["M3-sql"], contract_active, ["relational/contracts.csv"], sql="SELECT COUNT(*) FROM contracts WHERE start_date <= DATE '2026-08-31' AND end_date >= DATE '2026-08-31';")
    add("Q21", "What is the asset count by status?", ["M3-sql"], asset_status_counts, ["relational/assets.csv"], sql="SELECT status, COUNT(*) FROM assets GROUP BY status ORDER BY status;")
    add("Q22", "How are the 600 tickets distributed by final status?", ["M3-sql"], ticket_status_counts, ["relational/tickets.csv", "relational/ticket_events.csv"], sql="SELECT status, COUNT(*) FROM tickets GROUP BY status ORDER BY status;")
    add("Q23", "How many hours did each team log?", ["M3-sql"], time_by_team, ["relational/time_entries.csv", "relational/employees.csv", "relational/teams.csv"], sql="SELECT e.team_id, SUM(t.hours) FROM time_entries t JOIN employees e USING (employee_id) GROUP BY e.team_id ORDER BY e.team_id;")
    add("Q24", "Under the current SLA, how many P1 ticket rows exceed the 15-minute limit?", ["M1+M3"], {"policy_minutes": 15, "breached_p1": p1_current_breach}, ["documents/common/policy/sla-2026-08-current.md", "relational/tickets.csv"], sql="SELECT COUNT(*) FROM tickets WHERE priority = 'P1' AND EXTRACT(EPOCH FROM (first_response_at - created_at)) / 60 > 15;")
    add("Q25", "If the historical P1=30 minute rule applied, how many P1 tickets would breach the SLA?", ["M1+M3"], {"policy_minutes": 30, "breached_p1": p1_old_breach}, ["documents/common/policy/sla-2026-01-superseded.md", "relational/tickets.csv"], sql="SELECT COUNT(*) FROM tickets WHERE priority = 'P1' AND EXTRACT(EPOCH FROM (first_response_at - created_at)) / 60 > 30;")
    add("Q26", "Does the dataset contain Customer09?", ["M1-docs+M3-sql"], {"kind": "no_data", "reason": "C009 is absent from customers.csv"}, ["relational/customers.csv"], kind="no_data")
    add("Q27", "Show unpaid invoices to a user with the support-agent role.", ["M1-access"], {"kind": "permission_denied", "root": "documents/finance", "tables": ["invoices", "payments"]}, ["control/access-matrix.md"], kind="permission_denied", role="support-agent")
    customer_three_tickets = sum(ticket["customer_id"] == "C003" for ticket in data["tickets"])
    add("Q28", "How many C003 tickets can an ordinary support-agent view?", ["M1-access+M3"], customer_three_tickets, ["control/access-matrix.md", "relational/tickets.csv"], sql="SELECT COUNT(*) FROM tickets WHERE customer_id = 'C003';", role="support-agent")
    add("Q29", "How many hours did Engineering Platform T03 log?", ["M3-sql"], time_by_team["T03"], ["relational/time_entries.csv", "relational/employees.csv"], sql="SELECT SUM(t.hours) FROM time_entries t JOIN employees e USING (employee_id) WHERE e.team_id = 'T03';")
    add("Q30", "How many releases were published in August and what is the latest version?", ["M1-git+M3"], {"count": len(data["releases"]), "latest_version": latest_release["version"]}, ["documents/common/release-train.md", "relational/releases.csv"], sql="SELECT COUNT(*), MAX(release_date), (ARRAY_AGG(version ORDER BY release_date DESC))[1] FROM releases;")
    c004 = next(contract for contract in data["contracts"] if contract["contract_id"] == "K004")
    add("Q31", "When does contract K004 renew?", ["M1-docs"], c004["renewal_date"], ["documents/finance/contracts/K004.md"])
    add("Q32", "Is there evidence that the company uses Slack?", ["M1-docs"], {"kind": "no_data", "reason": "the source does not establish that fact"}, [], kind="no_data")
    add("Q33", "How much does maintenance cost?", ["M1-docs+M3"], {"kind": "clarification_required", "clarify": "clarify whether this means the monthly contract fee, invoice amount or service cost"}, [], kind="clarification_required", note="Deliberately ambiguous wording.")
    add("Q34", "What is the status sequence for TCK-0001?", ["M3-sql"], ticket_one_events, ["relational/ticket_events.csv"], sql="SELECT to_status FROM ticket_events WHERE ticket_id = 'TCK-0001' ORDER BY event_at, event_id;")
    add("Q35", "Which SLA policy is current at the snapshot cutoff?", ["M1-docs"], "sla-2026-08-current", ["documents/common/policy/sla-2026-08-current.md"])
    add("Q36", "What does the ellipsis mean in 'how many tickets were closed in week…'?", ["M1-docs"], {"kind": "clarification_required", "clarify": "ask for the week number if it is missing"}, [], kind="clarification_required", note="Example of acceptable ambiguity.")

    expected = {
        "dataset_revision": DATASET_REVISION,
        "month": month,
        "seed": seed,
        "timezone": TIMEZONE_NAME,
        "cutoff": timestamp(cutoff),
        "questions": q,
    }
    write_json(root, "control/expected-answers.json", expected)
    write_text(
        root,
        "control/README.md",
        """# Control oracle\n\n`manifest.json` and `expected-answers.json` are review controls, not knowledge sources. They contain hashes, counts, SQL expectations and answer oracles for the fixture. Do not mount `control/` into a KnowVault connector. Mount only the chosen source roots `documents/`, `repo/` and/or `relational/` according to `access-matrix.md`.\n\nThe seed is fictional, has no real credentials, and is not connected to any stand. `capabilities` in the question list mean the intended test surface: M1 documents/Git and M3 external SQL. They do not assert that a live connector is already configured.\n\nTo verify after generation:\n\n```text\npython3 tools/seeds/company-month/validate.py --seed-dir .local/release/company-month-seed-v2-en\n```\n""",
    )
    write_text(
        root,
        "control/access-matrix.md",
        """# Intended access matrix\n\n| Role | Documents | Git | External SQL tables | Finance |\n|---|---|---|---|---|\n| `support-agent` | `documents/common`, `documents/support` | read `repo` | `customers`, `assets`, `tickets`, `ticket_events` | deny `documents/finance`, `contracts`, `invoices`, `payments`, `time_entries` |\n| `platform-engineer` | `documents/common`, selected `documents/support` | read `repo` | `assets`, `tickets`, `ticket_events`, `releases`, `time_entries` | deny finance documents and invoices/payments |\n| `finance-analyst` | `documents/common`, `documents/finance` | no repo need | all `relational` tables | allow |\n| `workspace-admin` | all source roots | all refs | all tables | allow |\n\nThese are fixture intentions for connector setup and permission tests. They are not a product access policy. A connector mount must point at a source root or an allowlisted subdirectory; never mount the seed parent, `control/`, `.git/`, or a path that makes the oracle visible.\n""",
    )

    source_files: list[dict[str, Any]] = []
    docs_by_root: dict[str, int] = {"common": 0, "support": 0, "finance": 0}
    csv_counts: dict[str, int] = {}
    for source_root in SOURCE_ROOTS:
        source_path = root / source_root
        for path in sorted(source_path.rglob("*")):
            if not path.is_file() or ".git" in path.parts:
                continue
            relative = path.relative_to(root).as_posix()
            source_files.append({"path": relative, "bytes": path.stat().st_size, "sha256": sha256_file(path)})
            if relative.startswith("documents/"):
                bucket = relative.split("/")[1]
                docs_by_root[bucket] += 1
            if relative.startswith("relational/") and relative.endswith(".csv"):
                with path.open("r", encoding="utf-8", newline="") as handle:
                    csv_counts[relative] = max(0, sum(1 for _ in handle) - 1)
    manifest = {
        "dataset_revision": DATASET_REVISION,
        "month": month,
        "seed": seed,
        "timezone": TIMEZONE_NAME,
        "cutoff": timestamp(cutoff),
        "source_roots": list(SOURCE_ROOTS),
        "oracle_root": "control/",
        "counts": {
            "documents_total": sum(docs_by_root.values()),
            "documents_by_root": docs_by_root,
            "csv_rows": csv_counts,
            "staff": len(data["employees"]),
            "teams": len(data["teams"]),
            "customers": len(data["customers"]),
            "contracts": len(data["contracts"]),
            "assets": len(data["assets"]),
            "tickets": len(data["tickets"]),
            "ticket_events": len(data["ticket_events"]),
            "invoices": len(data["invoices"]),
            "payments": len(data["payments"]),
            "time_entries": len(data["time_entries"]),
            "releases": len(data["releases"]),
        },
        "git": {"branch": "main", "commit_count": len(commits), "commits": commits},
        "files": source_files,
    }
    write_json(root, "control/manifest.json", manifest)


def generate(out: Path, month: str, seed: str) -> None:
    if out.exists():
        if not out.is_dir():
            fail(f"--out points to a file: {out}")
        if any(out.iterdir()):
            fail(f"--out must be a new empty directory: {out}")
    out.mkdir(parents=True, exist_ok=True)
    first, last, cutoff = parse_month(month)
    data = make_base_data(first, last, seed)
    commits = build_repo(out / "repo", first)
    make_releases(data, commits, first)
    for table, rows in data.items():
        write_csv(out, f"relational/{table}.csv", TABLE_COLUMNS[table], rows)
    build_bootstrap(out)
    build_documents(out, data, commits, first, last)
    build_control(out, data, commits, first, last, cutoff, month, seed)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, help="new empty output directory")
    parser.add_argument("--month", default=DEFAULT_MONTH, help="month in YYYY-MM format")
    parser.add_argument("--seed", default=DEFAULT_SEED, help="stable fixture seed")
    args = parser.parse_args(argv)
    generate(Path(args.out), args.month, args.seed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
