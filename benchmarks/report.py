#!/usr/bin/env python3
import json
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
rows = [json.loads(line) for line in (root / "summary.jsonl").read_text().splitlines() if line]
truth_root = root.parent.parent / "ground-truth"
for row in rows:
    domain, tool = row["domain"], row["tool"]
    live_path = root / "live" / f"{domain}.{tool}.txt"
    found = set(live_path.read_text().splitlines()) if live_path.exists() else set()
    truth_path = truth_root / f"{domain}.txt"
    if truth_path.exists():
        truth = set(truth_path.read_text().splitlines())
        row["recall"] = len(found & truth) / len(truth) if truth else 1.0
        row["false_positives"] = len(found - truth)
    else:
        row["recall"] = None
        row["false_positives"] = None
    others = set()
    for candidate in rows:
        if candidate["domain"] == domain and candidate["tool"] != tool:
            path = root / "live" / f"{domain}.{candidate['tool']}.txt"
            if path.exists():
                others.update(path.read_text().splitlines())
    row["exclusive_validated"] = len(found - others)

domains = sorted({row["domain"] for row in rows})
wins = 0
fellaga_total = 0
best_competitor_total = 0
false_positives = 0
truth_names = 0
coverage_duration_ok = True
for domain in domains:
    domain_rows = [row for row in rows if row["domain"] == domain]
    fellaga = next((row for row in domain_rows if row["tool"] == "fellaga"), None)
    competitors = [row for row in domain_rows if row["tool"] != "fellaga"]
    if not fellaga or not competitors:
        continue
    best = max(competitors, key=lambda row: (row["live_names"], -row["duration_seconds"]))
    fellaga_total += fellaga["live_names"]
    best_competitor_total += best["live_names"]
    wins += fellaga["live_names"] > best["live_names"]
    coverage_duration_ok &= fellaga["duration_seconds"] <= 2 * max(best["duration_seconds"], 0.001)
    if fellaga["false_positives"] is not None:
        false_positives += fellaga["false_positives"]
        truth_path = truth_root / f"{domain}.txt"
        truth_names += len(set(truth_path.read_text().splitlines()))

win_rate = wins / len(domains) if domains else 0.0
validated_gain = (
    (fellaga_total - best_competitor_total) / best_competitor_total
    if best_competitor_total
    else None
)
false_positive_rate = false_positives / max(truth_names + false_positives, 1) if truth_names else None
dns_benchmark_path = root / "dns-engine.json"
dns_benchmark = json.loads(dns_benchmark_path.read_text()) if dns_benchmark_path.exists() else None
summary = {
    "authorized_domains": len(domains),
    "fellaga_wins": wins,
    "fellaga_win_rate": win_rate,
    "fellaga_live_total": fellaga_total,
    "best_competitor_live_total": best_competitor_total,
    "validated_gain": validated_gain,
    "false_positive_rate": false_positive_rate,
    "deep_within_2x_best_coverage": coverage_duration_ok,
    "dns_engine": dns_benchmark,
}
summary["market_claim_ready"] = bool(
    len(domains) >= 30
    and win_rate >= 0.80
    and validated_gain is not None
    and validated_gain >= 0.10
    and false_positive_rate is not None
    and false_positive_rate < 0.005
    and coverage_duration_ok
    and dns_benchmark
    and dns_benchmark.get("queries", 0) >= 10000000
    and dns_benchmark.get("queries_per_second", 0) >= 25000
    and dns_benchmark.get("loss_rate", 1) < 0.01
    and dns_benchmark.get("max_rss_kib", 1048577) < 1048576
)

report = {"summary": summary, "results": rows}
(root / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(json.dumps({"rows": len(rows), "report": str(root / "report.json")}))
