#!/usr/bin/env python3
"""Compare identical hotpath_bench tests in saved before/after release test binaries."""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess


def measure(binary, cpu):
    result = subprocess.run(
        [str(binary.resolve()), "hotpath_bench", "--ignored", "--nocapture", "--test-threads=1"],
        check=True, capture_output=True, text=True,
        preexec_fn=lambda: os.sched_setaffinity(0, {cpu}),
        timeout=120,
    )
    rows = {}
    for line in result.stdout.splitlines():
        match = re.search(r"BENCH (\S+) (\S+) (ns_per_\S+)=([0-9.]+)", line)
        if match:
            name, case, unit, value = match.groups()
            rows[f"{name} {case} {unit}"] = float(value)
    if not rows:
        raise RuntimeError(f"No benchmark results in {binary}")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for component in ("server", "client"):
        for variant in ("before", "after"):
            parser.add_argument(f"--{component}-{variant}", required=True, type=Path)
    parser.add_argument("--runs", type=int, default=7)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    if args.runs < 3:
        parser.error("Use at least three measured runs")
    cpu = min(os.sched_getaffinity(0))
    cpu_model = next((line.split(":", 1)[1].strip()
                      for line in Path("/proc/cpuinfo").read_text().splitlines()
                      if line.startswith("model name")), "unknown")
    report = {
        "baseline_commit": "1881c79b3de255a8026bcca1e221aa55f778ce2d",
        "build": "cargo test --release --locked; identical benchmark functions in both versions",
        "scope": "CPU microbenchmarks only; no TURN, encryption, TUN syscalls or Internet throughput",
        "architecture": platform.machine(), "cpu_model": cpu_model,
        "pinned_cpu": cpu, "runs": args.runs, "results": {},
    }
    for component in ("server", "client"):
        binaries = {variant: getattr(args, f"{component}_{variant}")
                    for variant in ("before", "after")}
        for binary in binaries.values():
            measure(binary, cpu)  # Untimed warm-up, including the allocator.
        samples = {"before": {}, "after": {}}
        for run in range(args.runs):
            for variant in (("before", "after") if run % 2 == 0 else ("after", "before")):
                for key, value in measure(binaries[variant], cpu).items():
                    samples[variant].setdefault(key, []).append(value)
        if samples["before"].keys() != samples["after"].keys():
            raise RuntimeError("Before/after must run identical benchmark cases")
        results = {}
        for key, before in samples["before"].items():
            after = samples["after"][key]
            old, new = statistics.median(before), statistics.median(after)
            results[key] = {"before": before, "after": after,
                            "median_before": old, "median_after": new,
                            "speedup": round(old / new, 3)}
            print(f"{component}: {key}: {old:.2f} -> {new:.2f} ns ({old / new:.2f}x)")
        report["results"][component] = results
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
