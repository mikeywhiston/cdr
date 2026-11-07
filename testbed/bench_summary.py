#!/usr/bin/env python3
"""Summarise bench results, stratified by declared scope.

In-scope channels produce the headline precision/recall. Boundary probes are
reported separately as measured negatives: they are expected to miss, and hiding
them would be the same dishonesty as folding them into the headline.
"""
import collections
import json
import os
import sys


def line(t, f, m):
    prec = t / (t + f) if t + f else 1.0
    rec = t / (t + m) if t + m else 1.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return prec, rec, f1


def table(title, rows):
    if not rows:
        return
    print(f"\n{title}  (n={len(rows)} episodes)")
    print(f"  {'channel':16} {'tp':>3} {'fp':>3} {'fn':>3} {'prec':>6} {'rec':>6} {'f1':>6} {'unsanc':>6}")
    by = collections.defaultdict(list)
    for r in rows:
        by[r["channel"]].append(r)
    for ch in sorted(by):
        g = by[ch]
        t = sum(x["tp"] for x in g)
        f = sum(x["fp"] for x in g)
        m = sum(x["fn"] for x in g)
        p, rc, f1 = line(t, f, m)
        u = sum(x["unsanctioned"] for x in g)
        print(f"  {ch:16} {t:>3} {f:>3} {m:>3} {p:>6.3f} {rc:>6.3f} {f1:>6.3f} {u:>6}")
    t = sum(x["tp"] for x in rows)
    f = sum(x["fp"] for x in rows)
    m = sum(x["fn"] for x in rows)
    p, rc, f1 = line(t, f, m)
    u = sum(x["unsanctioned"] for x in rows)
    print(f"  {'ALL':16} {t:>3} {f:>3} {m:>3} {p:>6.3f} {rc:>6.3f} {f1:>6.3f} {u:>6}")


def main():
    rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
    table("IN SCOPE (headline)", [r for r in rows if r.get("scope") == "in"])
    table("BOUNDARY PROBES (declared out of scope; misses expected)", [r for r in rows if r.get("scope") == "probe"])
    benign = [r for r in rows if r.get("scope") == "benign"]
    if benign:
        n = len(benign)
        uns = sum(r["unsanctioned"] for r in benign)
        fp = sum(r["fp"] for r in benign)
        print(f"\nBENIGN CONTROL  (n={n} episodes)")
        print(f"  unsanctioned edges : {uns}  ({uns / n:.2f} per episode)")
        print(f"  edges on unlabelled objects: {fp}")


def live(rows):
    if not rows:
        return
    print(f"\nLIVE AGENT SUITE  (n={len(rows)} episodes, omp agents)")
    print(f"  {'mode':15} {'edges':>5} {'tp':>3} {'fp':>3} {'fn':>3} {'unsanc':>6} {'tx recall':>9} {'desync m/mm':>12}")
    for r in sorted(rows, key=lambda x: (x["mode"], x["episode"])):
        b = r.get("baseline", {})
        recall = b.get("transcript_recall")
        recall_s = f"{recall:.2f}" if isinstance(recall, (int, float)) else "-"
        h = r.get("desync_honest", {})
        t = r.get("desync_tampered", {})
        print(f"  {r['mode']:15} {r['edges']:>5} {r['tp']:>3} {r['fp']:>3} {r['fn']:>3} "
              f"{r['unsanctioned']:>6} {recall_s:>9} {h.get('matched',0):>5}/{t.get('mismatch',0):<6}")
    tot_tx = [r["baseline"].get("transcript_detected", 0) for r in rows if r.get("baseline")]
    tot_k = [r["baseline"].get("kernel_edges", 0) for r in rows if r.get("baseline")]
    if tot_k:
        print(f"  transcript-detected {sum(tot_tx)} of {sum(tot_k)} kernel edges across all live episodes")


if __name__ == "__main__":
    main()
    if len(sys.argv) > 2 and os.path.exists(sys.argv[2]):
        live([json.loads(l) for l in open(sys.argv[2]) if l.strip()])
