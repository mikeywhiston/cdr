#!/usr/bin/env python3

import json
import sys
import urllib.request
import base64
import os

def _load_dotenv():
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(path):
        return
    for line in open(path):
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


_load_dotenv()
KIBANA = os.environ.get("KIBANA")
if not KIBANA:
    sys.exit("KIBANA is not set: add KIBANA=http://host:5601 to testbed/.env")
USER = os.environ.get("ES_USER", "cdr")
PASS = open(os.environ.get("ES_PASS_FILE", os.path.expanduser("~/.cdr-es-pass"))).read().strip()
DV = os.environ["DATA_VIEW_ID"]


def call(method, path, body_in):
    body = body_in
    req = urllib.request.Request(
        KIBANA + path,
        data=json.dumps(body).encode(),
        method=method,
        headers={
            "Content-Type": "application/json",
            "kbn-xsrf": "true",
            "Authorization": "Basic " + base64.b64encode(f"{USER}:{PASS}".encode()).decode(),
        },
    )
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        body = json.loads(e.read() or b"{}")
        if e.code == 409 and method == "POST":
            return call("PUT", path, body_in)
        return e.code, body


def search_source(query, filters=None):
    return json.dumps(
        {
            "query": {"query": query, "language": "kuery"},
            "filter": filters or [],
            "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
        }
    )


def dv_ref():
    return [{"name": "kibanaSavedObjectMeta.searchSourceJSON.index", "type": "index-pattern", "id": DV}]


def metric(ident, title, query, sub, color="Green to Red"):
    vis = {
        "title": title,
        "type": "metric",
        "params": {
            "addTooltip": True,
            "addLegend": False,
            "type": "metric",
            "metric": {
                "percentageMode": False,
                "useRanges": False,
                "colorSchema": color,
                "metricColorMode": "None",
                "colorsRange": [{"from": 0, "to": 100000}],
                "labels": {"show": True},
                "invertColors": False,
                "style": {
                    "bgFill": "#000",
                    "bgColor": False,
                    "labelColor": False,
                    "subText": sub,
                    "fontSize": 44,
                },
            },
        },
        "aggs": [{"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}}],
        "listeners": {},
    }
    body = {
        "attributes": {
            "title": title,
            "visState": json.dumps(vis),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)},
        },
        "references": dv_ref(),
    }
    return call("POST", f"/api/saved_objects/visualization/{ident}", body)


def vega(ident, title, spec):
    vis = {"title": title, "type": "vega", "params": {"spec": json.dumps(spec)}, "aggs": [], "listeners": {}}
    body = {
        "attributes": {
            "title": title,
            "visState": json.dumps(vis),
            "uiStateJSON": "{}",
            "description": "",
            "version": 1,
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source("")},
        },
        "references": dv_ref(),
    }
    return call("POST", f"/api/saved_objects/visualization/{ident}", body)


def search(ident, title, query, columns, sort_asc=True):
    body = {
        "attributes": {
            "title": title,
            "columns": columns,
            "sort": [["@timestamp", "asc" if sort_asc else "desc"]],
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source(query)},
        },
        "references": dv_ref(),
    }
    return call("POST", f"/api/saved_objects/search/{ident}", body)


def dashboard(ident, title, panels):
    refs, layout = [], []
    for i, (kind, obj_id, x, y, w, h) in enumerate(panels):
        name = f"panel_{i}"
        refs.append({"name": name, "type": kind, "id": obj_id})
        layout.append(
            {
                "version": "8.11.0",
                "type": "visualization" if kind == "visualization" else "search",
                "gridData": {"x": x, "y": y, "w": w, "h": h, "i": str(i + 1)},
                "panelIndex": str(i + 1),
                "embeddableConfig": {"hidePanelTitles": False},
                "panelRefName": name,
            }
        )
    body = {
        "attributes": {
            "title": title,
            "hits": 0,
            "description": "Kernel-provenance evidence, declared-vs-observed reconciliation and policy verdict",
            "panelsJSON": json.dumps(layout),
            "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
            "timeRestore": True,
            "timeFrom": "now-7d",
            "timeTo": "now",
            "kibanaSavedObjectMeta": {"searchSourceJSON": search_source("")},
        },
        "references": refs,
    }
    return call("POST", f"/api/saved_objects/dashboard/{ident}", body)


def main():
    steps = []

    steps.append(("metric unsanctioned", metric(
        "cdr-m-unsanctioned", "Unsanctioned edges",
        "kind:attribution and verdict:unsanctioned and variant:honest", "unsanctioned", "Green to Red")))
    steps.append(("metric sanctioned", metric(
        "cdr-m-sanctioned", "Sanctioned edges",
        "kind:attribution and verdict:sanctioned and variant:honest", "sanctioned", "Blues")))
    steps.append(("metric tamper", metric(
        "cdr-m-tamper", "Tamper findings",
        "kind:desync and class:(mismatch or surplus or omission)", "mismatch / surplus", "Green to Red")))
    steps.append(("metric objects", metric(
        "cdr-m-objects", "Object edges", "kind:edge", "shared-object accesses", "Blues")))

    verdict_spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "data": {
            "url": {
                "index": "cdr-*",
                "body": {
                    "size": 0,
                    "query": {"bool": {"filter": [{"term": {"kind": "attribution"}}, {"term": {"variant": "honest"}}]}},
                    "aggs": {"v": {"terms": {"field": "verdict", "size": 10}}},
                },
            },
            "format": {"property": "aggregations.v.buckets"},
        },
        "mark": {"type": "arc", "innerRadius": 55, "outerRadius": 100},
        "encoding": {
            "theta": {"field": "doc_count", "type": "quantitative", "title": "edges"},
            "color": {"field": "key", "type": "nominal", "title": "verdict",
                      "scale": {"domain": ["sanctioned", "unsanctioned"],
                                "range": ["#54B399", "#E7664C"]}},
        },
        "autosize": {"type": "fit", "contains": "padding"},
    }
    objects_spec = {
        "$schema": "https://vega.github.io/schema/vega-lite/v5.json",
        "data": {
            "url": {
                "index": "cdr-*",
                "body": {
                    "size": 0,
                    "query": {"bool": {"filter": [{"term": {"kind": "edge"}}]}},
                    "aggs": {"p": {"terms": {"field": "path", "size": 10}}},
                },
            },
            "format": {"property": "aggregations.p.buckets"},
        },
        "mark": "bar",
        "encoding": {
            "y": {"field": "key", "type": "nominal", "title": "object", "sort": "-x"},
            "x": {"field": "doc_count", "type": "quantitative", "title": "edges"},
            "color": {"field": "key", "type": "nominal", "legend": None},
        },
        "autosize": {"type": "fit", "contains": "padding"},
    }
    steps.append(("vega verdicts", vega("cdr-ts-verdict", "Verdict split", verdict_spec)))
    steps.append(("vega objects", vega("cdr-ts-desync", "Shared objects", objects_spec)))

    steps.append(("search findings", search(
        "cdr-findings", "CDR · findings (needs attention)",
        "verdict:unsanctioned or (kind:desync and class:(mismatch or surplus or omission))",
        ["kind", "class", "path", "declared", "unaccounted", "verdict"])))

    steps.append(("search evidence", search(
        "cdr-evidence", "CDR · evidence (all shared objects)",
        "kind:(edge or attribution or scrub) and path:/shared*",
        ["kind", "path", "src_declared", "dst_declared", "verdict", "dt_ns"])))

    steps.append(("search reasoning", search(
        "cdr-reasoning", "CDR · agent reasoning (untrusted)",
        "kind:reasoning", ["agent", "trust", "text"], sort_asc=False)))

    for name, (code, body) in steps:
        ok = "ok" if code in (200, 201) else f"FAIL {code} {json.dumps(body)[:160]}"
        print(f"{name}: {ok}")

    panels = [
        ("visualization", "cdr-m-unsanctioned", 0, 0, 12, 7),
        ("visualization", "cdr-m-sanctioned", 12, 0, 12, 7),
        ("visualization", "cdr-m-tamper", 24, 0, 12, 7),
        ("visualization", "cdr-m-objects", 36, 0, 12, 7),
        ("visualization", "cdr-ts-verdict", 0, 7, 24, 14),
        ("visualization", "cdr-ts-desync", 24, 7, 24, 14),
        ("search", "cdr-findings", 0, 21, 48, 14),
        ("search", "cdr-evidence", 0, 35, 48, 16),
        ("search", "cdr-reasoning", 0, 51, 48, 12),
    ]
    code, body = dashboard("cdr-oversight", "CDR · agent oversight", panels)
    print("dashboard:", "ok" if code in (200, 201) else f"FAIL {code} {json.dumps(body)[:200]}")


if __name__ == "__main__":
    if "DATA_VIEW_ID" not in os.environ:
        sys.exit("set DATA_VIEW_ID")
    main()
