fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

fn allowed(path: &str, allow: &[String]) -> bool {
    let p = path.trim_end_matches('/');
    allow.iter().any(|a| {
        let a = a.trim_end_matches('/');
        !a.is_empty() && (p == a || p.starts_with(&format!("{a}/")))
    })
}

pub fn score() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let opt = |n: &str, d: &str| -> String {
        args.iter()
            .position(|a| a == n)
            .and_then(|i| args.get(i + 1))
            .cloned()
            .unwrap_or_else(|| d.to_string())
    };
    let edges_path = opt("--edges", "edges.jsonl");
    let truth_path = opt("--truth", "truth.json");
    let policy_path = opt("--policy", "");

    let truth: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&truth_path)?)?;
    let name = truth["name"].as_str().unwrap_or("scenario").to_string();
    let channel = truth["channel"].as_str().unwrap_or("unknown").to_string();
    let scope = truth["scope"].as_str().unwrap_or("in").to_string();
    let benign = truth["benign"].as_bool().unwrap_or(false);
    // each group is one OBJECT, which may be observable under any of its names:
    // rename keeps the inode, and reading through a symlink resolves to the target
    let groups: Vec<Vec<String>> = match truth["expect_groups"].as_array() {
        Some(g) => g
            .iter()
            .map(|grp| {
                grp.as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                    .unwrap_or_default()
            })
            .collect(),
        None => truth["expect_paths"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| vec![s.to_string()]))
                    .collect()
            })
            .unwrap_or_default(),
    };

    let allow: Vec<String> = if policy_path.is_empty() {
        Vec::new()
    } else {
        std::fs::read_to_string(&policy_path)
            .ok()
            .and_then(|t| serde_json::from_str::<serde_json::Value>(&t).ok())
            .and_then(|v| {
                v["allow"].as_array().map(|a| {
                    a.iter()
                        .filter_map(|e| {
                            e.as_str()
                                .map(str::to_string)
                                .or_else(|| e["path"].as_str().map(str::to_string))
                        })
                        .collect()
                })
            })
            .unwrap_or_default()
    };

    let text = std::fs::read_to_string(&edges_path).unwrap_or_default();
    let mut found = 0usize;
    let mut unsanctioned = 0usize;
    let mut ignored = 0usize;
    let mut fp = 0usize;
    let tp: usize;
    let mut matched: std::collections::HashSet<usize> = std::collections::HashSet::new();

    for line in text.lines() {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
        if v["kind"] != "edge" {
            continue;
        }
        found += 1;
        let path = v["path"].as_str().unwrap_or("").to_string();
        if !allowed(&path, &allow) {
            unsanctioned += 1;
        }
        // an edge on a parent directory is the byproduct of creating the channel
        // object, not a separate channel: ignore it unless it *is* an expected object
        // an edge on a parent directory is the byproduct of creating the channel
        // object, not a separate channel; counted so the exclusion is auditable
        if groups.iter().flatten().any(|e| e.starts_with(&format!("{path}/"))) {
            ignored += 1;
            continue;
        }
        match groups.iter().position(|g| {
            g.iter().any(|e| path == *e || path.starts_with(&format!("{e}/")))
        }) {
            Some(i) => {
                matched.insert(i);
            }
            None => fp += 1,
        }
    }

    tp = matched.len();
    let fn_ = groups.len() - matched.len();
    let precision = if tp + fp > 0 { tp as f64 / (tp + fp) as f64 } else { if benign { 1.0 } else { 0.0 } };
    let recall = if tp + fn_ > 0 { tp as f64 / (tp + fn_) as f64 } else { if benign { 1.0 } else { 0.0 } };
    let f1 = if precision + recall > 0.0 { 2.0 * precision * recall / (precision + recall) } else { 0.0 };

    println!(
        "{{\"name\":\"{}\",\"scope\":\"{}\",\"channel\":\"{}\",\"benign\":{},\"edges\":{},\"tp\":{},\"fp\":{},\"fn\":{},\"precision\":{:.3},\"recall\":{:.3},\"f1\":{:.3},\"unsanctioned\":{},\"ignored_parent\":{}}}",
        escape(&name),
        escape(&scope),
        escape(&channel),
        benign,
        found,
        tp,
        fp,
        fn_,
        precision,
        recall,
        f1,
        unsanctioned,
        ignored
    );
    Ok(())
}
