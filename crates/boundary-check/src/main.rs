use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::{Context, Result, anyhow};
use cargo_metadata::MetadataCommand;

const BOUNDARY_RULES: &[(&str, &[&str])] = &[
    (
        "pecr-controller",
        &[
            "pecr-adapters",
            "pecr-ledger",
            "pecr-policy",
            "pecr-gateway",
        ],
    ),
    ("pecr-gateway", &["pecr-controller"]),
    (
        "pecr-contracts",
        &[
            "pecr-controller",
            "pecr-gateway",
            "pecr-ledger",
            "pecr-adapters",
            "pecr-policy",
            "pecr-auth",
        ],
    ),
    (
        "pecr-ledger",
        &[
            "pecr-controller",
            "pecr-gateway",
            "pecr-adapters",
            "pecr-policy",
        ],
    ),
];

fn main() -> Result<()> {
    let metadata = MetadataCommand::new()
        .exec()
        .context("failed to run `cargo metadata`")?;

    let resolve = metadata
        .resolve
        .as_ref()
        .context("`cargo metadata` did not include a resolved dependency graph")?;

    let id_to_name: HashMap<_, _> = metadata
        .packages
        .iter()
        .map(|p| (p.id.clone(), p.name.as_str()))
        .collect();

    let adjacency: HashMap<_, _> = resolve
        .nodes
        .iter()
        .map(|node| {
            let deps: Vec<_> = node.deps.iter().map(|dep| dep.pkg.clone()).collect();
            (node.id.clone(), deps)
        })
        .collect();

    let mut adjacency_by_name: HashMap<String, Vec<String>> = HashMap::new();
    for (node_id, deps) in adjacency {
        let Some(node_name) = id_to_name.get(&node_id).copied() else {
            continue;
        };
        let dep_names = deps
            .into_iter()
            .filter_map(|dep_id| id_to_name.get(&dep_id).copied().map(|s| s.to_string()))
            .collect::<Vec<_>>();
        adjacency_by_name.insert(node_name.to_string(), dep_names);
    }

    for (package_name, _) in BOUNDARY_RULES {
        if !adjacency_by_name.contains_key(*package_name) {
            return Err(anyhow!("package `{}` not found in workspace", package_name));
        }
    }

    let all_violations = find_boundary_violations(BOUNDARY_RULES, &adjacency_by_name);

    if !all_violations.is_empty() {
        eprintln!(
            "FAIL: forbidden workspace dependency edges found: {}",
            all_violations.join(", ")
        );
        std::process::exit(1);
    }

    println!("OK: boundary rules satisfied");

    Ok(())
}

fn find_boundary_violations(
    rules: &[(&str, &[&str])],
    adjacency_by_name: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    let mut all_violations = Vec::new();

    for (package_name, forbidden) in rules {
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back((*package_name).to_string());
        visited.insert((*package_name).to_string());

        while let Some(current) = queue.pop_front() {
            let Some(deps) = adjacency_by_name.get(&current) else {
                continue;
            };

            for dep in deps.iter().cloned() {
                if !visited.insert(dep.clone()) {
                    continue;
                }

                if forbidden.contains(&dep.as_str()) {
                    all_violations.push(format!("{} -> {}", package_name, dep));
                }

                queue.push_back(dep);
            }
        }
    }

    all_violations.sort();
    all_violations.dedup();
    all_violations
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_transitive_forbidden_edges() {
        let rules: &[(&str, &[&str])] = &[("a", &["c"])];
        let graph = HashMap::from([
            ("a".to_string(), vec!["b".to_string()]),
            ("b".to_string(), vec!["c".to_string()]),
            ("c".to_string(), vec![]),
        ]);

        let violations = find_boundary_violations(rules, &graph);
        assert_eq!(violations, vec!["a -> c".to_string()]);
    }

    #[test]
    fn de_duplicates_violations_across_multiple_paths() {
        let rules: &[(&str, &[&str])] = &[("a", &["d"])];
        let graph = HashMap::from([
            ("a".to_string(), vec!["b".to_string(), "c".to_string()]),
            ("b".to_string(), vec!["d".to_string()]),
            ("c".to_string(), vec!["d".to_string()]),
            ("d".to_string(), vec![]),
        ]);

        let violations = find_boundary_violations(rules, &graph);
        assert_eq!(violations, vec!["a -> d".to_string()]);
    }
}
