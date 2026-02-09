use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::{Context, Result};
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

    let mut all_violations = Vec::new();

    for (package_name, forbidden) in BOUNDARY_RULES {
        let package = metadata
            .packages
            .iter()
            .find(|p| p.name == *package_name)
            .with_context(|| format!("package `{}` not found in workspace", package_name))?;

        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();
        queue.push_back(package.id.clone());
        visited.insert(package.id.clone());

        while let Some(current) = queue.pop_front() {
            let Some(deps) = adjacency.get(&current) else {
                continue;
            };

            for dep in deps.iter().cloned() {
                if !visited.insert(dep.clone()) {
                    continue;
                }

                if let Some(name) = id_to_name.get(&dep)
                    && forbidden.contains(name)
                {
                    all_violations.push(format!("{} -> {}", package_name, name));
                }

                queue.push_back(dep);
            }
        }
    }

    if !all_violations.is_empty() {
        all_violations.sort();
        all_violations.dedup();
        eprintln!(
            "FAIL: forbidden workspace dependency edges found: {}",
            all_violations.join(", ")
        );
        std::process::exit(1);
    }

    println!("OK: boundary rules satisfied");

    Ok(())
}
