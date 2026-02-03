use std::collections::{HashMap, HashSet, VecDeque};

use anyhow::{Context, Result};
use cargo_metadata::MetadataCommand;

const CONTROLLER_PACKAGE_NAME: &str = "pecr-controller";
const FORBIDDEN_CONTROLLER_DEPENDENCIES: &[&str] = &["pecr-adapters", "pecr-ledger", "pecr-policy"];

fn main() -> Result<()> {
    let metadata = MetadataCommand::new()
        .exec()
        .context("failed to run `cargo metadata`")?;

    let resolve = metadata
        .resolve
        .as_ref()
        .context("`cargo metadata` did not include a resolved dependency graph")?;

    let controller = metadata
        .packages
        .iter()
        .find(|p| p.name == CONTROLLER_PACKAGE_NAME)
        .with_context(|| {
            format!(
                "package `{}` not found in workspace",
                CONTROLLER_PACKAGE_NAME
            )
        })?;

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

    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(controller.id.clone());
    visited.insert(controller.id.clone());

    let mut violations = Vec::new();

    while let Some(current) = queue.pop_front() {
        let Some(deps) = adjacency.get(&current) else {
            continue;
        };

        for dep in deps.iter().cloned() {
            if !visited.insert(dep.clone()) {
                continue;
            }

            if let Some(name) = id_to_name.get(&dep)
                && FORBIDDEN_CONTROLLER_DEPENDENCIES.contains(name)
            {
                violations.push((*name).to_string());
            }

            queue.push_back(dep);
        }
    }

    if !violations.is_empty() {
        violations.sort();
        violations.dedup();
        eprintln!(
            "FAIL: `{}` depends on forbidden crate(s): {}",
            CONTROLLER_PACKAGE_NAME,
            violations.join(", ")
        );
        std::process::exit(1);
    }

    println!(
        "OK: `{}` has no dependency edge to {}",
        CONTROLLER_PACKAGE_NAME,
        FORBIDDEN_CONTROLLER_DEPENDENCIES.join(", ")
    );

    Ok(())
}
