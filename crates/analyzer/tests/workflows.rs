use std::{fs, path::PathBuf};

#[test]
fn github_workflows_are_valid_yaml() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let workflows = root.join(".github/workflows");
    let entries = fs::read_dir(&workflows).unwrap();
    let mut checked = 0;
    for entry in entries {
        let path = entry.unwrap().path();
        if path.extension().and_then(|value| value.to_str()) != Some("yml") {
            continue;
        }
        let bytes = fs::read(&path).unwrap();
        serde_yaml::from_slice::<serde_yaml::Value>(&bytes)
            .unwrap_or_else(|error| panic!("invalid workflow {}: {error}", path.display()));
        checked += 1;
    }
    assert_eq!(checked, 3);
}
