use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "devctl-relocation-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    fn catalog(&self) -> PathBuf {
        let target = self.0.join("moved/catalog");
        fs::create_dir_all(target.join("contracts")).unwrap();
        for name in [
            "workspace.toml",
            "laws.toml",
            "archetypes.toml",
            "adjudications.toml",
        ] {
            fs::copy(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("catalog")
                    .join(name),
                target.join(name),
            )
            .unwrap();
        }
        target
    }

    fn forest(&self) -> PathBuf {
        let root = self.0.join("forest");
        let repo = root.join("example");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::write(repo.join("AGENTS.md"), "Local constraints live here.\n").unwrap();
        fs::write(
            repo.join("Cargo.toml"),
            "[package]\nname = \"example\"\nversion = \"0.1.0\"\n",
        )
        .unwrap();
        root
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn moved_catalog_audits_without_imposing_a_document_quartet() {
    let fixture = Fixture::new();
    let catalog = fixture.catalog();
    let forest = fixture.forest();
    let private = catalog.join("local/contracts");
    fs::create_dir_all(&private).unwrap();
    fs::write(
        private.join("operator-private.toml"),
        "invalid private fixture; must not be read",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_devctl"))
        .current_dir(&fixture.0)
        .args([
            "--catalog-root",
            catalog.to_str().unwrap(),
            "--no-private-contracts",
            "standards",
            "audit",
            forest.to_str().unwrap(),
            "--all",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let findings = value["findings"].as_array().unwrap();
    assert!(!findings.iter().any(|row| row["law"] == "doctrine-quartet"));
    assert!(
        findings
            .iter()
            .any(|row| row["law"] == "command-verification")
    );
    assert!(findings.iter().all(|row| {
        row["standard_refs"]
            .as_array()
            .is_some_and(|refs| !refs.is_empty())
    }));
    assert!(!forest.join("example/NORTH_STAR.md").exists());
    assert_eq!(
        fs::read_to_string(private.join("operator-private.toml")).unwrap(),
        "invalid private fixture; must not be read"
    );
}

#[test]
fn relocated_binary_uses_adjacent_catalog_and_reports_missing_inputs() {
    let fixture = Fixture::new();
    fixture.catalog();
    let forest = fixture.forest();
    let binary = fixture.0.join("moved/devctl");
    fs::copy(env!("CARGO_BIN_EXE_devctl"), &binary).unwrap();
    let run = || {
        Command::new(&binary)
            .current_dir(&fixture.0)
            .args(["inventory", forest.to_str().unwrap(), "--json"])
            .output()
            .unwrap()
    };
    let output = run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    fs::remove_file(fixture.0.join("moved/catalog/workspace.toml")).unwrap();
    let missing = run();
    assert!(!missing.status.success());
    assert!(String::from_utf8_lossy(&missing.stderr).contains("catalog"));
}

#[test]
fn private_overlay_requires_selection_and_errors_do_not_expose_values() {
    let fixture = Fixture::new();
    let catalog = fixture.catalog();
    let forest = fixture.forest();
    let overlay = fixture.0.join("private-contracts");
    fs::create_dir(&overlay).unwrap();
    let secret = "synthetic-private-value-must-not-appear";
    fs::write(overlay.join("example.toml"), secret).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_devctl"))
        .args([
            "--catalog-root",
            catalog.to_str().unwrap(),
            "--contracts-overlay",
            overlay.to_str().unwrap(),
            "standards",
            "contracts",
            forest.to_str().unwrap(),
            "--all",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Invalid contract schema"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
    assert_eq!(
        fs::read_to_string(overlay.join("example.toml")).unwrap(),
        secret
    );
}
