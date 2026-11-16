//! Explicit, relocatable catalog selection. Never writes catalogs or overlays.
use crate::{
    AdjudicationsCatalog, ArchetypesCatalog, CONTRACT_LAW, ContractsCatalog, DevResult,
    LawMaturity, LawsCatalog, RepoContract, SCHEMA_VERSION, SourcedRepoContract, Utf8Path,
    Utf8PathBuf, V0_LAWS, WorkspaceCatalog, toml_line_map,
};
use std::{collections::BTreeSet, fs};

pub(crate) struct CatalogPaths {
    pub(crate) root: Utf8PathBuf,
    pub(crate) overlay: Option<Utf8PathBuf>,
}

impl CatalogPaths {
    pub(crate) fn resolve(
        root: Option<Utf8PathBuf>,
        overlay: Option<Utf8PathBuf>,
        no_private: bool,
    ) -> DevResult<Self> {
        let root = match root {
            Some(root) => root,
            // Resolve launcher symlinks so the catalog is found beside the real executable.
            None => Utf8PathBuf::from_path_buf(std::env::current_exe()?.canonicalize()?)
                .map_err(|_| "Executable path is not UTF-8")?
                .parent()
                .ok_or("Executable has no parent")?
                .join("catalog"),
        };
        if !root.is_dir() {
            return Err(
                format!("Catalog directory missing: {root}; use --catalog-root PATH").into(),
            );
        }
        let root = Utf8PathBuf::from_path_buf(root.canonicalize()?)
            .map_err(|_| "Catalog path is not UTF-8")?;
        let overlay = if no_private {
            None
        } else if let Some(path) = overlay {
            if !path.is_dir() {
                return Err("Explicit private contracts directory is missing".into());
            }
            Some(path)
        } else {
            Some(root.join("local/contracts"))
        };
        Ok(Self { root, overlay })
    }

    pub(crate) fn read(&self, name: &str) -> DevResult<String> {
        std::fs::read_to_string(self.root.join(name))
            .map_err(|error| format!("Cannot read catalog {name}: {error}").into())
    }
}

pub(super) fn load_workspace_catalog(paths: &CatalogPaths) -> DevResult<WorkspaceCatalog> {
    toml::from_str(&paths.read("workspace.toml")?)
        .map_err(|_| "Invalid workspace catalog schema".into())
}

pub(super) fn load_laws_catalog(paths: &CatalogPaths) -> DevResult<LawsCatalog> {
    toml::from_str(&paths.read("laws.toml")?).map_err(|_| "Invalid laws catalog schema".into())
}

pub(super) fn load_archetypes_catalog(paths: &CatalogPaths) -> DevResult<ArchetypesCatalog> {
    toml::from_str(&paths.read("archetypes.toml")?)
        .map_err(|_| "Invalid archetypes catalog schema".into())
}

pub(super) fn load_contracts_catalog(paths: &CatalogPaths) -> DevResult<ContractsCatalog> {
    let mut catalog = ContractsCatalog::default();
    load_contracts_dir(&paths.root.join("contracts"), &mut catalog, false)?;
    if let Some(overlay) = &paths.overlay {
        load_contracts_dir(overlay, &mut catalog, true)?;
    }
    Ok(catalog)
}

fn load_contracts_dir(
    root: &Utf8Path,
    catalog: &mut ContractsCatalog,
    allow_override: bool,
) -> DevResult<()> {
    if !root.is_dir() {
        return Ok(());
    }
    let mut entries = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = Utf8PathBuf::from_path_buf(entry.path())
            .map_err(|path| format!("non-utf8 contract path: {}", path.display()))?;
        entries.push(path);
    }
    entries.sort();
    for path in entries {
        if !path.is_file() {
            continue;
        }
        if path.extension() != Some("toml") {
            continue;
        }
        let body = fs::read_to_string(&path)?;
        let lines = toml_line_map(&body);
        let contract: RepoContract = toml::from_str(&body)
            .map_err(|_| format!("Invalid contract schema: {path}; source values omitted"))?;
        if !allow_override && catalog.contracts.contains_key(&contract.repo) {
            return Err(format!("duplicate contract for repo {}", contract.repo).into());
        }
        catalog.contracts.insert(
            contract.repo.clone(),
            SourcedRepoContract {
                contract,
                path,
                lines,
            },
        );
    }
    Ok(())
}

pub(super) fn load_adjudications_catalog(paths: &CatalogPaths) -> DevResult<AdjudicationsCatalog> {
    let path = paths.root.join("adjudications.toml");
    if !path.is_file() {
        return Ok(AdjudicationsCatalog::default());
    }
    toml::from_str(&paths.read("adjudications.toml")?)
        .map_err(|_| "Invalid adjudications catalog schema; source values omitted".into())
}

pub(super) fn validate_laws_catalog(catalog: &LawsCatalog) -> DevResult<()> {
    if catalog.standards.repository != "https://github.com/mlnavigator-ai/standards"
        || catalog.standards.commit.len() != 40
        || !catalog
            .standards
            .commit
            .bytes()
            .all(|b| b.is_ascii_hexdigit())
    {
        return Err(
            "Laws must identify the canonical standards repository and exact revision".into(),
        );
    }
    if catalog.schema_version != "0.2.0" {
        return Err(format!(
            "catalog/laws.toml schema_version {} does not match 0.2.0",
            catalog.schema_version
        )
        .into());
    }
    let mut ids = BTreeSet::new();
    for law in &catalog.laws {
        if law.id.trim().is_empty()
            || law.title.trim().is_empty()
            || law.description.trim().is_empty()
        {
            return Err("catalog/laws.toml contains an incomplete law definition".into());
        }
        if matches!(law.maturity, LawMaturity::Retired) && active_laws().any(|id| id == law.id) {
            return Err(format!("catalog/laws.toml retires active law {}", law.id).into());
        }
        if law.standard_refs.is_empty()
            || law
                .standard_refs
                .iter()
                .any(|reference| !reference.starts_with("STD:"))
        {
            return Err(format!("Law {} needs canonical standard references", law.id).into());
        }
        if matches!(law.maturity, LawMaturity::Retired)
            && law
                .retirement_reason
                .as_ref()
                .is_none_or(|reason| reason.trim().is_empty())
        {
            return Err(format!("Retired law {} needs its historical reason", law.id).into());
        }
        if !ids.insert(law.id.as_str()) {
            return Err(format!("catalog/laws.toml repeats law id {}", law.id).into());
        }
    }
    for law in active_laws() {
        if !ids.contains(law) {
            return Err(format!("catalog/laws.toml is missing active law {law}").into());
        }
    }
    Ok(())
}

/// Laws with live scanners or contract checks; catalog edits may not retire or drop them.
fn active_laws() -> impl Iterator<Item = &'static str> {
    V0_LAWS.into_iter().chain([CONTRACT_LAW])
}

pub(super) fn validate_archetypes_catalog(catalog: &ArchetypesCatalog) -> DevResult<()> {
    if catalog.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "catalog/archetypes.toml schema_version {} does not match {SCHEMA_VERSION}",
            catalog.schema_version
        )
        .into());
    }
    let mut ids = BTreeSet::new();
    for archetype in &catalog.archetypes {
        if archetype.id.trim().is_empty() || archetype.title.trim().is_empty() {
            return Err("catalog/archetypes.toml contains an incomplete archetype".into());
        }
        if archetype.requires_cloudflare_posture && archetype.allowed_cloudflare_postures.is_empty()
        {
            return Err(format!(
                "archetype {} requires Cloudflare posture but has no allowed postures",
                archetype.id
            )
            .into());
        }
        if !ids.insert(archetype.id.as_str()) {
            return Err(format!("catalog/archetypes.toml repeats {}", archetype.id).into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_laws() -> LawsCatalog {
        let root = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("catalog");
        let paths = CatalogPaths::resolve(Some(root), None, true).unwrap();
        let laws = load_laws_catalog(&paths).unwrap();
        validate_laws_catalog(&laws).unwrap();
        laws
    }

    fn retire(laws: &mut LawsCatalog, id: &str) {
        let law = laws.laws.iter_mut().find(|law| law.id == id).unwrap();
        law.maturity = LawMaturity::Retired;
        law.retirement_reason = Some("synthetic catalog edit".to_string());
    }

    #[test]
    fn catalog_edits_cannot_retire_active_laws() {
        for id in [V0_LAWS[0], CONTRACT_LAW] {
            let mut laws = repo_laws();
            retire(&mut laws, id);
            let error = validate_laws_catalog(&laws).unwrap_err().to_string();
            assert!(
                error.contains(&format!("retires active law {id}")),
                "{error}"
            );
        }
    }

    #[test]
    fn catalog_edits_cannot_drop_the_contract_law() {
        let mut laws = repo_laws();
        laws.laws.retain(|law| law.id != CONTRACT_LAW);
        let error = validate_laws_catalog(&laws).unwrap_err().to_string();
        assert!(
            error.contains("missing active law repo-contract"),
            "{error}"
        );
    }
}
