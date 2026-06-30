use camino::{Utf8Path, Utf8PathBuf};
use clap::{Args, Parser, Subcommand, ValueEnum};
use ignore::WalkBuilder;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::time::{SystemTime, UNIX_EPOCH};

const SCHEMA_VERSION: &str = "0.1.0";
const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
const V0_LAWS: [&str; 6] = [
    "cloudflare-mutation",
    "token",
    "command-verification",
    "release-proof",
    "artifact-boundary",
    "doctrine-quartet",
];
const CONTRACT_LAW: &str = "repo-contract";

type DevResult<T> = Result<T, Box<dyn Error>>;

#[derive(Parser)]
#[command(name = "devctl")]
#[command(about = "Read-only standards control plane for a local repo forest")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Inventory(InventoryArgs),
    Standards(StandardsArgs),
    Repo(RepoArgs),
}

#[derive(Args)]
struct InventoryArgs {
    root: Utf8PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct StandardsArgs {
    #[command(subcommand)]
    command: StandardsCommand,
}

#[derive(Subcommand)]
enum StandardsCommand {
    Audit(AuditArgs),
    AdjudicationTemplate(AdjudicationTemplateArgs),
    Contracts(ContractsArgs),
    Packet(PacketArgs),
    Plan(PlanArgs),
    ProposeContract(ProposeContractArgs),
    Report(ReportArgs),
}

#[derive(Args)]
struct AuditArgs {
    root: Utf8PathBuf,
    #[arg(long, value_enum)]
    pilot: Option<Pilot>,
    #[arg(long)]
    all: bool,
    #[arg(long)]
    json: bool,
    #[arg(long)]
    fail_on: Option<Severity>,
}

#[derive(Clone, ValueEnum)]
enum Pilot {
    ThreeTier,
}

#[derive(Args)]
struct PlanArgs {
    root: Utf8PathBuf,
    #[arg(long, value_enum)]
    pilot: Option<Pilot>,
    #[arg(long)]
    all: bool,
    #[arg(long, default_value = "P0,P1")]
    risk: String,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct AdjudicationTemplateArgs {
    root: Utf8PathBuf,
    #[arg(long, value_enum)]
    pilot: Option<Pilot>,
    #[arg(long)]
    all: bool,
    #[arg(long, default_value = "P0,P1")]
    risk: String,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct ProposeContractArgs {
    repo: Utf8PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct ContractsArgs {
    root: Utf8PathBuf,
    #[arg(long, value_enum)]
    pilot: Option<Pilot>,
    #[arg(long)]
    all: bool,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct PacketArgs {
    root: Utf8PathBuf,
    #[arg(long, value_enum)]
    pilot: Option<Pilot>,
    #[arg(long)]
    all: bool,
    #[arg(long, default_value = "P0,P1")]
    risk: String,
    #[arg(long)]
    out: Option<Utf8PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct ReportArgs {
    root: Utf8PathBuf,
    #[arg(long, value_enum)]
    pilot: Option<Pilot>,
    #[arg(long)]
    all: bool,
    #[arg(long)]
    out: Option<Utf8PathBuf>,
    #[arg(long)]
    json: bool,
}

#[derive(Args)]
struct RepoArgs {
    #[command(subcommand)]
    command: RepoCommand,
}

#[derive(Subcommand)]
enum RepoCommand {
    Explain(ExplainArgs),
}

#[derive(Args)]
struct ExplainArgs {
    repo: Utf8PathBuf,
    #[arg(long)]
    json: bool,
}

#[derive(Debug, Deserialize)]
struct WorkspaceCatalog {
    pilot_three_tier: Vec<String>,
    repo_status: BTreeMap<String, RepoStatus>,
}

#[derive(Debug, Deserialize)]
struct LawsCatalog {
    schema_version: String,
    laws: Vec<LawDefinition>,
}

#[derive(Debug, Deserialize)]
struct ArchetypesCatalog {
    schema_version: String,
    archetypes: Vec<ArchetypeDefinition>,
}

#[derive(Debug, Clone, Deserialize)]
struct ArchetypeDefinition {
    id: String,
    title: String,
    requires_canonical_commands: bool,
    requires_cloudflare_posture: bool,
    allowed_cloudflare_postures: Vec<String>,
    requires_release_evidence: bool,
    requires_artifact_classification: bool,
}

#[derive(Debug, Default)]
struct ContractsCatalog {
    contracts: BTreeMap<String, SourcedRepoContract>,
}

#[derive(Debug, Clone)]
struct SourcedRepoContract {
    contract: RepoContract,
    path: Utf8PathBuf,
    lines: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepoContract {
    schema_version: String,
    repo: String,
    archetype: String,
    status: RepoStatus,
    #[serde(default)]
    canonical_commands: Vec<CommandContract>,
    #[serde(default)]
    cloudflare: ContractCloudflare,
    #[serde(default)]
    release: ContractRelease,
    #[serde(default)]
    artifacts: ContractArtifacts,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum CommandContract {
    Text(String),
    Detailed {
        id: String,
        command: String,
        #[serde(default = "default_required")]
        required: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ContractCloudflare {
    posture: String,
    #[serde(default)]
    surfaces: Vec<CloudflareSurface>,
    #[serde(default)]
    raw_exceptions: Vec<RawMutationException>,
    #[serde(default)]
    token_policy: TokenPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum CloudflareSurface {
    Path(String),
    Detailed {
        id: String,
        kind: String,
        #[serde(default)]
        path: Option<String>,
        #[serde(default)]
        wrangler_config: Option<String>,
        #[serde(default = "default_required")]
        required: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct RawMutationException {
    path: String,
    operation: String,
    reason: String,
    expires: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct TokenPolicy {
    #[serde(default)]
    parent_tokens: Vec<String>,
    #[serde(default)]
    parent_allowed_paths: Vec<String>,
    #[serde(default)]
    forbidden_sinks: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ContractRelease {
    #[serde(default)]
    evidence_dirs: Vec<String>,
    #[serde(default)]
    lanes: Vec<ReleaseLane>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ReleaseLane {
    id: String,
    command: String,
    preflight: String,
    post_verify: String,
    #[serde(default)]
    evidence: Vec<String>,
    #[serde(default)]
    mutates_cloudflare: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct ContractArtifacts {
    classifications: BTreeMap<String, String>,
}

fn default_required() -> bool {
    true
}

#[derive(Debug, Deserialize)]
struct LawDefinition {
    id: String,
    title: String,
    description: String,
    maturity: LawMaturity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LawMaturity {
    Advisory,
    Pilot,
    Gated,
    Retired,
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct AdjudicationsCatalog {
    adjudications: Vec<AdjudicationEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdjudicationEntry {
    fingerprint: String,
    status: AdjudicationStatus,
    reason: String,
    owner: Option<String>,
    expires: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AdjudicationStatus {
    TruePositive,
    AcceptedException,
    FalsePositive,
    LawNeedsWork,
}

impl std::fmt::Display for AdjudicationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::TruePositive => "true-positive",
            Self::AcceptedException => "accepted-exception",
            Self::FalsePositive => "false-positive",
            Self::LawNeedsWork => "law-needs-work",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum RepoStatus {
    ActiveProduct,
    ActiveControlPlane,
    ActiveLibrary,
    Template,
    Legacy,
    Experiment,
    Unknown,
}

impl std::fmt::Display for RepoStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::ActiveProduct => "active-product",
            Self::ActiveControlPlane => "active-control-plane",
            Self::ActiveLibrary => "active-library",
            Self::Template => "template",
            Self::Legacy => "legacy",
            Self::Experiment => "experiment",
            Self::Unknown => "unknown",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoRecord {
    pub name: String,
    pub path: Utf8PathBuf,
    pub status: RepoStatus,
    pub git: GitInfo,
    pub docs: DocsInfo,
    pub languages: BTreeSet<String>,
    pub command_surfaces: CommandSurfaces,
    pub cloudflare: CloudflareInfo,
    pub release: ReleaseInfo,
    pub artifacts: ArtifactInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GitInfo {
    pub present: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DocsInfo {
    pub north_star: Option<Utf8PathBuf>,
    pub anchor: Option<Utf8PathBuf>,
    pub agents: Option<Utf8PathBuf>,
    pub claude: Option<Utf8PathBuf>,
    pub readme: Option<Utf8PathBuf>,
    pub security: Option<Utf8PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CommandSurfaces {
    pub cargo_toml: bool,
    pub package_json: bool,
    pub makefile: bool,
    pub scripts_dir: bool,
    pub ops_dir: bool,
    pub check_scripts: Vec<Utf8PathBuf>,
    pub verify_scripts: Vec<Utf8PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CloudflareInfo {
    pub has_wrangler_config: bool,
    pub wrangler_configs: Vec<Utf8PathBuf>,
    pub has_functions_dir: bool,
    pub has_workers_dir: bool,
    pub has_pages_dir: bool,
    pub declared_status: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReleaseInfo {
    pub deploy_scripts: Vec<Utf8PathBuf>,
    pub release_scripts: Vec<Utf8PathBuf>,
    pub evidence_dirs: Vec<Utf8PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ArtifactInfo {
    pub present_top_level: Vec<Utf8PathBuf>,
    pub has_policy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub fingerprint: String,
    pub archetype: Option<String>,
    pub contract_source: Option<String>,
    pub requirement_id: Option<String>,
    pub law: String,
    pub severity: Severity,
    pub repo: String,
    pub file: Option<Utf8PathBuf>,
    pub line: Option<usize>,
    pub message: String,
    pub evidence: String,
    pub expected: Option<String>,
    pub observed: Option<String>,
    pub recommendation: String,
    pub confidence: Confidence,
    pub repair_group: String,
    pub adjudication: Option<AppliedAdjudication>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppliedAdjudication {
    pub status: AdjudicationStatus,
    pub reason: String,
    pub owner: Option<String>,
    pub expires: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
pub enum Severity {
    P0,
    P1,
    P2,
    P3,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::P0 => "P0",
            Self::P1 => "P1",
            Self::P2 => "P2",
            Self::P3 => "P3",
        };
        f.write_str(value)
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input.trim().to_ascii_uppercase().as_str() {
            "P0" => Ok(Self::P0),
            "P1" => Ok(Self::P1),
            "P2" => Ok(Self::P2),
            "P3" => Ok(Self::P3),
            other => Err(format!("unknown severity {other:?}")),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairTranche {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub repos: Vec<String>,
    pub findings: Vec<String>,
    pub recommended_actions: Vec<String>,
    pub proof_required: Vec<String>,
}

#[derive(Debug, Serialize)]
struct InventoryOutput {
    schema_version: &'static str,
    root: Utf8PathBuf,
    repos: Vec<RepoRecord>,
}

#[derive(Debug, Serialize)]
struct AuditOutput {
    schema_version: &'static str,
    root: Utf8PathBuf,
    scope: String,
    repos: Vec<RepoRecord>,
    findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
struct PlanOutput {
    schema_version: &'static str,
    root: Utf8PathBuf,
    risk: Vec<Severity>,
    tranches: Vec<RepairTranche>,
}

#[derive(Debug, Serialize)]
struct ContractsOutput {
    schema_version: &'static str,
    root: Utf8PathBuf,
    scope: String,
    contracts: Vec<RepoContractProposal>,
    findings: Vec<Finding>,
}

#[derive(Debug, Serialize)]
struct ReportOutput {
    schema_version: &'static str,
    tool_version: &'static str,
    root: Utf8PathBuf,
    scope: String,
    generated_at_epoch_seconds: u64,
    audit_json: Utf8PathBuf,
    audit_markdown: Utf8PathBuf,
    findings: usize,
    tranches: usize,
    adjudications: BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
struct ReportDocument<'a> {
    schema_version: &'static str,
    tool_version: &'static str,
    generated_at_epoch_seconds: u64,
    audit: &'a AuditOutput,
    tranches: &'a [RepairTranche],
    adjudications: &'a BTreeMap<String, usize>,
}

#[derive(Debug, Serialize)]
struct PacketOutput {
    schema_version: &'static str,
    tool_version: &'static str,
    root: Utf8PathBuf,
    scope: String,
    generated_at_epoch_seconds: u64,
    packet_json: Utf8PathBuf,
    packet_markdown: Utf8PathBuf,
    contracts: usize,
    adjudication_stubs: usize,
    tranches: usize,
    next_actions: usize,
}

#[derive(Debug, Serialize)]
struct OperatingPacketDocument<'a> {
    schema_version: &'static str,
    tool_version: &'static str,
    generated_at_epoch_seconds: u64,
    principle: &'static str,
    audit: &'a AuditOutput,
    contracts: &'a [RepoContractProposal],
    adjudication_template: &'a [AdjudicationEntry],
    tranches: &'a [RepairTranche],
    next_actions: &'a [String],
}

#[derive(Debug, Serialize)]
struct AdjudicationTemplateOutput {
    schema_version: &'static str,
    root: Utf8PathBuf,
    scope: String,
    risk: Vec<Severity>,
    adjudications: Vec<AdjudicationEntry>,
}

#[derive(Debug, Serialize)]
struct RepoContractProposal {
    schema_version: &'static str,
    repo: String,
    path: Utf8PathBuf,
    status: RepoStatus,
    inferred: bool,
    archetype: String,
    canonical_commands: Vec<String>,
    scripts: Vec<ScriptContract>,
    cloudflare: CloudflareContract,
    release: ReleaseContract,
    artifacts: ArtifactContract,
    exceptions: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ScriptContract {
    path: String,
    classification: String,
}

#[derive(Debug, Serialize)]
struct CloudflareContract {
    posture: String,
    surfaces: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ReleaseContract {
    deploy_scripts: Vec<String>,
    release_scripts: Vec<String>,
    evidence_dirs: Vec<String>,
}

#[derive(Debug, Serialize)]
struct ArtifactContract {
    present_top_level: Vec<String>,
    has_policy: bool,
    classifications: BTreeMap<String, String>,
}

pub fn run() -> DevResult<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Inventory(args) => {
            let catalog = load_workspace_catalog()?;
            let repos = inventory(&args.root, &catalog)?;
            let output = InventoryOutput {
                schema_version: SCHEMA_VERSION,
                root: normalize_path(&args.root),
                repos,
            };
            if args.json {
                print_json(&output)?;
            } else {
                print_inventory_human(&output);
            }
        }
        Commands::Standards(args) => match args.command {
            StandardsCommand::Audit(args) => {
                let output = audit_command(&args)?;
                if args.json {
                    print_json(&output)?;
                } else {
                    print_audit_human(&output);
                }
                if let Some(threshold) = args.fail_on
                    && output.findings.iter().any(|f| f.severity <= threshold)
                {
                    std::process::exit(1);
                }
            }
            StandardsCommand::AdjudicationTemplate(args) => {
                let output = adjudication_template_command(&args)?;
                if args.json {
                    print_json(&output)?;
                } else {
                    print_toml(&AdjudicationsCatalog {
                        adjudications: output.adjudications,
                    })?;
                }
            }
            StandardsCommand::Contracts(args) => {
                let output = contracts_command(&args)?;
                if args.json {
                    print_json(&output)?;
                } else {
                    print_contracts_human(&output);
                }
            }
            StandardsCommand::Packet(args) => {
                let output = packet_command(&args)?;
                if args.json {
                    print_json(&output)?;
                } else {
                    print_packet_human(&output);
                }
            }
            StandardsCommand::Plan(args) => {
                let output = plan_command(&args)?;
                if args.json {
                    print_json(&output)?;
                } else {
                    print_plan_human(&output);
                }
            }
            StandardsCommand::ProposeContract(args) => {
                let output = propose_contract_command(&args)?;
                if args.json {
                    print_json(&output)?;
                } else {
                    print_toml(&build_catalog_contract_draft(&output))?;
                }
            }
            StandardsCommand::Report(args) => {
                let output = report_command(&args)?;
                if args.json {
                    print_json(&output)?;
                } else {
                    print_report_human(&output);
                }
            }
        },
        Commands::Repo(args) => match args.command {
            RepoCommand::Explain(args) => {
                let catalog = load_workspace_catalog()?;
                let repo = scan_repo(&args.repo, &catalog)?;
                if args.json {
                    print_json(&repo)?;
                } else {
                    print_repo_human(&repo);
                }
            }
        },
    }
    Ok(())
}

fn audit_command(args: &AuditArgs) -> DevResult<AuditOutput> {
    let catalog = load_workspace_catalog()?;
    let laws = load_laws_catalog()?;
    let archetypes = load_archetypes_catalog()?;
    let contracts = load_contracts_catalog()?;
    let adjudications = load_adjudications_catalog()?;
    validate_laws_catalog(&laws)?;
    validate_archetypes_catalog(&archetypes)?;
    validate_contracts_catalog(&contracts, &archetypes)?;
    validate_adjudications_catalog(&adjudications)?;
    let root = normalize_path(&args.root);
    let mut repos = inventory(&root, &catalog)?;
    let scope = if args.all {
        "all".to_string()
    } else {
        "pilot:three-tier".to_string()
    };
    if !args.all {
        let pilot = match args.pilot {
            Some(Pilot::ThreeTier) | None => &catalog.pilot_three_tier,
        };
        repos.retain(|repo| pilot.contains(&repo.name));
    }
    let mut findings = audit_repos(&repos, Some(&contracts), Some(&archetypes))?;
    apply_adjudications(&mut findings, &adjudications);
    validate_findings_against_laws(&findings, &laws)?;
    Ok(AuditOutput {
        schema_version: SCHEMA_VERSION,
        root,
        scope,
        repos,
        findings,
    })
}

fn plan_command(args: &PlanArgs) -> DevResult<PlanOutput> {
    let risk = parse_risk(&args.risk)?;
    let audit = audit_command(&AuditArgs {
        root: args.root.clone(),
        pilot: args.pilot.clone(),
        all: args.all,
        json: true,
        fail_on: None,
    })?;
    let filtered: Vec<Finding> = audit
        .findings
        .into_iter()
        .filter(|finding| risk.contains(&finding.severity) && finding_is_actionable(finding))
        .collect();
    let tranches = build_tranches(&filtered);
    Ok(PlanOutput {
        schema_version: SCHEMA_VERSION,
        root: normalize_path(&args.root),
        risk,
        tranches,
    })
}

fn adjudication_template_command(
    args: &AdjudicationTemplateArgs,
) -> DevResult<AdjudicationTemplateOutput> {
    let risk = parse_risk(&args.risk)?;
    let audit = audit_command(&AuditArgs {
        root: args.root.clone(),
        pilot: args.pilot.clone(),
        all: args.all,
        json: true,
        fail_on: None,
    })?;
    let adjudications = build_adjudication_template(&audit.findings, &risk);
    Ok(AdjudicationTemplateOutput {
        schema_version: SCHEMA_VERSION,
        root: audit.root,
        scope: audit.scope,
        risk,
        adjudications,
    })
}

fn build_adjudication_template(findings: &[Finding], risk: &[Severity]) -> Vec<AdjudicationEntry> {
    findings
        .iter()
        .filter(|finding| risk.contains(&finding.severity))
        .filter(|finding| finding.adjudication.is_none())
        .map(|finding| AdjudicationEntry {
            fingerprint: finding.fingerprint.clone(),
            status: AdjudicationStatus::TruePositive,
            reason: format!(
                "TODO: review {} {} {}",
                finding.repo, finding.law, finding.id
            ),
            owner: None,
            expires: None,
        })
        .collect()
}

fn propose_contract_command(args: &ProposeContractArgs) -> DevResult<RepoContractProposal> {
    let catalog = load_workspace_catalog()?;
    let contracts = load_contracts_catalog()?;
    let repo = scan_repo(&args.repo, &catalog)?;
    Ok(build_contract_proposal(
        &repo,
        contracts.contracts.get(&repo.name),
    ))
}

fn contracts_command(args: &ContractsArgs) -> DevResult<ContractsOutput> {
    let catalog = load_workspace_catalog()?;
    let archetypes = load_archetypes_catalog()?;
    let contracts = load_contracts_catalog()?;
    validate_archetypes_catalog(&archetypes)?;
    validate_contracts_catalog(&contracts, &archetypes)?;
    let root = normalize_path(&args.root);
    let mut repos = inventory(&root, &catalog)?;
    let scope = if args.all {
        "all".to_string()
    } else {
        "pilot:three-tier".to_string()
    };
    if !args.all {
        let pilot = match args.pilot {
            Some(Pilot::ThreeTier) | None => &catalog.pilot_three_tier,
        };
        repos.retain(|repo| pilot.contains(&repo.name));
    }
    let proposals = repos
        .iter()
        .map(|repo| build_contract_proposal(repo, contracts.contracts.get(&repo.name)))
        .collect::<Vec<_>>();
    let mut findings = Vec::new();
    for repo in &repos {
        audit_contract(
            repo,
            contracts.contracts.get(&repo.name),
            &archetypes,
            &mut findings,
        );
    }
    findings.sort_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then_with(|| left.repo.cmp(&right.repo))
            .then_with(|| left.law.cmp(&right.law))
            .then_with(|| left.file.cmp(&right.file))
            .then_with(|| left.line.cmp(&right.line))
    });
    assign_finding_ids(&mut findings);
    Ok(ContractsOutput {
        schema_version: SCHEMA_VERSION,
        root,
        scope,
        contracts: proposals,
        findings,
    })
}

fn packet_command(args: &PacketArgs) -> DevResult<PacketOutput> {
    let risk = parse_risk(&args.risk)?;
    let audit = audit_command(&AuditArgs {
        root: args.root.clone(),
        pilot: args.pilot.clone(),
        all: args.all,
        json: true,
        fail_on: None,
    })?;
    let contracts_catalog = load_contracts_catalog()?;
    let contracts: Vec<RepoContractProposal> = audit
        .repos
        .iter()
        .map(|repo| build_contract_proposal(repo, contracts_catalog.contracts.get(&repo.name)))
        .collect();
    let adjudication_template = build_adjudication_template(&audit.findings, &risk);
    let actionable: Vec<Finding> = audit
        .findings
        .iter()
        .filter(|finding| risk.contains(&finding.severity) && finding_is_actionable(finding))
        .cloned()
        .collect();
    let tranches = build_tranches(&actionable);
    let next_actions = derive_next_actions(&contracts, &adjudication_template, &tranches);
    let generated_at_epoch_seconds = unix_timestamp()?;
    let out_root = resolve_report_root(args.out.as_ref())?;
    let packet_dir = out_root.join("packets");
    fs::create_dir_all(&packet_dir)?;
    let slug = audit.scope.replace(':', "-");
    let packet_json = packet_dir.join(format!("{generated_at_epoch_seconds}-{slug}.json"));
    let packet_markdown = packet_dir.join(format!("{generated_at_epoch_seconds}-{slug}.md"));
    let document = OperatingPacketDocument {
        schema_version: SCHEMA_VERSION,
        tool_version: TOOL_VERSION,
        generated_at_epoch_seconds,
        principle: "repo development flow is the system center; devctl is the read-only instrument panel",
        audit: &audit,
        contracts: &contracts,
        adjudication_template: &adjudication_template,
        tranches: &tranches,
        next_actions: &next_actions,
    };
    fs::write(&packet_json, serde_json::to_string_pretty(&document)?)?;
    fs::write(
        &packet_markdown,
        render_operating_packet_markdown(&document),
    )?;
    Ok(PacketOutput {
        schema_version: SCHEMA_VERSION,
        tool_version: TOOL_VERSION,
        root: audit.root,
        scope: audit.scope,
        generated_at_epoch_seconds,
        packet_json,
        packet_markdown,
        contracts: contracts.len(),
        adjudication_stubs: adjudication_template.len(),
        tranches: tranches.len(),
        next_actions: next_actions.len(),
    })
}

fn report_command(args: &ReportArgs) -> DevResult<ReportOutput> {
    let audit = audit_command(&AuditArgs {
        root: args.root.clone(),
        pilot: args.pilot.clone(),
        all: args.all,
        json: true,
        fail_on: None,
    })?;
    let actionable: Vec<Finding> = audit
        .findings
        .iter()
        .filter(|finding| finding_is_actionable(finding))
        .cloned()
        .collect();
    let tranches = build_tranches(&actionable);
    let generated_at_epoch_seconds = unix_timestamp()?;
    let out_root = resolve_report_root(args.out.as_ref())?;
    let audit_dir = out_root.join("audits");
    fs::create_dir_all(&audit_dir)?;
    let slug = audit.scope.replace(':', "-");
    let audit_json = audit_dir.join(format!("{generated_at_epoch_seconds}-{slug}.json"));
    let audit_markdown = audit_dir.join(format!("{generated_at_epoch_seconds}-{slug}.md"));
    let adjudications = summarize_adjudications(&audit.findings);
    let document = ReportDocument {
        schema_version: SCHEMA_VERSION,
        tool_version: TOOL_VERSION,
        generated_at_epoch_seconds,
        audit: &audit,
        tranches: &tranches,
        adjudications: &adjudications,
    };
    fs::write(&audit_json, serde_json::to_string_pretty(&document)?)?;
    fs::write(
        &audit_markdown,
        render_markdown_report(
            generated_at_epoch_seconds,
            &audit,
            &tranches,
            &adjudications,
        ),
    )?;
    Ok(ReportOutput {
        schema_version: SCHEMA_VERSION,
        tool_version: TOOL_VERSION,
        root: audit.root,
        scope: audit.scope,
        generated_at_epoch_seconds,
        audit_json,
        audit_markdown,
        findings: audit.findings.len(),
        tranches: tranches.len(),
        adjudications,
    })
}

fn parse_risk(value: &str) -> DevResult<Vec<Severity>> {
    value
        .split(',')
        .filter(|part| !part.trim().is_empty())
        .map(|part| part.parse::<Severity>().map_err(|err| err.into()))
        .collect()
}

fn load_workspace_catalog() -> DevResult<WorkspaceCatalog> {
    let path = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("catalog/workspace.toml");
    let body = fs::read_to_string(path)?;
    Ok(toml::from_str(&body)?)
}

fn load_laws_catalog() -> DevResult<LawsCatalog> {
    let path = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("catalog/laws.toml");
    let body = fs::read_to_string(path)?;
    Ok(toml::from_str(&body)?)
}

fn load_archetypes_catalog() -> DevResult<ArchetypesCatalog> {
    let path = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("catalog/archetypes.toml");
    let body = fs::read_to_string(path)?;
    Ok(toml::from_str(&body)?)
}

fn load_contracts_catalog() -> DevResult<ContractsCatalog> {
    let manifest_root = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut catalog = ContractsCatalog::default();
    load_contracts_dir(
        &manifest_root.join("catalog/contracts"),
        &mut catalog,
        false,
    )?;
    load_contracts_dir(
        &manifest_root.join("catalog/local/contracts"),
        &mut catalog,
        true,
    )?;
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
        let contract: RepoContract = toml::from_str(&body)?;
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

fn load_adjudications_catalog() -> DevResult<AdjudicationsCatalog> {
    let path = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("catalog/adjudications.toml");
    if !path.is_file() {
        return Ok(AdjudicationsCatalog::default());
    }
    let body = fs::read_to_string(path)?;
    Ok(toml::from_str(&body)?)
}

fn validate_laws_catalog(catalog: &LawsCatalog) -> DevResult<()> {
    if catalog.schema_version != SCHEMA_VERSION {
        return Err(format!(
            "catalog/laws.toml schema_version {} does not match {SCHEMA_VERSION}",
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
        if matches!(law.maturity, LawMaturity::Retired) && V0_LAWS.contains(&law.id.as_str()) {
            return Err(format!("catalog/laws.toml retires active V0 law {}", law.id).into());
        }
        if !ids.insert(law.id.as_str()) {
            return Err(format!("catalog/laws.toml repeats law id {}", law.id).into());
        }
    }
    for law in V0_LAWS {
        if !ids.contains(law) {
            return Err(format!("catalog/laws.toml is missing V0 law {law}").into());
        }
    }
    Ok(())
}

fn validate_archetypes_catalog(catalog: &ArchetypesCatalog) -> DevResult<()> {
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

fn validate_contracts_catalog(
    contracts: &ContractsCatalog,
    archetypes: &ArchetypesCatalog,
) -> DevResult<()> {
    let archetypes_by_id = archetypes
        .archetypes
        .iter()
        .map(|archetype| (archetype.id.as_str(), archetype))
        .collect::<BTreeMap<_, _>>();
    for sourced in contracts.contracts.values() {
        let contract = &sourced.contract;
        let contract_name = sourced.path.file_stem().unwrap_or_default();
        if contract_name != contract.repo {
            return Err(format!(
                "contract {} is stored in {} but filename must match repo",
                contract.repo, sourced.path
            )
            .into());
        }
        if contract.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "contract {} schema_version {} does not match {SCHEMA_VERSION}",
                contract.repo, contract.schema_version
            )
            .into());
        }
        let Some(archetype) = archetypes_by_id.get(contract.archetype.as_str()) else {
            return Err(format!(
                "contract {} references unknown archetype {}",
                contract.repo, contract.archetype
            )
            .into());
        };
        validate_contract_commands(sourced, archetype)?;
        validate_contract_cloudflare(sourced, archetype)?;
        validate_contract_release(sourced, archetype)?;
        validate_contract_artifacts(sourced, archetype)?;
    }
    Ok(())
}

fn validate_contract_commands(
    sourced: &SourcedRepoContract,
    archetype: &ArchetypeDefinition,
) -> DevResult<()> {
    let contract = &sourced.contract;
    let commands = command_contract_texts(&contract.canonical_commands);
    if archetype.requires_canonical_commands && commands.is_empty() {
        return Err(format!("contract {} has no canonical commands", contract.repo).into());
    }
    let mut ids = BTreeSet::new();
    for command in &contract.canonical_commands {
        let text = command_contract_text(command);
        if text.trim().is_empty() {
            return Err(format!(
                "contract {} contains an empty canonical command",
                contract.repo
            )
            .into());
        }
        if let Some(id) = command_contract_id(command) {
            if id.trim().is_empty() {
                return Err(
                    format!("contract {} contains an empty command id", contract.repo).into(),
                );
            }
            if !ids.insert(id.to_string()) {
                return Err(format!("contract {} repeats command id {}", contract.repo, id).into());
            }
        }
    }
    Ok(())
}

fn validate_contract_cloudflare(
    sourced: &SourcedRepoContract,
    archetype: &ArchetypeDefinition,
) -> DevResult<()> {
    let contract = &sourced.contract;
    let posture = contract.cloudflare.posture.as_str();
    if archetype.requires_cloudflare_posture {
        if posture.trim().is_empty() || posture == "undeclared" {
            return Err(format!(
                "contract {} has undeclared Cloudflare posture",
                contract.repo
            )
            .into());
        }
        if !archetype
            .allowed_cloudflare_postures
            .iter()
            .any(|allowed| allowed == posture)
        {
            return Err(format!(
                "contract {} uses invalid Cloudflare posture {}",
                contract.repo, posture
            )
            .into());
        }
    } else if !posture.trim().is_empty()
        && !archetype
            .allowed_cloudflare_postures
            .iter()
            .any(|allowed| allowed == posture)
    {
        return Err(format!(
            "contract {} uses invalid Cloudflare posture {}",
            contract.repo, posture
        )
        .into());
    }

    let mut ids = BTreeSet::new();
    let mut surfaces = BTreeSet::new();
    for surface in &contract.cloudflare.surfaces {
        let key = cloudflare_surface_key(surface);
        if key.trim().is_empty() {
            return Err(format!(
                "contract {} contains an empty Cloudflare surface",
                contract.repo
            )
            .into());
        }
        if !surfaces.insert(key.to_string()) {
            return Err(format!(
                "contract {} repeats Cloudflare surface {}",
                contract.repo, key
            )
            .into());
        }
        if let Some(id) = cloudflare_surface_id(surface) {
            if id.trim().is_empty() {
                return Err(format!(
                    "contract {} contains an empty Cloudflare surface id",
                    contract.repo
                )
                .into());
            }
            if !ids.insert(id.to_string()) {
                return Err(format!(
                    "contract {} repeats Cloudflare surface id {}",
                    contract.repo, id
                )
                .into());
            }
        }
    }

    for exception in &contract.cloudflare.raw_exceptions {
        if exception.path.trim().is_empty()
            || exception.operation.trim().is_empty()
            || exception.reason.trim().is_empty()
        {
            return Err(format!(
                "contract {} contains an incomplete raw Cloudflare exception",
                contract.repo
            )
            .into());
        }
        if let Some(expires) = exception.expires.as_deref()
            && !is_iso_date(expires)
        {
            return Err(format!(
                "contract {} raw Cloudflare exception has invalid expires date {}",
                contract.repo, expires
            )
            .into());
        }
    }

    for value in contract
        .cloudflare
        .token_policy
        .parent_tokens
        .iter()
        .chain(contract.cloudflare.token_policy.parent_allowed_paths.iter())
        .chain(contract.cloudflare.token_policy.forbidden_sinks.iter())
    {
        if value.trim().is_empty() {
            return Err(format!(
                "contract {} contains an empty Cloudflare token policy value",
                contract.repo
            )
            .into());
        }
    }
    Ok(())
}

fn is_iso_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 10
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes
            .iter()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
}

fn validate_contract_release(
    sourced: &SourcedRepoContract,
    archetype: &ArchetypeDefinition,
) -> DevResult<()> {
    let contract = &sourced.contract;
    if archetype.requires_release_evidence && contract.release.evidence_dirs.is_empty() {
        return Err(format!(
            "contract {} has no release evidence directories",
            contract.repo
        )
        .into());
    }
    let mut ids = BTreeSet::new();
    for lane in &contract.release.lanes {
        if lane.id.trim().is_empty()
            || lane.command.trim().is_empty()
            || lane.preflight.trim().is_empty()
            || lane.post_verify.trim().is_empty()
            || lane.evidence.is_empty()
        {
            return Err(format!(
                "contract {} contains an incomplete release lane",
                contract.repo
            )
            .into());
        }
        if !ids.insert(lane.id.clone()) {
            return Err(format!(
                "contract {} repeats release lane {}",
                contract.repo, lane.id
            )
            .into());
        }
    }
    Ok(())
}

fn validate_contract_artifacts(
    sourced: &SourcedRepoContract,
    archetype: &ArchetypeDefinition,
) -> DevResult<()> {
    let contract = &sourced.contract;
    if archetype.requires_artifact_classification && contract.artifacts.classifications.is_empty() {
        return Err(format!("contract {} has no artifact classifications", contract.repo).into());
    }
    Ok(())
}

fn command_contract_text(command: &CommandContract) -> &str {
    match command {
        CommandContract::Text(command) => command,
        CommandContract::Detailed { command, .. } => command,
    }
}

fn command_contract_id(command: &CommandContract) -> Option<&str> {
    match command {
        CommandContract::Text(_) => None,
        CommandContract::Detailed { id, .. } => Some(id),
    }
}

fn command_contract_texts(commands: &[CommandContract]) -> Vec<String> {
    sorted_unique(
        commands
            .iter()
            .filter(|command| command_contract_required(command))
            .map(command_contract_text)
            .filter(|command| !command.trim().is_empty())
            .map(ToString::to_string),
    )
}

fn command_contract_required(command: &CommandContract) -> bool {
    match command {
        CommandContract::Text(_) => true,
        CommandContract::Detailed { required, .. } => *required,
    }
}

fn cloudflare_surface_key(surface: &CloudflareSurface) -> &str {
    match surface {
        CloudflareSurface::Path(path) => path,
        CloudflareSurface::Detailed {
            path,
            wrangler_config,
            ..
        } => wrangler_config
            .as_deref()
            .or(path.as_deref())
            .unwrap_or_default(),
    }
}

fn cloudflare_surface_id(surface: &CloudflareSurface) -> Option<&str> {
    match surface {
        CloudflareSurface::Path(_) => None,
        CloudflareSurface::Detailed { id, .. } => Some(id),
    }
}

fn cloudflare_surface_keys(surfaces: &[CloudflareSurface]) -> Vec<String> {
    sorted_unique(
        surfaces
            .iter()
            .filter(|surface| cloudflare_surface_required(surface))
            .map(cloudflare_surface_key)
            .filter(|surface| !surface.trim().is_empty())
            .map(ToString::to_string),
    )
}

fn cloudflare_surface_required(surface: &CloudflareSurface) -> bool {
    match surface {
        CloudflareSurface::Path(_) => true,
        CloudflareSurface::Detailed { required, .. } => *required,
    }
}

fn validate_findings_against_laws(findings: &[Finding], catalog: &LawsCatalog) -> DevResult<()> {
    let known: BTreeSet<&str> = catalog.laws.iter().map(|law| law.id.as_str()).collect();
    for finding in findings {
        if !known.contains(finding.law.as_str()) {
            return Err(format!(
                "finding {} uses uncataloged law {}",
                finding.id, finding.law
            )
            .into());
        }
    }
    Ok(())
}

fn validate_adjudications_catalog(catalog: &AdjudicationsCatalog) -> DevResult<()> {
    let mut fingerprints = BTreeSet::new();
    for entry in &catalog.adjudications {
        if entry.fingerprint.trim().is_empty() {
            return Err("catalog/adjudications.toml contains an empty fingerprint".into());
        }
        if entry.reason.trim().is_empty() {
            return Err(format!(
                "catalog/adjudications.toml entry {} has no reason",
                entry.fingerprint
            )
            .into());
        }
        if !fingerprints.insert(entry.fingerprint.as_str()) {
            return Err(format!(
                "catalog/adjudications.toml repeats fingerprint {}",
                entry.fingerprint
            )
            .into());
        }
    }
    Ok(())
}

fn apply_adjudications(findings: &mut [Finding], catalog: &AdjudicationsCatalog) {
    let entries: BTreeMap<&str, &AdjudicationEntry> = catalog
        .adjudications
        .iter()
        .map(|entry| (entry.fingerprint.as_str(), entry))
        .collect();
    for finding in findings {
        if let Some(entry) = entries.get(finding.fingerprint.as_str()) {
            finding.adjudication = Some(AppliedAdjudication {
                status: entry.status.clone(),
                reason: entry.reason.clone(),
                owner: entry.owner.clone(),
                expires: entry.expires.clone(),
            });
        }
    }
}

fn inventory(root: &Utf8Path, catalog: &WorkspaceCatalog) -> DevResult<Vec<RepoRecord>> {
    let mut repos = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let path = Utf8PathBuf::from_path_buf(entry.path())
            .map_err(|path| format!("non-utf8 path: {}", path.display()))?;
        if path.join(".git").is_dir() {
            repos.push(scan_repo(&path, catalog)?);
        }
    }
    repos.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(repos)
}

fn scan_repo(path: &Utf8Path, catalog: &WorkspaceCatalog) -> DevResult<RepoRecord> {
    let path = normalize_path(path);
    let name = path
        .file_name()
        .ok_or_else(|| format!("repo path has no final component: {path}"))?
        .to_string();
    let status = catalog
        .repo_status
        .get(&name)
        .cloned()
        .unwrap_or_else(|| infer_status(&path));
    let docs = scan_docs(&path);
    let command_surfaces = scan_command_surfaces(&path)?;
    let cloudflare = scan_cloudflare(&path)?;
    let release = scan_release(&path)?;
    let artifacts = scan_artifacts(&path);
    let languages = scan_languages(&path, &command_surfaces, &cloudflare);
    Ok(RepoRecord {
        name,
        path,
        status,
        git: GitInfo { present: true },
        docs,
        languages,
        command_surfaces,
        cloudflare,
        release,
        artifacts,
    })
}

fn infer_status(path: &Utf8Path) -> RepoStatus {
    if path.join("AGENTS.md").exists() || path.join("CLAUDE.md").exists() {
        RepoStatus::ActiveProduct
    } else {
        RepoStatus::Unknown
    }
}

fn scan_docs(path: &Utf8Path) -> DocsInfo {
    DocsInfo {
        north_star: exists_path(path, "NORTH_STAR.md"),
        anchor: exists_path(path, "ANCHOR.md"),
        agents: exists_path(path, "AGENTS.md"),
        claude: exists_path(path, "CLAUDE.md"),
        readme: exists_path(path, "README.md"),
        security: exists_path(path, "SECURITY.md"),
    }
}

fn scan_command_surfaces(path: &Utf8Path) -> DevResult<CommandSurfaces> {
    let mut check_scripts = Vec::new();
    let mut verify_scripts = Vec::new();
    for dir in ["scripts", "ops"] {
        let full = path.join(dir);
        if full.is_dir() {
            for entry in fs::read_dir(&full)? {
                let entry = entry?;
                if !entry.file_type()?.is_file() {
                    continue;
                }
                let candidate = Utf8PathBuf::from_path_buf(entry.path())
                    .map_err(|path| format!("non-utf8 path: {}", path.display()))?;
                let Some(name) = candidate.file_name() else {
                    continue;
                };
                if name.starts_with("check-") || name.starts_with("check_") {
                    check_scripts.push(candidate);
                } else if name.starts_with("verify-") || name.starts_with("verify_") {
                    verify_scripts.push(candidate);
                }
            }
        }
    }
    check_scripts.sort();
    verify_scripts.sort();
    Ok(CommandSurfaces {
        cargo_toml: path.join("Cargo.toml").is_file(),
        package_json: path.join("package.json").is_file(),
        makefile: path.join("Makefile").is_file(),
        scripts_dir: path.join("scripts").is_dir(),
        ops_dir: path.join("ops").is_dir(),
        check_scripts,
        verify_scripts,
    })
}

fn scan_cloudflare(path: &Utf8Path) -> DevResult<CloudflareInfo> {
    let declared_status = read_candidate_docs(path)?
        .into_iter()
        .flat_map(|doc| doc.lines)
        .find_map(|line| {
            [
                "cfctl-native",
                "cfctl-aware-wrapper",
                "legacy/raw-wrangler-exception",
            ]
            .iter()
            .find(|status| line.text.contains(**status))
            .map(|status| (*status).to_string())
        });
    let wrangler_configs = discover_wrangler_configs(path)?;
    Ok(CloudflareInfo {
        has_wrangler_config: !wrangler_configs.is_empty(),
        wrangler_configs,
        has_functions_dir: path.join("functions").is_dir(),
        has_workers_dir: path.join("workers").is_dir(),
        has_pages_dir: path.join("pages").is_dir(),
        declared_status,
    })
}

fn discover_wrangler_configs(path: &Utf8Path) -> DevResult<Vec<Utf8PathBuf>> {
    let mut configs = Vec::new();
    for entry in WalkBuilder::new(path)
        .standard_filters(true)
        .filter_entry(|entry| !is_ignored_cloudflare_discovery_path(entry.path()))
        .build()
    {
        let entry = entry?;
        if !entry
            .file_type()
            .is_some_and(|file_type| file_type.is_file())
        {
            continue;
        }
        let Some(name) = entry.path().file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if name != "wrangler.toml" && name != "wrangler.jsonc" {
            continue;
        }
        let config = Utf8PathBuf::from_path_buf(entry.path().to_path_buf())
            .map_err(|path| format!("non-utf8 wrangler path: {}", path.display()))?;
        configs.push(config);
    }
    configs.sort();
    Ok(configs)
}

fn is_ignored_cloudflare_discovery_path(path: &std::path::Path) -> bool {
    path.components().any(|component| {
        let value = component.as_os_str().to_string_lossy();
        matches!(
            value.as_ref(),
            ".git" | "node_modules" | "target" | ".deploy" | "fixtures"
        )
    })
}

fn scan_release(path: &Utf8Path) -> DevResult<ReleaseInfo> {
    let mut deploy_scripts = Vec::new();
    let mut release_scripts = Vec::new();
    for dir in ["scripts", "ops"] {
        let full = path.join(dir);
        if !full.is_dir() {
            continue;
        }
        for entry in fs::read_dir(full)? {
            let entry = entry?;
            if !entry.file_type()?.is_file() {
                continue;
            }
            let candidate = Utf8PathBuf::from_path_buf(entry.path())
                .map_err(|path| format!("non-utf8 path: {}", path.display()))?;
            let name = candidate.file_name().unwrap_or_default();
            if name.contains("deploy") {
                deploy_scripts.push(candidate.clone());
            }
            if name.contains("release") {
                release_scripts.push(candidate);
            }
        }
    }
    deploy_scripts.sort();
    release_scripts.sort();
    let mut evidence_dirs = Vec::new();
    for candidate in ["var/logs", "artifacts", "release", ".deploy"] {
        let full = path.join(candidate);
        if full.exists() {
            evidence_dirs.push(full);
        }
    }
    Ok(ReleaseInfo {
        deploy_scripts,
        release_scripts,
        evidence_dirs,
    })
}

fn scan_artifacts(path: &Utf8Path) -> ArtifactInfo {
    let mut present_top_level = Vec::new();
    for candidate in [
        "var",
        "artifacts",
        "dist",
        "build",
        ".deploy",
        "reports",
        "output",
    ] {
        let full = path.join(candidate);
        if full.exists() {
            present_top_level.push(full);
        }
    }
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_dir() {
                continue;
            }
            let Ok(candidate) = Utf8PathBuf::from_path_buf(entry.path()) else {
                continue;
            };
            if candidate
                .file_name()
                .is_some_and(|name| name.starts_with("target-"))
            {
                present_top_level.push(candidate);
            }
        }
    }
    present_top_level.sort();
    ArtifactInfo {
        present_top_level,
        has_policy: path.join("docs/ARTIFACTS-POLICY.md").is_file()
            || path.join(".repo-artifacts.toml").is_file(),
    }
}

fn scan_languages(
    path: &Utf8Path,
    command_surfaces: &CommandSurfaces,
    cloudflare: &CloudflareInfo,
) -> BTreeSet<String> {
    let mut languages = BTreeSet::new();
    if command_surfaces.cargo_toml {
        languages.insert("rust".to_string());
    }
    if command_surfaces.package_json {
        languages.insert("javascript".to_string());
    }
    if path.join("Package.swift").is_file() {
        languages.insert("swift".to_string());
    }
    if command_surfaces.scripts_dir || command_surfaces.ops_dir {
        languages.insert("shell".to_string());
    }
    if cloudflare.has_wrangler_config
        || cloudflare.has_functions_dir
        || cloudflare.has_workers_dir
        || cloudflare.has_pages_dir
    {
        languages.insert("cloudflare".to_string());
    }
    languages
}

fn audit_repos(
    repos: &[RepoRecord],
    contracts: Option<&ContractsCatalog>,
    archetypes: Option<&ArchetypesCatalog>,
) -> DevResult<Vec<Finding>> {
    let mut findings = Vec::new();
    for repo in repos {
        if let (Some(contracts), Some(archetypes)) = (contracts, archetypes) {
            audit_contract(
                repo,
                contracts.contracts.get(&repo.name),
                archetypes,
                &mut findings,
            );
        }
        audit_cloudflare(repo, &mut findings)?;
        audit_tokens(repo, &mut findings)?;
        audit_doctrine_quartet(repo, &mut findings)?;
        audit_command_verification(repo, &mut findings)?;
        audit_release(repo, &mut findings)?;
        audit_artifacts(repo, &mut findings)?;
    }
    if let Some(contracts) = contracts {
        enrich_findings_with_contract_context(&mut findings, contracts);
    }
    findings.sort_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then_with(|| left.repo.cmp(&right.repo))
            .then_with(|| left.law.cmp(&right.law))
            .then_with(|| left.file.cmp(&right.file))
            .then_with(|| left.line.cmp(&right.line))
    });
    assign_finding_ids(&mut findings);
    Ok(findings)
}

fn enrich_findings_with_contract_context(findings: &mut [Finding], contracts: &ContractsCatalog) {
    for finding in findings {
        let contract = contracts.contracts.get(&finding.repo);
        if finding.archetype.is_none() {
            finding.archetype = contract
                .map(|contract| contract.contract.archetype.clone())
                .or_else(|| Some("inferred".to_string()));
        }
        if finding.contract_source.is_none() {
            finding.contract_source = contract
                .map(|contract| contract.path.to_string())
                .or_else(|| Some("inferred".to_string()));
        }
        if finding.requirement_id.is_none() {
            finding.requirement_id = Some(scanner_requirement_id(finding).to_string());
        }
        if finding.expected.is_none() {
            finding.expected = Some(scanner_expected(finding).to_string());
        }
        if finding.observed.is_none() {
            finding.observed = Some(finding.evidence.clone());
        }
    }
}

fn scanner_requirement_id(finding: &Finding) -> &'static str {
    match finding.repair_group.as_str() {
        "cloudflare-governance" => "cloudflare-mutation-lane-classified",
        "cloudflare-token-law" => "cloudflare-parent-token-contained",
        "secret-file-permissions" => "secret-file-permissions-private",
        "doctrine-quartet" => "contract-quartet-present",
        "verification-contract" => "canonical-verification-command-present",
        "script-ownership" => "script-state-classified",
        "release-proof" => "release-lane-proof-bound",
        "artifact-boundaries" => "artifact-boundaries-classified",
        _ => "scanner-evidence-reviewed",
    }
}

fn scanner_expected(finding: &Finding) -> &'static str {
    match finding.repair_group.as_str() {
        "cloudflare-governance" => {
            "Cloudflare mutation lanes route through cfctl or a bounded exception"
        }
        "cloudflare-token-law" => {
            "Parent Cloudflare tokens remain in allowlisted control-plane or rotation contexts"
        }
        "secret-file-permissions" => "Secret-bearing env files are not group/world readable",
        "doctrine-quartet" => {
            "Every real repo carries the NORTH_STAR/ANCHOR/AGENTS/CLAUDE contract quartet"
        }
        "verification-contract" => "Active repos declare a canonical verification surface",
        "script-ownership" => {
            "Check/verify scripts have a gated/recovery/transitive/retired classification"
        }
        "release-proof" => "Release lanes declare preflight, post-verify, and evidence",
        "artifact-boundaries" => "Top-level artifact/runtime paths are classified",
        _ => "Scanner evidence has been reviewed against the repo contract",
    }
}

fn build_contract_proposal(
    repo: &RepoRecord,
    contract: Option<&SourcedRepoContract>,
) -> RepoContractProposal {
    let archetype = contract
        .map(|contract| contract.contract.archetype.clone())
        .unwrap_or_else(|| infer_archetype(repo));
    let canonical_commands = contract
        .map(|contract| command_contract_texts(&contract.contract.canonical_commands))
        .unwrap_or_else(|| infer_canonical_commands(repo));
    let cloudflare = contract
        .map(|contract| CloudflareContract {
            posture: contract.contract.cloudflare.posture.clone(),
            surfaces: cloudflare_surface_keys(&contract.contract.cloudflare.surfaces),
        })
        .unwrap_or_else(|| infer_cloudflare_contract(repo));
    let release_evidence_dirs = contract
        .map(|contract| contract.contract.release.evidence_dirs.clone())
        .unwrap_or_else(|| relative_paths(&repo.path, &repo.release.evidence_dirs));
    let artifact_classifications = contract
        .map(|contract| contract.contract.artifacts.classifications.clone())
        .unwrap_or_default();
    RepoContractProposal {
        schema_version: SCHEMA_VERSION,
        repo: repo.name.clone(),
        path: repo.path.clone(),
        status: repo.status.clone(),
        inferred: contract.is_none(),
        archetype,
        canonical_commands,
        scripts: infer_script_contracts(repo),
        cloudflare,
        release: ReleaseContract {
            deploy_scripts: relative_paths(&repo.path, &repo.release.deploy_scripts),
            release_scripts: relative_paths(&repo.path, &repo.release.release_scripts),
            evidence_dirs: release_evidence_dirs,
        },
        artifacts: ArtifactContract {
            present_top_level: relative_paths(&repo.path, &repo.artifacts.present_top_level),
            has_policy: repo.artifacts.has_policy,
            classifications: artifact_classifications,
        },
        exceptions: Vec::new(),
    }
}

fn build_catalog_contract_draft(proposal: &RepoContractProposal) -> RepoContract {
    RepoContract {
        schema_version: proposal.schema_version.to_string(),
        repo: proposal.repo.clone(),
        archetype: proposal.archetype.clone(),
        status: proposal.status.clone(),
        canonical_commands: proposal
            .canonical_commands
            .iter()
            .cloned()
            .map(CommandContract::Text)
            .collect(),
        cloudflare: ContractCloudflare {
            posture: proposal.cloudflare.posture.clone(),
            surfaces: proposal
                .cloudflare
                .surfaces
                .iter()
                .cloned()
                .map(CloudflareSurface::Path)
                .collect(),
            ..Default::default()
        },
        release: ContractRelease {
            evidence_dirs: proposal.release.evidence_dirs.clone(),
            ..Default::default()
        },
        artifacts: ContractArtifacts {
            classifications: proposal.artifacts.classifications.clone(),
        },
    }
}

fn audit_contract(
    repo: &RepoRecord,
    contract: Option<&SourcedRepoContract>,
    archetypes: &ArchetypesCatalog,
    findings: &mut Vec<Finding>,
) {
    let Some(contract) = contract else {
        if !matches!(
            repo.status,
            RepoStatus::Template | RepoStatus::Legacy | RepoStatus::Experiment
        ) {
            findings.push(Finding::contract_gap(
                repo,
                None,
                "active-repo-contract-present",
                Severity::P1,
                repo_anchor(repo),
                None,
                "Active repo has no devctl contract",
                "contract=missing",
                "Create an operator-owned contract under devctl/catalog/contracts/<repo>.toml.",
                "catalog/contracts/<repo>.toml exists",
                "no contract loaded",
            ));
        }
        return;
    };

    let source = &contract.contract;
    if source.status != repo.status {
        findings.push(Finding::contract_gap(
            repo,
            Some(contract),
            "repo-status-matches-contract",
            Severity::P1,
            Some(contract.path.clone()),
            contract_line(contract, "status"),
            "Repo status differs from contract status",
            &format!("contract={}, observed={}", source.status, repo.status),
            "Update catalog/workspace.toml or the repo contract so status has one source of truth.",
            &format!("status={}", source.status),
            &format!("status={}", repo.status),
        ));
    }

    let Some(archetype) = find_archetype(archetypes, &source.archetype) else {
        findings.push(Finding::contract_gap(
            repo,
            Some(contract),
            "contract-archetype-known",
            Severity::P1,
            Some(contract.path.clone()),
            contract_line(contract, "archetype"),
            "Repo contract references an unknown archetype",
            &format!("archetype={}", source.archetype),
            "Use an archetype declared in catalog/archetypes.toml.",
            "known archetype",
            &source.archetype,
        ));
        return;
    };

    if archetype.requires_canonical_commands
        && command_contract_texts(&source.canonical_commands).is_empty()
    {
        findings.push(Finding::contract_gap(
            repo,
            Some(contract),
            "canonical-commands-declared",
            Severity::P1,
            Some(contract.path.clone()),
            contract_line(contract, "canonical_commands"),
            "Contract has no canonical commands",
            "canonical_commands=[]",
            "Declare the repo's canonical verification/build/release commands in the contract.",
            "at least one canonical command",
            "none",
        ));
    }

    if archetype.requires_cloudflare_posture {
        let posture = source.cloudflare.posture.as_str();
        if posture.is_empty() || posture == "undeclared" {
            findings.push(Finding::contract_gap(
                repo,
                Some(contract),
                "cloudflare-posture-declared",
                Severity::P1,
                Some(contract.path.clone()),
                contract_line(contract, "posture"),
                "Cloudflare posture is undeclared",
                &format!("posture={posture}"),
                "Declare cfctl-native, cfctl-aware-wrapper, legacy/raw-wrangler-exception, or none as appropriate.",
                "declared Cloudflare posture",
                posture,
            ));
        } else if !archetype
            .allowed_cloudflare_postures
            .iter()
            .any(|allowed| allowed == posture)
        {
            findings.push(Finding::contract_gap(
                repo,
                Some(contract),
                "cloudflare-posture-allowed",
                Severity::P1,
                Some(contract.path.clone()),
                contract_line(contract, "posture"),
                "Cloudflare posture is not allowed by the archetype",
                &format!("posture={posture}"),
                "Use an allowed posture for this archetype or change the archetype.",
                &format!("one of {}", archetype.allowed_cloudflare_postures.join(",")),
                posture,
            ));
        }

        let observed_surfaces = infer_cloudflare_contract(repo).surfaces;
        let declared_surfaces = cloudflare_surface_keys(&source.cloudflare.surfaces);
        let missing_surfaces = observed_surfaces
            .iter()
            .filter(|surface| !declared_surfaces.contains(*surface))
            .cloned()
            .collect::<Vec<_>>();
        if !missing_surfaces.is_empty() {
            findings.push(Finding::contract_gap(
                repo,
                Some(contract),
                "cloudflare-surfaces-declared",
                Severity::P1,
                Some(contract.path.clone()),
                contract_line(contract, "cloudflare.surfaces"),
                "Observed Cloudflare surfaces are not declared by the contract",
                &format!("missing={}", missing_surfaces.join(",")),
                "Declare each observed Wrangler/functions/workers/pages surface in the repo contract or remove stale surface files.",
                "all observed Cloudflare surfaces declared",
                &format!("missing={}", missing_surfaces.join(",")),
            ));
        }
    }

    if archetype.requires_release_evidence && source.release.evidence_dirs.is_empty() {
        findings.push(Finding::contract_gap(
            repo,
            Some(contract),
            "release-evidence-declared",
            Severity::P1,
            Some(contract.path.clone()),
            contract_line(contract, "evidence_dirs"),
            "Contract has no release evidence directories",
            "release.evidence_dirs=[]",
            "Declare where release evidence is written.",
            "one or more release evidence dirs",
            "none",
        ));
    }

    if archetype.requires_artifact_classification {
        let present = relative_paths(&repo.path, &repo.artifacts.present_top_level);
        let missing = present
            .iter()
            .filter(|path| !source.artifacts.classifications.contains_key(*path))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            findings.push(Finding::contract_gap(
                repo,
                Some(contract),
                "artifact-paths-classified",
                Severity::P2,
                Some(contract.path.clone()),
                contract_line(contract, "classifications"),
                "Observed artifact paths are not classified by the contract",
                &format!("missing={}", missing.join(",")),
                "Classify each observed top-level artifact/runtime path in the repo contract.",
                "all observed artifact paths classified",
                &format!("missing={}", missing.join(",")),
            ));
        }
    }
}

fn derive_next_actions(
    contracts: &[RepoContractProposal],
    adjudications: &[AdjudicationEntry],
    tranches: &[RepairTranche],
) -> Vec<String> {
    let mut actions = Vec::new();
    if !adjudications.is_empty() {
        actions.push(format!(
            "Adjudicate {} unreviewed risk findings before treating any warning count as strategy.",
            adjudications.len()
        ));
    }
    let undeclared_cloudflare = contracts
        .iter()
        .filter(|contract| contract.cloudflare.posture == "undeclared")
        .map(|contract| contract.repo.clone())
        .collect::<Vec<_>>();
    if !undeclared_cloudflare.is_empty() {
        actions.push(format!(
            "Declare Cloudflare posture for repos: {}.",
            undeclared_cloudflare.join(",")
        ));
    }
    let missing_artifact_policy = contracts
        .iter()
        .filter(|contract| {
            !contract.artifacts.present_top_level.is_empty() && !contract.artifacts.has_policy
        })
        .map(|contract| contract.repo.clone())
        .collect::<Vec<_>>();
    if !missing_artifact_policy.is_empty() {
        actions.push(format!(
            "Classify artifact boundaries for repos: {}.",
            missing_artifact_policy.join(",")
        ));
    }
    for tranche in tranches {
        actions.push(format!(
            "Open a targeted repair PR for '{}': repos={}, findings={}.",
            tranche.title,
            tranche.repos.join(","),
            tranche.findings.len()
        ));
    }
    if actions.is_empty() {
        actions.push("No pilot operating actions remain for the selected risk scope.".to_string());
    }
    actions
}

fn infer_canonical_commands(repo: &RepoRecord) -> Vec<String> {
    let mut commands = Vec::new();
    if repo.path.join("ops/verify.sh").is_file() {
        commands.push("./ops/verify.sh".to_string());
    }
    if repo.command_surfaces.makefile {
        commands.push("make check".to_string());
    }
    if repo.command_surfaces.cargo_toml {
        commands.push("cargo check --workspace".to_string());
        commands.push("cargo test --workspace".to_string());
    }
    if repo.command_surfaces.package_json {
        commands.push("npm test".to_string());
    }
    if commands.is_empty() {
        commands.push("TODO: declare canonical verification command".to_string());
    }
    sorted_unique(commands.into_iter())
}

fn infer_archetype(repo: &RepoRecord) -> String {
    if repo_has_cloudflare(repo) {
        "cloudflare-product".to_string()
    } else if repo.command_surfaces.cargo_toml && repo.command_surfaces.package_json {
        "rust-web-product".to_string()
    } else if repo.command_surfaces.cargo_toml {
        "rust-workspace".to_string()
    } else {
        "generic-active-repo".to_string()
    }
}

fn find_archetype<'a>(catalog: &'a ArchetypesCatalog, id: &str) -> Option<&'a ArchetypeDefinition> {
    catalog
        .archetypes
        .iter()
        .find(|archetype| archetype.id == id)
}

fn toml_line_map(body: &str) -> BTreeMap<String, usize> {
    let mut lines = BTreeMap::new();
    let mut section = String::new();
    for (index, raw) in body.lines().enumerate() {
        let line = raw.trim();
        if line.starts_with("[[") && line.ends_with("]]") {
            section = line.trim_matches(['[', ']']).to_string();
            lines.entry(section.clone()).or_insert(index + 1);
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line.trim_matches(['[', ']']).to_string();
            lines.entry(section.clone()).or_insert(index + 1);
            continue;
        }
        let Some((key, _)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        lines.entry(key.to_string()).or_insert(index + 1);
        if !section.is_empty() {
            lines.entry(format!("{section}.{key}")).or_insert(index + 1);
        }
    }
    lines
}

fn contract_line(contract: &SourcedRepoContract, field: &str) -> Option<usize> {
    contract
        .lines
        .get(field)
        .or_else(|| {
            contract
                .lines
                .get(field.rsplit_once('.').map_or(field, |(_, key)| key))
        })
        .copied()
        .or(Some(1))
}

fn infer_script_contracts(repo: &RepoRecord) -> Vec<ScriptContract> {
    repo.command_surfaces
        .check_scripts
        .iter()
        .chain(repo.command_surfaces.verify_scripts.iter())
        .map(|path| ScriptContract {
            path: relative_display(&repo.path, path),
            classification: "unclassified".to_string(),
        })
        .collect()
}

fn infer_cloudflare_contract(repo: &RepoRecord) -> CloudflareContract {
    let mut surfaces = relative_paths(&repo.path, &repo.cloudflare.wrangler_configs);
    if repo.cloudflare.has_functions_dir {
        surfaces.push("functions".to_string());
    }
    if repo.cloudflare.has_workers_dir {
        surfaces.push("workers".to_string());
    }
    if repo.cloudflare.has_pages_dir {
        surfaces.push("pages".to_string());
    }
    let posture = repo.cloudflare.declared_status.clone().unwrap_or_else(|| {
        if surfaces.is_empty() {
            "none".to_string()
        } else {
            "undeclared".to_string()
        }
    });
    CloudflareContract { posture, surfaces }
}

fn audit_cloudflare(repo: &RepoRecord, findings: &mut Vec<Finding>) -> DevResult<()> {
    if !repo_has_cloudflare(repo) {
        return Ok(());
    }
    if repo.cloudflare.declared_status.is_none() {
        findings.push(Finding::new(
            "cloudflare-mutation",
            Severity::P1,
            repo,
            repo_anchor(repo),
            None,
            "Cloudflare-owning repo has no declared Cloudflare governance status",
            "repo contains Wrangler config, functions, workers, or pages but no cfctl-native/cfctl-aware-wrapper/legacy exception declaration",
            "Declare cfctl-native, cfctl-aware-wrapper, or legacy/raw-wrangler-exception in AGENTS.md or CLAUDE.md.",
            Confidence::High,
            "cloudflare-governance",
        ));
    }
    let raw_patterns = Regex::new(
        r"\b(npx\s+wrangler|bunx\s+wrangler|wrangler\s+(deploy|pages\s+deploy|d1\s+migrations\s+apply|secret\s+put)|curl\s+.*api\.cloudflare\.com)",
    )?;
    for doc in read_policy_text_files(&repo.path)? {
        for line in doc.lines {
            if raw_patterns.is_match(&line.text) && !line.text.contains("cfctl") {
                findings.push(Finding::new(
                    "cloudflare-mutation",
                    Severity::P1,
                    repo,
                    Some(doc.path.clone()),
                    Some(line.number),
                    "Raw Cloudflare mutation path appears outside an explicit cfctl context",
                    &redact_line(&line.text),
                    "Route live/account mutations through cfctl or mark this path as a legacy/raw-wrangler-exception with a reason.",
                    Confidence::Medium,
                    "cloudflare-governance",
                ));
            }
        }
    }
    Ok(())
}

fn audit_tokens(repo: &RepoRecord, findings: &mut Vec<Finding>) -> DevResult<()> {
    let assignment = Regex::new(r"CLOUDFLARE_API_TOKEN\s*=\s*.*CF_(DEV|GLOBAL)_TOKEN")?;
    for doc in read_policy_text_files(&repo.path)? {
        for line in doc.lines {
            if assignment.is_match(&line.text) {
                findings.push(Finding::new(
                    "token",
                    Severity::P0,
                    repo,
                    Some(doc.path.clone()),
                    Some(line.number),
                    "Parent Cloudflare token appears to be assigned into CLOUDFLARE_API_TOKEN",
                    &redact_line(&line.text),
                    "Use a scoped child token or an allowlisted control-plane minting path instead of parent token propagation.",
                    Confidence::High,
                    "cloudflare-token-law",
                ));
            } else if line.text.contains("CF_DEV_TOKEN") || line.text.contains("CF_GLOBAL_TOKEN") {
                let allowlisted = doc.path.starts_with(repo.path.join("AGENTS.md"))
                    || doc.path.starts_with(repo.path.join("CLAUDE.md"))
                    || doc.path.starts_with(repo.path.join("README.md"))
                    || doc.path.to_string().contains("rotate")
                    || doc.path.to_string().contains("guard")
                    || repo.name == "cloudflare";
                if !allowlisted {
                    findings.push(Finding::new(
                        "token",
                        Severity::P1,
                        repo,
                        Some(doc.path.clone()),
                        Some(line.number),
                        "Parent Cloudflare token appears outside an allowlisted documentation or rotation context",
                        &redact_line(&line.text),
                        "Move parent-token access behind an allowlisted control-plane or rotation script, or document the exception.",
                        Confidence::Medium,
                        "cloudflare-token-law",
                    ));
                }
            }
        }
    }
    for env_name in [".env", ".dev.vars"] {
        let env_path = repo.path.join(env_name);
        if env_path.is_file() {
            let mode = fs::metadata(&env_path)?.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                findings.push(Finding::new(
                    "token",
                    Severity::P0,
                    repo,
                    Some(env_path),
                    None,
                    "Repo-local env file is readable by group or world",
                    &format!("{env_name} mode {:o}", mode),
                    "Restrict secret-bearing env files to mode 600 or move secrets to the declared control-plane path.",
                    Confidence::High,
                    "secret-file-permissions",
                ));
            }
        }
    }
    Ok(())
}

fn audit_doctrine_quartet(repo: &RepoRecord, findings: &mut Vec<Finding>) -> DevResult<()> {
    if matches!(repo.status, RepoStatus::Template | RepoStatus::Unknown) {
        return Ok(());
    }
    let quartet: [(&str, &Option<Utf8PathBuf>); 4] = [
        ("NORTH_STAR.md", &repo.docs.north_star),
        ("ANCHOR.md", &repo.docs.anchor),
        ("AGENTS.md", &repo.docs.agents),
        ("CLAUDE.md", &repo.docs.claude),
    ];
    for (name, present) in quartet {
        if present.is_some() {
            continue;
        }
        let message = format!("Repo is missing contract quartet file {name}");
        let evidence = format!(
            "{name} not found at repo root; workspace doctrine expects the full \
             NORTH_STAR/ANCHOR/AGENTS/CLAUDE quartet"
        );
        let recommendation = format!(
            "Author {name} from live repo truth so workspace standards sprinkle down \
             and stay enforceable."
        );
        findings.push(Finding::new(
            "doctrine-quartet",
            Severity::P2,
            repo,
            repo_anchor(repo),
            None,
            &message,
            &evidence,
            &recommendation,
            Confidence::High,
            "doctrine-quartet",
        ));
    }
    Ok(())
}

fn audit_command_verification(repo: &RepoRecord, findings: &mut Vec<Finding>) -> DevResult<()> {
    if matches!(
        repo.status,
        RepoStatus::Template | RepoStatus::Legacy | RepoStatus::Experiment
    ) {
        return Ok(());
    }
    let has_verify_surface = repo.command_surfaces.makefile
        || !repo.command_surfaces.check_scripts.is_empty()
        || !repo.command_surfaces.verify_scripts.is_empty()
        || repo.path.join("ops/verify.sh").is_file();
    if !has_verify_surface {
        findings.push(Finding::new(
            "command-verification",
            Severity::P1,
            repo,
            repo_anchor(repo),
            None,
            "Active repo has no obvious canonical verification surface",
            "no Makefile, check-* scripts, verify-* scripts, or ops/verify.sh found",
            "Declare and implement a canonical check or verify command in the repo command surface.",
            Confidence::High,
            "verification-contract",
        ));
    }
    if (!repo.command_surfaces.check_scripts.is_empty()
        || !repo.command_surfaces.verify_scripts.is_empty())
        && !repo.path.join("docs/SCRIPT-OWNERSHIP.md").is_file()
    {
        findings.push(Finding::new(
            "command-verification",
            Severity::P2,
            repo,
            repo_anchor(repo),
            None,
            "Repo has check/verify scripts without a script ownership ledger",
            "check-* and verify-* scripts exist but docs/SCRIPT-OWNERSHIP.md is absent",
            "Classify check/verify scripts as gated, operator-recovery, transitive, or retired.",
            Confidence::Medium,
            "script-ownership",
        ));
    }
    Ok(())
}

fn audit_release(repo: &RepoRecord, findings: &mut Vec<Finding>) -> DevResult<()> {
    let mut release_paths = repo.release.deploy_scripts.clone();
    release_paths.extend(repo.release.release_scripts.clone());
    if release_paths.is_empty() {
        return Ok(());
    }
    for path in release_paths {
        let lines = read_lines(&path).unwrap_or_default();
        let body = lines
            .iter()
            .map(|line| line.text.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let has_preflight = body.contains("preflight")
            || body.contains("verify.sh")
            || body.contains("release_check")
            || body.contains("cargo check")
            || body.contains("cargo test");
        let has_post_verify = body.contains("post-deploy")
            || body.contains("verify-prod")
            || body.contains("verify_")
            || body.contains("verify-")
            || body.contains("live");
        if !has_preflight || !has_post_verify {
            findings.push(Finding::new(
                "release-proof",
                Severity::P1,
                repo,
                Some(path.clone()),
                None,
                "Release/deploy script does not clearly show both preflight and post-deploy verification",
                &format!(
                    "preflight={}, post_deploy_verify={}",
                    has_preflight, has_post_verify
                ),
                "Declare the release contract and wire preflight plus post-deploy verification into the release/deploy lane.",
                Confidence::Medium,
                "release-proof",
            ));
        }
    }
    if repo.release.evidence_dirs.is_empty() {
        findings.push(Finding::new(
            "release-proof",
            Severity::P2,
            repo,
            repo_anchor(repo),
            None,
            "Repo has release/deploy scripts but no obvious evidence directory",
            "no top-level var/logs, artifacts, release, or .deploy path found",
            "Declare where release evidence lands, even if the directory is gitignored until runtime.",
            Confidence::Medium,
            "release-proof",
        ));
    }
    Ok(())
}

fn audit_artifacts(repo: &RepoRecord, findings: &mut Vec<Finding>) -> DevResult<()> {
    if repo.artifacts.present_top_level.is_empty() || repo.artifacts.has_policy {
        return Ok(());
    }
    findings.push(Finding::new(
        "artifact-boundary",
        Severity::P2,
        repo,
        repo_anchor(repo),
        None,
        "Repo has top-level runtime/build/evidence artifact paths without an artifact policy",
        &format!(
            "paths={}",
            repo.artifacts
                .present_top_level
                .iter()
                .map(|path| relative_display(&repo.path, path))
                .collect::<Vec<_>>()
                .join(",")
        ),
        "Add docs/ARTIFACTS-POLICY.md or .repo-artifacts.toml to classify runtime, build, release, fixture, scratch, and archive paths.",
        Confidence::Medium,
        "artifact-boundaries",
    ));
    Ok(())
}

fn repo_anchor(repo: &RepoRecord) -> Option<Utf8PathBuf> {
    repo.docs
        .agents
        .clone()
        .or_else(|| repo.docs.claude.clone())
        .or_else(|| repo.docs.readme.clone())
}

fn build_tranches(findings: &[Finding]) -> Vec<RepairTranche> {
    let mut groups: BTreeMap<String, Vec<&Finding>> = BTreeMap::new();
    for finding in findings {
        groups
            .entry(tranche_group_key(finding))
            .or_default()
            .push(finding);
    }
    groups
        .into_iter()
        .map(|(group, items)| {
            let severity = items
                .iter()
                .map(|finding| finding.severity)
                .min()
                .unwrap_or(Severity::P3);
            let repos = sorted_unique(items.iter().map(|finding| finding.repo.clone()));
            let finding_ids = items.iter().map(|finding| finding.id.clone()).collect();
            let repair_group = items
                .first()
                .map(|finding| finding.repair_group.as_str())
                .unwrap_or(group.as_str());
            let (title, recommended_actions, proof_required) = tranche_guidance(repair_group);
            RepairTranche {
                id: group,
                title,
                severity,
                repos,
                findings: finding_ids,
                recommended_actions,
                proof_required,
            }
        })
        .collect()
}

fn tranche_group_key(finding: &Finding) -> String {
    let requirement = finding
        .requirement_id
        .as_deref()
        .unwrap_or(finding.repair_group.as_str());
    format!("{}:{}:{requirement}", finding.repo, finding.law)
}

fn tranche_guidance(group: &str) -> (String, Vec<String>, Vec<String>) {
    match group {
        "cloudflare-token-law" | "secret-file-permissions" => (
            "Normalize Cloudflare credential law".to_string(),
            vec![
                "Remove parent-token propagation into deploy credentials.".to_string(),
                "Restrict secret-bearing env files or move secrets to the declared control-plane path."
                    .to_string(),
            ],
            vec![
                "Audit output shows no P0 token findings.".to_string(),
                "No secret values appear in devctl JSON or human reports.".to_string(),
            ],
        ),
        "cloudflare-governance" => (
            "Classify Cloudflare mutation lanes".to_string(),
            vec![
                "Declare cfctl-native, cfctl-aware-wrapper, or legacy/raw-wrangler-exception per Cloudflare repo."
                    .to_string(),
                "Route live/account mutations through cfctl or document the legacy exception."
                    .to_string(),
            ],
            vec!["devctl standards audit reports no P1 Cloudflare governance findings for the pilot repos.".to_string()],
        ),
        "verification-contract" | "script-ownership" => (
            "Declare verification command ownership".to_string(),
            vec![
                "Name the canonical check/verify command for each active repo.".to_string(),
                "Classify check/verify scripts as gated, recovery, transitive, or retired."
                    .to_string(),
            ],
            vec!["Each active repo has a discoverable verification surface.".to_string()],
        ),
        "release-proof" => (
            "Bind release lanes to proof".to_string(),
            vec![
                "Add or document preflight and post-deploy verification for release/deploy scripts."
                    .to_string(),
                "Declare the release evidence directory.".to_string(),
            ],
            vec!["Release/deploy scripts have named preflight, mutation, verification, and evidence lanes.".to_string()],
        ),
        "artifact-boundaries" => (
            "Classify artifact boundaries".to_string(),
            vec![
                "Add an artifact policy or manifest for top-level runtime/build/evidence paths."
                    .to_string(),
                "Mark generated or runtime-only paths ignored unless they are deliberate release evidence."
                    .to_string(),
            ],
            vec!["devctl reports no unclassified top-level artifact paths for pilot repos.".to_string()],
        ),
        _ => (
            format!("Repair {group}"),
            vec!["Review grouped findings and make the smallest repo-local correction.".to_string()],
            vec!["Re-run devctl standards audit and verify the group is closed.".to_string()],
        ),
    }
}

fn assign_finding_ids(findings: &mut [Finding]) {
    for (index, finding) in findings.iter_mut().enumerate() {
        finding.id = format!("F{:04}", index + 1);
    }
}

impl Finding {
    #[allow(clippy::too_many_arguments)]
    fn new(
        law: &str,
        severity: Severity,
        repo: &RepoRecord,
        file: Option<Utf8PathBuf>,
        line: Option<usize>,
        message: &str,
        evidence: &str,
        recommendation: &str,
        confidence: Confidence,
        repair_group: &str,
    ) -> Self {
        let normalized_line = if file.is_some() {
            line.or(Some(1))
        } else {
            None
        };
        let file_key = file
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<repo>".to_string());
        let line_key = normalized_line
            .map(|line| line.to_string())
            .unwrap_or_else(|| "0".to_string());
        let fingerprint =
            finding_fingerprint(&[law, &repo.name, &file_key, &line_key, message, repair_group]);
        Self {
            id: String::new(),
            fingerprint,
            archetype: None,
            contract_source: None,
            requirement_id: None,
            law: law.to_string(),
            severity,
            repo: repo.name.clone(),
            file,
            line: normalized_line,
            message: message.to_string(),
            evidence: evidence.to_string(),
            expected: None,
            observed: None,
            recommendation: recommendation.to_string(),
            confidence,
            repair_group: repair_group.to_string(),
            adjudication: None,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn contract_gap(
        repo: &RepoRecord,
        contract: Option<&SourcedRepoContract>,
        requirement_id: &str,
        severity: Severity,
        file: Option<Utf8PathBuf>,
        line: Option<usize>,
        message: &str,
        evidence: &str,
        recommendation: &str,
        expected: &str,
        observed: &str,
    ) -> Self {
        let normalized_line = if file.is_some() {
            line.or(Some(1))
        } else {
            None
        };
        let file_key = file
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<repo>".to_string());
        let line_key = normalized_line
            .map(|line| line.to_string())
            .unwrap_or_else(|| "0".to_string());
        let archetype = contract
            .map(|contract| contract.contract.archetype.clone())
            .unwrap_or_else(|| infer_archetype(repo));
        let contract_source = contract
            .map(|contract| contract.path.to_string())
            .unwrap_or_else(|| "missing".to_string());
        let fingerprint = finding_fingerprint(&[
            CONTRACT_LAW,
            &repo.name,
            requirement_id,
            &file_key,
            &line_key,
        ]);
        Self {
            id: String::new(),
            fingerprint,
            archetype: Some(archetype),
            contract_source: Some(contract_source),
            requirement_id: Some(requirement_id.to_string()),
            law: CONTRACT_LAW.to_string(),
            severity,
            repo: repo.name.clone(),
            file,
            line: normalized_line,
            message: message.to_string(),
            evidence: evidence.to_string(),
            expected: Some(expected.to_string()),
            observed: Some(observed.to_string()),
            recommendation: recommendation.to_string(),
            confidence: Confidence::High,
            repair_group: format!("contract:{requirement_id}"),
            adjudication: None,
        }
    }
}

fn finding_fingerprint(parts: &[&str]) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for part in parts {
        for byte in part.as_bytes().iter().chain([0].iter()) {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    format!("{hash:016x}")
}

#[derive(Debug)]
struct TextFile {
    path: Utf8PathBuf,
    lines: Vec<Line>,
}

#[derive(Debug)]
struct Line {
    number: usize,
    text: String,
}

fn read_candidate_docs(path: &Utf8Path) -> DevResult<Vec<TextFile>> {
    let mut files = Vec::new();
    for name in ["AGENTS.md", "CLAUDE.md", "README.md", "SECURITY.md"] {
        let candidate = path.join(name);
        if candidate.is_file() {
            files.push(TextFile {
                path: candidate.clone(),
                lines: read_lines(&candidate)?,
            });
        }
    }
    Ok(files)
}

fn read_policy_text_files(path: &Utf8Path) -> DevResult<Vec<TextFile>> {
    let mut files = read_candidate_docs(path)?;
    for name in [
        "package.json",
        "Makefile",
        "wrangler.toml",
        "wrangler.jsonc",
    ] {
        let candidate = path.join(name);
        if candidate.is_file() {
            files.push(TextFile {
                path: candidate.clone(),
                lines: read_lines(&candidate)?,
            });
        }
    }
    for dir in ["scripts", "ops", "docs"] {
        let full = path.join(dir);
        if !full.is_dir() {
            continue;
        }
        collect_text_files(&full, &mut files)?;
    }
    Ok(files)
}

fn collect_text_files(root: &Utf8Path, files: &mut Vec<TextFile>) -> DevResult<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let candidate = Utf8PathBuf::from_path_buf(entry.path())
            .map_err(|path| format!("non-utf8 path: {}", path.display()))?;
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            let name = candidate.file_name().unwrap_or_default();
            if matches!(name, "target" | "node_modules" | ".git" | "var") {
                continue;
            }
            collect_text_files(&candidate, files)?;
        } else if file_type.is_file() && is_text_candidate(&candidate) {
            files.push(TextFile {
                path: candidate.clone(),
                lines: read_lines(&candidate)?,
            });
        }
    }
    Ok(())
}

fn is_text_candidate(path: &Utf8Path) -> bool {
    match path.extension().unwrap_or_default() {
        "md" | "sh" | "toml" | "json" | "jsonc" | "yml" | "yaml" | "txt" | "ts" | "js" | "rs"
        | "py" => true,
        _ => path.file_name().is_some_and(|name| {
            name == "Makefile" || name.starts_with("check-") || name.starts_with("verify-")
        }),
    }
}

fn read_lines(path: &Utf8Path) -> DevResult<Vec<Line>> {
    let body = fs::read_to_string(path)?;
    Ok(body
        .lines()
        .enumerate()
        .map(|(index, text)| Line {
            number: index + 1,
            text: text.to_string(),
        })
        .collect())
}

fn repo_has_cloudflare(repo: &RepoRecord) -> bool {
    repo.cloudflare.has_wrangler_config
        || repo.cloudflare.has_functions_dir
        || repo.cloudflare.has_workers_dir
        || repo.cloudflare.has_pages_dir
}

fn exists_path(root: &Utf8Path, relative: &str) -> Option<Utf8PathBuf> {
    let path = root.join(relative);
    path.exists().then_some(path)
}

fn normalize_path(path: &Utf8Path) -> Utf8PathBuf {
    path.canonicalize_utf8()
        .unwrap_or_else(|_| path.to_path_buf())
}

fn relative_display(root: &Utf8Path, path: &Utf8Path) -> String {
    path.strip_prefix(root)
        .map(|stripped| stripped.to_string())
        .unwrap_or_else(|_| path.to_string())
}

fn relative_paths(root: &Utf8Path, paths: &[Utf8PathBuf]) -> Vec<String> {
    paths
        .iter()
        .map(|path| relative_display(root, path))
        .collect()
}

fn sorted_unique(values: impl Iterator<Item = String>) -> Vec<String> {
    values.collect::<BTreeSet<_>>().into_iter().collect()
}

fn finding_is_actionable(finding: &Finding) -> bool {
    !matches!(
        finding.adjudication.as_ref().map(|entry| &entry.status),
        Some(AdjudicationStatus::AcceptedException)
            | Some(AdjudicationStatus::FalsePositive)
            | Some(AdjudicationStatus::LawNeedsWork)
    )
}

fn summarize_adjudications(findings: &[Finding]) -> BTreeMap<String, usize> {
    let mut summary = BTreeMap::new();
    for finding in findings {
        let key = finding
            .adjudication
            .as_ref()
            .map(|entry| entry.status.to_string())
            .unwrap_or_else(|| "unreviewed".to_string());
        *summary.entry(key).or_insert(0) += 1;
    }
    summary
}

fn resolve_report_root(out: Option<&Utf8PathBuf>) -> DevResult<Utf8PathBuf> {
    let root = out
        .cloned()
        .unwrap_or_else(|| Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("reports"));
    if root.is_absolute() {
        Ok(root)
    } else {
        let joined = std::env::current_dir()?.join(root);
        Utf8PathBuf::from_path_buf(joined)
            .map_err(|path| format!("non-utf8 report path: {}", path.display()).into())
    }
}

fn unix_timestamp() -> DevResult<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn render_markdown_report(
    generated_at_epoch_seconds: u64,
    audit: &AuditOutput,
    tranches: &[RepairTranche],
    adjudications: &BTreeMap<String, usize>,
) -> String {
    let mut body = String::new();
    body.push_str("# devctl standards report\n\n");
    body.push_str(&format!("- schema_version: `{SCHEMA_VERSION}`\n"));
    body.push_str(&format!("- tool_version: `{TOOL_VERSION}`\n"));
    body.push_str(&format!(
        "- generated_at_epoch_seconds: `{generated_at_epoch_seconds}`\n"
    ));
    body.push_str(&format!("- root: `{}`\n", audit.root));
    body.push_str(&format!("- scope: `{}`\n", audit.scope));
    body.push_str(&format!("- repos: `{}`\n", audit.repos.len()));
    body.push_str(&format!("- findings: `{}`\n", audit.findings.len()));
    body.push_str(&format!("- tranches: `{}`\n\n", tranches.len()));

    body.push_str("## Adjudications\n\n");
    for (status, count) in adjudications {
        body.push_str(&format!("- `{status}`: `{count}`\n"));
    }

    body.push_str("\n## Repair Tranches\n\n");
    if tranches.is_empty() {
        body.push_str("No actionable repair tranches.\n");
    } else {
        for tranche in tranches {
            body.push_str(&format!(
                "- **{}** `{}` repos=`{}` findings=`{}`\n",
                tranche.title,
                tranche.severity,
                tranche.repos.join(","),
                tranche.findings.join(",")
            ));
        }
    }

    body.push_str("\n## Findings\n\n");
    for finding in &audit.findings {
        let location = finding
            .file
            .as_ref()
            .map(|file| match finding.line {
                Some(line) => format!("{file}:{line}"),
                None => file.to_string(),
            })
            .unwrap_or_else(|| "<repo>".to_string());
        let adjudication = finding
            .adjudication
            .as_ref()
            .map(|entry| entry.status.to_string())
            .unwrap_or_else(|| "unreviewed".to_string());
        body.push_str(&format!(
            "- `{}` `{}` `{}` `{}` `{}` `{}` - {}\n",
            finding.severity,
            finding.id,
            finding.fingerprint,
            finding.repo,
            finding.law,
            adjudication,
            finding.message
        ));
        body.push_str(&format!("  - location: `{location}`\n"));
    }
    body
}

fn render_operating_packet_markdown(document: &OperatingPacketDocument<'_>) -> String {
    let mut body = String::new();
    body.push_str("# devctl pilot operating packet\n\n");
    body.push_str(&format!(
        "- schema_version: `{}`\n",
        document.schema_version
    ));
    body.push_str(&format!("- tool_version: `{}`\n", document.tool_version));
    body.push_str(&format!(
        "- generated_at_epoch_seconds: `{}`\n",
        document.generated_at_epoch_seconds
    ));
    body.push_str(&format!("- root: `{}`\n", document.audit.root));
    body.push_str(&format!("- scope: `{}`\n", document.audit.scope));
    body.push_str(&format!("- principle: `{}`\n", document.principle));
    body.push_str(&format!("- repos: `{}`\n", document.audit.repos.len()));
    body.push_str(&format!(
        "- findings: `{}`\n",
        document.audit.findings.len()
    ));
    body.push_str(&format!(
        "- adjudication_stubs: `{}`\n",
        document.adjudication_template.len()
    ));
    body.push_str(&format!("- tranches: `{}`\n\n", document.tranches.len()));

    body.push_str("## Next Actions\n\n");
    for action in document.next_actions {
        body.push_str(&format!("- {action}\n"));
    }

    body.push_str("\n## Repo Contracts\n\n");
    for contract in document.contracts {
        body.push_str(&format!(
            "- `{}` status=`{}` cloudflare=`{}` commands=`{}` artifacts=`{}`\n",
            contract.repo,
            contract.status,
            contract.cloudflare.posture,
            contract.canonical_commands.join(" | "),
            contract.artifacts.present_top_level.join(",")
        ));
    }

    body.push_str("\n## Repair Tranches\n\n");
    for tranche in document.tranches {
        body.push_str(&format!(
            "- `{}` `{}` repos=`{}` findings=`{}`\n",
            tranche.severity,
            tranche.title,
            tranche.repos.join(","),
            tranche.findings.join(",")
        ));
    }

    body.push_str("\n## Adjudication Template\n\n");
    for entry in document.adjudication_template {
        body.push_str(&format!(
            "- `{}` status=`{}` reason=`{}`\n",
            entry.fingerprint, entry.status, entry.reason
        ));
    }
    body
}

fn redact_line(line: &str) -> String {
    let tokenish = Regex::new(
        r#"(?i)(TOKEN|SECRET|PASSWORD|API_KEY|ACCESS_KEY)([A-Z0-9_]*)(\s*[:=]\s*)(['"]?)[^'"\s]+"#,
    )
    .expect("redaction regex compiles");
    tokenish
        .replace_all(line.trim(), "$1$2$3$4[REDACTED]")
        .to_string()
}

fn print_json(value: &impl Serialize) -> DevResult<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

fn print_toml(value: &impl Serialize) -> DevResult<()> {
    println!("{}", toml::to_string_pretty(value)?);
    Ok(())
}

fn print_inventory_human(output: &InventoryOutput) {
    println!("devctl inventory");
    println!("root: {}", output.root);
    println!("repos: {}", output.repos.len());
    for repo in &output.repos {
        println!(
            "- {} [{}] languages={}",
            repo.name,
            repo.status,
            repo.languages.iter().cloned().collect::<Vec<_>>().join(",")
        );
    }
}

fn print_audit_human(output: &AuditOutput) {
    println!("devctl standards audit");
    println!("root: {}", output.root);
    println!("scope: {}", output.scope);
    println!("repos: {}", output.repos.len());
    println!("findings: {}", output.findings.len());
    for finding in &output.findings {
        let location = finding
            .file
            .as_ref()
            .map(|file| match finding.line {
                Some(line) => format!("{file}:{line}"),
                None => file.to_string(),
            })
            .unwrap_or_else(|| "<repo>".to_string());
        println!(
            "{} {} {} {} {} - {}",
            finding.severity,
            finding.id,
            finding.fingerprint,
            finding.repo,
            location,
            finding.message
        );
    }
}

fn print_plan_human(output: &PlanOutput) {
    println!("devctl standards plan");
    println!("root: {}", output.root);
    println!(
        "risk: {}",
        output
            .risk
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("tranches: {}", output.tranches.len());
    for tranche in &output.tranches {
        println!(
            "- {} [{}] repos={} findings={}",
            tranche.title,
            tranche.severity,
            tranche.repos.join(","),
            tranche.findings.join(",")
        );
    }
}

fn print_report_human(output: &ReportOutput) {
    println!("devctl standards report");
    println!("tool_version: {}", output.tool_version);
    println!("root: {}", output.root);
    println!("scope: {}", output.scope);
    println!(
        "generated_at_epoch_seconds: {}",
        output.generated_at_epoch_seconds
    );
    println!("findings: {}", output.findings);
    println!("tranches: {}", output.tranches);
    println!("audit_json: {}", output.audit_json);
    println!("audit_markdown: {}", output.audit_markdown);
    let summary = output
        .adjudications
        .iter()
        .map(|(status, count)| format!("{status}={count}"))
        .collect::<Vec<_>>()
        .join(",");
    println!("adjudications: {summary}");
}

fn print_packet_human(output: &PacketOutput) {
    println!("devctl standards packet");
    println!("tool_version: {}", output.tool_version);
    println!("root: {}", output.root);
    println!("scope: {}", output.scope);
    println!(
        "generated_at_epoch_seconds: {}",
        output.generated_at_epoch_seconds
    );
    println!("contracts: {}", output.contracts);
    println!("adjudication_stubs: {}", output.adjudication_stubs);
    println!("tranches: {}", output.tranches);
    println!("next_actions: {}", output.next_actions);
    println!("packet_json: {}", output.packet_json);
    println!("packet_markdown: {}", output.packet_markdown);
}

fn print_contracts_human(output: &ContractsOutput) {
    println!("devctl standards contracts");
    println!("root: {}", output.root);
    println!("scope: {}", output.scope);
    println!("contracts: {}", output.contracts.len());
    println!("findings: {}", output.findings.len());
    for contract in &output.contracts {
        println!(
            "- {} [{}] archetype={} source={} posture={} commands={} artifacts={}",
            contract.repo,
            contract.status,
            contract.archetype,
            if contract.inferred {
                "inferred"
            } else {
                "catalog"
            },
            contract.cloudflare.posture,
            contract.canonical_commands.len(),
            contract.artifacts.present_top_level.join(",")
        );
    }
    for finding in &output.findings {
        let location = finding
            .file
            .as_ref()
            .map(|file| match finding.line {
                Some(line) => format!("{file}:{line}"),
                None => file.to_string(),
            })
            .unwrap_or_else(|| "<repo>".to_string());
        println!(
            "{} {} {} {} {} - {}",
            finding.severity,
            finding.id,
            finding.repo,
            finding
                .requirement_id
                .as_deref()
                .unwrap_or(finding.law.as_str()),
            location,
            finding.message
        );
    }
}

fn print_repo_human(repo: &RepoRecord) {
    println!("devctl repo explain");
    println!("name: {}", repo.name);
    println!("path: {}", repo.path);
    println!("status: {}", repo.status);
    println!(
        "docs: NORTH_STAR={} ANCHOR={} AGENTS={} CLAUDE={} README={} SECURITY={}",
        repo.docs.north_star.is_some(),
        repo.docs.anchor.is_some(),
        repo.docs.agents.is_some(),
        repo.docs.claude.is_some(),
        repo.docs.readme.is_some(),
        repo.docs.security.is_some()
    );
    println!(
        "commands: cargo={} package={} make={} scripts={} ops={}",
        repo.command_surfaces.cargo_toml,
        repo.command_surfaces.package_json,
        repo.command_surfaces.makefile,
        repo.command_surfaces.scripts_dir,
        repo.command_surfaces.ops_dir
    );
    println!(
        "cloudflare: wrangler={} functions={} workers={} pages={} status={}",
        repo.cloudflare.has_wrangler_config,
        repo.cloudflare.has_functions_dir,
        repo.cloudflare.has_workers_dir,
        repo.cloudflare.has_pages_dir,
        repo.cloudflare
            .declared_status
            .as_deref()
            .unwrap_or("undeclared")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn redacts_secret_values() {
        let line = "CLOUDFLARE_API_TOKEN=${CF_DEV_TOKEN:-super-secret}";
        let redacted = redact_line(line);
        assert!(redacted.contains("CLOUDFLARE_API_TOKEN="));
        assert!(!redacted.contains("super-secret"));
    }

    #[test]
    fn token_assignment_produces_p0() {
        let fixture = TestRepo::new("token-repo");
        fixture.write(
            "scripts/rotate-secrets.sh",
            "CLOUDFLARE_API_TOKEN=${CF_DEV_TOKEN}\n",
        );
        let findings = fixture.audit();
        assert!(
            findings
                .iter()
                .any(|finding| finding.law == "token" && finding.severity == Severity::P0)
        );
        assert!(
            findings
                .iter()
                .all(|finding| !finding.evidence.contains("abc123"))
        );
    }

    #[test]
    fn raw_wrangler_docs_produce_cloudflare_finding() {
        let fixture = TestRepo::new("cf-repo");
        fixture.write("wrangler.toml", "name = \"cf-repo\"\n");
        fixture.write("README.md", "Deploy with npx wrangler deploy\n");
        let findings = fixture.audit();
        assert!(findings.iter().any(
            |finding| finding.law == "cloudflare-mutation" && finding.severity == Severity::P1
        ));
    }

    #[test]
    fn deploy_without_post_verify_produces_release_finding() {
        let fixture = TestRepo::new("release-repo");
        fixture.write("AGENTS.md", "canonical commands\n");
        fixture.write(
            "scripts/deploy.sh",
            "#!/usr/bin/env bash\ncargo check\nwrangler deploy\n",
        );
        let findings = fixture.audit();
        assert!(findings.iter().any(|finding| finding.law == "release-proof"
            && finding.message.contains("preflight and post-deploy")));
    }

    #[test]
    fn check_script_without_ledger_produces_verification_finding() {
        let fixture = TestRepo::new("script-repo");
        fixture.write("AGENTS.md", "active repo\n");
        fixture.write("scripts/check-local.sh", "#!/usr/bin/env bash\ntrue\n");
        let findings = fixture.audit();
        assert!(findings.iter().any(|finding| {
            finding.law == "command-verification" && finding.repair_group == "script-ownership"
        }));
    }

    #[test]
    fn unclassified_artifact_path_produces_boundary_finding() {
        let fixture = TestRepo::new("artifact-repo");
        fixture.write("AGENTS.md", "active repo\n");
        fixture.mkdir("var/logs");
        let findings = fixture.audit();
        assert!(
            findings
                .iter()
                .any(|finding| finding.law == "artifact-boundary")
        );
    }

    #[test]
    fn missing_quartet_files_produce_doctrine_findings() {
        let fixture = TestRepo::new("doctrine-repo");
        fixture.write("AGENTS.md", "active repo\n");
        fixture.write("Cargo.toml", "[package]\nname = \"doctrine-repo\"\n");
        let messages: Vec<String> = fixture
            .audit()
            .into_iter()
            .filter(|finding| finding.law == "doctrine-quartet")
            .map(|finding| finding.message)
            .collect();
        // AGENTS.md is present, so only the other three quartet files are findings.
        assert!(messages.iter().any(|m| m.contains("NORTH_STAR.md")));
        assert!(messages.iter().any(|m| m.contains("ANCHOR.md")));
        assert!(messages.iter().any(|m| m.contains("CLAUDE.md")));
        assert!(!messages.iter().any(|m| m.contains("AGENTS.md")));
    }

    #[test]
    fn complete_quartet_produces_no_doctrine_finding() {
        let fixture = TestRepo::new("complete-repo");
        fixture.write("NORTH_STAR.md", "north\n");
        fixture.write("ANCHOR.md", "anchor\n");
        fixture.write("AGENTS.md", "agents\n");
        fixture.write("CLAUDE.md", "claude\n");
        fixture.write("Cargo.toml", "[package]\nname = \"complete-repo\"\n");
        assert!(
            !fixture
                .audit()
                .iter()
                .any(|finding| finding.law == "doctrine-quartet")
        );
    }

    #[test]
    fn local_contract_overlay_is_loaded() {
        let _fixture = LocalCatalogFixture::contract(
            "tdd-private-overlay",
            r#"schema_version = "0.1.0"
repo = "tdd-private-overlay"
archetype = "rust-workspace"
status = "active-product"
canonical_commands = ["cargo test --workspace"]

[cloudflare]
posture = "none"

[release]
evidence_dirs = []
"#,
        );
        let contracts = load_contracts_catalog().expect("contracts load");
        assert!(contracts.contracts.contains_key("tdd-private-overlay"));
    }

    #[test]
    fn inventory_json_has_schema_version() {
        let fixture = TestWorkspace::new();
        fixture
            .repo("sample-web-product")
            .write("AGENTS.md", "repo\n");
        let catalog = test_catalog();
        let repos = inventory(&fixture.root, &catalog).expect("inventory succeeds");
        let output = InventoryOutput {
            schema_version: SCHEMA_VERSION,
            root: fixture.root.clone(),
            repos,
        };
        let json = serde_json::to_string(&output).expect("json serializes");
        assert!(json.contains("\"schema_version\":\"0.1.0\""));
        assert!(json.contains("\"sample-web-product\""));
    }

    #[test]
    fn plan_groups_findings_into_tranches() {
        let repo = RepoRecord {
            name: "demo".to_string(),
            path: Utf8PathBuf::from("/tmp/demo"),
            status: RepoStatus::ActiveProduct,
            git: GitInfo { present: true },
            docs: DocsInfo::default(),
            languages: BTreeSet::new(),
            command_surfaces: CommandSurfaces::default(),
            cloudflare: CloudflareInfo::default(),
            release: ReleaseInfo::default(),
            artifacts: ArtifactInfo::default(),
        };
        let findings = vec![Finding::new(
            "token",
            Severity::P0,
            &repo,
            None,
            None,
            "message",
            "evidence",
            "recommendation",
            Confidence::High,
            "cloudflare-token-law",
        )];
        let tranches = build_tranches(&findings);
        assert_eq!(tranches.len(), 1);
        assert_eq!(tranches[0].severity, Severity::P0);
        assert_eq!(tranches[0].repos, vec!["demo"]);
    }

    #[test]
    fn plan_all_includes_contract_findings_outside_pilot() {
        let workspace = TestWorkspace::new();
        let repo = workspace.repo("contractless-plan-repo");
        repo.write("NORTH_STAR.md", "north\n");
        repo.write("ANCHOR.md", "anchor\n");
        repo.write("AGENTS.md", "agents\n");
        repo.write("CLAUDE.md", "claude\n");
        repo.write(
            "Cargo.toml",
            "[package]\nname = \"contractless-plan-repo\"\n",
        );

        let output = plan_command(&PlanArgs {
            root: workspace.root.clone(),
            pilot: None,
            all: true,
            risk: "P1".to_string(),
            json: true,
        })
        .expect("plan succeeds");

        assert!(output.tranches.iter().any(|tranche| {
            tranche.id == "contractless-plan-repo:repo-contract:active-repo-contract-present"
        }));
    }

    #[test]
    fn accepted_exception_is_not_actionable() {
        let repo = test_repo_record("demo");
        let mut findings = vec![Finding::new(
            "token",
            Severity::P0,
            &repo,
            None,
            None,
            "message",
            "evidence",
            "recommendation",
            Confidence::High,
            "cloudflare-token-law",
        )];
        let fingerprint = findings[0].fingerprint.clone();
        let catalog = AdjudicationsCatalog {
            adjudications: vec![AdjudicationEntry {
                fingerprint,
                status: AdjudicationStatus::AcceptedException,
                reason: "known pilot exception with owner".to_string(),
                owner: Some("standards".to_string()),
                expires: Some("2026-06-01".to_string()),
            }],
        };
        apply_adjudications(&mut findings, &catalog);
        assert!(!finding_is_actionable(&findings[0]));
        assert_eq!(
            findings[0].adjudication.as_ref().map(|entry| &entry.status),
            Some(&AdjudicationStatus::AcceptedException)
        );
    }

    #[test]
    fn markdown_report_contains_fingerprint_and_tranches() {
        let repo = test_repo_record("demo");
        let mut findings = vec![Finding::new(
            "token",
            Severity::P0,
            &repo,
            None,
            None,
            "message",
            "evidence",
            "recommendation",
            Confidence::High,
            "cloudflare-token-law",
        )];
        assign_finding_ids(&mut findings);
        let tranches = build_tranches(&findings);
        let audit = AuditOutput {
            schema_version: SCHEMA_VERSION,
            root: Utf8PathBuf::from("/tmp"),
            scope: "pilot:three-tier".to_string(),
            repos: vec![repo],
            findings,
        };
        let markdown = render_markdown_report(
            1,
            &audit,
            &tranches,
            &summarize_adjudications(&audit.findings),
        );
        assert!(markdown.contains("# devctl standards report"));
        assert!(markdown.contains("Repair Tranches"));
        assert!(markdown.contains(&audit.findings[0].fingerprint));
    }

    #[test]
    fn adjudication_template_filters_to_unreviewed_risk() {
        let repo = test_repo_record("demo");
        let mut findings = vec![
            Finding::new(
                "token",
                Severity::P0,
                &repo,
                None,
                None,
                "message",
                "evidence",
                "recommendation",
                Confidence::High,
                "cloudflare-token-law",
            ),
            Finding::new(
                "artifact-boundary",
                Severity::P2,
                &repo,
                None,
                None,
                "message",
                "evidence",
                "recommendation",
                Confidence::Medium,
                "artifact-boundaries",
            ),
        ];
        assign_finding_ids(&mut findings);
        let risk = [Severity::P0, Severity::P1];
        let template: Vec<AdjudicationEntry> = findings
            .iter()
            .filter(|finding| risk.contains(&finding.severity))
            .map(|finding| AdjudicationEntry {
                fingerprint: finding.fingerprint.clone(),
                status: AdjudicationStatus::TruePositive,
                reason: format!(
                    "TODO: review {} {} {}",
                    finding.repo, finding.law, finding.id
                ),
                owner: None,
                expires: None,
            })
            .collect();
        assert_eq!(template.len(), 1);
        assert_eq!(template[0].fingerprint, findings[0].fingerprint);
    }

    #[test]
    fn contract_proposal_is_inferred_and_read_only() {
        let fixture = TestRepo::new("contract-repo");
        fixture.write("AGENTS.md", "active repo\n");
        fixture.write("Cargo.toml", "[package]\nname = \"contract-repo\"\n");
        fixture.write("wrangler.toml", "name = \"contract-repo\"\n");
        fixture.write("scripts/check-local.sh", "#!/usr/bin/env bash\ntrue\n");
        fixture.mkdir("artifacts");
        let catalog = test_catalog();
        let repo = scan_repo(&fixture.root, &catalog).expect("repo scans");
        let proposal = build_contract_proposal(&repo, None);
        assert!(proposal.inferred);
        assert!(
            proposal
                .canonical_commands
                .contains(&"cargo check --workspace".to_string())
        );
        assert_eq!(proposal.cloudflare.posture, "undeclared");
        assert_eq!(proposal.artifacts.present_top_level, vec!["artifacts"]);
    }

    #[test]
    fn contract_proposal_uses_catalog_contract_when_present() {
        let fixture = TestRepo::new("contract-repo");
        fixture.write("AGENTS.md", "active repo\n");
        fixture.write("Cargo.toml", "[package]\nname = \"contract-repo\"\n");
        let catalog = test_catalog();
        let repo = scan_repo(&fixture.root, &catalog).expect("repo scans");
        let sourced = test_sourced_contract("contract-repo", "rust-workspace");
        let proposal = build_contract_proposal(&repo, Some(&sourced));
        assert!(!proposal.inferred);
        assert_eq!(proposal.archetype, "rust-workspace");
        assert_eq!(proposal.canonical_commands, vec!["cargo test --workspace"]);
    }

    #[test]
    fn catalog_contract_draft_strips_local_proposal_metadata() {
        let fixture = TestRepo::new("contract-repo");
        fixture.write("AGENTS.md", "active repo\n");
        fixture.write("Cargo.toml", "[package]\nname = \"contract-repo\"\n");
        fixture.write("wrangler.toml", "name = \"contract-repo\"\n");
        fixture.mkdir("artifacts");
        let catalog = test_catalog();
        let repo = scan_repo(&fixture.root, &catalog).expect("repo scans");
        let proposal = build_contract_proposal(&repo, None);
        let draft = build_catalog_contract_draft(&proposal);
        let toml = toml::to_string_pretty(&draft).expect("draft serializes");

        assert!(toml.contains("repo = \"contract-repo\""));
        assert!(toml.contains("cargo check --workspace"));
        assert!(toml.contains("posture = \"undeclared\""));
        assert!(!toml.contains("path = "));
        assert!(!toml.contains("inferred"));
        assert!(!toml.contains("present_top_level"));
        assert!(!toml.contains("has_policy"));
        assert!(!toml.contains(fixture.root.as_str()));
    }

    #[test]
    fn contract_validation_rejects_unknown_archetype() {
        let mut contracts = ContractsCatalog::default();
        contracts.contracts.insert(
            "demo".to_string(),
            test_sourced_contract("demo", "unknown-archetype"),
        );
        let err = validate_contracts_catalog(&contracts, &test_archetypes())
            .expect_err("unknown archetype rejected")
            .to_string();
        assert!(err.contains("unknown archetype"));
    }

    #[test]
    fn contract_validation_rejects_filename_repo_drift() {
        let mut contracts = ContractsCatalog::default();
        let mut sourced = test_sourced_contract("demo", "rust-workspace");
        sourced.path = Utf8PathBuf::from("/tmp/not-demo.toml");
        contracts.contracts.insert("demo".to_string(), sourced);
        let err = validate_contracts_catalog(&contracts, &test_archetypes())
            .expect_err("filename drift rejected")
            .to_string();
        assert!(err.contains("filename must match repo"));
    }

    #[test]
    fn contract_validation_rejects_invalid_cloudflare_posture() {
        let mut contracts = ContractsCatalog::default();
        let mut sourced = test_sourced_contract("demo", "cloudflare-product");
        sourced.contract.cloudflare.posture = "raw-wrangler-everywhere".to_string();
        contracts.contracts.insert("demo".to_string(), sourced);
        let err = validate_contracts_catalog(&contracts, &test_archetypes())
            .expect_err("invalid posture rejected")
            .to_string();
        assert!(err.contains("invalid Cloudflare posture"));
    }

    #[test]
    fn contract_validation_rejects_duplicate_cloudflare_surface() {
        let mut contracts = ContractsCatalog::default();
        let mut sourced = test_sourced_contract("demo", "cloudflare-product");
        sourced.contract.cloudflare.posture = "cfctl-aware-wrapper".to_string();
        sourced.contract.cloudflare.surfaces = vec![
            CloudflareSurface::Path("wrangler.toml".to_string()),
            CloudflareSurface::Detailed {
                id: "dupe".to_string(),
                kind: "worker".to_string(),
                path: None,
                wrangler_config: Some("wrangler.toml".to_string()),
                required: true,
            },
        ];
        contracts.contracts.insert("demo".to_string(), sourced);
        let err = validate_contracts_catalog(&contracts, &test_archetypes())
            .expect_err("duplicate surface rejected")
            .to_string();
        assert!(err.contains("repeats Cloudflare surface"));
    }

    #[test]
    fn contract_validation_rejects_invalid_raw_exception_expiry() {
        let mut contracts = ContractsCatalog::default();
        let mut sourced = test_sourced_contract("demo", "cloudflare-product");
        sourced.contract.cloudflare.posture = "legacy/raw-wrangler-exception".to_string();
        sourced.contract.cloudflare.raw_exceptions = vec![RawMutationException {
            path: "ops/deploy.sh".to_string(),
            operation: "pages deploy".to_string(),
            reason: "legacy lane".to_string(),
            expires: Some("soon".to_string()),
        }];
        contracts.contracts.insert("demo".to_string(), sourced);
        let err = validate_contracts_catalog(&contracts, &test_archetypes())
            .expect_err("invalid expiry rejected")
            .to_string();
        assert!(err.contains("invalid expires date"));
    }

    #[test]
    fn contract_validation_rejects_incomplete_release_lane() {
        let mut contracts = ContractsCatalog::default();
        let mut sourced = test_sourced_contract("demo", "rust-workspace");
        sourced.contract.release.lanes = vec![ReleaseLane {
            id: "deploy".to_string(),
            command: "scripts/deploy.sh".to_string(),
            preflight: String::new(),
            post_verify: "scripts/verify.sh".to_string(),
            evidence: vec!["reports".to_string()],
            mutates_cloudflare: false,
        }];
        contracts.contracts.insert("demo".to_string(), sourced);
        let err = validate_contracts_catalog(&contracts, &test_archetypes())
            .expect_err("incomplete release lane rejected")
            .to_string();
        assert!(err.contains("incomplete release lane"));
    }

    #[test]
    fn contract_audit_finds_missing_canonical_commands() {
        let repo = test_repo_record("demo");
        let mut sourced = test_sourced_contract("demo", "rust-workspace");
        sourced.contract.canonical_commands.clear();
        let mut findings = Vec::new();
        audit_contract(&repo, Some(&sourced), &test_archetypes(), &mut findings);
        assert!(findings.iter().any(|finding| {
            finding.law == CONTRACT_LAW
                && finding.requirement_id.as_deref() == Some("canonical-commands-declared")
                && finding.file == Some(sourced.path.clone())
                && finding.line.is_some()
        }));
    }

    #[test]
    fn scanner_findings_are_enriched_with_contract_context() {
        let fixture = TestRepo::new("demo");
        fixture.write("AGENTS.md", "active repo\n");
        fixture.write("wrangler.toml", "name = \"demo\"\n");
        fixture.write("README.md", "deploy with npx wrangler deploy\n");
        let catalog = test_catalog();
        let repo = scan_repo(&fixture.root, &catalog).expect("repo scans");
        let mut contracts = ContractsCatalog::default();
        contracts.contracts.insert(
            "demo".to_string(),
            test_sourced_contract("demo", "rust-workspace"),
        );
        let findings = audit_repos(&[repo], Some(&contracts), Some(&test_archetypes()))
            .expect("audit succeeds");
        let raw = findings
            .iter()
            .find(|finding| finding.law == "cloudflare-mutation")
            .expect("raw wrangler finding exists");
        assert_eq!(raw.archetype.as_deref(), Some("rust-workspace"));
        assert_eq!(
            raw.requirement_id.as_deref(),
            Some("cloudflare-mutation-lane-classified")
        );
        assert!(raw.expected.is_some());
        assert!(raw.observed.is_some());
    }

    #[test]
    fn nested_wrangler_configs_must_be_declared_contract_surfaces() {
        let fixture = TestRepo::new("demo");
        fixture.write("AGENTS.md", "cfctl-aware-wrapper\n");
        fixture.write(
            "cloudflare/app-worker/wrangler.jsonc",
            "{ \"name\": \"app\" }\n",
        );
        fixture.write(
            "scripts/fixtures/cloudflare/example/wrangler.jsonc",
            "{ \"name\": \"fixture\" }\n",
        );
        let catalog = test_catalog();
        let repo = scan_repo(&fixture.root, &catalog).expect("repo scans");
        assert_eq!(
            relative_paths(&repo.path, &repo.cloudflare.wrangler_configs),
            vec!["cloudflare/app-worker/wrangler.jsonc"]
        );
        let mut sourced = test_sourced_contract("demo", "cloudflare-product");
        sourced.contract.cloudflare.posture = "cfctl-aware-wrapper".to_string();
        let mut findings = Vec::new();
        audit_contract(&repo, Some(&sourced), &test_archetypes(), &mut findings);
        let finding = findings
            .iter()
            .find(|finding| {
                finding.requirement_id.as_deref() == Some("cloudflare-surfaces-declared")
            })
            .expect("undeclared nested Cloudflare surface is reported");
        assert!(finding.observed.as_deref().is_some_and(|observed| {
            observed.contains("cloudflare/app-worker/wrangler.jsonc")
                && !observed.contains("scripts/fixtures")
        }));
    }

    #[test]
    fn tranches_split_shared_repair_group_by_requirement() {
        let repo = test_repo_record("demo");
        let mut first = Finding::new(
            "cloudflare-mutation",
            Severity::P1,
            &repo,
            None,
            None,
            "message",
            "evidence",
            "recommendation",
            Confidence::High,
            "cloudflare-governance",
        );
        first.requirement_id = Some("cloudflare-posture-declared".to_string());
        let mut second = first.clone();
        second.requirement_id = Some("cloudflare-surfaces-declared".to_string());
        let tranches = build_tranches(&[first, second]);
        assert_eq!(tranches.len(), 2);
        assert!(tranches.iter().any(|tranche| {
            tranche.id == "demo:cloudflare-mutation:cloudflare-posture-declared"
        }));
        assert!(tranches.iter().any(|tranche| {
            tranche.id == "demo:cloudflare-mutation:cloudflare-surfaces-declared"
        }));
    }

    #[test]
    fn operating_packet_centers_contracts_and_next_actions() {
        let repo = test_repo_record("demo");
        let mut findings = vec![Finding::new(
            "token",
            Severity::P0,
            &repo,
            None,
            None,
            "message",
            "evidence",
            "recommendation",
            Confidence::High,
            "cloudflare-token-law",
        )];
        assign_finding_ids(&mut findings);
        let audit = AuditOutput {
            schema_version: SCHEMA_VERSION,
            root: Utf8PathBuf::from("/tmp"),
            scope: "pilot:three-tier".to_string(),
            repos: vec![repo.clone()],
            findings,
        };
        let contracts = vec![build_contract_proposal(&repo, None)];
        let risk = [Severity::P0, Severity::P1];
        let adjudications = build_adjudication_template(&audit.findings, &risk);
        let actionable = audit.findings.clone();
        let tranches = build_tranches(&actionable);
        let next_actions = derive_next_actions(&contracts, &adjudications, &tranches);
        let document = OperatingPacketDocument {
            schema_version: SCHEMA_VERSION,
            tool_version: TOOL_VERSION,
            generated_at_epoch_seconds: 1,
            principle: "repo development flow is the system center; devctl is the read-only instrument panel",
            audit: &audit,
            contracts: &contracts,
            adjudication_template: &adjudications,
            tranches: &tranches,
            next_actions: &next_actions,
        };
        let markdown = render_operating_packet_markdown(&document);
        assert!(markdown.contains("devctl pilot operating packet"));
        assert!(markdown.contains("repo development flow"));
        assert!(markdown.contains("Repo Contracts"));
        assert!(!next_actions.is_empty());
    }

    struct TestWorkspace {
        root: Utf8PathBuf,
    }

    impl TestWorkspace {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "devctl-test-{}",
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time works")
                    .as_nanos()
            ));
            fs::create_dir_all(&root).expect("fixture root created");
            Self {
                root: Utf8PathBuf::from_path_buf(root).expect("utf8 temp path"),
            }
        }

        fn repo(&self, name: &str) -> TestRepo {
            let repo = TestRepo {
                root: self.root.join(name),
            };
            repo.mkdir(".git");
            repo
        }
    }

    struct TestRepo {
        root: Utf8PathBuf,
    }

    struct LocalCatalogFixture {
        path: Utf8PathBuf,
    }

    impl LocalCatalogFixture {
        fn contract(name: &str, body: &str) -> Self {
            let path = Utf8PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("catalog/local/contracts")
                .join(format!("{name}.toml"));
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("local catalog dir created");
            }
            let mut file = fs::File::create(&path).expect("local contract created");
            file.write_all(body.as_bytes())
                .expect("local contract written");
            Self { path }
        }
    }

    impl Drop for LocalCatalogFixture {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.path);
        }
    }

    impl TestRepo {
        fn new(name: &str) -> Self {
            TestWorkspace::new().repo(name)
        }

        fn write(&self, relative: &str, body: &str) {
            let path = self.root.join(relative);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("parent created");
            }
            let mut file = fs::File::create(path).expect("file created");
            file.write_all(body.as_bytes()).expect("fixture written");
        }

        fn mkdir(&self, relative: &str) {
            fs::create_dir_all(self.root.join(relative)).expect("dir created");
        }

        fn audit(&self) -> Vec<Finding> {
            let catalog = test_catalog();
            let repo = scan_repo(&self.root, &catalog).expect("repo scans");
            audit_repos(&[repo], None, None).expect("audit succeeds")
        }
    }

    fn test_catalog() -> WorkspaceCatalog {
        WorkspaceCatalog {
            pilot_three_tier: vec![
                "sample-web-product".to_string(),
                "sample-worker-product".to_string(),
                "sample-desktop-edge".to_string(),
            ],
            repo_status: BTreeMap::new(),
        }
    }

    fn test_repo_record(name: &str) -> RepoRecord {
        RepoRecord {
            name: name.to_string(),
            path: Utf8PathBuf::from(format!("/tmp/{name}")),
            status: RepoStatus::ActiveProduct,
            git: GitInfo { present: true },
            docs: DocsInfo::default(),
            languages: BTreeSet::new(),
            command_surfaces: CommandSurfaces::default(),
            cloudflare: CloudflareInfo::default(),
            release: ReleaseInfo::default(),
            artifacts: ArtifactInfo::default(),
        }
    }

    fn test_archetypes() -> ArchetypesCatalog {
        ArchetypesCatalog {
            schema_version: SCHEMA_VERSION.to_string(),
            archetypes: vec![
                ArchetypeDefinition {
                    id: "rust-workspace".to_string(),
                    title: "Rust workspace".to_string(),
                    requires_canonical_commands: true,
                    requires_cloudflare_posture: false,
                    allowed_cloudflare_postures: vec!["none".to_string()],
                    requires_release_evidence: false,
                    requires_artifact_classification: false,
                },
                ArchetypeDefinition {
                    id: "cloudflare-product".to_string(),
                    title: "Cloudflare product".to_string(),
                    requires_canonical_commands: true,
                    requires_cloudflare_posture: true,
                    allowed_cloudflare_postures: vec![
                        "cfctl-native".to_string(),
                        "cfctl-aware-wrapper".to_string(),
                        "legacy/raw-wrangler-exception".to_string(),
                        "none".to_string(),
                    ],
                    requires_release_evidence: false,
                    requires_artifact_classification: false,
                },
            ],
        }
    }

    fn test_sourced_contract(repo: &str, archetype: &str) -> SourcedRepoContract {
        let body = format!(
            r#"schema_version = "{SCHEMA_VERSION}"
repo = "{repo}"
archetype = "{archetype}"
status = "active-product"
canonical_commands = ["cargo test --workspace"]

[cloudflare]
posture = "none"

[release]
evidence_dirs = []
"#
        );
        SourcedRepoContract {
            contract: toml::from_str(&body).expect("contract parses"),
            path: Utf8PathBuf::from(format!("/tmp/{repo}.toml")),
            lines: toml_line_map(&body),
        }
    }
}
