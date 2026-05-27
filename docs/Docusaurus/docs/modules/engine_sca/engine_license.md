# Module Engine License

## Overview

The `engine_license` module is a **standalone** license-compliance reporter inside the DevSecOps Engine Tools platform. It always scans the local repository, generates a fresh CycloneDX SBOM, runs the [Anchore Grant](https://github.com/anchore/grant) license inspector against that SBOM, classifies every dependency against a policy declared in remote configuration, and emits a single artifact: `{pipeline_name}_LICENSE.json`.

Unlike other engines, `engine_license` does **not**:

- Participate in `THRESHOLD` / break-build decisions.
- Use `Exclusions.json`.
- Push findings to vulnerability management or risk score.
- Reuse SBOMs from previous runs.
- Scan container images (the artifact is repository-only).

The intent is to ship an audit-friendly, policy-driven JSON that downstream consumers can analyse out-of-band of build pipelines.

> **Platform support:** Anchore Grant only ships binaries for **Linux (amd64, arm64)** and **macOS (amd64, arm64)**. Windows is not supported by upstream; the scanner is skipped with a logged warning.

## Flow

```mermaid
flowchart TD
    A[handle_scan: engine_license branch] --> B[runner_engine_license]
    B --> C[init_engine_license entry_point_tool]
    C --> D[SbomManager.get_components<br/>fresh {pipeline}_SBOM.json]
    D --> E[GrantScan.run_tool_license_sca<br/>analyses the SBOM]
    E --> F[BuildLicenseReport<br/>applies LICENSE_POLICY]
    F --> G["Writes {pipeline}_LICENSE.json in CWD"]
    G --> H[runner returns findings=[], input_core, sbom_components]
    H --> I[handle_scan forwards findings, input_core]
```

The runner returns the standard `(findings_list, input_core, sbom_components)` triple to keep parity with other engines, but `findings_list` is always empty: the report itself lives in the LICENSE.json file referenced by `input_core.path_file_results`.

## Configuration Structure

Only one configuration file is consumed: `engine_sca/engine_license/ConfigTool.json`. There is no `Exclusions.json` and no `.grant.yaml`; the policy is declared inline.

### ConfigTool.json

```json
{
    "GRANT": {
        "GRANT_VERSION": "0.6.4",
        "OUTPUT_FORMAT": "json",
        "QUIET": true,
        "DEBUG_PIPELINES": [],
        "LICENSE_POLICY": {
            "fail": ["AGPL-*", "SSPL-*"],
            "warn": ["BUSL-*", "EPL-*", "LGPL-3.0*"],
            "synonyms": {
            },
            "unlicensed_action": "ignore",
            "unknown_action": "ignore"
        }
    }
}
```

#### `GRANT` block

- **GRANT_VERSION**: Anchore Grant version to download. If `grant` is on `PATH`, it is reused.
- **OUTPUT_FORMAT**: Required to be `"json"` so the deserializer can parse Grant's report. Other values disable the report builder.
- **QUIET**: When `true`, passes `--quiet` to Grant.
- **DEBUG_PIPELINES**: Pipeline names that should log Grant's stdout/stderr for troubleshooting.

#### `LICENSE_POLICY` block

Declarative policy applied to every dependency Grant identifies. **All keys are required** for `engine_license` to produce a report; if `LICENSE_POLICY` is missing, no report is generated.

- **fail**: Glob patterns (case-insensitive `fnmatch`) whose match marks the package as `fail` (severity `critical`).
- **warn**: Glob patterns whose match marks the package as `warn` (severity `medium`).
- **synonyms**: Object that rewrites raw license identifiers (e.g. `{"BSD": "BSD-3-Clause"}`) before matching.
- **unlicensed_action**: Action assigned to packages with no detected license. One of `fail` | `warn` | `info` | `ignore`. Controls only the severity tier; the package is always listed in the report under the `unlicensed` bucket.
- **unknown_action**: Action assigned to packages whose license label does not look like a valid SPDX identifier and matches no policy pattern. Same value set as above. The package is always listed under the `unknown` bucket.

## Output Artifact: `{pipeline_name}_LICENSE.json`

The report is written to the current working directory and uses a hybrid layout: a `metadata` block plus a flat `dependencies` array.

```json
{
  "metadata": {
    "pipeline_name": "AP0008001_CargaMasiva_HB_Lambda",
    "scan_date": "2026-05-27T16:30:00",
    "tool": "GRANT",
    "policy_used": {
      "fail": ["AGPL-*", "SSPL-*"],
      "warn": ["BUSL-*", "EPL-*", "LGPL-3.0*"],
      "synonyms": {},
      "unlicensed_action": "ignore",
      "unknown_action": "ignore"
    },
    "summary": {
      "total_dependencies": 50,
      "ok": 45,
      "fail": 1,
      "warn": 2,
      "unlicensed": 1,
      "unknown": 1
    }
  },
  "dependencies": [
    {
      "name": "lodash",
      "version": "4.17.21",
      "licenses": ["MIT"],
      "policy_applied": "ok",
      "policy_reason": "compliant SPDX license",
      "policy_pattern_matched": null
    }
  ]
}
```

### Field reference

#### `metadata`
- **pipeline_name**: Value of the `pipeline_name` DevOps platform variable.
- **scan_date**: ISO-8601 timestamp (seconds resolution) when the report was assembled.
- **tool**: Always `"GRANT"`.
- **policy_used**: Verbatim deep copy of `GRANT.LICENSE_POLICY` for auditability.
- **summary.total_dependencies**: Number of entries in `dependencies` (root project is excluded).
- **summary.{ok,fail,warn,unlicensed,unknown}**: Count per `policy_applied` bucket.

#### `dependencies[]`
- **name / version**: Package identifiers as reported by Grant.
- **licenses**: List of normalized license identifiers (after applying `synonyms`).
- **policy_applied**: Bucket of the package — one of `ok`, `fail`, `warn`, `unlicensed`, `unknown`.
- **policy_reason**: Human-readable explanation (e.g. `matches FAIL pattern 'AGPL-*'`).
- **policy_pattern_matched**: Original policy pattern that matched, or `null`.

### Classification rules

For each package Grant reports:

1. If the package has **no licenses** → bucket `unlicensed`.
2. Otherwise the licenses are normalized through `synonyms` and each is classified:
   - Match against `fail` patterns → `fail`.
   - Match against `warn` patterns → `warn`.
   - Otherwise, looks like an SPDX id → `ok`.
   - Otherwise → `unknown`.
3. **Dual-license semantics:** if any license on the package classifies as `ok`, the package is `ok` (the consumer can legally pick the permissive option).
4. Otherwise the most permissive non-OK bucket is reported in this rank order: `warn` < `fail` < `unknown` (lighter restriction reported when both exist).
5. The package whose name equals the SBOM's source root (heuristically derived from the source `ref`) is dropped to avoid reporting the project against itself.

## Main Responsibilities

- **SBOM Generation:** Always invokes the SBOM manager (`cdxgen`) to produce `{pipeline_name}_SBOM.json` in CWD; previous SBOM files are overwritten.
- **License Scan:** Runs `grant list` against the freshly generated SBOM and saves Grant's JSON report.
- **Policy Application:** Classifies every package using `LICENSE_POLICY` from remote config.
- **Report Emission:** Writes the hybrid `{pipeline_name}_LICENSE.json` artifact in CWD.
- **Platform Detection:** Linux/macOS × amd64/arm64; Windows logs a warning and aborts the license step.

## Key Components

- `applications/runner_license_scan.py`: Entry point invoked by `engine_core/handle_scan`. Selects the tool (currently only Grant), runs the standalone flow, and assembles the minimal `InputCore` returned to downstream consumers.
- `infrastructure/entry_points/entry_point_tool.py`: Use case orchestrator: fetch remote config → fresh SBOM → Grant scan → build report.
- `infrastructure/driven_adapters/grant_tool/grant_manager_scan.py`: Driven adapter that downloads/installs the Grant binary and runs `grant list <sbom>`.
- `domain/usecases/license_policy.py`: Pure helpers — `build_policy_from_remote_config`, `classify_package`, `looks_like_spdx_id`, etc. No I/O, fully unit-testable.
- `domain/usecases/build_license_report.py`: `BuildLicenseReport` use case that reads Grant's JSON, classifies every dependency through `license_policy`, and writes the LICENSE.json artifact.

## Supported Tools and Features

- **Anchore Grant** (`grant list`) over CycloneDX SBOMs.
- **Multi-platform:** Linux amd64/arm64, macOS amd64/arm64.
- **Policy as configuration:** allow / fail / warn / ignore rules declared inline in `LICENSE_POLICY` (no separate `.grant.yaml`).
- **Audit-friendly artifact:** the LICENSE.json includes the original policy and per-dependency justification.

## Example Usage

### Repository (default — folder mode)
```sh
devsecops-engine-tools \
    --platform_devops local \
    --remote_config_source local \
    --remote_config_repo example_remote_config_local \
    --module engine_license \
    --tool grant \
    --folder_path path/to/project
```

If `--folder_path` is omitted, the current working directory is scanned.

> Container image scanning is intentionally not part of this module; it relies on the SBOM produced from the repository.

> Windows runners will log a warning and skip the scan; configure your pipeline to run `engine_license` on Linux or macOS agents.

## Configuration Guidelines

- Pin `GRANT_VERSION` to a tested release of Anchore Grant.
- Keep `LICENSE_POLICY` in remote configuration so policy changes are reviewed and auditable; the report echoes it verbatim under `metadata.policy_used`.
- Use specific SPDX identifiers in `fail` / `warn` patterns when possible (e.g. `AGPL-3.0`, `LGPL-3.0*`); use globs sparingly.
- Use `synonyms` to canonicalize ambiguous labels coming from the SBOM (e.g. `"BSD"` → `"BSD-3-Clause"`).
- Choose `unlicensed_action` and `unknown_action` deliberately:
  - `ignore` keeps the package in the report (so the auditor sees it) but assigns `info` severity.
  - `warn` / `fail` raise the severity attached to those buckets.
- `engine_license` is intended for audit/reporting workflows and should typically run on its own pipeline (or a separate stage) rather than gating builds.
