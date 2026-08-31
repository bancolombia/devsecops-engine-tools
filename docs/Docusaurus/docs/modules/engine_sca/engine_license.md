# Module Engine License

## Overview

The `engine_license` module is a **standalone** license-compliance reporter inside the DevSecOps Engine Tools platform. It scans the local repository, generates a fresh CycloneDX SBOM via **CdxGen**, classifies every dependency against a policy declared in remote configuration, and emits a single artifact: `{pipeline_name}_LICENSE.json`.

Unlike other engines, `engine_license` does **not**:

- Participate in `THRESHOLD` / break-build decisions.
- Use `Exclusions.json`.
- Push findings to vulnerability management.
- Reuse SBOMs from previous runs.
- Scan container images (the artifact is repository-only).

The intent is to ship an audit-friendly, policy-driven JSON that downstream consumers can analyse out-of-band of build pipelines.

> **Why CdxGen?** The module relies on CdxGen because it is the only mainstream SBOM generator that enriches license data by querying the package registry (e.g. Maven Central, npm, NuGet) via its `FETCH_LICENSE` option. Tools such as Syft and Trivy report only locally declared licenses (from lockfiles or existing package metadata) and do not perform active registry lookups, so licenses missing from local manifests (common in Maven/Gradle projects) would not be resolved. This is why `SBOM_MANAGER.CDXGEN.FETCH_LICENSE` must be `true` for the report to be complete.

## Configuration Structure

Only one configuration file is consumed: `engine_sca/engine_license/ConfigTool.json`. There is no `Exclusions.json`; the policy is declared inline.

### ConfigTool.json

```json
{
    "LICENSE": {
        "LICENSE_POLICY": {
            "fail": ["AGPL-*", "SSPL-*"],
            "warn": ["BUSL-*", "EPL-*", "LGPL-3.0*"],
            "synonyms": {},
            "unlicensed_action": "ignore",
            "unknown_action": "ignore"
        }
    }
}
```

#### `LICENSE_POLICY` block

Declarative policy applied to every dependency in the SBOM. **All keys are required** for `engine_license` to produce a report; if `LICENSE_POLICY` is missing, no report is generated.

- **fail**: Glob patterns (case-insensitive `fnmatch`) whose match marks the package as `fail` (severity `critical`).
- **warn**: Glob patterns whose match marks the package as `warn` (severity `medium`).
- **synonyms**: Object that rewrites raw license identifiers (e.g. `{"BSD": "BSD-3-Clause"}`) before matching.
- **unlicensed_action**: Action assigned to packages with no detected license. One of `fail` | `warn` | `info` | `ignore`.
- **unknown_action**: Action assigned to packages whose license label does not look like a valid SPDX identifier. Same value set as above.

## Output Artifact: `{pipeline_name}_LICENSE.json`

The report is written to the current working directory with a `metadata` block plus a flat `dependencies` array.

```json
{
  "metadata": {
    "pipeline_name": "my_service",
    "scan_date": "2026-06-12T14:30:00",
    "tool": "CDXGEN",
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
      "policy_pattern_matched": null,
      "license_matched": "MIT"
    }
  ]
}
```

### Field reference

#### `metadata`
- **pipeline_name**: Value of the `pipeline_name` DevOps platform variable.
- **scan_date**: ISO-8601 timestamp when the report was assembled.
- **tool**: `"CDXGEN"`.
- **policy_used**: Deep copy of `LICENSE.LICENSE_POLICY` for auditability.
- **summary.total_dependencies**: Number of entries in `dependencies`.
- **`summary.{ok,fail,warn,unlicensed,unknown}`**: Count per `policy_applied` bucket.

#### `dependencies[]`
- **name / version**: Package identifiers from the CycloneDX SBOM.
- **licenses**: List of normalized license identifiers (after applying `synonyms`).
- **policy_applied**: Bucket — one of `ok`, `fail`, `warn`, `unlicensed`, `unknown`.
- **policy_reason**: Human-readable explanation (e.g. `matches FAIL pattern 'AGPL-*'`).
- **policy_pattern_matched**: Original policy pattern that matched, or `null`.
- **license_matched**: The specific license that triggered the classification.

### Classification rules

For each component in the SBOM:

1. If the component has **no licenses** → bucket `unlicensed`.
2. Otherwise the licenses are normalized through `synonyms` and each is classified:
   - Match against `fail` patterns → `fail`.
   - Match against `warn` patterns → `warn`.
   - Looks like an SPDX id → `ok`.
   - Otherwise → `unknown`.
3. **Highest-risk-wins:** if any license on the package matches `fail`, the package is `fail`; if any matches `warn`, it's `warn`. Only when all licenses are compliant is the package `ok`.

## Console Output (Findings)

When run with `--context false` (default), `engine_license` prints a compliance table showing only `fail` and `warn` findings:

| Severity | ID | Description | Where |
|---|---|---|---|
| critical | AGPL-3.0-itext | License 'AGPL-3.0' for package 'itext' (...) | itext:9.2.0 |
| medium | EPL-2.0-junit-bom | License 'EPL-2.0' for package 'junit-bom' (...) | junit-bom:5.10.2 |

Dependencies classified as `ok`, `unlicensed`, or `unknown` do **not** appear in the console findings.

## Structured Context (`--context true`)

Structured context generation and file saving are controlled by the `GENERATE_CONTEXT` property under `ENGINE_LICENSE` in the remote config. When `GENERATE_CONTEXT` is `true`, the engine writes a `license_context.json` file to the current working directory, and the `--context` flag only controls whether that same JSON is additionally printed to the execution logs:

```
===== BEGIN CONTEXT OUTPUT =====
{
  "license_context": [
    {
      "name": "itext",
      "version": "9.2.0",
      "licenses": ["AGPL-3.0"],
      "policy_applied": "fail",
      "policy_reason": "matches FAIL pattern 'AGPL-*'",
      "policy_pattern_matched": "AGPL-*",
      "severity": "critical",
      "priority": "very critical"
    }
  ]
}
===== END CONTEXT OUTPUT =====
```

Only `fail` and `warn` dependencies appear in the context output.

## Key Components

- `applications/runner_license_scan.py`: Entry point invoked by `engine_core/handle_scan`. Runs the flow and builds `Finding` objects for the compliance table.
- `infrastructure/entry_points/entry_point_tool.py`: Orchestrator: fetch remote config → fresh SBOM → build report.
- `infrastructure/driven_adapters/license_scan/license_scan_manager.py`: Reads the LICENSE.json and provides structured context extraction.
- `infrastructure/helpers/license_policy.py`: Pure helpers — `build_policy_from_remote_config`, `classify_package`, `looks_like_spdx_id`.
- `domain/usecases/build_license_report.py`: `BuildLicenseReport` use case that reads the CycloneDX SBOM, classifies every dependency, and writes the LICENSE.json artifact.

## Example Usage

```sh
devsecops-engine-tools \
    --platform_devops local \
    --remote_config_source local \
    --remote_config_repo example_remote_config_local \
    --module engine_license \
    --folder_path path/to/project
```

If `--folder_path` is omitted, the current working directory is scanned.

## Configuration Guidelines

- Keep `LICENSE_POLICY` in remote configuration so policy changes are reviewed and auditable; the report echoes it verbatim under `metadata.policy_used`.
- Use specific SPDX identifiers in `fail` / `warn` patterns when possible (e.g. `AGPL-3.0`, `LGPL-3.0*`); use globs sparingly.
- Use `synonyms` to canonicalize ambiguous labels from the SBOM (e.g. `"BSD"` → `"BSD-3-Clause"`).
- Ensure `SBOM_MANAGER.CDXGEN.FETCH_LICENSE` is `true` so the SBOM includes license metadata.
- Choose `unlicensed_action` and `unknown_action` deliberately:
  - `ignore` keeps the package in the report but assigns `info` severity (not shown in findings).
  - `warn` / `fail` raises the severity for those buckets.
