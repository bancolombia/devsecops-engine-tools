# DevSecOps Engine Tools

![Maintained by Bancolombia](https://img.shields.io/badge/maintained_by-Bancolombia-yellow)
[![Build](https://github.com/bancolombia/devsecops-engine-tools/actions/workflows/build.yml/badge.svg)](https://github.com/bancolombia/devsecops-engine-tools/actions/workflows/build)

# Objective

Tool that unifies the evaluation of the different devsecops practices being agnostic to the devops platform, using both open source and market tools.

# Component

📦 [tools](https://github.com/bancolombia/devsecops-engine-tools/tree/trunk/tools): DevSecOps Practice Modules

# Communications channel

Here are the channels we use to communicate about the project:

**1. Mailing list:** You can join our mailing list to always be informed at the following link: [CommunityDevsecopsEngine](https://groups.google.com/g/CommunityDevsecopsEngine)

**2. Email:** You can write to us by email:  MaintainersDevsecopsEngine@googlegroups.com

# Getting started

### Requirements

- Python >= 3.8

### Installation

```bash
pip3 install devsecops_engine_tools
```

### Scan running - flags (CLI)

```bash
devsecops_engine_tools --platform_devops ["local","azure"] --remote_config_repo ["remote_config_repo"] --tool ["engine_iac", "engine_dast", "engine_secret", "engine_dependencies", "engine_container"] --folder_path ["Folder path scan engine_iac"] --platform ["eks","openshift"] --use_secrets_manager ["false", "true"] --use_vulnerability_management ["false", "true"] --send_metrics ["false", "true"] --token_cmdb ["token_cmdb"] --token_vulnerability_management ["token_vulnerability_management"] --token_engine_container ["token_engine_container"] --token_engine_dependencies ["token_engine_dependencies"] 
```

### Structure Remote Config
[example_remote_config_local](https://github.com/bancolombia/devsecops-engine-tools/blob/trunk/example_remote_config_local/)
```bash
📦Remote_Config
   ┣ 📂engine_core
   ┃ ┗ 📜ConfigTool.json
   ┣ 📂engine_sast
   ┃ ┗ 📂engine_iac
   ┃   ┗ 📜ConfigTool.json
   ┃   ┗ 📜Exclusions.json
   ┃ ┗ 📂engine_secret
   ┃   ┗ 📜ConfigTool.json
   ┣ 📂engine_sca
   ┃ ┗ 📂engine_container
   ┃   ┗ 📜ConfigTool.json
   ┃   ┗ 📜Exclusions.json
   ┃ ┗ 📂engine_dependencies
   ┃   ┗ 📜ConfigTool.json
   ┃   ┗ 📜Exclusions.json
```
### Scan running sample (CLI) - Local

> Complete the value in **.envdetlocal** file a set in execution environment
```
$ set -a
$ source .envdetlocal
$ set +a
```


```bash
devsecops_engine_tools --platform_devops local --remote_config_repo DevSecOps_Remote_Config --tool engine_iac

```
### Scan result sample (CLI)

```bash
    ____            _____           ____                ______            _               ______            __    
   / __ \___ _   __/ ___/___  _____/ __ \____  _____   / ____/___  ____ _(_)___  ___     /_  __/___  ____  / /____
  / / / / _ \ | / /\__ \/ _ \/ ___/ / / / __ \/ ___/  / __/ / __ \/ __ `/ / __ \/ _ \     / / / __ \/ __ \/ / ___/
 / /_/ /  __/ |/ /___/ /  __/ /__/ /_/ / /_/ (__  )  / /___/ / / / /_/ / / / / /  __/    / / / /_/ / /_/ / (__  ) 
/_____/\___/|___//____/\___/\___/\____/ .___/____/  /_____/_/ /_/\__, /_/_/ /_/\___/    /_/  \____/\____/_/____/  
                                     /_/                        /____/                                            

Secrets manager is not enabled to configure external checks

Below are all vulnerabilities detected.
╔══════════╦════════════╦════════════════════════════════════════════════════════════════════════════════════╦════════════════════════╗
║ Severity ║ ID         ║ Description                                                                        ║ Where                  ║
╠══════════╬════════════╬════════════════════════════════════════════════════════════════════════════════════╬════════════════════════╣
║ critical ║ CKV_K8S_37 ║ IAC-CKV_K8S_37 Minimize the admission of containers with capabilities assigned     ║ /_AW1234/app.yaml      ║
║ critical ║ CKV_K8S_20 ║ IAC-CKV_K8S_20 Containers should not run with allowPrivilegeEscalation             ║ /_AW1234/app.yaml      ║
║ critical ║ CKV_K8S_30 ║ IAC-CKV_K8S_30 Apply security context to your containers                           ║ /_AW1234/app.yaml      ║
║ critical ║ CKV_K8S_23 ║ IAC-CKV_K8S_23 Minimize the admission of root containers                           ║ /_AW1234/app.yaml      ║
║ high     ║ CKV_AWS_20 ║ C-S3-005-AWS S3 buckets are accessible to public                                   ║ /_AW1234/template.yaml ║
║ high     ║ CKV_K8S_22 ║ IAC-CKV_K8S_22 Use read-only filesystem for containers where possible              ║ /_AW1234/app.yaml      ║
║ high     ║ CKV_K8S_28 ║ IAC-CKV_K8S_28 Minimize the admission of containers with the NET_RAW capability    ║ /_AW1234/app.yaml      ║
║ high     ║ CKV_K8S_38 ║ IAC-CKV_K8S_38 Ensure that Service Account Tokens are only mounted where necessary ║ /_AW1234/app.yaml      ║
╚══════════╩════════════╩════════════════════════════════════════════════════════════════════════════════════╩════════════════════════╝
Security count issues (critical: 4, high: 4, medium: 0, low: 0) is greater than or equal to failure criteria (critical: 1, high: 8, medium: 10, low:15, operator: or)
✘Failed

Below are all compliances issues detected.
╔══════════╦═══════════╦════════════════════════════════════════════════════╦═══════════════════╗
║ Severity ║ ID        ║ Description                                        ║ Where             ║
╠══════════╬═══════════╬════════════════════════════════════════════════════╬═══════════════════╣
║ critical ║ CKV_K8S_8 ║ IAC-CKV_K8S_8 Liveness Probe Should be Configured  ║ /_AW1234/app.yaml ║
║ critical ║ CKV_K8S_9 ║ IAC-CKV_K8S_9 Readiness Probe Should be Configured ║ /_AW1234/app.yaml ║
╚══════════╩═══════════╩════════════════════════════════════════════════════╩═══════════════════╝
Compliance issues count (critical: 2) is greater than or equal to failure criteria (critical: 1)
✘Failed

Bellow are all the findings that were accepted.
╔══════════╦════════════╦═══════════════════╦═════════════╦══════════════╦══════════════════╗
║ Severity ║ ID         ║ Where             ║ Create Date ║ Expired Date ║ Reason           ║
╠══════════╬════════════╬═══════════════════╬═════════════╬══════════════╬══════════════════╣
║ high     ║ CKV_K8S_38 ║ /_AW1234/app.yaml ║ 18/11/2023  ║ 18/03/2024   ║ False Positive   ║
╚══════════╩════════════╩═══════════════════╩═════════════╩══════════════╩══════════════════╝

message custom
```

# How can I help?

Review the issues, we hear new ideas. Read more [Contributing](https://github.com/bancolombia/devsecops-engine-tools/blob/trunk/docs/CONTRIBUTING.md)





