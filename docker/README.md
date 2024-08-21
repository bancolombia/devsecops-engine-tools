# DevSecOps Engine Tools

[![Maintained by Bancolombia](https://img.shields.io/badge/maintained_by-Bancolombia-yellow)](#)
[![Build](https://github.com/bancolombia/devsecops-engine-tools/actions/workflows/build.yml/badge.svg)](https://github.com/bancolombia/devsecops-engine-tools/actions/workflows/build.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=bancolombia_devsecops-engine-tools&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=bancolombia_devsecops-engine-tools)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=bancolombia_devsecops-engine-tools&metric=coverage)](https://sonarcloud.io/summary/new_code?id=bancolombia_devsecops-engine-tools)
[![Python Version](https://img.shields.io/badge/python%20-%203.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20-blue)](#)

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

- docker

### Installation

```bash
docker pull bancolombia/devsecops-engine-tools
```

### Scan running - flags (CLI)

```bash
docker run --rm devsecops-engine-tools --platform_devops ["local","azure","github"] --remote_config_repo ["remote_config_repo"] --tool ["engine_iac", "engine_dast", "engine_secret", "engine_dependencies", "engine_container"] --folder_path ["Folder path scan engine_iac"] --platform ["k8s","cloudformation","docker", "openapi"] --use_secrets_manager ["false", "true"] --use_vulnerability_management ["false", "true"] --send_metrics ["false", "true"] --token_cmdb ["token_cmdb"] --token_vulnerability_management ["token_vulnerability_management"] --token_engine_container ["token_engine_container"] --token_engine_dependencies ["token_engine_dependencies"] --xray_mode ["scan", "audit"]
```

### Structure Remote Config
[example_remote_config_local](https://github.com/bancolombia/devsecops-engine-tools/blob/trunk/example_remote_config_local/)
#### The docker image have it own default remote config with basic configuration called docker_default_remote_config, but you can define your own config and pass it as volume
```bash
docker run --rm -v ./folder_to_analyze:/folder_to_analyze -v ./custom_remote_config:/custom_remote_config bancolombia/devsecops-engine-tools:1.7.35 devsecops-engine-tools --platform_devops local --remote_config_repo custom_remote_config --tool engine_iac --folder_path /ms_artifact
```

#### Tools available for the modules (Configuration engine_core/ConfigTool.json)


<table>
  <tr>
    <th>Module</th>
    <th>Tool</th>
    <th>Type</th>
  </tr>
  <tr>
    <td rowspan="3">ENGINE_IAC</td>
    <td><a href="https://www.checkov.io/">CHECKOV</a></td>
    <td>Free</td>
  </tr>
  <tr>
    <td><a href="https://kubescape.io/">KUBESCAPE</a></td>
    <td>Free</td>
  </tr>
  <tr>
    <td><a href="https://www.kics.io/">KICS</a></td>
    <td>Free</td>
  </tr>
   <tr>
    <td>ENGINE_DAST</td>
    <td><a href="https://projectdiscovery.io/nuclei">NUCLEI</a></td>
    <td>Free</td>
  </tr>
  <tr>
    <td>ENGINE_SECRET</td>
    <td><a href="https://trufflesecurity.com/trufflehog">TRUFFLEHOG</a></td>
    <td>Free</td>
  </tr>
  <tr>
    <td rowspan="2">ENGINE_CONTAINER</td>
    <td><a href="https://www.paloaltonetworks.com/prisma/cloud">PRISMA</a></td>
    <td>Paid</td>
  </tr>
  <tr>
    <td><a href="https://trivy.dev/">TRIVY</a></td>
    <td>Free</td>
  </tr>
  <tr>
    <td>ENGINE_DEPENDENCIES</td>
    <td><a href="https://jfrog.com/help/r/get-started-with-the-jfrog-platform/jfrog-xray">XRAY</a></td>
    <td>Paid</td>
  </tr>
</table>

### Scan running sample (CLI) - Local

```bash
docker run --rm -v ./folder_to_analyze:/folder_to_analyze bancolombia/devsecops-engine-tools:1.7.35 devsecops-engine-tools --platform_devops local --remote_config_repo docker_default_remote_config --tool engine_iac --folder_path /folder_to_analyze
```

# Metrics

With the flag **--send_metrics true** and the configuration of the AWS-METRICS_MANAGER driven adapter in ConfigTool.json of the engine_core the tool will send the report to bucket s3. In the [metrics](https://github.com/bancolombia/devsecops-engine-tools/blob/trunk/metrics/) folder you will find the base of the cloud formation template to deploy the infra and dashboard in grafana.

![Dashboard Grafana](../docs/metrics.png)

# How can I help?

Review the issues, we hear new ideas. Read more [Contributing](https://github.com/bancolombia/devsecops-engine-tools/blob/trunk/docs/CONTRIBUTING.md)