# DevSecOps Engine Tools

[![Maintained by Bancolombia](https://img.shields.io/badge/maintained_by-Bancolombia-yellow)](#)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/bancolombia/devsecops-engine-tools/intellij-build.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=bancolombia_devsecops-engine-tool-intellij&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=bancolombia_devsecops-engine-tool-intellij)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=bancolombia_devsecops-engine-tool-intellij&metric=coverage)](https://sonarcloud.io/summary/new_code?id=bancolombia_devsecops-engine-tool-intellij)
![Downloads](https://img.shields.io/jetbrains/plugin/d/25069-devsecops-engine-tools)
![Rating](https://img.shields.io/jetbrains/plugin/r/rating/25069-devsecops-engine-tools)
![Version](https://img.shields.io/jetbrains/plugin/v/25069-devsecops-engine-tools)


## Description

Intellij plugin that allows you to run DevSecOps Engine Tools from the IDE.

## Installation

You can install the plugin from the [JetBrains Plugin Repository](https://plugins.jetbrains.com/plugin/25069-devsecops-engine-tools), or from the plugin marketplace from you IDE.

## Usage

1. Open the plugin window by clicking on the DevSecOps Engine Tools icon in the bottom left corner of the IDE.
2. Click on the "Run" button to execute the DevSecOps Engine Tools.
3. The output will be displayed in the "Console" tab.

### Azure DevOps Integration

You can have IaC templates with some placeholders that can be replaced by the plugin with values stored on an `.env` file.
The `.env` file can be generated from values of the Azure DevOps (pipeline, release and stage) variables.

## Known Issues

### Binary not found

When running scans you may encounter the following error:

```
Error running scan IaC command: java.io.IOException: Cannot run program "docker": error=2, No such file or directory
	at java.base/java.lang.ProcessBuilder.start(ProcessBuilder.java:1143)
    ...
```

In this case we recommend you to run the scan after a command that loads your env, for example if you use zsh, you can 
change the command to `zsh -c "source ~/.zshrc && <scan command here>"`.
