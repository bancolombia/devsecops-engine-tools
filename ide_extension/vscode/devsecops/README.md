# DevSecOps Engine Tools

[![Maintained by Bancolombia](https://img.shields.io/badge/maintained_by-Bancolombia-yellow)](#)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/bancolombia/devsecops-engine-tools/intellij-build.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=bancolombia_devsecops-engine-tool-intellij&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=bancolombia_devsecops-engine-tool-intellij)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=bancolombia_devsecops-engine-tool-intellij&metric=coverage)](https://sonarcloud.io/summary/new_code?id=bancolombia_devsecops-engine-tool-intellij)
![Downloads](https://img.shields.io/jetbrains/plugin/d/25069-devsecops-engine-tools)
![Rating](https://img.shields.io/jetbrains/plugin/r/rating/25069-devsecops-engine-tools)
![Version](https://img.shields.io/jetbrains/plugin/v/25069-devsecops-engine-tools)

---

## 🚀 Description

**DevSecOps Engine Tools** is a Visual Studio Code extension developed by Bancolombia to detect security vulnerabilities early in the development lifecycle without depending solely on pipelines.

It enables static scans for **Infrastructure as Code (IaC)**, **Container Images**, and **Dependencies**, using custom and industry-recognized tools. It highlights vulnerable lines in the code, suggests fixes with GitHub Copilot, and presents interactive results.

---

## 📦 Key Features 

### 🛠️ Infrastructure as Code (IaC)

- Scan files such as Terraform, Dockerfiles, Kubernetes manifests, and CloudFormation templates
- File-based findings panel
- Highlights the vulnerable line directly in the editor
- Hover support for vulnerability details and contextual Copilot fix
- Support for environment variable substitution (as in pipeline configs)
- Executed using [**Checkov**](https://www.checkov.io/) 

### 🐳 Container

- Scans locally available container images
- Displays scan findings per image
- Right-side panel with detailed vulnerability info for the selected image
- Executed using [**Trivy**](https://github.com/aquasecurity/trivy)

### 📦 Dependencies

- Analyze project dependencies with:
  - [JFrog Xray](https://jfrog.com/xray/)
  - [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)
- Detect known CVEs in third-party libraries
- Compatible with Maven, Gradle, npm, yarn, etc.
- Includes impact path to determine transitive vs direct vulnerabilities
- Organized panel with detailed information and suggested updates

---

## 🤖 AI Assistant Actions

Take advantage of the integration with **GitHub Copilot** for an intelligent, assisted security workflow:

### 1. 💡 Fix with Copilot  
- **Color:** Blue
- **Icon:** 💡
- **Function:**
  - Generates a contextual prompt for GitHub Copilot to help fix the vulnerability
  - Includes vulnerability details specific to:
    - Dependencies → impact path & affected libraries
    - Containers → image context & Dockerfile snippet
    - IaC → validation rules for the vulnerable resource

### 2. ℹ️ Explain Vulnerability  
- **Color:** Purple
- **Icon:** ℹ️
- **Function:**
  - Generates a prompt for GitHub Copilot to explain the vulnerability
  - Provides educational context about the type of issue
  - Details potential impact and security risks
  - Helps you understand the issue before taking action

### 3. 📦 Generate Update Solution *(Dependencies & Images)*  
- **Color:** Orange
- **Icon:** 📦
- **Function:**
  - Available for dependency vulnerabilities and container image vulnerabilities
  - Targets **all** vulnerabilities found in that scan, not just the one you clicked
  - Includes a compact CVE + fixed version list per finding (to keep the prompt short) instead of full details for each one
  - For dependencies: generates a single consolidated set of CLI commands (`npm`, `yarn`, `maven`, etc.) to update all affected libraries
  - For images: generates a single consolidated update plan (base image/package updates, Dockerfile changes) to fix all affected packages

---

## 📥 Installation

1. Install the extension from the [VSCode Marketplace](https://marketplace.visualstudio.com/items?itemName=bancolombia.devsecops-engine-tools)
2. Requirements:
   - ✅ [WSL](https://learn.microsoft.com/en-us/windows/wsl/install)
   - ✅ Docker or Podman
3. Setup:
   - Enable Docker before scanning containers
   - Grant internet access for CVE updates (Dependency-Check/Xray)
4. Launch:
   - Open a folder in VSCode
   - Select the desired scan (IaC, Container, Dependencies)
   - View and interact with results from the left sidebar

---

## 🧪 Usage Considerations

- Vulnerabilities are shown by file, line, and severity
- Validate that results shown in the webview match the expected file and line
- Use workspace settings for advanced configs:
  - Custom variables
  - Scanner arguments
  - Exclusion rules
- Copilot support is context-aware; use it to get the most helpful fix suggestions

---
## 📚 Additional Resources

- [Extension Guidelines](https://code.visualstudio.com/api/references/extension-guidelines)
- [Visual Studio Code Markdown Support](http://code.visualstudio.com/docs/languages/markdown)
- [Markdown Syntax Reference](https://help.github.com/articles/markdown-basics/)

---

**Thanks for being part of the shift toward secure development from day one!**