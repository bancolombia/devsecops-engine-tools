---
sidebar_position: 2
---

# Structure Remote Config

[example_remote_config_local](https://github.com/bancolombia/devsecops-engine-tools/blob/trunk/example_remote_config_local/)
```bash
📦Remote_Config
   ┣ 📂engine_core
   ┃ ┗ 📜ConfigTool.json
   ┣ 📂engine_dast
   ┃ ┗ 📜ConfigTool.json
   ┃ ┗ 📜Exclusions.json
   ┣ 📂engine_integrations
   ┃ ┗ 📂report_sonar
   ┃   ┗ 📜ConfigTool.json
   ┃   ┗ 📜Exclusions.json
   ┃ ┗ 📂copacetic
   ┃   ┗ 📜ConfigTool.json
   ┃   ┗ 📜Exclusions.json
   ┣ 📂engine_risk
   ┃ ┗ 📜ConfigTool.json
   ┃ ┗ 📜Exclusions.json
   ┣ 📂engine_sast
   ┃ ┗ 📂engine_iac
   ┃   ┗ 📜ConfigTool.json
   ┃   ┗ 📜Exclusions.json
   ┃ ┗ 📂engine_secret
   ┃   ┗ 📜ConfigTool.json
   ┃ ┗ 📂engine_code
   ┃   ┗ 📜ConfigTool.json
   ┃   ┗ 📜Exclusions.json
   ┣ 📂engine_sca
   ┃ ┗ 📂engine_container
   ┃   ┗ 📜ConfigTool.json
   ┃   ┗ 📜Exclusions.json
   ┃ ┗ 📂engine_dependencies
   ┃   ┗ 📜ConfigTool.json
   ┃   ┗ 📜Exclusions.json
   ┃ ┗ 📂engine_function
   ┃   ┗ 📜ConfigTool.json
   ┃   ┗ 📜Exclusions.json
```

## **engine_core**

Module is responsible to handle core configurations

For more information about structure remote config for this module, visit [engine core](../modules/engine_core.md)

## **engine_dast**

Module is responsible for orchestrating Dynamic Application Security Testing (DAST) within the DevSecOps Engine Tools platform. It automates the execution of DAST tools, processes scan configurations, manages authentication flows, and integrates results for further risk analysis and reporting

For more information about structure remote config for this module, [engine dast](../modules/engine_dast.md)

## **engine_integrations**

The engine_integrations module enables the integration of DevSecOps Engine Tools with external systems and platforms, focusing on orchestrating and automating reporting and data exchange processes. It is designed to be extensible, allowing new integrations to be added as needed.

### **report_sonar**
For more information about structure remote config for this integration, [copacetic](../modules/engine_integrations/copacetic.md)

### **report_sonar**
For more information about structure remote config for this integration, [report sonar](../modules/engine_integrations/report_sonar.md)

## **engine_risk**
Module for prioritizing the resolution of findings reported in Vulnerability Management.

For more information about structure remote config for this module, [engine risk](../modules/engine_risk.md)

## **engine_sast**

### **engine_code**

The engine_code module is responsible for orchestrating Static Application Security Testing (SAST) within the DevSecOps Engine Tools platform. It automates the execution of SAST tools, processes code scan configurations, manages exclusions, and integrates results for further risk analysis and reporting.

For more information about structure remote config for this module, [engine code](../modules/engine_sast/engine_code.md)

### **engine_iac**

Static infrastructure analysis (k8s, dockerfile, cft) is a process that detects vulnerabilities in an application's defined infrastructure. This automated process is part of Bancolombia's DevSecOps practices, which evaluate security, code quality, and compliance.

For more information about structure remote config for this module, [engine iac](../modules/engine_sast/engine_iac.md)

### **engine_secret**

Secret scanning is a process that detects vulnerabilities in the application's source code. This automated process is part of Bancolombia's DevSecOps practices, through which security, code quality, and compliance are evaluated.

For more information about structure remote config for this module, [engine secret](../modules/engine_sast/engine_secret.md)

## **engine_sca**

### **engine_container**

Container Security Analysis (CSA) is a practice focused on ensuring the integrity, confidentiality, and availability of container-based applications, promoting a security culture from the early stages of development through deployment and production operations.

For more information about structure remote config for this module, [engine container](../modules/engine_sca/engine_container.md)

### **engine_dependencies**

Software Composition Analysis (SCA) is a process that detects compromised or vulnerable open-source components used in an application's source code. This automated process is part of Bancolombia's DevSecOps practices, through which security, code quality, and compliance are evaluated.

For more information about structure remote config for this module, [engine dependencies](../modules/engine_sca/engine_dependencies.md)

## **vulnerability_management**

## **vulnerability_management/cmdb_mapping**

Mapping configuration for the names of the evcs obtained from the cmdb, to centralize a single name and have unified product types in Vulnerability Management.

 > types_product:
  - "CMDB Name" : "Unique product type name for Vulnerability Management"

> Example vulnerability_management/cmdb_mapping.json
```json
{
  "types_product": {
    "IT ARCHITECTURE": "PT1 - ARCHITECTURE",
    "SOFTWARE ENGINEERING": "PT2 - IT ENGINEERING"
  }
}
```