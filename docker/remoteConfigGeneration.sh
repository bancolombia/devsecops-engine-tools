#!/bin/bash

mv /app/example_remote_config_local /app/docker_default_remote_config
json_file_iac="/app/docker_default_remote_config/engine_core/ConfigTool.json"
sed -i 's/"TOOL": "CHECKOV|KUBESCAPE|KICS"/"TOOL": "CHECKOV"/' "$json_file_iac"

json_file_container="/app/docker_default_remote_config/engine_core/ConfigTool.json"
sed -i 's/"TOOL": "PRISMA|TRIVY"/"TOOL": "PRISMA"/' "$json_file_container"