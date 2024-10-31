#!/bin/bash

mv /app/example_remote_config_local /app/docker_default_remote_config
json_file_iac="/app/docker_default_remote_config/engine_core/ConfigTool.json"
sed -i 's/"TOOL": "CHECKOV|KUBESCAPE|KICS"/"TOOL": "CHECKOV"/' "$json_file_iac"

json_file_container="/app/docker_default_remote_config/engine_core/ConfigTool.json"
sed -i 's/"TOOL": "PRISMA|TRIVY"/"TOOL": "PRISMA"/' "$json_file_container"

# json_file_container_config="/app/docker_default_remote_config/engine_sca/engine_container/ConfigTool.json"
# sed -i 's/"PRISMA_CONSOLE_URL": "",/"PRISMA_CONSOLE_URL": "https://us-west1.cloud.twistlock.com/us-3-159209233",/' "$json_file_container_config"
# sed -i 's/"PRISMA_ACCESS_KEY": "",/"PRISMA_ACCESS_KEY": "a84036ca-96f2-41cc-95d4-b84c0658fc50",/' "$json_file_container_config"
# sed -i 's/"PRISMA_API_VERSION": "",/"PRISMA_API_VERSION": "v32.03",/' "$json_file_container_config"