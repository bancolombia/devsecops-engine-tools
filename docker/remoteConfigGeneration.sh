#!/bin/bash

mv /app/example_remote_config_local /app/docker_default_remote_config
json_file="/app/docker_default_remote_config/engine_core/ConfigTool.json"
sed -i 's/"TOOL": "CHECKOV|KUBESCAPE|KICS"/"TOOL": "CHECKOV"/' "$json_file"