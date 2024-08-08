#!/bin/bash

cp -r ../example_remote_config_local ./
mv example_remote_config_local docker_default_remote_config

# Define the JSON file path
json_file="docker_default_remote_config/engine_core/ConfigTool.json"

# Use sed to replace the line containing the specific key
sed -i 's/"TOOL": "CHECKOV|KUBESCAPE|KICS"/"TOOL": "CHECKOV"/' "$json_file"
