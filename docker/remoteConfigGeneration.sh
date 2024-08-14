#!/bin/bash

cp -r ../example_remote_config_local ./
mv example_remote_config_local docker_default_remote_config
json_file="docker_default_remote_config/engine_core/ConfigTool.json"
sed -i 's/"TOOL": "CHECKOV|KUBESCAPE|KICS"/"TOOL": "CHECKOV"/' "$json_file"
