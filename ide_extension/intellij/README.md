```shell
docker run --rm -v {projectPath}/dev-sec-ops/iac:/iac devsecops-engine-tools:1 devsecops-engine-tools --platform_devops local --remote_config_repo example_remote_config_local --tool engine_iac --folder_path /iac
```