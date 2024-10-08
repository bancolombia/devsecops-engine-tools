Use Dependency-Check
================
For using dependency-check, it is recommended to use the NVD API Key, which can be requested at the provided 
in [Request NVD API Key](https://nvd.nist.gov/developers/request-an-api-key). Keep in mind that without an NVD API Key, dependency-check updates will be extremely slow.

The API Key can be passed to the devsecops engine tools using the flag `--token_engine_dependencies`. For example:

```bash
devsecops-engine-tools --platform_devops local --remote_config_repo DevSecOps_Remote_Config --tool engine_dependencies --token_engine_dependencies nvd_api_key
```

#### The NVD API Key, CI, and Rate Limiting

The NVD API has enforced rate limits. If you are using a single API KEY and multiple builds occur you could hit the 
rate limit and receive 403 errors. In a CI environment one must use a caching strategy. For more information you can 
visit the documentation in [GitHub Dependency-Check](https://github.com/jeremylong/DependencyCheck)
