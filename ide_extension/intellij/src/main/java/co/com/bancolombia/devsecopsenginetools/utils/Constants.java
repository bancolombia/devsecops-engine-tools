package co.com.bancolombia.devsecopsenginetools.utils;

import lombok.experimental.UtilityClass;

@UtilityClass
public class Constants {
    public static final String CONFIGURATION_NAME =  "GlobalSettings";
    public static final String CONFIGURATION_FILE =  "devsecops-engine-tools.xml";

    public static final String TOOL_WINDOW_ID = "DevSecOps Engine Tools";

    public static final String AZURE_CREDENTIALS = "azure";
    public static final String DEFAULT_URL_PATTERN = "{...}";
    public static final String DEFAULT_PATTERN = "#{...}#";
    public static final String AZURE_PLACEHOLDER = "$(...)";
    public static final String SERVICE_NAME = "co.com.bancolombia.devsecopsenginetools";
    public static final String DEFAULT_IAC_SCAN_COMMAND = "docker run --rm -v {projectPath}/dev-sec-ops/iac:/iac {image} devsecops-engine-tools --platform_devops local --remote_config_repo docker_default_remote_config --tool engine_iac --folder_path /iac";
    public static final String DEFAULT_IMAGE_SCAN_COMMAND = "echo \"coming soon\"";
    public static final String DEFAULT_IMAGE = "bancolombia/devsecops-engine-tools:1.8.6";
}
