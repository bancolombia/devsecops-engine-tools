package co.com.bancolombia.devsecopsenginetools.configuration;

import com.intellij.openapi.application.Application;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.components.PersistentStateComponent;
import com.intellij.openapi.components.State;
import com.intellij.openapi.components.Storage;
import com.intellij.util.xmlb.XmlSerializerUtil;
import lombok.Data;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

@Data
@State(name = "GlobalSettings", storages = {@Storage("devsecops-engine-tools.xml")})
public class GlobalSettings implements PersistentStateComponent<GlobalSettings> {
    public static final String DEFAULT_IAC_SCAN_COMMAND = "docker run --rm -v {projectPath}/dev-sec-ops/iac:/iac {image} devsecops-engine-tools --platform_devops local --remote_config_repo docker_default_remote_config --tool engine_iac --folder_path /iac";
    public static final String DEFAULT_IMAGE_SCAN_COMMAND = "echo \"coming soon\"";
    public static final String DEFAULT_IMAGE = "bancolombia/devsecops-engine-tools:1.8.6";

    private String scanIacCommand;
    private String scanImageCommand;
    private String devSecOpsImage;
    private boolean checkForLatestImage = true;
    // Azure DevOps
    private String azureDevOpsOrganization = "";
    private String azureDevOpsProject = "";

    public static GlobalSettings getInstance() {
        Application app = ApplicationManager.getApplication();
        if (app == null) {
            return new GlobalSettings(); // For testing purposes
        }
        return app.getService(GlobalSettings.class);
    }

    @Override
    public @Nullable GlobalSettings getState() {
        return this;
    }

    @Override
    public void loadState(@NotNull GlobalSettings state) {
        XmlSerializerUtil.copyBean(state, this);
    }
}
