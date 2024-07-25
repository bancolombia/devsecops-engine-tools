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
    private String scanIacCommand;
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
