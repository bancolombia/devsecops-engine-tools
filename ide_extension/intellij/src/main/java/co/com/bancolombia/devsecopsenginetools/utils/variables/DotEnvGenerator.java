package co.com.bancolombia.devsecopsenginetools.utils.variables;

import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettings;
import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettingsUtils;
import co.com.bancolombia.devsecopsenginetools.ui.tool.LogPanelLogger;
import co.com.bancolombia.devsecopsenginetools.utils.FileUtils;
import co.com.bancolombia.devsecopsenginetools.utils.http.HttpClient;
import co.com.bancolombia.devsecopsenginetools.utils.variables.azure.AzureVariableProvider;
import com.intellij.openapi.project.Project;
import lombok.experimental.UtilityClass;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Map;

import static co.com.bancolombia.devsecopsenginetools.utils.Constants.AZURE_PLACEHOLDER;

@UtilityClass
public class DotEnvGenerator {

    public static String updateDotEnv(Project project) throws IOException {
        ProjectSettings settings = ProjectSettingsUtils.getProjectSettings(project);
        settings.fillIfDefaults(project);
        AzureVariableProvider azureVariableProvider = new AzureVariableProvider(settings, new HttpClient());
        return updateDotEnv(project.getBasePath(), settings, azureVariableProvider);
    }

    public static String updateDotEnv(String root, ProjectSettings settings, VariableProvider variableProvider)
            throws IOException {
        Map<String, String> dotEnv = FileUtils.readEnvFile(Path.of(root, settings.getDotEnvFile()));
        LogPanelLogger.info(".env read with " + dotEnv.size() + " entries");

        variableProvider.getVariables()
                .forEach(variable -> dotEnv.put(variable.getName(), variable.getValue()));

        Map<String, String> parsedDotEnv = VariablePlaceholder.resolvePlaceholders(dotEnv, AZURE_PLACEHOLDER);

        String message = "✔ Writing .env with " + parsedDotEnv.size() + " entries";
        LogPanelLogger.success(message);
        FileUtils.writeEnvFile(Path.of(root, settings.getDotEnvFile()), parsedDotEnv);
        return message;
    }
}
