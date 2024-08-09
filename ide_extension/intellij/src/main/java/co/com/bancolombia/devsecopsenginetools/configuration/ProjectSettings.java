package co.com.bancolombia.devsecopsenginetools.configuration;


import co.com.bancolombia.devsecopsenginetools.utils.FileUtils;
import com.intellij.openapi.project.Project;
import lombok.Data;

import java.nio.file.Paths;

@Data
public class ProjectSettings {
    // iac settings
    private String iacDirectory;
    // image settings
    private String dockerFilePath;
    private String buildContextPath;
    private String buildCommand;
    private String preBuildScript;

    // Variables settings
    private boolean replaceTokens;
    private String replacePattern;
    private String dotEnvFile;
    private String azureDevOpsVariableGroups;
    private String azureReleaseDefinitionId;
    private String azureReleaseStageName;

    public void fillIfDefaults(Project project) {
        if (isDefault()) {
            iacDirectory = "resources,deployment";
            replaceTokens = false;
            replacePattern = "#{...}#";
            dotEnvFile = ".env";
            azureDevOpsVariableGroups = "";
            azureReleaseDefinitionId = "";
            azureReleaseStageName = "";
            buildContextPath = "";
            // calculable values
            String projectPath = project.getBasePath() == null ? "" : project.getBasePath();
            if (Paths.get(projectPath, "build.gradle").toFile().exists()) {
                preBuildScript = "gradle build";
                buildContextPath = "build/libs";
            } else {
                preBuildScript = "";
            }
            if (Paths.get(projectPath, "applications", "app-service", "build.gradle").toFile().exists()) {
                buildContextPath = "applications/app-service/build/libs";
            }
            dockerFilePath = FileUtils.findDockerfile(projectPath);
            buildCommand = "docker build -t image-to-scan -f {dockerFilePath} {buildContextPath}";
        }
    }

    public boolean isDefault() {
        return iacDirectory == null
                && !replaceTokens
                && replacePattern == null
                && dotEnvFile == null
                && azureDevOpsVariableGroups == null
                && azureReleaseDefinitionId == null
                && azureReleaseStageName == null
                && dockerFilePath == null
                && buildContextPath == null
                && preBuildScript == null
                && buildCommand == null;
    }
}
