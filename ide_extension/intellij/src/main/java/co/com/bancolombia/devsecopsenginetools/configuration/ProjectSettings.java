package co.com.bancolombia.devsecopsenginetools.configuration;


import lombok.Data;

@Data
public class ProjectSettings {
    private String iacDirectory;
    private boolean replaceTokens;
    private String replacePattern;
    private String dotEnvFile;
    private String azureDevOpsVariableGroups;
    private String azureReleaseDefinitionId;
    private String azureReleaseStageName;

    public void fillIfDefaults() {
        if (isDefault()) {
            iacDirectory = "resources,deployment";
            replaceTokens = false;
            replacePattern = "#{...}#";
            dotEnvFile = ".env";
            azureDevOpsVariableGroups = "";
            azureReleaseDefinitionId = "";
            azureReleaseStageName = "";
        }
    }

    public boolean isDefault() {
        return iacDirectory == null
                && !replaceTokens
                && replacePattern == null
                && dotEnvFile == null
                && azureDevOpsVariableGroups == null
                && azureReleaseDefinitionId == null
                && azureReleaseStageName == null;
    }
}
