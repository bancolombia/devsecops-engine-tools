package co.com.bancolombia.devsecopsenginetools.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.intellij.credentialStore.CredentialAttributes;
import com.intellij.credentialStore.Credentials;
import com.intellij.ide.passwordSafe.PasswordSafe;
import com.intellij.ide.util.PropertiesComponent;
import com.intellij.openapi.project.Project;
import lombok.experimental.UtilityClass;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static co.com.bancolombia.devsecopsenginetools.utils.Constants.SERVICE_NAME;

@UtilityClass
public class ProjectSettingsUtils {
    private static final Logger log = LoggerFactory.getLogger(ProjectSettingsUtils.class);

    public static ProjectSettings getProjectSettings(Project project) {
        PropertiesComponent propertiesComponent = PropertiesComponent.getInstance(project);
        return getFromProperties(propertiesComponent);
    }

    private static ProjectSettings getFromProperties(PropertiesComponent propertiesComponent) {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, Object> properties = new HashMap<>();
        List.of("iacDirectory", "replacePattern", "dotEnvFile", "azureDevOpsVariableGroups",
                        "azureReleaseDefinitionId", "azureReleaseStageName", "preBuildScript",
                        "dockerFilePath", "buildContextPath", "buildCommand")
                .forEach(key -> properties.put(key, propertiesComponent.getValue(key)));
        List.of("replaceTokens")
                .forEach(key -> properties.put(key, propertiesComponent.getBoolean(key, false)));
        return mapper.convertValue(properties, ProjectSettings.class);
    }

    @SuppressWarnings("unchecked")
    public static void toProperties(ProjectSettings projectSettings, PropertiesComponent propertiesComponent) {
        ObjectMapper mapper = new ObjectMapper();
        mapper.convertValue(projectSettings, Map.class)
                .forEach((key, value) -> {
                    if (value instanceof Boolean) {
                        propertiesComponent.setValue((String) key, (Boolean) value);
                    } else {
                        propertiesComponent.setValue((String) key, (String) value);
                    }
                });
    }

    public static void savePassword(String key, AzureCredentials azure) {
        CredentialAttributes attributes = new CredentialAttributes(SERVICE_NAME + "." + key);
        Credentials credentials = new Credentials(azure.getAzureDevOpsUsername(), azure.getAzureDevopsPassword());
        PasswordSafe.getInstance().set(attributes, credentials);
    }

    public static AzureCredentials getPassword(String key) {
        CredentialAttributes attributes = new CredentialAttributes(SERVICE_NAME + "." + key);
        try {
            Credentials credentials = PasswordSafe.getInstance().get(attributes);
            if (credentials != null) {
                return new AzureCredentials(credentials.getUserName(), credentials.getPasswordAsString());
            }
        } catch (NullPointerException e) {
            log.warn("Error getting credentials", e);
        }
        return new AzureCredentials("", "");
    }
}
