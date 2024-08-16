package co.com.bancolombia.devsecopsenginetools.utils.variables.azure;

import co.com.bancolombia.devsecopsenginetools.configuration.AzureCredentials;
import co.com.bancolombia.devsecopsenginetools.configuration.GlobalSettings;
import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettings;
import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettingsUtils;
import co.com.bancolombia.devsecopsenginetools.ui.tool.LogPanelLogger;
import co.com.bancolombia.devsecopsenginetools.utils.DataUtils;
import co.com.bancolombia.devsecopsenginetools.utils.FileUtils;
import co.com.bancolombia.devsecopsenginetools.utils.http.AuthMethod;
import co.com.bancolombia.devsecopsenginetools.utils.http.HttpClient;
import co.com.bancolombia.devsecopsenginetools.utils.variables.Variable;
import co.com.bancolombia.devsecopsenginetools.utils.variables.VariableProvider;
import co.com.bancolombia.devsecopsenginetools.utils.variables.azure.AzureVariableGroupResponse.AzureVariableGroup;
import co.com.bancolombia.devsecopsenginetools.utils.variables.azure.AzureVariableGroupResponse.AzureVariableGroup.AzureVariable;
import co.com.bancolombia.devsecopsenginetools.utils.variables.azure.exceptions.VariableGroupNotFoundException;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Collectors;

import static co.com.bancolombia.devsecopsenginetools.utils.Constants.AZURE_CREDENTIALS;
import static co.com.bancolombia.devsecopsenginetools.utils.Constants.DEFAULT_URL_PATTERN;

@RequiredArgsConstructor
public class AzureVariableProvider implements VariableProvider {
    public static final String ORGANIZATION = "organization";
    public static final String PROJECT = "project";
    public static final String FROM = "' from: ";
    public static final String VARIABLE_GROUP = "Variable group '";
    private final ProjectSettings settings;
    private final HttpClient httpClient;

    @Override
    public List<Variable> getVariables() {
        List<Variable> variables = new ArrayList<>();
        List<AzureVariableGroupResponse.AzureVariableGroup> groups = new ArrayList<>();
        if (StringUtils.isNotEmpty(settings.getAzureDevOpsVariableGroups())) {
            List<String> groupNames = List.of(settings.getAzureDevOpsVariableGroups().split(","));
            LogPanelLogger.info("Downloading " + groupNames.size() + " variable groups");
            groups.addAll(getVariableGroupsByName(groupNames));
        }
        if (StringUtils.isNotEmpty(settings.getAzureReleaseDefinitionId()) &&
                StringUtils.isNotEmpty(settings.getAzureReleaseStageName())) {
            Map<String, AzureVariable> azureVariables = getVariablesFromReleaseAndStage(settings);
            AzureVariableGroupResponse.AzureVariableGroup group = new AzureVariableGroupResponse.AzureVariableGroup();
            group.setName("Release and Stage");
            group.setVariables(azureVariables);
            groups.add(group);
        }
        groups.forEach(group -> group.getVariables().forEach((key, value) -> {
            if (!value.isSecret()) {
                variables.add(Variable.builder().name(key).value(value.getValue()).build());
            }
        }));
        return variables;
    }

    public List<AzureVariableGroup> getVariableGroupsByName(List<String> groups) {
        GlobalSettings globalSettings = GlobalSettings.getInstance();
        AzureCredentials credentials = ProjectSettingsUtils.getPassword(AZURE_CREDENTIALS);
        AuthMethod auth = DataUtils.toBasicAuth(credentials.getAzureDevOpsUsername(), credentials.getAzureDevopsPassword());

        String endpoint = FileUtils.getProperties().getString("azure-group-by-name");

        return groups.stream().map(group -> {
                    String url = DataUtils.replaceTokens(endpoint, DEFAULT_URL_PATTERN,
                            Map.of(ORGANIZATION, DataUtils.urlEncode(globalSettings.getAzureDevOpsOrganization()),
                                    PROJECT, DataUtils.urlEncode(globalSettings.getAzureDevOpsProject()),
                                    "groupName", group));

                    LogPanelLogger.info("Downloading variable group '" + group + FROM + url);

                    AzureVariableGroupResponse res = httpClient.get(url, AzureVariableGroupResponse.class, auth);
                    if (res.getValue().isEmpty()) {
                        throw new VariableGroupNotFoundException(VARIABLE_GROUP + group + "' not found");
                    }
                    LogPanelLogger.info(VARIABLE_GROUP + group + "' downloaded");
                    return res.getValue().get(0);
                })
                .collect(Collectors.toList());
    }

    public List<AzureVariableGroup> getVariableGroupsById(List<Long> groups) {
        GlobalSettings globalSettings = GlobalSettings.getInstance();
        AzureCredentials credentials = ProjectSettingsUtils.getPassword(AZURE_CREDENTIALS);
        AuthMethod auth = DataUtils.toBasicAuth(credentials.getAzureDevOpsUsername(), credentials.getAzureDevopsPassword());

        List<String> groupsStr = groups.stream()
                .map(String::valueOf)
                .toList();

        String groupIds = String.join(",", groupsStr);

        String endpoint = FileUtils.getProperties().getString("azure-group-by-id");

        String url = DataUtils.replaceTokens(endpoint, DEFAULT_URL_PATTERN,
                Map.of(ORGANIZATION, DataUtils.urlEncode(globalSettings.getAzureDevOpsOrganization()),
                        PROJECT, DataUtils.urlEncode(globalSettings.getAzureDevOpsProject()),
                        "groupIds", groupIds));

        LogPanelLogger.info("Downloading variable groups '" + groupIds + FROM + url);

        AzureVariableGroupResponse res = httpClient.get(url, AzureVariableGroupResponse.class, auth);
        if (res.getValue().isEmpty()) {
            throw new VariableGroupNotFoundException(VARIABLE_GROUP + groupIds + "' not found");
        }
        return res.getValue().stream()
                .peek(group -> LogPanelLogger.info(VARIABLE_GROUP + group.getId() + "' downloaded"))
                .toList();
    }


    public Map<String, AzureVariable> getVariablesFromReleaseAndStage(ProjectSettings projectSettings) {
        GlobalSettings globalSettings = GlobalSettings.getInstance();
        AzureCredentials credentials = ProjectSettingsUtils.getPassword(AZURE_CREDENTIALS);
        AuthMethod auth = DataUtils.toBasicAuth(credentials.getAzureDevOpsUsername(), credentials.getAzureDevopsPassword());

        String endpoint = FileUtils.getProperties().getString("azure-release");

        String url = DataUtils.replaceTokens(endpoint, DEFAULT_URL_PATTERN,
                Map.of(ORGANIZATION, DataUtils.urlEncode(globalSettings.getAzureDevOpsOrganization()),
                        PROJECT, DataUtils.urlEncode(globalSettings.getAzureDevOpsProject()),
                        "definitionId", projectSettings.getAzureReleaseDefinitionId()));

        LogPanelLogger.info("Downloading variable groups from release '" +
                projectSettings.getAzureReleaseDefinitionId() + "' and stage name '" +
                projectSettings.getAzureReleaseStageName() + FROM + url);

        AzureReleaseDefinitionResponse res = httpClient.get(url, AzureReleaseDefinitionResponse.class, auth);
        AzureReleaseDefinitionResponse.Environment env = getEnvironment(projectSettings, res);
        List<Long> variableGroups = new ArrayList<>();
        variableGroups.addAll(res.getVariableGroups()); // Release groups
        variableGroups.addAll(env.getVariableGroups()); // Environment groups

        Map<String, AzureVariable> variableMaps = new TreeMap<>();
        variableMaps.putAll(res.getVariables()); // Release variables
        variableMaps.putAll(env.getVariables()); // Environment variables

        for (AzureVariableGroup group : getVariableGroupsById(variableGroups)) { // Get all groups
            variableMaps.putAll(group.getVariables());
        }
        return variableMaps;
    }

    private static AzureReleaseDefinitionResponse.@NotNull Environment getEnvironment(ProjectSettings projectSettings, AzureReleaseDefinitionResponse res) {
        AzureReleaseDefinitionResponse.Environment env = null;
        for (int i = 0; i < res.getEnvironments().size(); i++) {
            AzureReleaseDefinitionResponse.Environment environment = res.getEnvironments().get(i);
            if (environment.getName().equals(projectSettings.getAzureReleaseStageName())) {
                env = environment;
                break;
            }
        }
        if (env == null) {
            throw new VariableGroupNotFoundException("Stage '" + projectSettings.getAzureReleaseStageName() +
                    "' not found in release '" + projectSettings.getAzureReleaseDefinitionId() + "'");
        }
        return env;
    }
}
