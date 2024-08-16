package co.com.bancolombia.devsecopsenginetools.utils.variables.azure;


import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class AzureReleaseDefinitionResponse {
    private Map<String, AzureVariableGroupResponse.AzureVariableGroup.AzureVariable> variables;
    private List<Long> variableGroups;
    private List<Environment> environments;

    @Data
    public static class Environment {
        private String name;
        private Map<String, AzureVariableGroupResponse.AzureVariableGroup.AzureVariable> variables;
        private List<Long> variableGroups;
    }
}
