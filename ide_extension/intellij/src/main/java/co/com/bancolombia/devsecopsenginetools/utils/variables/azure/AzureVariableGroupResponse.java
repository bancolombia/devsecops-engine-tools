package co.com.bancolombia.devsecopsenginetools.utils.variables.azure;

import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class AzureVariableGroupResponse {
    private List<AzureVariableGroup> value;

    @Data
    public static class AzureVariableGroup {
        private Long id;
        private String name;
        private Map<String, AzureVariable> variables;

        @Data
        public static class AzureVariable {
            private String value;
            private boolean isSecret;
        }
    }
}
