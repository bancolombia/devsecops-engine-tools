package co.com.bancolombia.devsecopsenginetools.configuration;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class AzureCredentials {
    private String azureDevOpsUsername;
    private String azureDevopsPassword;
}
