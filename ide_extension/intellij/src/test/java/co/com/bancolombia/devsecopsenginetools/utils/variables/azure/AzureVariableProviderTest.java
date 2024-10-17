package co.com.bancolombia.devsecopsenginetools.utils.variables.azure;

import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettings;
import co.com.bancolombia.devsecopsenginetools.utils.http.HttpClient;
import co.com.bancolombia.devsecopsenginetools.utils.variables.Variable;
import co.com.bancolombia.devsecopsenginetools.utils.variables.VariableProvider;
import co.com.bancolombia.devsecopsenginetools.utils.variables.azure.AzureVariableGroupResponse.AzureVariableGroup;
import co.com.bancolombia.devsecopsenginetools.utils.variables.azure.AzureVariableGroupResponse.AzureVariableGroup.AzureVariable;
import co.com.bancolombia.devsecopsenginetools.utils.variables.azure.exceptions.VariableGroupNotFoundException;
import com.intellij.openapi.project.Project;
import org.jetbrains.annotations.NotNull;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class AzureVariableProviderTest {
    private static final long GROUP_ID_RELEASE_1 = 12345L;
    private static final long GROUP_ID_RELEASE_2 = 67890L;
    private static final long GROUP_ID_ENV_1 = 9876L;
    private static final long GROUP_ID_ENV_2 = 54321L;
    @Mock
    private HttpClient httpClient;
    @Mock
    private Project project;
    private VariableProvider provider;

    @Before
    public void setUp() {
        ProjectSettings settings = new ProjectSettings();
        when(project.getBasePath()).thenReturn("");
        settings.fillIfDefaults(project);
        settings.setDotEnvFile("build/.env");
        settings.setAzureDevOpsVariableGroups("group1");
        settings.setAzureReleaseDefinitionId("123");
        settings.setAzureReleaseStageName("stage1");
        provider = new AzureVariableProvider(settings, httpClient);
    }

    // Assert
    @Test(expected = VariableGroupNotFoundException.class)
    public void shouldFailGettingVariableGroupByName() {
        // Arrange
        doAnswer(invocation -> {
            String url = invocation.getArgument(0, String.class);
            if (url.contains("group1")) {
                return getAzureVariableGroupResponseMock(0, 0);
            }
            throw new RuntimeException("Unexpected URL");
        }).when(httpClient).get(anyString(), any(), any());
        // Act
        provider.getVariables();
    }

    // Assert
    @Test(expected = VariableGroupNotFoundException.class)
    public void shouldFailGettingVariableGroupById() {
        // Arrange
        doAnswer(invocation -> {
            String url = invocation.getArgument(0, String.class);
            if (url.contains("group1")) {
                return getAzureVariableGroupResponseMock(1, 1);
            }
            if (url.contains("release")) {
                return getAzureReleaseDefinitionResponseMock(true);
            }
            if (url.contains("groupIds")) {
                return getAzureVariableGroupResponseMock(0, 7);
            }
            throw new RuntimeException("Unexpected URL");
        }).when(httpClient).get(anyString(), any(), any());
        // Act
        provider.getVariables();
    }

    // Assert
    @Test(expected = VariableGroupNotFoundException.class)
    public void shouldFailGettingVariablesWhenNoStageExists() {
        // Arrange
        doAnswer(invocation -> {
            String url = invocation.getArgument(0, String.class);
            if (url.contains("group1")) {
                return getAzureVariableGroupResponseMock(1, 1);
            }
            if (url.contains("release")) {
                return getAzureReleaseDefinitionResponseMock(false);
            }
            throw new RuntimeException("Unexpected URL");
        }).when(httpClient).get(anyString(), any(), any());
        // Act
        provider.getVariables();
    }

    @Test
    public void shouldGetVariables() {
        // Arrange
        doAnswer(invocation -> {
            String url = invocation.getArgument(0, String.class);
            if (url.contains("group1")) {
                return getAzureVariableGroupResponseMock(1, 1);
            }
            if (url.contains("release")) {
                return getAzureReleaseDefinitionResponseMock(true);
            }
            if (url.contains("groupIds")) {
                return getAzureVariableGroupResponseMock(4, 7);
            }
            throw new RuntimeException("Unexpected URL");
        }).when(httpClient).get(anyString(), any(), any());
        // Act
        List<Variable> variables = provider.getVariables();
        // Assert
        assertEquals(14, variables.size());
    }

    private static @NotNull AzureVariableGroupResponse getAzureVariableGroupResponseMock(int groups, long idx) {
        AzureVariableGroupResponse azureVariableGroupResponse = new AzureVariableGroupResponse();
        azureVariableGroupResponse.setValue(new ArrayList<>());
        for (int i = 0; i < groups; i++) {
            long current = idx + (i * 2L);
            Map<String, AzureVariable> variables = getStringAzureVariableMap(current);

            AzureVariableGroup variableGroup = new AzureVariableGroup();
            variableGroup.setName("group" + current);
            variableGroup.setId(idx);
            variableGroup.setVariables(variables);

            azureVariableGroupResponse.getValue().add(variableGroup);
        }
        return azureVariableGroupResponse;
    }

    private static @NotNull Map<String, AzureVariable> getStringAzureVariableMap(long current) {
        long currentNext = current + 1;
        AzureVariable variable1 = new AzureVariable();
        variable1.setValue("value" + current);
        AzureVariable variable2 = new AzureVariable();
        variable2.setValue("value" + currentNext);
        return Map.of("variable" + current, variable1, "variable" + currentNext, variable2);
    }

    private static @NotNull AzureReleaseDefinitionResponse getAzureReleaseDefinitionResponseMock(boolean existing) {
        AzureVariable variable3 = new AzureVariable();
        variable3.setValue("value3");
        AzureVariable variable4 = new AzureVariable();
        variable4.setValue("value4");
        Map<String, AzureVariable> variables = Map.of("variable3", variable3, "variable4", variable4);

        AzureVariable variable5 = new AzureVariable();
        variable3.setValue("value5");
        AzureVariable variable6 = new AzureVariable();
        variable4.setValue("value6");
        Map<String, AzureVariable> variablesEnv = Map.of("variable5", variable5, "variable6", variable6);

        AzureReleaseDefinitionResponse.Environment environment = new AzureReleaseDefinitionResponse.Environment();
        environment.setVariables(variablesEnv);
        environment.setVariableGroups(List.of(GROUP_ID_ENV_1, GROUP_ID_ENV_2));
        if (existing) {
            environment.setName("stage1");
        } else {
            environment.setName("stage2");
        }

        AzureReleaseDefinitionResponse azureReleaseDefinitionResponse = new AzureReleaseDefinitionResponse();
        azureReleaseDefinitionResponse.setVariableGroups(List.of(GROUP_ID_RELEASE_1, GROUP_ID_RELEASE_2));
        azureReleaseDefinitionResponse.setVariables(variables);
        azureReleaseDefinitionResponse.setEnvironments(List.of(environment));

        return azureReleaseDefinitionResponse;
    }
}
