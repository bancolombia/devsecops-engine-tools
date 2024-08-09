package co.com.bancolombia.devsecopsenginetools.utils.variables.azure;

import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettings;
import co.com.bancolombia.devsecopsenginetools.utils.http.HttpClient;
import co.com.bancolombia.devsecopsenginetools.utils.variables.Variable;
import co.com.bancolombia.devsecopsenginetools.utils.variables.VariableProvider;
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

    @Test
    public void shouldGetVariables() {
        // Arrange
        doAnswer(invocation -> {
            String url = invocation.getArgument(0, String.class);
            if (url.contains("group1")) {
                return getAzureVariableGroupResponseMock(1, 1);
            }
            if (url.contains("release")) {
                return getAzureReleaseDefinitionResponseMock();
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
            long currentNext = current + 1;
            AzureVariableGroupResponse.AzureVariableGroup.AzureVariable variable1 = new AzureVariableGroupResponse.AzureVariableGroup.AzureVariable();
            variable1.setValue("value" + current);
            AzureVariableGroupResponse.AzureVariableGroup.AzureVariable variable2 = new AzureVariableGroupResponse.AzureVariableGroup.AzureVariable();
            variable2.setValue("value" + currentNext);
            Map<String, AzureVariableGroupResponse.AzureVariableGroup.AzureVariable> variables = Map.of("variable" + current, variable1, "variable" + currentNext, variable2);

            AzureVariableGroupResponse.AzureVariableGroup variableGroup = new AzureVariableGroupResponse.AzureVariableGroup();
            variableGroup.setName("group" + current);
            variableGroup.setId(idx);
            variableGroup.setVariables(variables);

            azureVariableGroupResponse.getValue().add(variableGroup);
        }
        return azureVariableGroupResponse;
    }

    private static @NotNull AzureReleaseDefinitionResponse getAzureReleaseDefinitionResponseMock() {
        AzureVariableGroupResponse.AzureVariableGroup.AzureVariable variable3 = new AzureVariableGroupResponse.AzureVariableGroup.AzureVariable();
        variable3.setValue("value3");
        AzureVariableGroupResponse.AzureVariableGroup.AzureVariable variable4 = new AzureVariableGroupResponse.AzureVariableGroup.AzureVariable();
        variable4.setValue("value4");
        Map<String, AzureVariableGroupResponse.AzureVariableGroup.AzureVariable> variables = Map.of("variable3", variable3, "variable4", variable4);

        AzureVariableGroupResponse.AzureVariableGroup.AzureVariable variable5 = new AzureVariableGroupResponse.AzureVariableGroup.AzureVariable();
        variable3.setValue("value5");
        AzureVariableGroupResponse.AzureVariableGroup.AzureVariable variable6 = new AzureVariableGroupResponse.AzureVariableGroup.AzureVariable();
        variable4.setValue("value6");
        Map<String, AzureVariableGroupResponse.AzureVariableGroup.AzureVariable> variablesEnv = Map.of("variable5", variable5, "variable6", variable6);

        AzureReleaseDefinitionResponse.Environment environment = new AzureReleaseDefinitionResponse.Environment();
        environment.setVariables(variablesEnv);
        environment.setVariableGroups(List.of(GROUP_ID_ENV_1, GROUP_ID_ENV_2));
        environment.setName("stage1");

        AzureReleaseDefinitionResponse azureReleaseDefinitionResponse = new AzureReleaseDefinitionResponse();
        azureReleaseDefinitionResponse.setVariableGroups(List.of(GROUP_ID_RELEASE_1, GROUP_ID_RELEASE_2));
        azureReleaseDefinitionResponse.setVariables(variables);
        azureReleaseDefinitionResponse.setEnvironments(List.of(environment));

        return azureReleaseDefinitionResponse;
    }
}
