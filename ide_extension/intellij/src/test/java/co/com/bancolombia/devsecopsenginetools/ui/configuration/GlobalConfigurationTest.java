package co.com.bancolombia.devsecopsenginetools.ui.configuration;

import co.com.bancolombia.devsecopsenginetools.configuration.AzureCredentials;
import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettingsUtils;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mockStatic;

@RunWith(MockitoJUnitRunner.class)
public class GlobalConfigurationTest {
    private GlobalConfiguration globalConfiguration;

    @Before
    public void setup() {
        globalConfiguration = new GlobalConfiguration();
    }

    @Test
    public void shouldCreate() {
        // Arrange
        // Act
        String text = globalConfiguration.getDisplayName();
        String help = globalConfiguration.getHelpTopic();
        // Assert
        assertEquals("DevSecOps Engine Tools Configuration", text);
        assertEquals("Setup page for DevSecOps Engine Tools and Azure connection details.", help);
        assertTrue(globalConfiguration.isModified());
    }

    @Test
    public void shouldApply() {
        // Arrange
        try (MockedStatic<ProjectSettingsUtils> projectSettingsUtils = mockStatic(ProjectSettingsUtils.class)) {
            projectSettingsUtils.when(() -> ProjectSettingsUtils.savePassword(anyString(), any(AzureCredentials.class)))
                    .thenAnswer(invocation -> null);
            // Act
            globalConfiguration.apply();
            // Assert
            projectSettingsUtils.verify(() -> ProjectSettingsUtils.savePassword(anyString(), any(AzureCredentials.class)));
        }
    }
}
