package co.com.bancolombia.devsecopsenginetools.ui.configuration;

import com.intellij.ide.util.PropertiesComponent;
import com.intellij.openapi.project.Project;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class ProjectConfigurationTest {

    @Mock
    private Project mockProject;
    @Mock
    private PropertiesComponent propertiesComponent;
    private ProjectConfiguration projectConfiguration;

    @Before
    public void setup() {
        when(mockProject.getService(PropertiesComponent.class)).thenReturn(propertiesComponent);
        projectConfiguration = new ProjectConfiguration(mockProject);
    }

    @Test
    public void shouldCreate() {
        // Arrange
        // Act
        String text = projectConfiguration.getDisplayName();
        String help = projectConfiguration.getHelpTopic();
        // Assert
        assertEquals("DevSecOps Engine Tools Configuration", text);
        assertEquals("Setup project settings for DevSecOps Engine Tools.", help);
        assertTrue(projectConfiguration.isModified());
    }
}
