package co.com.bancolombia.devsecopsenginetools.utils.variables;

import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettings;
import com.intellij.openapi.project.Project;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.io.IOException;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class DotEnvGeneratorTest {
    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();

    @Mock
    private Project project;
    @Mock
    private VariableProvider provider;

    @Test
    public void testUpdateDotEnv() throws IOException {
        // Arrange
        String root = temporaryFolder.newFolder("tempDir").getAbsolutePath();
        when(provider.getVariables()).thenReturn(List.of(
                Variable.builder().name("name").value("value").build(),
                Variable.builder().name("name2").value("value2").build())
        );
        when(project.getBasePath()).thenReturn(root);
        ProjectSettings settings = new ProjectSettings();
        settings.fillIfDefaults(project);
        // Act
        String res = DotEnvGenerator.updateDotEnv(root, settings, provider);
        // Assert
        assertEquals("✔ Writing .env with 2 entries", res);
    }
}
