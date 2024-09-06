package co.com.bancolombia.devsecopsenginetools.configuration;

import com.intellij.credentialStore.CredentialAttributes;
import com.intellij.credentialStore.Credentials;
import com.intellij.ide.passwordSafe.PasswordSafe;
import com.intellij.ide.util.PropertiesComponent;
import com.intellij.openapi.project.Project;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class ProjectSettingsUtilsTest {
    @Mock
    private Project project;
    @Mock
    private PropertiesComponent propertiesComponent;
    @Mock
    private Credentials credentials;

    @Test
    public void shouldGetProjectSettings() {
        // Arrange
        when(project.getService(PropertiesComponent.class)).thenReturn(propertiesComponent);
        when(propertiesComponent.getValue(anyString())).thenReturn("mocked");
        // Act
        ProjectSettings settings = ProjectSettingsUtils.getProjectSettings(project);
        // Assert
        assertEquals("mocked", settings.getIacDirectory());
        assertFalse(settings.isReplaceTokens());
    }

    @Test
    public void shouldSetProjectSettings() {
        // Arrange
        when(project.getService(PropertiesComponent.class)).thenReturn(propertiesComponent);
        when(propertiesComponent.getValue(anyString())).thenReturn("mocked");
        ProjectSettings settings = ProjectSettingsUtils.getProjectSettings(project);
        // Act
        ProjectSettingsUtils.toProperties(settings, propertiesComponent);
        // Assert
        verify(propertiesComponent, times(1)).setValue("iacDirectory", "mocked");
        verify(propertiesComponent, times(1)).setValue("replaceTokens", false);
    }

    @Test
    public void shouldGetPassword() {
        // Arrange
        String mocked = "mocked";
        String mockedPass = "mockedPass";
        try (MockedStatic<PasswordSafe> mockedPasswordSafe = Mockito.mockStatic(PasswordSafe.class)) {
            PasswordSafe mockPasswordSafe = mock(PasswordSafe.class);
            mockedPasswordSafe.when(PasswordSafe::getInstance).thenReturn(mockPasswordSafe);
            when(mockPasswordSafe.get(any(CredentialAttributes.class))).thenReturn(credentials);
            when(credentials.getUserName()).thenReturn(mocked);
            when(credentials.getPasswordAsString()).thenReturn(mockedPass);
            // Act
            AzureCredentials credentials = ProjectSettingsUtils.getPassword("azure");
            // Assert
            assertEquals(mocked, credentials.getAzureDevOpsUsername());
            assertEquals(mockedPass, credentials.getAzureDevopsPassword());
        }
    }

    @Test
    public void shouldGetEmptyPassword() {
        // Arrange
        // Act
        AzureCredentials credentials = ProjectSettingsUtils.getPassword("azure");
        // Assert
        assertEquals("", credentials.getAzureDevOpsUsername());
        assertEquals("", credentials.getAzureDevopsPassword());
    }

    @Test
    public void shouldSavePassword() {
        // Arrange
        String mocked = "mocked";
        String mockedPass = "mockedPass";
        AzureCredentials credentials = new AzureCredentials(mocked, mockedPass);
        try (MockedStatic<PasswordSafe> mockedPasswordSafe = Mockito.mockStatic(PasswordSafe.class)) {
            PasswordSafe mockPasswordSafe = mock(PasswordSafe.class);
            mockedPasswordSafe.when(PasswordSafe::getInstance).thenReturn(mockPasswordSafe);
            // Act
            ProjectSettingsUtils.savePassword("azure", credentials);
            // Assert
            verify(mockPasswordSafe, times(1))
                    .set(any(CredentialAttributes.class), any(Credentials.class));
        }
    }

}
