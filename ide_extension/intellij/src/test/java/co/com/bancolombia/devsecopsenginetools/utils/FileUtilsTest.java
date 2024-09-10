package co.com.bancolombia.devsecopsenginetools.utils;

import com.intellij.ide.util.PropertiesComponent;
import com.intellij.openapi.project.Project;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.ResourceBundle;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class FileUtilsTest {
    @Rule
    public TemporaryFolder temporaryFolder = new TemporaryFolder();
    private Path tempDir;

    @Before
    public void setUp() throws IOException {
        tempDir = temporaryFolder.newFolder("tempDir").toPath();
    }

    @Test
    public void shouldDeleteDir() throws IOException {
        // Arrange
        Path dir1 = tempDir.resolve("dir1");
        Path dir2 = dir1.resolve("dir2");
        Files.createDirectories(dir2);

        Path file1 = dir1.resolve("file1.txt");
        Path file2 = dir2.resolve("file2.txt");
        Files.createFile(file1);
        Files.createFile(file2);

        assertTrue(Files.exists(dir1));
        assertTrue(Files.exists(dir2));
        assertTrue(Files.exists(file1));
        assertTrue(Files.exists(file2));

        // Act
        FileUtils.deleteDirectory(tempDir);

        // Assert
        assertFalse(Files.exists(tempDir));
    }

    @Test
    public void shouldCopyDir() throws IOException {
        // Arrange
        Path source = tempDir.resolve("source");
        Path destination = tempDir.resolve("destination");

        Path subDir = source.resolve("dir2");
        Files.createDirectories(subDir);

        Path file1 = source.resolve("file1.txt");
        Path file2 = subDir.resolve("file2.txt");
        Files.createFile(file1);
        Files.createFile(file2);

        assertTrue(Files.exists(source));
        assertTrue(Files.exists(subDir));
        assertTrue(Files.exists(file1));
        assertTrue(Files.exists(file2));

        // Act
        FileUtils.copyDirectory(source, destination);

        // Assert
        assertTrue(Files.exists(destination));
        assertTrue(Files.exists(destination.resolve("source").resolve("dir2")));
        assertTrue(Files.exists(destination.resolve("source").resolve("file1.txt")));
        assertTrue(Files.exists(destination.resolve("source").resolve("dir2").resolve("file2.txt")));
    }

    @Test
    public void shouldApplyChangesToAllFiles() throws IOException {
        // Arrange
        Path dir = tempDir.resolve("sample");

        Path subDir = dir.resolve("dir2");
        Files.createDirectories(subDir);

        Path file1 = dir.resolve("file1.txt");
        Path file2 = subDir.resolve("file2.txt");
        Files.createFile(file1);
        Files.createFile(file2);

        // Act
        FileUtils.walkDirectory(dir, string -> string + "MODIFIED");

        // Assert
        assertEquals("MODIFIED", Files.readString(file1));
        assertEquals("MODIFIED", Files.readString(file2));
    }

    @Test
    public void shouldReadDotEnv() throws IOException {
        // Arrange
        Path dotEnv = tempDir.resolve(".env");
        Files.createFile(dotEnv);
        Files.writeString(dotEnv, "KEY1=VALUE1\nKEY2=VALUE2\n#COMMENT\nKEY3=VALUE3");

        // Act
        Map<String, String> env = FileUtils.readEnvFile(dotEnv);

        // Assert
        assertEquals(3, env.size());
        assertEquals("VALUE1", env.get("KEY1"));
        assertEquals("VALUE2", env.get("KEY2"));
        assertEquals("VALUE3", env.get("KEY3"));
    }

    @Test
    public void shouldWriteDotEnv() throws IOException {
        // Arrange
        Path dotEnv = tempDir.resolve(".env");
        Map<String, String> env = Map.of("KEY1", "VALUE1", "KEY2", "VALUE2", "KEY3", "VALUE3");
        // Act
        FileUtils.writeEnvFile(dotEnv, env);
        // Assert
        String content = Files.readString(dotEnv);
        assertTrue(content.contains("KEY1=VALUE1"));
        assertTrue(content.contains("KEY2=VALUE2"));
        assertTrue(content.contains("KEY3=VALUE3"));
    }

    @Test
    public void shouldLoadProperties() {
        // Act
        // Act
        ResourceBundle bundle = FileUtils.getProperties();
        // Assert
        assertEquals("https://dev.azure.com/{organization}/{project}/_apis/distributedtask/variablegroups?groupIds={groupIds}&api-version=7.1-preview.2",
                bundle.getString("azure-group-by-id"));
    }

    @Test
    public void shouldCopyIaCFiles() throws IOException {
        // Arrange
        Project project = mock(Project.class);
        PropertiesComponent propertiesComponent = mock(PropertiesComponent.class);
        when(project.getBasePath()).thenReturn(tempDir.toString());
        when(project.getService(PropertiesComponent.class)).thenReturn(propertiesComponent);
        when(propertiesComponent.getValue("iacDirectory")).thenReturn("source");
        when(propertiesComponent.getValue("dotEnvFile")).thenReturn(".env");
        when(propertiesComponent.getValue("replacePattern")).thenReturn("#{...}#");
        when(propertiesComponent.getBoolean(anyString(), anyBoolean())).thenReturn(true);

        Path source = tempDir.resolve("source");
        Path destination = tempDir.resolve("build").resolve("dev-sec-ops").resolve("iac");
        Path dotEnv = tempDir.resolve(".env");
        Files.write(dotEnv, "KEY1=VALUE1\nKEY2=VALUE2\n#COMMENT\nKEY3=VALUE3".getBytes());

        Path subDir = source.resolve("dir2");
        Files.createDirectories(subDir);

        Path file1 = source.resolve("file1.txt");
        Path file2 = subDir.resolve("file2.txt");
        Files.createFile(file1);
        Files.createFile(file2);

        assertTrue(Files.exists(source));
        assertTrue(Files.exists(subDir));
        assertTrue(Files.exists(file1));
        assertTrue(Files.exists(file2));

        // Act
        FileUtils.copyIaCFiles(project);
        // Assert
        assertTrue(Files.exists(destination));
        assertTrue(Files.exists(destination.resolve("source").resolve("dir2")));
        assertTrue(Files.exists(destination.resolve("source").resolve("file1.txt")));
        assertTrue(Files.exists(destination.resolve("source").resolve("dir2").resolve("file2.txt")));
    }

    @Test
    public void shouldFindDockerFile() throws IOException {
        // Arrange
        Path dir = tempDir.resolve("cloud").resolve("docker");
        Path dockerfile = dir.resolve("Dockerfile");
        Files.createDirectories(dir);
        Files.write(dockerfile, "FROM sample".getBytes());
        // Act
        String path = FileUtils.findDockerfile(tempDir.toString());
        // Assert
        assertEquals("cloud/docker/Dockerfile", path);
    }
}
