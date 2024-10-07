package co.com.bancolombia.devsecopsenginetools.utils;

import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettings;
import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettingsUtils;
import co.com.bancolombia.devsecopsenginetools.ui.tool.LogPanelLogger;
import com.intellij.openapi.project.Project;
import lombok.experimental.UtilityClass;
import org.apache.commons.io.file.PathUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.ResourceBundle;
import java.util.function.UnaryOperator;

import static java.nio.file.StandardCopyOption.REPLACE_EXISTING;

@UtilityClass
public class FileUtils {

    public static void deleteDirectory(Path directory) throws IOException {
        PathUtils.deleteDirectory(directory);
    }

    public static void copyDirectory(Path source, Path target) throws IOException {
        Path finalTarget = Path.of(target.toString(), source.getFileName().toString());
        Files.createDirectories(finalTarget);
        PathUtils.copyDirectory(source, finalTarget, REPLACE_EXISTING);
    }

    public static void walkDirectory(Path start, UnaryOperator<String> action) throws IOException {
        Files.walkFileTree(start, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                LogPanelLogger.info("Processing file: " + file);
                Files.writeString(file, action.apply(Files.readString(file)));
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFileFailed(Path file, IOException exc) {
                LogPanelLogger.error("Failed to visit file: " + file, exc);
                return FileVisitResult.CONTINUE;
            }
        });
    }

    public static Map<String, String> readEnvFile(Path path) throws IOException {
        if (!Files.exists(path)) {
            return new HashMap<>();
        }
        List<String> lines = Files.readAllLines(path);
        Map<String, String> envMap = new HashMap<>();

        for (String line : lines) {
            if (line.trim().isEmpty() || line.startsWith("#")) {
                continue; // Skip empty lines and comments
            }

            String[] parts = line.split("=", 2);
            if (parts.length == 2) {
                String key = parts[0].trim();
                String value = parts[1].trim();
                envMap.put(key, value);
            }
        }

        return envMap;
    }

    public static void writeEnvFile(Path path, Map<String, String> env) throws IOException {
        List<String> lines = env.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .toList();
        Files.write(path, lines);
    }

    public static ResourceBundle getProperties() {
        return ResourceBundle.getBundle("plugin");
    }

    public static void copyIaCFiles(Project project) throws IOException {
        String projectPath = project.getBasePath() != null ? project.getBasePath() : "";
        Path iacDestination = Path.of(projectPath, "build", "dev-sec-ops", "iac");
        Files.createDirectories(iacDestination);
        FileUtils.deleteDirectory(iacDestination);
        ProjectSettings settings = ProjectSettingsUtils.getProjectSettings(project);
        for (String source : settings.getIacDirectory().split(",")) {
            Path iacSource = Path.of(projectPath, source);
            LogPanelLogger.info("Copying IaC files from " + iacSource + " to " + iacDestination);
            FileUtils.copyDirectory(iacSource, iacDestination);
        }
        if (settings.isReplaceTokens()) {
            LogPanelLogger.info("Replacing tokens in IaC files");
            Map<String, String> env = FileUtils.readEnvFile(Path.of(projectPath, settings.getDotEnvFile()));
            FileUtils.walkDirectory(iacDestination, content ->
                    DataUtils.replaceTokens(content, settings.getReplacePattern(), env));
        }
    }

    public static String findDockerfile(String projectPath) {
        String path = findDockerfile(new File(projectPath))
                .map(File::getAbsolutePath).orElse("").replace(projectPath, "");
        if (path.startsWith("/")) {
            return path.substring(1);
        }
        return path;
    }

    private static Optional<File> findDockerfile(File directory) {
        // List files and directories in the current directory
        File[] files = directory.listFiles();

        if (files != null) {
            for (File file : files) {
                // Check if the current file is Dockerfile
                if (file.isFile() && file.getName().equals("Dockerfile")) {
                    return Optional.of(file);
                }

                // If it's a directory, recursively search inside it
                if (file.isDirectory()) {
                    Optional<File> result = findDockerfile(file);
                    if (result.isPresent()) {
                        return result;
                    }
                }
            }
        }
        return Optional.empty();
    }
}
