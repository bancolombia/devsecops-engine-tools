package co.com.bancolombia.devsecopsenginetools.utils;

import co.com.bancolombia.devsecopsenginetools.ui.tool.LogPanelLogger;
import lombok.experimental.UtilityClass;
import org.apache.commons.io.file.PathUtils;

import java.io.IOException;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.function.Function;

@UtilityClass
public class FileUtils {

    public static void deleteDirectory(Path directory) throws IOException {
        PathUtils.deleteDirectory(directory);
    }

    public static void copyDirectory(Path source, Path target) throws IOException {
        PathUtils.copyDirectory(source, target);
    }

    public static void walkDirectory(Path start, Function<String, String> action) throws IOException {
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
        if(!Files.exists(path)) {
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
}
