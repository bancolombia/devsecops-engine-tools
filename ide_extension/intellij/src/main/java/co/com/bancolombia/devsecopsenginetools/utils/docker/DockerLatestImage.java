package co.com.bancolombia.devsecopsenginetools.utils.docker;

import co.com.bancolombia.devsecopsenginetools.configuration.GlobalSettings;
import co.com.bancolombia.devsecopsenginetools.ui.tool.LogPanelLogger;
import co.com.bancolombia.devsecopsenginetools.utils.FileUtils;
import co.com.bancolombia.devsecopsenginetools.utils.http.HttpClient;
import lombok.RequiredArgsConstructor;
import lombok.extern.java.Log;

import java.util.Optional;
import java.util.logging.Level;

@Log
@RequiredArgsConstructor
public class DockerLatestImage {
    private final GlobalSettings settings;
    private final HttpClient httpClient;

    public String getLatestImage() {
        String image = settings.getDevSecOpsImage();
        Optional<String> latestTag = getLatestTag();
        return latestTag.map(tag -> {
            String resolved = injectTag(image, tag);
            LogPanelLogger.success("Latest scan image resolved: " + resolved);
            return resolved;
        }).orElse(image);
    }

    private String injectTag(String image, String tag) {
        String[] parts = image.split(":");
        parts[parts.length - 1] = tag;
        return String.join(":", parts);
    }

    private Optional<String> getLatestTag() {
        try {
            String endpoint = FileUtils.getProperties().getString("docker-tags");
            Tags tags = httpClient.get(endpoint, Tags.class);
            if (tags != null && tags.getResults() != null && !tags.getResults().isEmpty()) {
                return Optional.of(tags.getResults().get(0).getName());
            }
        } catch (Exception ex) {
            log.log(Level.ALL, "Error getting latest image tag: ", ex);
            LogPanelLogger.warn("Error getting latest image, current will be used", ex);
        }
        return Optional.empty();
    }
}