package co.com.bancolombia.devsecopsenginetools.utils.docker;

import co.com.bancolombia.devsecopsenginetools.configuration.GlobalSettings;
import co.com.bancolombia.devsecopsenginetools.utils.http.HttpClient;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import java.util.List;

import static co.com.bancolombia.devsecopsenginetools.utils.Constants.DEFAULT_IMAGE;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class DockerLatestImageTest {
    @Mock
    private GlobalSettings globalSettings;
    @Mock
    private HttpClient httpClient;

    @InjectMocks
    private DockerLatestImage dockerLatestImage;

    @Test
    public void shouldGetLatestImage() {
        // Arrange
        Tags tags = new Tags();
        Tags.Tag tag = new Tags.Tag();
        tag.setName("100.100.100");
        tags.setResults(List.of(tag));
        when(httpClient.get(anyString(), any())).thenReturn(tags);
        when(globalSettings.getDevSecOpsImage()).thenReturn(DEFAULT_IMAGE);
        // Act
        String latest = dockerLatestImage.getLatestImage();
        // Assert
        assertEquals("bancolombia/devsecops-engine-tools:100.100.100", latest);
    }

    @Test
    public void shouldReturnDefaultWhenNoResponseGettingLatestImage() {
        // Arrange
        when(httpClient.get(anyString(), any())).thenReturn(new Tags());
        when(globalSettings.getDevSecOpsImage()).thenReturn(DEFAULT_IMAGE);
        // Act
        String latest = dockerLatestImage.getLatestImage();
        // Assert
        assertEquals(DEFAULT_IMAGE, latest);
    }

    @Test
    public void shouldReturnDefaultWhenErrorGettingLatestImage() {
        // Arrange
        when(httpClient.get(anyString(), any())).thenThrow(new RuntimeException());
        when(globalSettings.getDevSecOpsImage()).thenReturn(DEFAULT_IMAGE);
        // Act
        String latest = dockerLatestImage.getLatestImage();
        // Assert
        assertEquals(DEFAULT_IMAGE, latest);
    }
}
