package co.com.bancolombia.devsecopsenginetools.configuration;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class GlobalSettingsTest {
    @Test
    public void shouldLoadState() {
        // Arrange
        GlobalSettings settings = GlobalSettings.getInstance().getState();
        GlobalSettings settingsToLoad = GlobalSettings.getInstance();
        assert settings.equals(settingsToLoad);
        settingsToLoad.setScanIacCommand("SCAN");
        // Act
        settings.loadState(settingsToLoad);
        // Assert
        assertEquals("SCAN", settings.getScanIacCommand());
    }
}
