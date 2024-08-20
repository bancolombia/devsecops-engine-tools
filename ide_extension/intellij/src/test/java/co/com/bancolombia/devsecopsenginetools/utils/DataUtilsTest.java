package co.com.bancolombia.devsecopsenginetools.utils;


import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.assertEquals;


public class DataUtilsTest {

    @Test
    public void shouldReplaceTokens() {
        // Arrange
        String content = "my #{text}# variable is #{replaced}# successfully with #{values}# instead of #{text}#";
        String pattern = "#{...}#";
        Map<String, String> env = Map.of("text", "text", "replaced", "replaced", "values", "values");
        // Act
        String result = DataUtils.replaceTokens(content, pattern, env);
        // Assert
        assertEquals("my text variable is replaced successfully with values instead of text", result);
    }

    @Test
    public void shouldReplaceTokensWhenNotExistVariable() {
        // Arrange
        String content = "my #{empty}# variable will be replaced too";
        String pattern = "#{...}#";
        Map<String, String> env = Map.of();
        // Act
        String result = DataUtils.replaceTokens(content, pattern, env);
        // Assert
        assertEquals("my  variable will be replaced too", result);
    }

    @Test
    public void shouldRemovePrefixes() {
        // Arrange
        String paths = "/my/project/path/resources,/my/project/path/deployment";
        String root = "/my/project/path/";
        String expected = "resources,deployment";
        // Act
        String result = DataUtils.removeRoot(root, paths);
        // Assert
        assertEquals(expected, result);
    }

    @Test
    public void shouldEncode() {
        // Arrange
        String value = "Group Name";
        // Act
        String result = DataUtils.urlEncode(value);
        // Assert
        assertEquals("Group%20Name", result);
    }

    @Test
    public void shouldNotEncodeWhenAlreadyEncoded() {
        // Arrange
        String value = "Group%2FName";
        // Act
        String result = DataUtils.urlEncode(value);
        // Assert
        assertEquals("Group%2FName", result);
    }
}
