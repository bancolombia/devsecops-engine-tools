package co.com.bancolombia.devsecopsenginetools.utils.variables;

import org.junit.Test;

import java.util.Map;
import java.util.TreeMap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

public class VariablePlaceholderTest {

    @Test
    public void shouldResolvePlaceholderRecursively() {
        // Arrange
        Map<String, String> variables = new TreeMap<>();
        variables.put("key", "value");
        variables.put("key1", "value2");
        variables.put("key2", "${key}");
        variables.put("key3", "${key}-${key2}");
        variables.put("key4", "${key1}-${key3}");

        // Act
        Map<String, String> resolved = VariablePlaceholder.resolvePlaceholders(variables, "${...}");

        // Assert
        assertEquals("value2-value-value", resolved.get("key4"));
        assertEquals("value-value", resolved.get("key3"));
        assertEquals("value", resolved.get("key2"));
        assertEquals("value2", resolved.get("key1"));
        assertEquals("value", resolved.get("key"));
    }

    @Test
    public void shouldFailIfCircularDependency() {
        // Arrange
        Map<String, String> variables = new TreeMap<>();
        variables.put("key", "value");
        variables.put("key1", "$(key2)");
        variables.put("key2", "$(key1)");

        // Assert
        assertThrows(IllegalStateException.class, () -> {
            // Act
            VariablePlaceholder.resolvePlaceholders(variables, "$(...)");
        });
    }
}
