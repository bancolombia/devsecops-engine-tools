package co.com.bancolombia.devsecopsenginetools.utils.variables;

import lombok.experimental.UtilityClass;

import java.util.HashMap;
import java.util.Map;

@UtilityClass
public class VariablePlaceholder {

    public static Map<String, String> resolvePlaceholders(Map<String, String> map, String pattern) {
        String[] parts = pattern.split("\\.\\.\\.");
        Map<String, String> resolvedMap = new HashMap<>(map);

        for (String key : map.keySet()) {
            resolvedMap.put(key, resolveValue(map, key, new HashMap<>(), parts[0], parts[1]));
        }

        return resolvedMap;
    }

    private static String resolveValue(Map<String, String> map, String key, Map<String, Boolean> resolving,
                                       String placeholderStart, String placeholderEnd) {
        if (resolving.containsKey(key)) {
            throw new IllegalStateException("Circular reference detected for key: " + key);
        }

        String value = map.get(key);
        if (value == null) {
            return null;
        }

        resolving.put(key, true);
        StringBuilder resolvedValue = new StringBuilder();
        int startIndex = 0;

        while (startIndex < value.length()) {
            int startPlaceholder = value.indexOf(placeholderStart, startIndex);
            if (startPlaceholder == -1) {
                resolvedValue.append(value.substring(startIndex));
                break;
            }

            resolvedValue.append(value, startIndex, startPlaceholder);
            int endPlaceholder = value.indexOf(placeholderEnd, startPlaceholder);
            if (endPlaceholder == -1) {
                throw new IllegalArgumentException("Invalid placeholder in value: " + value);
            }

            String placeholderKey = value.substring(startPlaceholder + 2, endPlaceholder);
            String placeholderValue = resolveValue(map, placeholderKey, resolving, placeholderStart, placeholderEnd);
            if (placeholderValue != null) {
                resolvedValue.append(placeholderValue);
            }

            startIndex = endPlaceholder + 1;
        }

        resolving.remove(key);
        return resolvedValue.toString();
    }
}
