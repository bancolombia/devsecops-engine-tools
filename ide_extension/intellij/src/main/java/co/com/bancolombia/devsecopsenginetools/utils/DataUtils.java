package co.com.bancolombia.devsecopsenginetools.utils;

import co.com.bancolombia.devsecopsenginetools.ui.tool.LogPanelLogger;
import co.com.bancolombia.devsecopsenginetools.utils.http.BasicAuthMethod;
import lombok.experimental.UtilityClass;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@UtilityClass
public class DataUtils {

    public static String replaceTokens(String content, String pattern, Map<String, String> env) {
        String[] parts = pattern.split("\\.\\.\\.");
        return replaceTokens(content, parts[0], parts[1], env);
    }

    private static String replaceTokens(String content, String prefix, String suffix, Map<String, String> variables) {
        String regex = Pattern.quote(prefix) + "(.*?)" + Pattern.quote(suffix);
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(content);

        StringBuilder result = new StringBuilder();
        int total = 0;
        int replaced = 0;
        while (matcher.find()) {
            String key = matcher.group(1).trim();
            String replacement = variables.get(key);
            total++;
            if (replacement == null) {
                LogPanelLogger.warn("Variable '" + key + "' not found in .env file");
                replacement = "";
            } else {
                replaced++;
            }
            matcher.appendReplacement(result, Matcher.quoteReplacement(replacement));
        }
        matcher.appendTail(result);
        if (total > 0) {
            if (total != replaced) {
                LogPanelLogger.warn("Replaced " + replaced + " of " + total + " variables");
            } else {
                LogPanelLogger.success("Replaced " + replaced + " of " + total + " variables");
            }
        } else {
            LogPanelLogger.info("File has no variables to replace");
        }

        return result.toString();
    }

    public static String removeRoot(String root, String paths) {
        return paths.replaceAll(root, "");
    }

    public static BasicAuthMethod toBasicAuth(String username, String password) {
        return new BasicAuthMethod(username, password);
    }

    public static String urlEncode(String text) {
        if (!containsEncodedCharacters(text)) {
            return URLEncoder.encode(text, StandardCharsets.UTF_8)
                    .replace("+", "%20")
                    .replace("%2F", "/");
        }
        return text;
    }

    public static String[] splitCommand(String command) {
        List<String> args = new ArrayList<>();
        StringBuilder currentArg = new StringBuilder();
        boolean insideQuotes = false;

        for (char c : command.toCharArray()) {
            if (c == '"' || c == '\'') {
                insideQuotes = !insideQuotes;
                if (!insideQuotes && !currentArg.isEmpty()) {
                    args.add(currentArg.toString());
                    currentArg.setLength(0);
                }
            } else if (c == ' ' && !insideQuotes) {
                if (!currentArg.isEmpty()) {
                    args.add(currentArg.toString());
                    currentArg.setLength(0);
                }
            } else {
                currentArg.append(c);
            }
        }

        if (!currentArg.isEmpty()) {
            args.add(currentArg.toString());
        }

        return args.toArray(new String[0]);
    }

    private static boolean containsEncodedCharacters(String text) {
        String regex = "%[0-9a-fA-F]{2}";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(text);
        return matcher.find();
    }
}
