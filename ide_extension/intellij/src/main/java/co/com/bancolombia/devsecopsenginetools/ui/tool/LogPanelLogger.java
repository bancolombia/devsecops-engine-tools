package co.com.bancolombia.devsecopsenginetools.ui.tool;

import co.com.bancolombia.devsecopsenginetools.utils.Commands;
import com.intellij.openapi.project.DumbAware;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.openapi.wm.ToolWindowManager;
import com.intellij.ui.JBColor;
import com.intellij.ui.components.JBPanel;
import com.intellij.ui.components.JBScrollPane;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentFactory;
import lombok.extern.log4j.Log4j2;
import org.jetbrains.annotations.NotNull;

import javax.swing.*;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.Element;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Log4j2
public class LogPanelLogger implements ToolWindowFactory, DumbAware {
    protected static final String TOOL_WINDOW_ID = "DevSecOps Engine Tools";
    protected static LogPanel logPanel;

    public static void info(String string) {
        appendText(string, "37");
    }

    public static void success(String string) {
        appendText(string, "32");
    }

    public static void warn(String string) {
        appendText(string, "33");
    }

    public static void error(String string) {
        appendText(string, "31");
    }

    public static void error(String string, Throwable throwable) {
        error(string + toString(throwable));
    }

    public static void clear() {
        info("\n######################################################################################################");
    }

    public static Commands.Appender getAppender() {
        return new Commands.Appender() {
            @Override
            public void onNext(String text) {
                LogPanelLogger.info(text);
            }

            @Override
            public void success(String text) {
                LogPanelLogger.success(text);
            }

            @Override
            public void error(String text) {
                LogPanelLogger.error(text);
            }
        };
    }

    private static void appendText(String string, String color) {
        if (logPanel != null) {
            logPanel.appendText(string, color);
        }
    }

    public static String toString(Throwable throwable) {
        Writer writer = new StringWriter();
        throwable.printStackTrace(new PrintWriter(writer));
        return writer.toString();
    }

    public static void activate(Project project) {
        ToolWindow toolWindow = ToolWindowManager.getInstance(project).getToolWindow(TOOL_WINDOW_ID);
        if (toolWindow != null && toolWindow.isAvailable()) {
            if (!toolWindow.isActive()) {
                try {
                    toolWindow.activate(() -> {
                    }, true, true);
                } catch (Exception e) {
                    log.warn("Error activating tool window", e);
                }
            }
        }
    }

    @Override
    public void createToolWindowContent(@NotNull Project project, @NotNull ToolWindow toolWindow) {
        logPanel = new LogPanel();
        ContentFactory contentFactory = ContentFactory.getInstance();
        Content content = contentFactory.createContent(logPanel, "Scan Output", false);
        toolWindow.getContentManager().addContent(content);
        logPanel.appendText("Welcome to the DevSecOps Engine Tools!", "37");
        logPanel.appendText("You can display your scan output here.", "37");
    }

    public static class LogPanel extends JBPanel<LogPanel> {
        private final StyledDocument doc;
        private final JTextPane textPane;
        private final Map<String, SimpleAttributeSet> ansiCodeToStyle;

        public LogPanel() {
            super();
            setLayout(new BorderLayout());
            textPane = new JTextPane();
            textPane.setEditable(false);
            textPane.setFont(new Font("Monospaced", Font.PLAIN, 12));
            textPane.setContentType("text/html"); // Enable HTML support
            textPane.setBackground(JBColor.WHITE);
            doc = textPane.getStyledDocument();

            ansiCodeToStyle = createAnsiCodeToStyleMap();

            JScrollPane scrollPane = new JBScrollPane(textPane);
            add(scrollPane, BorderLayout.CENTER);

            textPane.addMouseListener(new LinkMouseListener());
        }

        public void appendText(String message, String color) {
            try {
                parseAndAppend("\033[" + color + "m" + message + "\033[0m\n");
            } catch (BadLocationException e) {
                log.warn("Error appending text", e);
            }
        }

        private void parseAndAppend(String log) throws BadLocationException {
            Pattern pattern = Pattern.compile("\\033\\[([;\\d]*)m");
            Matcher matcher = pattern.matcher(log);
            int lastEnd = 0;
            SimpleAttributeSet currentStyle = new SimpleAttributeSet();
            while (matcher.find()) {
                String textBeforeCode = log.substring(lastEnd, matcher.start());
                appendTextWithLinks(textBeforeCode, currentStyle);

                String ansiCode = matcher.group(1);

                currentStyle = ansiCodeToStyle.getOrDefault(ansiCode, new SimpleAttributeSet());
                lastEnd = matcher.end();
            }
            appendTextWithLinks(log.substring(lastEnd), currentStyle);
        }

        private void appendTextWithLinks(String text, SimpleAttributeSet style) throws BadLocationException {
            Pattern linkPattern = Pattern.compile("(https?://\\S+)");
            Matcher linkMatcher = linkPattern.matcher(text);
            int lastEnd = 0;
            while (linkMatcher.find()) {
                String textBeforeLink = text.substring(lastEnd, linkMatcher.start());
                doc.insertString(doc.getLength(), textBeforeLink, style);

                String url = linkMatcher.group(1);
                SimpleAttributeSet linkStyle = new SimpleAttributeSet(style);
                StyleConstants.setForeground(linkStyle, JBColor.BLUE);
                StyleConstants.setUnderline(linkStyle, true);
                doc.insertString(doc.getLength(), url, linkStyle);


                lastEnd = linkMatcher.end();
            }
            doc.insertString(doc.getLength(), text.substring(lastEnd), style);
            textPane.setCaretPosition(doc.getLength());
        }

        private Map<String, SimpleAttributeSet> createAnsiCodeToStyleMap() {
            Map<String, SimpleAttributeSet> map = new HashMap<>();

            // Define styles for ANSI codes
            map.put("0", new SimpleAttributeSet()); // Reset
            map.put("1", createStyle(Font.BOLD)); // Bold
            map.put("4", createStyle(Font.ITALIC)); // Italic for underline
            map.put("30", createStyle(JBColor.WHITE)); // Black
            map.put("31", createStyle(JBColor.RED)); // Red
            map.put("32", createStyle(JBColor.GREEN)); // Green
            map.put("33", createStyle(JBColor.YELLOW)); // Yellow
            map.put("34", createStyle(JBColor.BLUE)); // Blue
            map.put("35", createStyle(JBColor.MAGENTA)); // Magenta
            map.put("36", createStyle(JBColor.CYAN)); // Cyan
            map.put("37", createStyle(JBColor.BLACK)); // White
            map.put("90", createStyle(JBColor.DARK_GRAY)); // Bright Black
            map.put("91", createStyle(JBColor.RED)); // Bright Red
            map.put("92", createStyle(JBColor.GREEN)); // Bright Green
            map.put("93", createStyle(JBColor.YELLOW)); // Bright Yellow
            map.put("94", createStyle(new JBColor(new Color(107, 142, 178), new Color(107, 142, 178)))); // Bright Blue
            map.put("95", createStyle(new JBColor(new Color(142, 107, 178), new Color(107, 142, 178)))); // Bright Magenta
            map.put("96", createStyle(new JBColor(new Color(107, 178, 178), new Color(107, 142, 178)))); // Bright Cyan
            map.put("97", createStyle(JBColor.LIGHT_GRAY)); // Bright White
            return map;
        }

        private SimpleAttributeSet createStyle(Color color) {
            SimpleAttributeSet style = new SimpleAttributeSet();
            StyleConstants.setForeground(style, color);
            return style;
        }

        private SimpleAttributeSet createStyle(int fontStyle) {
            SimpleAttributeSet style = new SimpleAttributeSet();
            StyleConstants.setBold(style, (fontStyle & Font.BOLD) != 0);
            StyleConstants.setItalic(style, (fontStyle & Font.ITALIC) != 0);
            return style;
        }

        private class LinkMouseListener extends MouseAdapter {
            @Override
            public void mouseClicked(MouseEvent e) {
                int offset = textPane.viewToModel2D(e.getPoint());
                StyledDocument doc = textPane.getStyledDocument();
                Element element = doc.getCharacterElement(offset);
                AttributeSet attrs = element.getAttributes();
                if (StyleConstants.isUnderline(attrs) && StyleConstants.getForeground(attrs).equals(JBColor.BLUE)) {
                    String link = getText(element);
                    if (link != null) {
                        openLink(link);
                    }
                }
            }

            private String getText(Element element) {
                try {
                    return textPane.getDocument().getText(element.getStartOffset(),
                            element.getEndOffset() - element.getStartOffset()).trim();
                } catch (BadLocationException e) {
                    log.warn("Error getting text from element", e);
                    return null;
                }
            }

            private void openLink(String link) {
                try {
                    Desktop.getDesktop().browse(new URI(link));
                } catch (Exception e) {
                    log.warn("Error opening link: {}", link, e);
                }
            }
        }
    }
}
