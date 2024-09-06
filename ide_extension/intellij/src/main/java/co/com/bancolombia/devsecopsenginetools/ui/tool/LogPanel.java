package co.com.bancolombia.devsecopsenginetools.ui.tool;

import com.intellij.ui.JBColor;
import com.intellij.ui.components.JBPanel;
import com.intellij.ui.components.JBScrollPane;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.SneakyThrows;
import lombok.extern.java.Log;

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
import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Log
@Getter(AccessLevel.PROTECTED)
public class LogPanel extends JBPanel<LogPanel> {
    private final transient StyledDocument doc;
    private final JTextPane textPane;
    private final JPopupMenu contextMenu;
    private final Map<String, SimpleAttributeSet> ansiCodeToStyle;

    public LogPanel() {
        this(new JTextPane());
    }

    public LogPanel(JTextPane textPane) {
        super();
        setLayout(new BorderLayout());
        this.textPane = textPane;
        textPane.setEditable(false);
        textPane.setFont(new Font("Monospaced", Font.PLAIN, 12));
        textPane.setContentType("text/html"); // Enable HTML support
        textPane.setBackground(JBColor.WHITE);
        doc = textPane.getStyledDocument();

        contextMenu = new JPopupMenu();
        JMenuItem clearItem = new JMenuItem("Clear");
        clearItem.addActionListener(e -> clear());
        contextMenu.add(clearItem);

        ansiCodeToStyle = createAnsiCodeToStyleMap();

        JScrollPane scrollPane = new JBScrollPane(textPane);
        add(scrollPane, BorderLayout.CENTER);

        textPane.addMouseListener(new LinkMouseListener());
    }

    public void appendText(String message, String color) {
        try {
            parseAndAppend("\033[" + color + "m" + message + "\033[0m\n");
        } catch (BadLocationException e) {
            log.log(Level.WARNING, "Error appending text", e);
        }
    }

    @SneakyThrows
    protected void clear() {
        doc.remove(0, doc.getLength());
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

    protected class LinkMouseListener extends MouseAdapter {
        @Override
        public void mouseClicked(MouseEvent e) {
            int offset = textPane.viewToModel2D(e.getPoint());
            StyledDocument styledDocument = textPane.getStyledDocument();
            Element element = styledDocument.getCharacterElement(offset);
            AttributeSet attrs = element.getAttributes();
            if (StyleConstants.isUnderline(attrs) && StyleConstants.getForeground(attrs).equals(JBColor.BLUE)) {
                String link = getText(element);
                if (link != null) {
                    openLink(link);
                }
            }
        }

        @Override
        public void mousePressed(MouseEvent e) {
            if (e.isPopupTrigger()) {
                showContextMenu(e);
            }
        }

        @Override
        public void mouseReleased(MouseEvent e) {
            if (e.isPopupTrigger()) {
                showContextMenu(e);
            }
        }

        private String getText(Element element) {
            try {
                return textPane.getDocument().getText(element.getStartOffset(),
                        element.getEndOffset() - element.getStartOffset()).trim();
            } catch (BadLocationException e) {
                log.log(Level.WARNING, "Error getting text from element", e);
                return null;
            }
        }

        private void openLink(String link) {
            try {
                Desktop.getDesktop().browse(new URI(link));
            } catch (Exception e) {
                log.log(Level.WARNING, "Error opening link: " + link, e);
            }
        }

        private void showContextMenu(MouseEvent e) {
            contextMenu.show(e.getComponent(), e.getX(), e.getY());
        }
    }
}