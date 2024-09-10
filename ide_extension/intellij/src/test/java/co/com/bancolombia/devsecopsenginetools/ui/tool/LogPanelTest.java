package co.com.bancolombia.devsecopsenginetools.ui.tool;

import org.junit.Before;
import org.junit.Test;
import org.mockito.MockedStatic;

import javax.swing.*;
import javax.swing.text.BadLocationException;
import javax.swing.text.StyledDocument;
import java.awt.*;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.URI;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class LogPanelTest {
    private LogPanel logPanel;
    private StyledDocument mockedDoc;
    private JTextPane textPane;

    @Before
    public void setUp() {
        textPane = spy(new JTextPane());
        logPanel = new LogPanel(textPane);
        mockedDoc = spy(textPane.getStyledDocument());
    }

    @Test
    public void testAppendText() throws BadLocationException {
        // Arrange
        // Act
        logPanel.appendText("Test message", "32"); // Green color
        // Assert
        String content = mockedDoc.getText(0, mockedDoc.getLength());
        assertEquals("Test message\n", content);
    }

    @Test
    public void testClear() throws BadLocationException {
        // Arrange
        // Act
        logPanel.clear();
        // Assert
        String content = mockedDoc.getText(0, mockedDoc.getLength());
        assertEquals("", content);
    }

    @Test
    public void testAppendTextWithLink() throws BadLocationException {
        // Act
        logPanel.appendText("Visit https://example.com", "34"); // Blue color
        // Assert
        String content = mockedDoc.getText(0, mockedDoc.getLength());
        assertEquals("Visit https://example.com\n", content);
    }

    @Test
    public void shouldBrowseWhenLinkClicked() throws IOException {
        // Arrange
        Desktop mockDesktop = mock(Desktop.class);
        try (MockedStatic<Desktop> desktopStatic = mockStatic(Desktop.class)) {
            desktopStatic.when(Desktop::getDesktop).thenReturn(mockDesktop);

            logPanel.appendText("https://example.com", "34"); // Blue color
            MouseEvent e = mock(MouseEvent.class);
            Point point = mock(Point.class);
            when(e.getPoint()).thenReturn(point);
            when(point.getX()).thenReturn(0.0);
            when(point.getY()).thenReturn(0.0);
            // Act
            Arrays.stream(textPane.getMouseListeners())
                    .filter(m -> m instanceof LogPanel.LinkMouseListener)
                    .findFirst()
                    .ifPresent(l -> l.mouseClicked(e));
            // Assert
            verify(mockDesktop, times(1)).browse(URI.create("https://example.com"));
        }
    }
}
