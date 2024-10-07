package co.com.bancolombia.devsecopsenginetools.ui.tool;

import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowManager;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static co.com.bancolombia.devsecopsenginetools.utils.Constants.TOOL_WINDOW_ID;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.contains;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class LogPanelLoggerTest {

    @Mock
    private Project mockProject;

    @Mock
    private ToolWindow mockToolWindow;

    @Mock
    private ToolWindowManager mockToolWindowManager;

    @Test
    public void testActivateToolWindow() {
        when(mockProject.getService(ToolWindowManager.class)).thenReturn(mockToolWindowManager);
        when(mockToolWindowManager.getToolWindow(TOOL_WINDOW_ID)).thenReturn(mockToolWindow);
        when(mockToolWindow.isAvailable()).thenReturn(true);
        when(mockToolWindow.isActive()).thenReturn(false);

        LogPanelLogger.activate(mockProject);

        verify(mockToolWindow).activate(any(Runnable.class), eq(true), eq(true));
    }

    @Test
    public void testInfo() {
        LogPanelLogger.logPanelInstance = mock(LogPanel.class);

        LogPanelLogger.info("Info message");

        verify(LogPanelLogger.logPanelInstance).appendText("Info message", "37");
    }

    @Test
    public void testSuccess() {
        LogPanelLogger.logPanelInstance = mock(LogPanel.class);

        LogPanelLogger.success("Success message");

        verify(LogPanelLogger.logPanelInstance).appendText("Success message", "32");
    }

    @Test
    public void testWarn() {
        LogPanelLogger.logPanelInstance = mock(LogPanel.class);

        LogPanelLogger.warn("Warn message");

        verify(LogPanelLogger.logPanelInstance).appendText("Warn message", "33");
    }

    @Test
    public void testError() {
        LogPanelLogger.logPanelInstance = mock(LogPanel.class);

        LogPanelLogger.error("Error message");

        verify(LogPanelLogger.logPanelInstance).appendText("Error message", "31");
    }

    @Test
    public void testErrorWithException() {
        LogPanelLogger.logPanelInstance = mock(LogPanel.class);
        Throwable throwable = new RuntimeException("Test exception");

        LogPanelLogger.error("Error message", throwable);

        verify(LogPanelLogger.logPanelInstance).appendText(contains("Error message"), contains("31"));
    }

    @Test
    public void testClear() {
        LogPanelLogger.logPanelInstance = mock(LogPanel.class);

        LogPanelLogger.clear();

        verify(LogPanelLogger.logPanelInstance).appendText(anyString(), eq("37"));
    }
}
