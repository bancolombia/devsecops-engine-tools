package co.com.bancolombia.devsecopsenginetools.ui.tool;

import co.com.bancolombia.devsecopsenginetools.actions.ScanIacAction;
import co.com.bancolombia.devsecopsenginetools.actions.ScanImageAction;
import co.com.bancolombia.devsecopsenginetools.utils.Commands;
import com.intellij.openapi.actionSystem.ActionManager;
import com.intellij.openapi.actionSystem.ActionToolbar;
import com.intellij.openapi.actionSystem.DefaultActionGroup;
import com.intellij.openapi.project.DumbAware;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.wm.ToolWindow;
import com.intellij.openapi.wm.ToolWindowFactory;
import com.intellij.openapi.wm.ToolWindowManager;
import com.intellij.ui.content.Content;
import com.intellij.ui.content.ContentFactory;
import lombok.AccessLevel;
import lombok.Setter;
import lombok.extern.java.Log;
import org.jetbrains.annotations.NotNull;

import java.awt.*;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.util.logging.Level;

@Log
public class LogPanelLogger implements ToolWindowFactory, DumbAware {
    protected static final String TOOL_WINDOW_ID = "DevSecOps Engine Tools";

    @Setter(AccessLevel.PRIVATE)
    protected static LogPanel logPanelInstance;

    public static void info(String string) {
        appendText(string, "37");
    }

    public static void success(String string) {
        appendText(string, "32");
    }

    public static void warn(String string) {
        appendText(string, "33");
    }

    public static void warn(String string, Throwable throwable) {
        warn(string + toString(throwable));
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
        if (logPanelInstance != null) {
            logPanelInstance.appendText(string, color);
        }
    }

    public static String toString(Throwable throwable) {
        Writer writer = new StringWriter();
        throwable.printStackTrace(new PrintWriter(writer));
        return writer.toString();
    }

    public static void activate(Project project) {
        ToolWindow toolWindow = ToolWindowManager.getInstance(project).getToolWindow(TOOL_WINDOW_ID);
        if (toolWindow != null && toolWindow.isAvailable() && !toolWindow.isActive()) {
            try {
                toolWindow.activate(() -> {
                }, true, true);
            } catch (Exception e) {
                log.log(Level.WARNING, "Error activating tool window", e);
            }
        }
    }

    @Override
    public void createToolWindowContent(@NotNull Project project, @NotNull ToolWindow toolWindow) {
        DefaultActionGroup actionGroup = new DefaultActionGroup();
        actionGroup.add(ScanIacAction.forUI());
        actionGroup.add(ScanImageAction.forUI());
        ActionToolbar actionToolbar = ActionManager.getInstance()
                .createActionToolbar("LogPanelToolbar", actionGroup, false);

        LogPanel logPanel = new LogPanel();
        actionToolbar.setTargetComponent(logPanel);
        logPanel.add(actionToolbar.getComponent(), BorderLayout.WEST);
        ContentFactory contentFactory = ContentFactory.getInstance();
        Content content = contentFactory.createContent(logPanel, "Scan Output", false);
        toolWindow.getContentManager().addContent(content);
        logPanel.appendText("Welcome to the DevSecOps Engine Tools!", "37");
        logPanel.appendText("You can display your scan output here.", "37");
        LogPanelLogger.setLogPanelInstance(logPanel);
    }

}
