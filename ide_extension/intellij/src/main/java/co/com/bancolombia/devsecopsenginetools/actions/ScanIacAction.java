package co.com.bancolombia.devsecopsenginetools.actions;

import co.com.bancolombia.devsecopsenginetools.tasks.ScanIacTask;
import co.com.bancolombia.devsecopsenginetools.ui.tool.LogPanelLogger;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.actionSystem.Presentation;
import com.intellij.openapi.progress.ProgressManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.NlsActions;
import icons.DevSecOpsIcons;
import lombok.SneakyThrows;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;

public class ScanIacAction extends AnAction {
    private boolean isTaskRunning = false;

    public ScanIacAction() {
        super();
    }

    public ScanIacAction(@Nullable @NlsActions.ActionText String text,
                         @Nullable @NlsActions.ActionDescription String description, @Nullable Icon icon) {
        super(text, description, icon);
    }

    public static ScanIacAction forUI() {
        return new ScanIacAction("Scan IaC", "Run iac scan", DevSecOpsIcons.ScanIaC);
    }

    @SneakyThrows
    @Override
    public void actionPerformed(AnActionEvent e) {
        Project project = e.getProject();
        LogPanelLogger.activate(project);
        if (project != null) {
            LogPanelLogger.success("START");
            isTaskRunning = true;
            ScanIacTask task = new ScanIacTask(project, "Scanning iac", () -> isTaskRunning = false);
            ProgressManager.getInstance().run(task);
            LogPanelLogger.success("END");
        }
    }

    @Override
    public void update(@NotNull AnActionEvent e) {
        Presentation presentation = e.getPresentation();
        presentation.setEnabled(!isTaskRunning);
    }
}
