package co.com.bancolombia.devsecopsenginetools.actions;

import co.com.bancolombia.devsecopsenginetools.tasks.ScanIacTask;
import co.com.bancolombia.devsecopsenginetools.ui.tool.LogPanelLogger;
import com.intellij.icons.AllIcons;
import com.intellij.openapi.actionSystem.AnAction;
import com.intellij.openapi.actionSystem.AnActionEvent;
import com.intellij.openapi.progress.ProgressManager;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.NlsActions;
import lombok.SneakyThrows;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;

public class ScanIacAction extends AnAction {

    public ScanIacAction() {
        super();
    }

    public ScanIacAction(@Nullable @NlsActions.ActionText String text,
                         @Nullable @NlsActions.ActionDescription String description, @Nullable Icon icon) {
        super(text, description, icon);
    }

    public static ScanIacAction forUI() {
        return new ScanIacAction("Scan IaC", "Run iac scan", AllIcons.Actions.Execute);
    }

    @SneakyThrows
    @Override
    public void actionPerformed(AnActionEvent e) {
        Project project = e.getProject();
        LogPanelLogger.activate(project);
        if (project != null) {
            ScanIacTask task = new ScanIacTask(project, "Scanning iac");
            ProgressManager.getInstance().run(task);
        }
    }
}
