package co.com.bancolombia.devsecopsenginetools.actions;

import co.com.bancolombia.devsecopsenginetools.tasks.ScanImageTask;
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

public class ScanImageAction extends AnAction {
    public ScanImageAction() {
        super();
    }

    public ScanImageAction(@Nullable @NlsActions.ActionText String text,
                           @Nullable @NlsActions.ActionDescription String description, @Nullable Icon icon) {
        super(text, description, icon);
    }

    public static ScanImageAction forUI() {
        return new ScanImageAction("Scan Image", "Run image scan", AllIcons.Actions.Rerun);
    }

    @SneakyThrows
    @Override
    public void actionPerformed(AnActionEvent e) {
        Project project = e.getProject();
        LogPanelLogger.activate(project);
        if (project != null) {
            ScanImageTask task = new ScanImageTask(project, "Scanning image");
            ProgressManager.getInstance().run(task);
        }
    }
}
