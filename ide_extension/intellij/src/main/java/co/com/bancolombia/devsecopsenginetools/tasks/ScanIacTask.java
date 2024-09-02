package co.com.bancolombia.devsecopsenginetools.tasks;

import co.com.bancolombia.devsecopsenginetools.configuration.GlobalSettings;
import co.com.bancolombia.devsecopsenginetools.ui.tool.LogPanelLogger;
import co.com.bancolombia.devsecopsenginetools.utils.Commands;
import co.com.bancolombia.devsecopsenginetools.utils.FileUtils;
import co.com.bancolombia.devsecopsenginetools.utils.docker.DockerLatestImage;
import co.com.bancolombia.devsecopsenginetools.utils.http.HttpClient;
import com.intellij.openapi.progress.ProgressIndicator;
import com.intellij.openapi.progress.Task;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.NlsContexts;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import static java.util.Objects.requireNonNull;

public class ScanIacTask extends Task.Backgroundable {
    private final Completable completable;

    public ScanIacTask(@Nullable Project project, @NlsContexts.ProgressTitle @NotNull String title, Completable completable) {
        super(project, title, false);
        this.completable = completable;
    }

    @Override
    public void run(@NotNull ProgressIndicator progressIndicator) {
        try {
            LogPanelLogger.clear();
            FileUtils.copyIaCFiles(requireNonNull(myProject));
            String command = getCommand();
            LogPanelLogger.info("Running scan IaC command: " + command);
            Commands.runCommand(command, LogPanelLogger.getAppender());
        } catch (Exception ex) {
            LogPanelLogger.error("Error running scan IaC command: ", ex);
        }
        completable.complete();
    }

    private @NotNull String getCommand() {
        GlobalSettings settings = GlobalSettings.getInstance();
        String image = settings.getDevSecOpsImage();
        if (settings.isCheckForLatestImage()) {
            DockerLatestImage dockerLatestImage = new DockerLatestImage(settings, new HttpClient());
            image = dockerLatestImage.getLatestImage();
        }
        return settings.getScanIacCommand()
                .replace("{projectPath}", requireNonNull(myProject.getBasePath()))
                .replace("{image}", image);
    }
}
