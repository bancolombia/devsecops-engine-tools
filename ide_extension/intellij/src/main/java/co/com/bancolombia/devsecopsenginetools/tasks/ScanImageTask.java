package co.com.bancolombia.devsecopsenginetools.tasks;

import co.com.bancolombia.devsecopsenginetools.configuration.GlobalSettings;
import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettings;
import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettingsUtils;
import co.com.bancolombia.devsecopsenginetools.ui.tool.LogPanelLogger;
import co.com.bancolombia.devsecopsenginetools.utils.Commands;
import co.com.bancolombia.devsecopsenginetools.utils.FileUtils;
import com.intellij.openapi.progress.ProgressIndicator;
import com.intellij.openapi.progress.Task;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.NlsContexts;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.nio.file.Path;

import static java.util.Objects.requireNonNull;

public class ScanImageTask extends Task.Backgroundable {
    private final Completable completable;

    public ScanImageTask(@Nullable Project project, @NlsContexts.ProgressTitle @NotNull String title,
                         Completable completable) {
        super(project, title, false);
        this.completable = completable;
    }

    @Override
    public void run(@NotNull ProgressIndicator progressIndicator) {
        try {
            LogPanelLogger.clear();
            FileUtils.copyIaCFiles(requireNonNull(myProject));
            GlobalSettings settings = GlobalSettings.getInstance();
            String scanCommand = settings.getScanImageCommand().replace("{image}", settings.getDevSecOpsImage());
            ProjectSettings projectSettings = ProjectSettingsUtils.getProjectSettings(myProject);
            String projectPath = myProject.getBasePath();
            if (!StringUtils.isEmpty(projectSettings.getPreBuildScript())) {
                LogPanelLogger.info("Running prebuild command: " + projectSettings.getPreBuildScript());
                Commands.runCommandInDirectory(projectSettings.getPreBuildScript(), LogPanelLogger.getAppender(), projectPath);
            }
            if (!StringUtils.isEmpty(projectSettings.getDockerFilePath())) {
                Path dockerFilePath = Path.of(myProject.getBasePath(), "build", "dev-sec-ops", "iac",
                        projectSettings.getDockerFilePath());
                LogPanelLogger.info("Running image build command with Dockerfile " + dockerFilePath);
                String buildCommand = projectSettings.getBuildCommand()
                        .replace("{dockerFilePath}", dockerFilePath.toString())
                        .replace("{buildContextPath}", projectSettings.getBuildContextPath());
                Commands.runCommandInDirectory(buildCommand, LogPanelLogger.getAppender(), projectPath);
            }
            LogPanelLogger.info("Running scan Image command: " + scanCommand);
            Commands.runCommand(scanCommand, LogPanelLogger.getAppender());
        } catch (Exception ex) {
            LogPanelLogger.error("Error running scan Image command: ", ex);
        }
        completable.complete();
    }
}
