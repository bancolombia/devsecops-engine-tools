package co.com.bancolombia.devsecopsenginetools.tasks;

import co.com.bancolombia.devsecopsenginetools.configuration.GlobalSettings;
import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettings;
import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettingsUtils;
import co.com.bancolombia.devsecopsenginetools.ui.tool.LogPanelLogger;
import co.com.bancolombia.devsecopsenginetools.utils.Commands;
import co.com.bancolombia.devsecopsenginetools.utils.DataUtils;
import co.com.bancolombia.devsecopsenginetools.utils.FileUtils;
import com.intellij.openapi.progress.ProgressIndicator;
import com.intellij.openapi.progress.Task;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.util.NlsContexts;
import org.apache.commons.lang3.StringUtils;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;

import static java.util.Objects.requireNonNull;

public class ScanImageTask extends Task.Backgroundable {
    public ScanImageTask(@Nullable Project project, @NlsContexts.ProgressTitle @NotNull String title) {
        super(project, title, false);
    }

    @Override
    public void run(@NotNull ProgressIndicator progressIndicator) {
        try {
            LogPanelLogger.clear();
            prepareFiles(requireNonNull(myProject));
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
            LogPanelLogger.error("Error running scan IaC command: ", ex);
        }
    }

    private void prepareFiles(Project project) throws IOException {
        String projectPath = project.getBasePath() != null ? project.getBasePath() : "";
        Path iacDestination = Path.of(projectPath, "build", "dev-sec-ops", "iac");
        FileUtils.deleteDirectory(iacDestination);
        Files.createDirectories(iacDestination);
        ProjectSettings settings = ProjectSettingsUtils.getProjectSettings(project);
        for (String source : settings.getIacDirectory().split(",")) {
            Path iacSource = Path.of(projectPath, source);
            LogPanelLogger.info("Copying IaC files from " + iacSource + " to " + iacDestination);
            FileUtils.copyDirectory(iacSource, iacDestination);
        }
        if (settings.isReplaceTokens()) {
            LogPanelLogger.info("Replacing tokens in IaC files");
            Map<String, String> env = FileUtils.readEnvFile(Path.of(projectPath, settings.getDotEnvFile()));
            FileUtils.walkDirectory(iacDestination, content ->
                    DataUtils.replaceTokens(content, settings.getReplacePattern(), env));
        }
    }
}
