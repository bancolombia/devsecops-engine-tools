package co.com.bancolombia.devsecopsenginetools.ui.configuration;

import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettings;
import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettingsUtils;
import co.com.bancolombia.devsecopsenginetools.ui.tool.LogPanelLogger;
import co.com.bancolombia.devsecopsenginetools.utils.variables.DotEnvGenerator;
import com.intellij.ide.util.PropertiesComponent;
import com.intellij.openapi.application.ApplicationManager;
import com.intellij.openapi.fileChooser.FileChooserDescriptorFactory;
import com.intellij.openapi.options.Configurable;
import com.intellij.openapi.project.Project;
import com.intellij.openapi.ui.TextFieldWithBrowseButton;
import com.intellij.ui.components.JBTabbedPane;
import com.intellij.ui.components.JBTextField;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;
import java.io.IOException;

import static co.com.bancolombia.devsecopsenginetools.utils.DataUtils.removeRoot;

public class ProjectConfiguration implements Configurable, Configurable.NoScroll {
    // Tabs
    private JPanel variablesPanel;
    private JButton toDotEnv;
    private TextFieldWithBrowseButton iacDirectory;
    private JCheckBox replaceTokens;
    private JTextField variableGroups;
    private JBTextField replaceTokensPattern;
    private TextFieldWithBrowseButton dotEnvVariables;
    private JProgressBar processingGroups;
    private JTextField releaseDefinition;
    private JTextField stageName;
    private JLabel dotEnvOutput;
    private JTextArea preBuildScript;
    private TextFieldWithBrowseButton dockerFilePath;
    private TextFieldWithBrowseButton buildContextPath;
    private JTextField buildCommand;
    private JPanel iacPanel;
    private JPanel imagePanel;

    private final Project project;

    public ProjectConfiguration(Project project) {
        this.project = project;
        createComponent();

        // Variable groups
        initDownloadVariableGroups();

        processingGroups.setVisible(false);
        dotEnvOutput.setVisible(false);

        loadConfig();
    }

    @Nullable
    @Override
    public JComponent createComponent() {
        JTabbedPane tabbedPane = new JBTabbedPane();
        tabbedPane.add("Variables", variablesPanel);
        tabbedPane.add("IaC Scan", iacPanel);
        tabbedPane.add("Image Scan", imagePanel);
        tabbedPane.setSelectedIndex(0);
        return tabbedPane;
    }

    @Nls
    @Override
    public String getDisplayName() {
        return "DevSecOps Engine Tools Configuration";
    }

    @Nullable
    @Override
    public String getHelpTopic() {
        return "Setup project settings for DevSecOps Engine Tools.";
    }

    @Override
    public boolean isModified() {
        return !createServerConfig().equals(ProjectSettingsUtils.getProjectSettings(project));
    }

    private ProjectSettings createServerConfig() {
        ProjectSettings settings = new ProjectSettings();
        String root = project.getBasePath() + "/";
        // iac
        settings.setIacDirectory(removeRoot(root, iacDirectory.getText()));
        // image
        settings.setDockerFilePath(dockerFilePath.getText());
        settings.setBuildContextPath(buildContextPath.getText());
        settings.setBuildCommand(buildCommand.getText());
        settings.setPreBuildScript(preBuildScript.getText());
        // variables
        settings.setReplaceTokens(replaceTokens.isSelected());
        settings.setReplacePattern(replaceTokensPattern.getText());
        settings.setDotEnvFile(removeRoot(root, dotEnvVariables.getText()));
        settings.setAzureDevOpsVariableGroups(variableGroups.getText());
        settings.setAzureReleaseDefinitionId(releaseDefinition.getText());
        settings.setAzureReleaseStageName(stageName.getText());
        return settings;
    }

    @Override
    public void apply() {
        ProjectSettingsUtils.toProperties(createServerConfig(), PropertiesComponent.getInstance(project));
        loadConfig();
    }

    @Override
    public void reset() {
        loadConfig();
    }


    /**
     * Load the config and populate the UI fields.
     */
    private void loadConfig() {
        ProjectSettings projectSettings = ProjectSettingsUtils.getProjectSettings(project);
        projectSettings.fillIfDefaults(project);
        // iac
        iacDirectory.setText(projectSettings.getIacDirectory());
        // image
        dockerFilePath.setText(projectSettings.getDockerFilePath());
        buildContextPath.setText(projectSettings.getBuildContextPath());
        buildCommand.setText(projectSettings.getBuildCommand());
        preBuildScript.setText(projectSettings.getPreBuildScript());
        // variables
        replaceTokens.setSelected(projectSettings.isReplaceTokens());
        replaceTokensPattern.setText(projectSettings.getReplacePattern());
        dotEnvVariables.setText(projectSettings.getDotEnvFile());
        variableGroups.setText(projectSettings.getAzureDevOpsVariableGroups());
        releaseDefinition.setText(projectSettings.getAzureReleaseDefinitionId());
        stageName.setText(projectSettings.getAzureReleaseStageName());

        iacDirectory.addBrowseFolderListener("Select IaC Resources", "Select IaC resources directory",
                project, FileChooserDescriptorFactory.createMultipleFoldersDescriptor());
        dotEnvVariables.addBrowseFolderListener("Select .env File", "Select .env file",
                project, FileChooserDescriptorFactory.createSingleFileDescriptor());

        dockerFilePath.addBrowseFolderListener("Select Dockerfile", "Select Dockerfile resource",
                project, FileChooserDescriptorFactory.createSingleFileDescriptor());
        buildContextPath.addBrowseFolderListener("Select Build Context Path", "Select image build context",
                project, FileChooserDescriptorFactory.createSingleFolderDescriptor());
    }


    /**
     * Initialize the download button.
     */
    private void initDownloadVariableGroups() {
        toDotEnv.addActionListener(e -> {
            LogPanelLogger.activate(project);
            ApplicationManager.getApplication().executeOnPooledThread(() -> {
                LogPanelLogger.clear();
                processingGroups.setVisible(true);
                dotEnvOutput.setVisible(false);
                apply();
                try {
                    String message = DotEnvGenerator.updateDotEnv(project);
                    dotEnvOutput.setText(message);
                    dotEnvOutput.setVisible(true);
                } catch (IOException ioException) {
                    dotEnvOutput.setText(ioException.getMessage());
                    dotEnvOutput.setVisible(true);
                    LogPanelLogger.error("Error updating .env file", ioException);
                }
                processingGroups.setVisible(false);
            });
        });
    }
}
