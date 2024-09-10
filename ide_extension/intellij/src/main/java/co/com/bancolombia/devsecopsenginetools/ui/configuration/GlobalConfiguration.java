package co.com.bancolombia.devsecopsenginetools.ui.configuration;

import co.com.bancolombia.devsecopsenginetools.configuration.AzureCredentials;
import co.com.bancolombia.devsecopsenginetools.configuration.GlobalSettings;
import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettingsUtils;
import com.intellij.openapi.options.Configurable;
import com.intellij.ui.components.JBPasswordField;
import com.intellij.ui.components.JBTabbedPane;
import com.intellij.ui.components.JBTextField;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;

import static co.com.bancolombia.devsecopsenginetools.utils.Constants.AZURE_CREDENTIALS;
import static co.com.bancolombia.devsecopsenginetools.utils.Constants.DEFAULT_IAC_SCAN_COMMAND;
import static co.com.bancolombia.devsecopsenginetools.utils.Constants.DEFAULT_IMAGE_SCAN_COMMAND;

public class GlobalConfiguration implements Configurable, Configurable.NoScroll {
    private GlobalSettings globalSettings;

    // Tabs
    private JPanel connectionDetails;
    private JPanel settings;

    // Connection Details
    private JBPasswordField azureAccessToken;
    private JTextField azureOrganization;
    private JTextField azureProject;
    private JTextField azureUserName;

    // Settings
    private JBTextField scanIacCommand;
    private JButton resetIaCButton;
    private JBTextField scanImageCommand;
    private JButton resetImageButton;
    private JBTextField dockerImage;
    private JCheckBox checkForLatestImageCheckBox;


    public GlobalConfiguration() {
        createComponent();
        loadConfig();
    }

    @Nullable
    @Override
    public JComponent createComponent() {
        JTabbedPane tabbedPane = new JBTabbedPane();
        tabbedPane.add("Connection Details", connectionDetails);
        tabbedPane.add("Settings", settings);
        tabbedPane.setSelectedIndex(0);
        resetIaCButton.addActionListener(e -> scanIacCommand.setText(DEFAULT_IAC_SCAN_COMMAND));
        resetImageButton.addActionListener(e -> scanImageCommand.setText(DEFAULT_IMAGE_SCAN_COMMAND));
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
        return "Setup page for DevSecOps Engine Tools and Azure connection details.";
    }

    @Override
    public boolean isModified() {
        AzureCredentials credentials = ProjectSettingsUtils.getPassword(AZURE_CREDENTIALS);
        return !createServerConfig().equals(GlobalSettings.getInstance()) ||
                !credentials.getAzureDevopsPassword().equals(new String(azureAccessToken.getPassword())) ||
                !credentials.getAzureDevOpsUsername().equals(azureUserName.getText());
    }

    private GlobalSettings createServerConfig() {
        GlobalSettings newGlobalSettings = new GlobalSettings();
        // iac
        newGlobalSettings.setScanIacCommand(scanIacCommand.getText());
        // image
        newGlobalSettings.setDevSecOpsImage(dockerImage.getText());
        newGlobalSettings.setScanImageCommand(scanImageCommand.getText());
        newGlobalSettings.setCheckForLatestImage(checkForLatestImageCheckBox.isSelected());
        // variables
        newGlobalSettings.setAzureDevOpsOrganization(azureOrganization.getText());
        newGlobalSettings.setAzureDevOpsProject(azureProject.getText());
        return newGlobalSettings;
    }

    @Override
    public void apply() {
        // iac
        globalSettings.setScanIacCommand(scanIacCommand.getText());
        // image
        globalSettings.setDevSecOpsImage(dockerImage.getText());
        globalSettings.setScanImageCommand(scanImageCommand.getText());
        globalSettings.setCheckForLatestImage(checkForLatestImageCheckBox.isSelected());
        // variables
        globalSettings.setAzureDevOpsOrganization(azureOrganization.getText());
        globalSettings.setAzureDevOpsProject(azureProject.getText());
        AzureCredentials credentials = new AzureCredentials(azureUserName.getText(), new String(azureAccessToken.getPassword()));
        ProjectSettingsUtils.savePassword(AZURE_CREDENTIALS, credentials);
    }

    @Override
    public void reset() {
        loadConfig();
    }

    /**
     * Load the config and populate the UI fields.
     */
    private void loadConfig() {

        globalSettings = GlobalSettings.getInstance();
        if (globalSettings != null) {
            scanIacCommand.setText(globalSettings.getScanIacCommand());

            dockerImage.setText(globalSettings.getDevSecOpsImage());
            scanImageCommand.setText(globalSettings.getScanImageCommand());
            checkForLatestImageCheckBox.setSelected(globalSettings.isCheckForLatestImage());

            azureOrganization.setText(globalSettings.getAzureDevOpsOrganization());
            azureProject.setText(globalSettings.getAzureDevOpsProject());
            AzureCredentials credentials = ProjectSettingsUtils.getPassword(AZURE_CREDENTIALS);
            azureUserName.setText(credentials.getAzureDevOpsUsername());
            azureAccessToken.setText(credentials.getAzureDevopsPassword());
        }
    }
}
