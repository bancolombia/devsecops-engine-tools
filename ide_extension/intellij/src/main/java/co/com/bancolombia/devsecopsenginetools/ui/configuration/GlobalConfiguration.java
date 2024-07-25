package co.com.bancolombia.devsecopsenginetools.ui.configuration;

import co.com.bancolombia.devsecopsenginetools.configuration.AzureCredentials;
import co.com.bancolombia.devsecopsenginetools.configuration.GlobalSettings;
import co.com.bancolombia.devsecopsenginetools.configuration.ProjectSettingsUtils;
import com.intellij.openapi.options.Configurable;
import com.intellij.openapi.options.ConfigurationException;
import com.intellij.ui.components.JBPasswordField;
import com.intellij.ui.components.JBTabbedPane;
import com.intellij.ui.components.JBTextField;
import org.jetbrains.annotations.Nls;
import org.jetbrains.annotations.Nullable;

import javax.swing.*;

public class GlobalConfiguration implements Configurable, Configurable.NoScroll {
    private GlobalSettings globalSettings;

    // Tabs
    private JPanel connectionDetails, settings;

    // Connection Details
    private JBPasswordField azureAccessToken;
    private JTextField azureOrganization;
    private JTextField azureProject;
    private JTextField azureUserName;

    // Settings
    private JBTextField scanIacCommand;


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
        AzureCredentials credentials = ProjectSettingsUtils.getPassword("azure");
        return !createServerConfig().equals(GlobalSettings.getInstance()) ||
                !credentials.getAzureDevopsPassword().equals(new String(azureAccessToken.getPassword())) ||
                !credentials.getAzureDevOpsUsername().equals(azureUserName.getText());
    }

    private GlobalSettings createServerConfig() {
        GlobalSettings settings = new GlobalSettings();
        settings.setScanIacCommand(scanIacCommand.getText());
        settings.setAzureDevOpsOrganization(azureOrganization.getText());
        settings.setAzureDevOpsProject(azureProject.getText());
        return settings;
    }

    @Override
    public void apply() throws ConfigurationException {
        globalSettings.setScanIacCommand(scanIacCommand.getText());
        globalSettings.setAzureDevOpsOrganization(azureOrganization.getText());
        globalSettings.setAzureDevOpsProject(azureProject.getText());
        AzureCredentials credentials = new AzureCredentials(azureUserName.getText(), new String(azureAccessToken.getPassword()));
        ProjectSettingsUtils.savePassword("azure", credentials);
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
            azureOrganization.setText(globalSettings.getAzureDevOpsOrganization());
            azureProject.setText(globalSettings.getAzureDevOpsProject());
            AzureCredentials credentials = ProjectSettingsUtils.getPassword("azure");
            azureUserName.setText(credentials.getAzureDevOpsUsername());
            azureAccessToken.setText(credentials.getAzureDevopsPassword());
        }
    }
}
