package pingvin;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import lombok.SneakyThrows;
import org.apache.commons.lang.StringUtils;
import pingvin.tokenposition.Config;

import javax.swing.*;
import javax.swing.event.TableModelEvent;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.Objects;

public class JwtPublicSecretsTab implements ITab {

    private final JPanel mainPanel;
    private final IBurpExtenderCallbacks callbacks;
    
    // Configuration UI components
    private final JTabbedPane tabbedPane;
    private final JPanel configPanel;
    
    // Configuration lists
    private final DefaultTableModel secretsTableModel;
    private final JTable secretsTable;
    private final JTextField secretsTextField;
    
    private final DefaultListModel<String> jwtKeywordsListModel;
    private final JList<String> jwtKeywordsList;
    private final JTextField jwtKeywordsTextField;
    
    private final DefaultListModel<String> tokenKeywordsListModel;
    private final JList<String> tokenKeywordsList;
    private final JTextField tokenKeywordsTextField;
    
    // Log UI components
    private final JPanel logPanel;
    private final DefaultTableModel logTableModel;
    private final JTable logTable;
    
    // Counter for log entries
    private int logIdCounter = 1;

    @SneakyThrows
    public JwtPublicSecretsTab(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        
        // Create main panel with BorderLayout
        mainPanel = new JPanel(new BorderLayout());
        
        // Create tabbed pane for configuration and log
        tabbedPane = new JTabbedPane();
        
        // Initialize configuration panel
        configPanel = new JPanel(new BorderLayout());
        
        // Create tabbed pane for different configuration sections
        JTabbedPane configTabbedPane = new JTabbedPane();
        
        // Create secrets panel with table for URL and Lines columns
        String[] secretsColumns = {"URL", "Lines"};
        secretsTableModel = new DefaultTableModel(secretsColumns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Make table non-editable
            }
            
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                return columnIndex == 1 ? Integer.class : String.class;
            }
        };
        
        secretsTable = new JTable(secretsTableModel);
        secretsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        secretsTable.getColumnModel().getColumn(0).setPreferredWidth(400);
        secretsTable.getColumnModel().getColumn(1).setPreferredWidth(100);
        
        // Enable sorting for the secrets table
        TableRowSorter<DefaultTableModel> secretsSorter = new TableRowSorter<>(secretsTableModel);
        secretsTable.setRowSorter(secretsSorter);
        
        JScrollPane secretsScrollPane = new JScrollPane(secretsTable);
        secretsScrollPane.setPreferredSize(new Dimension(500, 300));
        
        secretsTextField = new JTextField(30);
        JButton addSecretButton = new JButton("Add");
        addSecretButton.addActionListener(e -> addSecret());
        
        JButton removeSecretButton = new JButton("Remove");
        removeSecretButton.addActionListener(e -> removeSecret());
        
        JPanel secretsInputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        secretsInputPanel.add(new JLabel("URL:"));
        secretsInputPanel.add(secretsTextField);
        secretsInputPanel.add(addSecretButton);
        secretsInputPanel.add(removeSecretButton);
        
        JPanel secretsPanel = new JPanel(new BorderLayout());
        secretsPanel.add(secretsScrollPane, BorderLayout.CENTER);
        secretsPanel.add(secretsInputPanel, BorderLayout.SOUTH);
        
        configTabbedPane.addTab("Secrets", secretsPanel);
        
        // Create JWT keywords panel
        jwtKeywordsListModel = new DefaultListModel<>();
        jwtKeywordsList = new JList<>(jwtKeywordsListModel);
        jwtKeywordsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane jwtKeywordsScrollPane = new JScrollPane(jwtKeywordsList);
        jwtKeywordsScrollPane.setPreferredSize(new Dimension(500, 300));
        
        jwtKeywordsTextField = new JTextField(30);
        JButton addJwtKeywordButton = new JButton("Add");
        addJwtKeywordButton.addActionListener(e -> addJwtKeyword());
        
        JButton removeJwtKeywordButton = new JButton("Remove");
        removeJwtKeywordButton.addActionListener(e -> removeJwtKeyword());
        
        JPanel jwtKeywordsInputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        jwtKeywordsInputPanel.add(new JLabel("Keyword:"));
        jwtKeywordsInputPanel.add(jwtKeywordsTextField);
        jwtKeywordsInputPanel.add(addJwtKeywordButton);
        jwtKeywordsInputPanel.add(removeJwtKeywordButton);
        
        JPanel jwtKeywordsPanel = new JPanel(new BorderLayout());
        jwtKeywordsPanel.add(jwtKeywordsScrollPane, BorderLayout.CENTER);
        jwtKeywordsPanel.add(jwtKeywordsInputPanel, BorderLayout.SOUTH);
        
        configTabbedPane.addTab("JWT Keywords", jwtKeywordsPanel);
        
        // Create token keywords panel
        tokenKeywordsListModel = new DefaultListModel<>();
        tokenKeywordsList = new JList<>(tokenKeywordsListModel);
        tokenKeywordsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        JScrollPane tokenKeywordsScrollPane = new JScrollPane(tokenKeywordsList);
        tokenKeywordsScrollPane.setPreferredSize(new Dimension(500, 300));
        
        tokenKeywordsTextField = new JTextField(30);
        JButton addTokenKeywordButton = new JButton("Add");
        addTokenKeywordButton.addActionListener(e -> addTokenKeyword());
        
        JButton removeTokenKeywordButton = new JButton("Remove");
        removeTokenKeywordButton.addActionListener(e -> removeTokenKeyword());
        
        JPanel tokenKeywordsInputPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        tokenKeywordsInputPanel.add(new JLabel("Keyword:"));
        tokenKeywordsInputPanel.add(tokenKeywordsTextField);
        tokenKeywordsInputPanel.add(addTokenKeywordButton);
        tokenKeywordsInputPanel.add(removeTokenKeywordButton);
        
        JPanel tokenKeywordsPanel = new JPanel(new BorderLayout());
        tokenKeywordsPanel.add(tokenKeywordsScrollPane, BorderLayout.CENTER);
        tokenKeywordsPanel.add(tokenKeywordsInputPanel, BorderLayout.SOUTH);
        
        configTabbedPane.addTab("Token Keywords", tokenKeywordsPanel);
        
        configPanel.add(configTabbedPane, BorderLayout.CENTER);
        
        // Create button panel for configuration
        JPanel configButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton reloadConfigButton = new JButton("Reload Config");
        reloadConfigButton.addActionListener(this::reloadConfig);
        configButtonPanel.add(reloadConfigButton);
        
        JButton saveConfigButton = new JButton("Save Config");
        saveConfigButton.addActionListener(this::saveConfig);
        configButtonPanel.add(saveConfigButton);
        
        // Add links panel
        JPanel linksPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        JButton sourceButton = new JButton("Source Code");
        try {
            final URI sourceUri = new URI("https://github.com/Wallarm/jwt-heartbreaker");
            sourceButton.addActionListener(e -> openLink(sourceUri));
        } catch (URISyntaxException e) {
            callbacks.printError("Error creating URI: " + e.getMessage());
        }
        linksPanel.add(sourceButton);

        JButton releaseNotesButton = new JButton("Release Notes");
        try {
            final URI releaseNotesUri = new URI("https://lab.wallarm.com/jwt-heartbreaker/");
            releaseNotesButton.addActionListener(e -> openLink(releaseNotesUri));
        } catch (URISyntaxException e) {
            callbacks.printError("Error creating URI: " + e.getMessage());
        }
        linksPanel.add(releaseNotesButton);
        
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(configButtonPanel, BorderLayout.WEST);
        bottomPanel.add(linksPanel, BorderLayout.EAST);
        
        configPanel.add(bottomPanel, BorderLayout.SOUTH);
        
        // Initialize log panel
        logPanel = new JPanel(new BorderLayout());
        
        // Create log table
        String[] logColumns = {"ID", "Time", "URL", "JWT Token Field Name", "JWT Token Value", "Corresponding Secret"};
        logTableModel = new DefaultTableModel(logColumns, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false; // Make log table non-editable
            }
        };
        
        logTable = new JTable(logTableModel);
        
        // Enable sorting for the log table
        TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(logTableModel);
        logTable.setRowSorter(sorter);
        
        // Set column widths
        logTable.getColumnModel().getColumn(0).setPreferredWidth(50);  // ID
        logTable.getColumnModel().getColumn(1).setPreferredWidth(150); // Time
        logTable.getColumnModel().getColumn(2).setPreferredWidth(200); // URL
        logTable.getColumnModel().getColumn(3).setPreferredWidth(150); // JWT Token Field Name
        logTable.getColumnModel().getColumn(4).setPreferredWidth(300); // JWT Token Value
        logTable.getColumnModel().getColumn(5).setPreferredWidth(200); // Corresponding Secret
        
        JScrollPane logScrollPane = new JScrollPane(logTable);
        logPanel.add(logScrollPane, BorderLayout.CENTER);
        
        // Create button panel for log
        JPanel logButtonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        
        JButton clearLogButton = new JButton("Clear Log");
        clearLogButton.addActionListener(e -> clearLog());
        logButtonPanel.add(clearLogButton);
        
        JButton exportLogButton = new JButton("Export Log");
        exportLogButton.addActionListener(e -> exportLog());
        logButtonPanel.add(exportLogButton);
        
        logPanel.add(logButtonPanel, BorderLayout.SOUTH);
        
        // Add panels to tabbed pane
        tabbedPane.addTab("Configuration", configPanel);
        tabbedPane.addTab("Log", logPanel);
        
        mainPanel.add(tabbedPane, BorderLayout.CENTER);
        
        // Load initial configuration
        loadConfigurationData();
        
        callbacks.customizeUiComponent(mainPanel);
    }
    
    /**
     * Add a secret URL to the list
     */
    private void addSecret() {
        String url = secretsTextField.getText().trim();
        if (StringUtils.isNotBlank(url)) {
            try {
                new URL(url); // Validate URL
                if (!tableContainsUrl(secretsTableModel, url)) {
                    secretsTableModel.addRow(new Object[]{url, 0});
                    secretsTextField.setText("");
                } else {
                    JOptionPane.showMessageDialog(mainPanel, 
                        "URL already exists in the list", 
                        "Duplicate Entry", 
                        JOptionPane.WARNING_MESSAGE);
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(mainPanel, 
                    "Invalid URL: " + url, 
                    "Error", 
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    /**
     * Remove selected secret URL from the list
     */
    private void removeSecret() {
        int selectedRow = secretsTable.getSelectedRow();
        if (selectedRow != -1) {
            // Convert view row index to model row index in case table is sorted
            int modelRow = secretsTable.convertRowIndexToModel(selectedRow);
            secretsTableModel.removeRow(modelRow);
        } else {
            JOptionPane.showMessageDialog(mainPanel, 
                "Please select a URL to remove", 
                "No Selection", 
                JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    /**
     * Add a JWT keyword to the list
     */
    private void addJwtKeyword() {
        String keyword = jwtKeywordsTextField.getText().trim();
        if (StringUtils.isNotBlank(keyword)) {
            if (!listContains(jwtKeywordsListModel, keyword)) {
                jwtKeywordsListModel.addElement(keyword);
                jwtKeywordsTextField.setText("");
            } else {
                JOptionPane.showMessageDialog(mainPanel, 
                    "Keyword already exists in the list", 
                    "Duplicate Entry", 
                    JOptionPane.WARNING_MESSAGE);
            }
        }
    }
    
    /**
     * Remove selected JWT keyword from the list
     */
    private void removeJwtKeyword() {
        int selectedIndex = jwtKeywordsList.getSelectedIndex();
        if (selectedIndex != -1) {
            jwtKeywordsListModel.remove(selectedIndex);
        } else {
            JOptionPane.showMessageDialog(mainPanel, 
                "Please select a keyword to remove", 
                "No Selection", 
                JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    /**
     * Add a token keyword to the list
     */
    private void addTokenKeyword() {
        String keyword = tokenKeywordsTextField.getText().trim();
        if (StringUtils.isNotBlank(keyword)) {
            if (!listContains(tokenKeywordsListModel, keyword)) {
                tokenKeywordsListModel.addElement(keyword);
                tokenKeywordsTextField.setText("");
            } else {
                JOptionPane.showMessageDialog(mainPanel, 
                    "Keyword already exists in the list", 
                    "Duplicate Entry", 
                    JOptionPane.WARNING_MESSAGE);
            }
        }
    }
    
    /**
     * Remove selected token keyword from the list
     */
    private void removeTokenKeyword() {
        int selectedIndex = tokenKeywordsList.getSelectedIndex();
        if (selectedIndex != -1) {
            tokenKeywordsListModel.remove(selectedIndex);
        } else {
            JOptionPane.showMessageDialog(mainPanel, 
                "Please select a keyword to remove", 
                "No Selection", 
                JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    /**
     * Check if a list model contains a specific string (case-insensitive)
     */
    private boolean listContains(DefaultListModel<String> model, String value) {
        for (int i = 0; i < model.getSize(); i++) {
            if (model.getElementAt(i).equalsIgnoreCase(value)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Check if a table model contains a specific URL (case-insensitive)
     */
    private boolean tableContainsUrl(DefaultTableModel model, String url) {
        for (int i = 0; i < model.getRowCount(); i++) {
            String tableUrl = (String) model.getValueAt(i, 0);
            if (tableUrl.equalsIgnoreCase(url)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Loads configuration data from Config class into UI components
     */
    private void loadConfigurationData() {
        // Clear existing data
        secretsTableModel.setRowCount(0);
        jwtKeywordsListModel.clear();
        tokenKeywordsListModel.clear();
        
        // Load secrets with line counts
        Map<URL, Integer> secrets = JwtKeyProvider.getSecrets();
        for (Map.Entry<URL, Integer> entry : secrets.entrySet()) {
            secretsTableModel.addRow(new Object[]{entry.getKey().toString(), entry.getValue()});
        }
        
        // Load JWT keywords
        for (String keyword : Config.jwtKeywords) {
            jwtKeywordsListModel.addElement(keyword);
        }
        
        // Load token keywords
        for (String keyword : Config.tokenKeywords) {
            tokenKeywordsListModel.addElement(keyword);
        }
    }
    
    /**
     * Reloads configuration from disk
     */
    @SneakyThrows
    private void reloadConfig(ActionEvent e) {
        Config.loadConfig();
        JwtKeyProvider.loadKeys();
        loadConfigurationData();
        JOptionPane.showMessageDialog(mainPanel, "Configuration reloaded successfully", "Success", JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * Saves configuration to disk
     */
    @SneakyThrows
    private void saveConfig(ActionEvent e) {
        // Collect secrets
        List<String> secrets = new ArrayList<>();
        for (int i = 0; i < secretsTableModel.getRowCount(); i++) {
            String url = (String) secretsTableModel.getValueAt(i, 0);
            try {
                new URL(url); // Validate URL
                secrets.add(url);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(mainPanel, 
                    "Invalid URL: " + url, 
                    "Error", 
                    JOptionPane.ERROR_MESSAGE);
                return;
            }
        }
        
        // Collect JWT keywords
        List<String> jwtKeywords = new ArrayList<>();
        for (int i = 0; i < jwtKeywordsListModel.getSize(); i++) {
            jwtKeywords.add(jwtKeywordsListModel.getElementAt(i));
        }
        
        // Collect token keywords
        List<String> tokenKeywords = new ArrayList<>();
        for (int i = 0; i < tokenKeywordsListModel.getSize(); i++) {
            tokenKeywords.add(tokenKeywordsListModel.getElementAt(i));
        }
        
        // Update configuration
        Config.updateSecrets(secrets);
        Config.updateJwtKeywords(jwtKeywords);
        Config.updateTokenKeywords(tokenKeywords);
        
        // Reload configuration
        Config.loadConfig();
        JwtKeyProvider.loadKeys();
        
        // Refresh UI
        loadConfigurationData();
        
        JOptionPane.showMessageDialog(mainPanel, "Configuration saved successfully", "Success", JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * Adds a new entry to the log table
     */
    public void addLogEntry(String url, String tokenFieldName, String tokenValue, String secret) {
        // Check for duplicates before adding
        if (isDuplicateLogEntry(url, tokenFieldName, tokenValue)) {
            // Skip adding duplicate entry
            return;
        }
        
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String timestamp = dateFormat.format(new Date());
        
        logTableModel.addRow(new Object[]{
            logIdCounter++,
            timestamp,
            url,
            tokenFieldName,
            tokenValue,
            secret
        });
        
        // Switch to log tab to show the new entry
        tabbedPane.setSelectedComponent(logPanel);
    }
    
    /**
     * Checks if a log entry with the same URL, token field name, and token value already exists
     */
    private boolean isDuplicateLogEntry(String url, String tokenFieldName, String tokenValue) {
        for (int i = 0; i < logTableModel.getRowCount(); i++) {
            String existingUrl = (String) logTableModel.getValueAt(i, 2); // URL column
            String existingTokenFieldName = (String) logTableModel.getValueAt(i, 3); // JWT Token Field Name column
            String existingTokenValue = (String) logTableModel.getValueAt(i, 4); // JWT Token Value column
            
            // Check if all three values match
            if (Objects.equals(existingUrl, url) && 
                Objects.equals(existingTokenFieldName, tokenFieldName) && 
                Objects.equals(existingTokenValue, tokenValue)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Clears the log table
     */
    private void clearLog() {
        logTableModel.setRowCount(0);
        logIdCounter = 1;
    }
    
    /**
     * Exports the log table to a file
     */
    private void exportLog() {
        JFileChooser fileChooser = new JFileChooser();
        fileChooser.setDialogTitle("Export Log");
        
        int userSelection = fileChooser.showSaveDialog(mainPanel);
        
        if (userSelection == JFileChooser.APPROVE_OPTION) {
            try {
                java.io.File fileToSave = fileChooser.getSelectedFile();
                if (!fileToSave.getName().toLowerCase().endsWith(".csv")) {
                    fileToSave = new java.io.File(fileToSave.getAbsolutePath() + ".csv");
                }
                
                try (java.io.PrintWriter writer = new java.io.PrintWriter(fileToSave)) {
                    // Write header
                    StringBuilder header = new StringBuilder();
                    for (int i = 0; i < logTableModel.getColumnCount(); i++) {
                        header.append(logTableModel.getColumnName(i));
                        if (i < logTableModel.getColumnCount() - 1) {
                            header.append(",");
                        }
                    }
                    writer.println(header.toString());
                    
                    // Write data
                    for (int row = 0; row < logTableModel.getRowCount(); row++) {
                        StringBuilder sb = new StringBuilder();
                        for (int col = 0; col < logTableModel.getColumnCount(); col++) {
                            Object value = logTableModel.getValueAt(row, col);
                            sb.append(value != null ? value.toString() : "");
                            if (col < logTableModel.getColumnCount() - 1) {
                                sb.append(",");
                            }
                        }
                        writer.println(sb.toString());
                    }
                }
                
                JOptionPane.showMessageDialog(mainPanel, 
                    "Log exported successfully to " + fileToSave.getAbsolutePath(), 
                    "Export Successful", 
                    JOptionPane.INFORMATION_MESSAGE);
                
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(mainPanel, 
                    "Error exporting log: " + ex.getMessage(), 
                    "Export Error", 
                    JOptionPane.ERROR_MESSAGE);
            }
        }
    }
    
    @SneakyThrows
    private void openLink(final URI uri) {
        if (Desktop.isDesktopSupported()) {
            try {
                Desktop.getDesktop().browse(uri);
            } catch (IOException e) {
                callbacks.printError("Error opening link: " + e.getMessage());
            }
        }
    }

    @Override
    public String getTabCaption() {
        return "JWT Heartbreaker";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }
}
