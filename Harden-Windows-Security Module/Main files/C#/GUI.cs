using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Markup;
using System.Xml;
using System.Windows.Media.Imaging;
using System.Linq;
using System.Windows.Forms;
using System.Collections.Concurrent;


namespace HardenWindowsSecurity
{
    /// <summary>
    /// A class to store all of the data that is related to the GUI and its operations
    /// </summary>
    public static class GUI
    {
        // During offline mode, this is the path that the button for MicrosoftSecurityBaselineZipPath assigns
        public static string MicrosoftSecurityBaselineZipPath = string.Empty;

        // During offline mode, this is the path that the button for Microsoft365AppsSecurityBaselineZipPath assigns
        public static string Microsoft365AppsSecurityBaselineZipPath = string.Empty;

        // During offline mode, this is the path that the button for LGPOZipPath assigns
        public static string LGPOZipPath = string.Empty;

        // List of all the selected categories in a thread safe way
        public static ConcurrentQueue<string> SelectedCategories = new ConcurrentQueue<string>();

        // List of all the selected subcategories in a thread safe way
        public static ConcurrentQueue<string> SelectedSubCategories = new ConcurrentQueue<string>();

        // To store the log messages in a thread safe way that will be displayed on the GUI and stored in the Logs text file
        public static ArrayList Logger = ArrayList.Synchronized(new ArrayList());

        // Initialize a flag to determine whether to write logs or not, set to false by default
        public static bool ShouldWriteLogs = false;


        // Set a flag indicating that the required files for the Offline operation mode have been processed
        // When the execute button was clicked, so it won't run twice
        public static bool StartFileDownloadHasRun = false;


        // The following are XAML GUI Elements
        public static string xamlPath;
        public static string xamlContent;
        public static System.Xml.XmlDocument xamlDocument;
        public static System.Xml.XmlNodeReader reader;
        public static System.Windows.Window window;
        public static System.Windows.Controls.Grid parentGrid;
        public static System.Windows.Controls.Primitives.ToggleButton mainTabControlToggle;
        public static System.Windows.Controls.ContentControl mainContentControl;
        public static System.Windows.Style mainContentControlStyle;
        public static System.Windows.Controls.TextBox outputTextBlock;
        public static System.Windows.Controls.ScrollViewer scrollerForOutputTextBlock;
        public static System.Collections.Hashtable correlation;
        public static System.Windows.Controls.ListView categories;
        public static System.Windows.Controls.ListView subCategories;
        public static System.Windows.Controls.CheckBox selectAllCategories;
        public static System.Windows.Controls.CheckBox selectAllSubCategories;


        // fields for Log related elements
        public static System.Windows.Controls.TextBox txtFilePath;
        public static System.Windows.Controls.Button logPath;
        public static System.Windows.Controls.Primitives.ToggleButton log;
        public static System.Windows.Controls.Viewbox loggingViewBox;


        // fields for Offline-Mode related elements
        public static System.Windows.Controls.Grid grid2;
        public static System.Windows.Controls.Primitives.ToggleButton enableOfflineMode;
        public static System.Windows.Controls.Button microsoftSecurityBaselineZipButton;
        public static System.Windows.Controls.TextBox microsoftSecurityBaselineZipTextBox;
        public static System.Windows.Controls.Button microsoft365AppsSecurityBaselineZipButton;
        public static System.Windows.Controls.TextBox microsoft365AppsSecurityBaselineZipTextBox;
        public static System.Windows.Controls.Button lgpoZipButton;
        public static System.Windows.Controls.TextBox lgpoZipTextBox;


        // static constructor of the class
        static GUI()
        {
            // Defining the correlation between Categories and which Sub-Categories they activate
            correlation = new System.Collections.Hashtable
            {
                { "MicrosoftSecurityBaselines", new string[] { "SecBaselines_NoOverrides" } },
                { "MicrosoftDefender", new string[] { "MSFTDefender_SAC", "MSFTDefender_NoDiagData", "MSFTDefender_NoScheduledTask", "MSFTDefender_BetaChannels" } },
                { "LockScreen", new string[] { "LockScreen_CtrlAltDel", "LockScreen_NoLastSignedIn" } },
                { "UserAccountControl", new string[] { "UAC_NoFastSwitching", "UAC_OnlyElevateSigned" } },
                { "CountryIPBlocking", new string[] { "CountryIPBlocking_OFAC" } },
                { "DownloadsDefenseMeasures", new string[] { "DangerousScriptHostsBlocking" } },
                { "NonAdminCommands", new string[] { "ClipboardSync" } }
            };
        }

        /// <summary>
        /// Main method of the class called from the PowerShell code
        /// </summary>
        public static void LoadXaml()
        {
            // Defining the path to the XAML XML file
            xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "Main.xml");
            // Read the content of the XML
            xamlContent = System.IO.File.ReadAllText(xamlPath);

            // Convert the text to XML document
            xamlDocument = new System.Xml.XmlDocument();
            xamlDocument.LoadXml(xamlContent);
            reader = new System.Xml.XmlNodeReader(xamlDocument);

            window = (System.Windows.Window)System.Windows.Markup.XamlReader.Load(reader);

            parentGrid = (System.Windows.Controls.Grid)window.FindName("ParentGrid");
            mainTabControlToggle = (System.Windows.Controls.Primitives.ToggleButton)parentGrid.FindName("MainTabControlToggle");
            mainContentControl = (System.Windows.Controls.ContentControl)mainTabControlToggle.FindName("MainContentControl");

            // Assigning the icon for the Harden Windows Security GUI
            window.Icon = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "ProgramIcon.ico")));

            // Due to using ToggleButton as Tab Control element, this is now considered the parent of all inner elements
            mainContentControlStyle = (System.Windows.Style)mainContentControl.FindName("MainContentControlStyle");

            outputTextBlock = (System.Windows.Controls.TextBox)parentGrid.FindName("OutputTextBlock");
            scrollerForOutputTextBlock = (System.Windows.Controls.ScrollViewer)parentGrid.FindName("ScrollerForOutputTextBlock");

            // Assigning image source paths to the buttons
            // Need to cast the Style to the INameScope before using FindName method on it
            // more info: https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/interfaces/explicit-interface-implementation
            // in PowerShell this would simply work:
            //
            // [System.Windows.Style]$MainContentControlStyle = $MainContentControl.FindName('MainContentControlStyle')
            // $MainContentControlStyle.FindName('PathIcon1').Source
            ((System.Windows.Controls.Image)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("PathIcon1")).Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "path.png")));
            ((System.Windows.Controls.Image)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("PathIcon2")).Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "path.png")));
            ((System.Windows.Controls.Image)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("PathIcon3")).Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "path.png")));
            ((System.Windows.Controls.Image)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("LogButtonIcon")).Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "log.png")));
            ((System.Windows.Controls.Image)parentGrid.FindName("ExecuteButtonIcon")).Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "start.png")));

            categories = (System.Windows.Controls.ListView)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("Categories");
            subCategories = (System.Windows.Controls.ListView)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("SubCategories");
            selectAllCategories = (System.Windows.Controls.CheckBox)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("SelectAllCategories");
            selectAllSubCategories = (System.Windows.Controls.CheckBox)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("SelectAllSubCategories");

            // New initialization for Log related elements
            txtFilePath = (System.Windows.Controls.TextBox)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("txtFilePath");
            logPath = (System.Windows.Controls.Button)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("LogPath");
            log = (System.Windows.Controls.Primitives.ToggleButton)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("Log");
            loggingViewBox = (System.Windows.Controls.Viewbox)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("LoggingViewBox");


            // initializations for Offline-Mode related elements
            grid2 = (System.Windows.Controls.Grid)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("Grid2");
            enableOfflineMode = (System.Windows.Controls.Primitives.ToggleButton)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("EnableOfflineMode");
            microsoftSecurityBaselineZipButton = (System.Windows.Controls.Button)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("MicrosoftSecurityBaselineZipButton");
            microsoftSecurityBaselineZipTextBox = (System.Windows.Controls.TextBox)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("MicrosoftSecurityBaselineZipTextBox");
            microsoft365AppsSecurityBaselineZipButton = (System.Windows.Controls.Button)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("Microsoft365AppsSecurityBaselineZipButton");
            microsoft365AppsSecurityBaselineZipTextBox = (System.Windows.Controls.TextBox)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("Microsoft365AppsSecurityBaselineZipTextBox");
            lgpoZipButton = (System.Windows.Controls.Button)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("LGPOZipButton");
            lgpoZipTextBox = (System.Windows.Controls.TextBox)((System.Windows.Markup.INameScope)mainContentControlStyle).FindName("LGPOZipTextBox");

            // Initially set the visibility of the text area for the selected LogPath to Collapsed
            txtFilePath.Visibility = Visibility.Collapsed;

            // Initialize the LogPath button element as disabled
            logPath.IsEnabled = false;

            // Defining event handler
            // When the Log checkbox is checked, enable the LogPath button
            log.Checked += (sender, e) => logPath.IsEnabled = true;

            // Defining event handler
            // When the Log checkbox is unchecked, disable the LogPath button and set the visibility of the LogPath text area to Collapsed
            log.Unchecked += (sender, e) =>
            {
                logPath.IsEnabled = false;
                txtFilePath.Visibility = Visibility.Collapsed;
            };

            // Event handler for the Log Path button click to open a file path picker dialog
            logPath.Click += (sender, e) =>
            {
                using (SaveFileDialog dialog = new SaveFileDialog())
                {
                    // Defining the initial directory where the file picker GUI will be opened for the user
                    dialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    dialog.Filter = "Text files (*.txt)|*.txt";
                    dialog.Title = "Choose where to save the log file";

                    if (dialog.ShowDialog() == DialogResult.OK)
                    {
                        txtFilePath.Text = dialog.FileName;
                        txtFilePath.Visibility = Visibility.Visible;

                        HardenWindowsSecurity.Logger.LogMessage($"Logs will be saved in: {txtFilePath.Text}");
                    }
                }

                ShouldWriteLogs = true;
            };

            // Initially disable the Offline Mode configuration inputs until the Offline Mode checkbox is checked
            DisableOfflineModeConfigInputs();

            // Implement the event handlers for the UI elements
            AddEventHandlers();

            // Update the sub-categories based on the initial unchecked state of the categories
            UpdateSubCategories();


            if (!HardenWindowsSecurity.GlobalVars.Offline)
            {
                // Disable the Offline mode toggle button if -Offline parameter was not used with the function
                enableOfflineMode.IsEnabled = false;

                // Display a message showing how to activate the offline mode

                // Add a new row definition for the text message
                System.Windows.Controls.RowDefinition offlineModeUnavailableRow = new System.Windows.Controls.RowDefinition
                {
                    Height = new System.Windows.GridLength(50)
                };
                grid2.RowDefinitions.Add(offlineModeUnavailableRow);

                // Create a new text box
                System.Windows.Controls.TextBox offlineModeUnavailableNoticeBox = new System.Windows.Controls.TextBox
                {
                    HorizontalAlignment = System.Windows.HorizontalAlignment.Stretch,
                    VerticalAlignment = System.Windows.VerticalAlignment.Stretch,
                    TextWrapping = System.Windows.TextWrapping.Wrap,
                    Text = "To enable offline mode, use: Protect-WindowsSecurity -GUI -Offline",
                    TextAlignment = System.Windows.TextAlignment.Center,
                    Background = System.Windows.Media.Brushes.Transparent,
                    FontSize = 20,
                    BorderThickness = new System.Windows.Thickness(0),
                    Margin = new System.Windows.Thickness(10, 20, 10, 0),
                    ToolTip = "To enable offline mode, use: Protect-WindowsSecurity -GUI -Offline"
                };
                offlineModeUnavailableNoticeBox.SetValue(System.Windows.Controls.Grid.ColumnSpanProperty, 2);
                offlineModeUnavailableNoticeBox.SetValue(System.Windows.Controls.Grid.RowProperty, 4);

                // Create a gradient brush for the text color
                System.Windows.Media.LinearGradientBrush gradientBrush = new System.Windows.Media.LinearGradientBrush();
                gradientBrush.GradientStops.Add(new System.Windows.Media.GradientStop(System.Windows.Media.Colors.Purple, 0));
                gradientBrush.GradientStops.Add(new System.Windows.Media.GradientStop(System.Windows.Media.Colors.Blue, 1));
                offlineModeUnavailableNoticeBox.Foreground = gradientBrush;

                // Add the text box to the grid
                grid2.Children.Add(offlineModeUnavailableNoticeBox);
            };
        }


        /// <summary>
        /// A method to update sub-category items based on the checked categories
        /// </summary>
        private static void UpdateSubCategories()
        {
            // Disable all sub-category items first
            foreach (var item in subCategories.Items)
            {
                ((System.Windows.Controls.ListViewItem)item).IsEnabled = false;
            }

            // Get all checked categories
            var checkedCategories = categories.Items
                .Cast<System.Windows.Controls.ListViewItem>()
                .Where(item => ((System.Windows.Controls.CheckBox)item.Content).IsChecked == true)
                .ToList();

            // Enable the corresponding sub-category items
            foreach (var categoryItem in checkedCategories)
            {
                string categoryContent = ((System.Windows.Controls.CheckBox)categoryItem.Content).Name;
                if (correlation.Contains(categoryContent))
                {
                    foreach (string subCategoryName in (string[])correlation[categoryContent])
                    {
                        foreach (var item in subCategories.Items)
                        {
                            System.Windows.Controls.ListViewItem subCategoryItem = (System.Windows.Controls.ListViewItem)item;
                            if (((System.Windows.Controls.CheckBox)subCategoryItem.Content).Name == subCategoryName)
                            {
                                subCategoryItem.IsEnabled = true;
                            }
                        }
                    }
                }
            }

            // Uncheck sub-category items whose category is not selected
            foreach (var item in subCategories.Items)
            {
                System.Windows.Controls.ListViewItem subCategoryItem = (System.Windows.Controls.ListViewItem)item;
                if (!subCategoryItem.IsEnabled)
                {
                    ((System.Windows.Controls.CheckBox)subCategoryItem.Content).IsChecked = false;
                }
            }

            // Disable categories that are not valid for the current session
            foreach (var item in categories.Items)
            {
                System.Windows.Controls.ListViewItem categoryItem = (System.Windows.Controls.ListViewItem)item;
                if (!HardenWindowsSecurity.GlobalVars.HardeningCategorieX.Contains(((System.Windows.Controls.CheckBox)categoryItem.Content).Name))
                {
                    categoryItem.IsEnabled = false;
                }
            }
        }


        // Method to disable the Offline Mode configuration inputs
        private static void DisableOfflineModeConfigInputs()
        {
            microsoftSecurityBaselineZipButton.IsEnabled = false;
            microsoftSecurityBaselineZipTextBox.IsEnabled = false;
            microsoft365AppsSecurityBaselineZipButton.IsEnabled = false;
            microsoft365AppsSecurityBaselineZipTextBox.IsEnabled = false;
            lgpoZipButton.IsEnabled = false;
            lgpoZipTextBox.IsEnabled = false;
        }

        // The method that defines all of the event handlers for the UI elements
        private static void AddEventHandlers()
        {
            // Add Checked and Unchecked event handlers to category checkboxes
            foreach (var item in categories.Items)
            {
                System.Windows.Controls.ListViewItem categoryItem = (System.Windows.Controls.ListViewItem)item;
                System.Windows.Controls.CheckBox checkBox = (System.Windows.Controls.CheckBox)categoryItem.Content;
                checkBox.DataContext = categoryItem;
                checkBox.Checked += (sender, e) => UpdateSubCategories();
                checkBox.Unchecked += (sender, e) => UpdateSubCategories();
            }

            // Register an event handler for the window size changed event
            window.SizeChanged += (sender, e) =>
            {
                // Calculate the max width based on the window width
                // Subtract 50 to account for the padding and margin
                long newMaxWidth = (long)window.ActualWidth - 50;

                // Update the main TextBox's MaxWidth property dynamically, instead of setting it to a fixed value in the XAML
                outputTextBlock.MaxWidth = newMaxWidth;
            };

            // Add click event for 'Check All' button
            selectAllCategories.Checked += (sender, e) =>
            {
                foreach (var item in categories.Items)
                {
                    System.Windows.Controls.ListViewItem categoryItem = (System.Windows.Controls.ListViewItem)item;
                    if (HardenWindowsSecurity.GlobalVars.HardeningCategorieX.Contains(((System.Windows.Controls.CheckBox)categoryItem.Content).Name))
                    {
                        ((System.Windows.Controls.CheckBox)categoryItem.Content).IsChecked = true;
                    }
                }
            };

            // Add click event for 'Uncheck All' button
            selectAllCategories.Unchecked += (sender, e) =>
            {
                foreach (var item in categories.Items)
                {
                    ((System.Windows.Controls.CheckBox)((System.Windows.Controls.ListViewItem)item).Content).IsChecked = false;
                }
            };

            // Add click event for 'Check All' button for enabled sub-categories
            selectAllSubCategories.Checked += (sender, e) =>
            {
                foreach (var item in subCategories.Items)
                {
                    System.Windows.Controls.ListViewItem subCategoryItem = (System.Windows.Controls.ListViewItem)item;
                    if (subCategoryItem.IsEnabled)
                    {
                        ((System.Windows.Controls.CheckBox)subCategoryItem.Content).IsChecked = true;
                    }
                }
            };

            // Add click event for 'Uncheck All' button from sub-categories, regardless of whether they are enabled or disabled
            selectAllSubCategories.Unchecked += (sender, e) =>
            {
                foreach (var item in subCategories.Items)
                {
                    ((System.Windows.Controls.CheckBox)((System.Windows.Controls.ListViewItem)item).Content).IsChecked = false;
                }
            };


            // Add Checked event handler to enable offline mode controls/buttons
            // When the Offline Mode button it toggled
            enableOfflineMode.Checked += (sender, e) =>
            {
                microsoftSecurityBaselineZipButton.IsEnabled = true;
                microsoftSecurityBaselineZipTextBox.IsEnabled = true;
                microsoft365AppsSecurityBaselineZipButton.IsEnabled = true;
                microsoft365AppsSecurityBaselineZipTextBox.IsEnabled = true;
                lgpoZipButton.IsEnabled = true;
                lgpoZipTextBox.IsEnabled = true;
            };

            // Add Unchecked event handler to disable offline mode controls/buttons
            enableOfflineMode.Unchecked += (sender, e) =>
            {
                DisableOfflineModeConfigInputs();
            };


            // Define the click event for the Microsoft Security Baseline Zip button
            microsoftSecurityBaselineZipButton.Click += (sender, e) =>
            {
                using (var dialog = new System.Windows.Forms.OpenFileDialog())
                {
                    dialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    dialog.Filter = "Zip files (*.zip)|*.zip";
                    dialog.Title = "Select the Microsoft Security Baseline Zip file";

                    if (dialog.ShowDialog() == DialogResult.OK)
                    {
                        try
                        {
                            if (!HardenWindowsSecurity.SneakAndPeek.Search("Windows*Security Baseline/Scripts/Baseline-LocalInstall.ps1", dialog.FileName))
                            {
                                HardenWindowsSecurity.Logger.LogMessage("The selected Zip file does not contain the Microsoft Security Baselines Baseline-LocalInstall.ps1 which is required for the Protect-WindowsSecurity function to work properly");
                            }
                            else
                            {
                                // For displaying the text on the GUI's text box
                                microsoftSecurityBaselineZipTextBox.Text = dialog.FileName;
                                // The actual value that will be used
                                HardenWindowsSecurity.GUI.MicrosoftSecurityBaselineZipPath = dialog.FileName;
                            }
                        }
                        catch (Exception ex)
                        {
                            HardenWindowsSecurity.Logger.LogMessage(ex.Message);
                        }
                    }
                }
            };

            // Define the click event for the Microsoft 365 Apps Security Baseline Zip button
            microsoft365AppsSecurityBaselineZipButton.Click += (sender, e) =>
            {
                using (var dialog = new System.Windows.Forms.OpenFileDialog())
                {
                    dialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    dialog.Filter = "Zip files (*.zip)|*.zip";
                    dialog.Title = "Select the Microsoft 365 Apps Security Baseline Zip file";

                    if (dialog.ShowDialog() == DialogResult.OK)
                    {
                        try
                        {
                            if (!HardenWindowsSecurity.SneakAndPeek.Search("Microsoft 365 Apps for Enterprise*/Scripts/Baseline-LocalInstall.ps1", dialog.FileName))
                            {
                                HardenWindowsSecurity.Logger.LogMessage("The selected Zip file does not contain the Microsoft 365 Apps for Enterprise Security Baselines Baseline-LocalInstall.ps1 which is required for the Protect-WindowsSecurity function to work properly");
                            }
                            else
                            {
                                // For displaying the text on the GUI's text box
                                microsoft365AppsSecurityBaselineZipTextBox.Text = dialog.FileName;
                                // The actual value that will be used
                                HardenWindowsSecurity.GUI.Microsoft365AppsSecurityBaselineZipPath = dialog.FileName;
                            }
                        }
                        catch (Exception ex)
                        {
                            HardenWindowsSecurity.Logger.LogMessage(ex.Message);
                        }
                    }
                }
            };

            // Define the click event for the LGPO Zip button
            lgpoZipButton.Click += (sender, e) =>
            {
                using (var dialog = new System.Windows.Forms.OpenFileDialog())
                {
                    dialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    dialog.Filter = "Zip files (*.zip)|*.zip";
                    dialog.Title = "Select the LGPO Zip file";

                    if (dialog.ShowDialog() == DialogResult.OK)
                    {
                        try
                        {
                            if (!HardenWindowsSecurity.SneakAndPeek.Search("LGPO_*/LGPO.exe", dialog.FileName))
                            {
                                HardenWindowsSecurity.Logger.LogMessage("The selected Zip file does not contain the LGPO.exe which is required for the Protect-WindowsSecurity function to work properly");
                            }
                            else
                            {
                                // For displaying the text on the GUI's text box
                                lgpoZipTextBox.Text = dialog.FileName;
                                // The actual value that will be used
                                HardenWindowsSecurity.GUI.LGPOZipPath = dialog.FileName;
                            }
                        }
                        catch (Exception ex)
                        {
                            HardenWindowsSecurity.Logger.LogMessage(ex.Message);
                        }
                    }
                }
            };

            // Defining what happens when the GUI window is closed
            window.Closed += (sender, e) =>
            {
                // Only proceed further if user enabled logging
                if (HardenWindowsSecurity.GUI.ShouldWriteLogs)
                {

                    // Create the footer to the log file
                    string endOfLogFile = $"""
**********************
Harden Windows Security operation log end
End time: {DateTime.Now}
**********************
""";

                    // Add the footer to the log file
                    HardenWindowsSecurity.GUI.Logger.Add(endOfLogFile);

                    // Convert ArrayList to List<string>
                    List<string> logEntries = new List<string>();
                    foreach (string item in HardenWindowsSecurity.GUI.Logger)
                    {
                        logEntries.Add(item);
                    }

                    // Append log entries to the file
                    File.AppendAllLines(txtFilePath.Text, logEntries);
                };

            };
        }
    }
}
