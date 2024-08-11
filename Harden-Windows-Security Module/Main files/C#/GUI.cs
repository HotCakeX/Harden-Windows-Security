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
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
// additional assemblies
using System.Diagnostics;
using System.Windows.Automation;
using System.Windows.Controls.Ribbon;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Forms.Integration;
using System.Windows.Ink;
using System.Windows.Media.Animation;
using System.Windows.Media.Media3D;
using System.Windows.Media.TextFormatting;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Shell;

#nullable enable

namespace HardenWindowsSecurity
{
    /// <summary>
    /// A class to store all of the data that is related to the GUI and its operations
    /// </summary>
    public partial class GUI
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
        public static string? xamlPath;
        public static string? xamlContent;
        public static System.Xml.XmlDocument? xamlDocument;
        public static System.Xml.XmlNodeReader? reader;
        public static System.Windows.Window? window;
        public static System.Windows.Controls.Grid? parentGrid;
        public static System.Windows.Controls.Primitives.ToggleButton? mainTabControlToggle;
        public static System.Windows.Controls.ContentControl? mainContentControl;
        public static System.Windows.Style? mainContentControlStyle;
        public static System.Windows.Controls.TextBox? outputTextBlock;
        public static System.Windows.Controls.ScrollViewer? scrollerForOutputTextBlock;


        // Defining the correlation between Categories and which Sub-Categories they activate
        public static System.Collections.Hashtable correlation = new System.Collections.Hashtable(StringComparer.OrdinalIgnoreCase)
            {
                { "MicrosoftSecurityBaselines", new string[] { "SecBaselines_NoOverrides" } },
                { "MicrosoftDefender", new string[] { "MSFTDefender_SAC", "MSFTDefender_NoDiagData", "MSFTDefender_NoScheduledTask", "MSFTDefender_BetaChannels" } },
                { "LockScreen", new string[] { "LockScreen_CtrlAltDel", "LockScreen_NoLastSignedIn" } },
                { "UserAccountControl", new string[] { "UAC_NoFastSwitching", "UAC_OnlyElevateSigned" } },
                { "CountryIPBlocking", new string[] { "CountryIPBlocking_OFAC" } },
                { "DownloadsDefenseMeasures", new string[] { "DangerousScriptHostsBlocking" } },
                { "NonAdminCommands", new string[] { "ClipboardSync" } }
            };

        public static System.Windows.Controls.ListView? categories;
        public static System.Windows.Controls.ListView? subCategories;
        public static System.Windows.Controls.CheckBox? selectAllCategories;
        public static System.Windows.Controls.CheckBox? selectAllSubCategories;
        public static System.Windows.Controls.ProgressBar? mainProgressBar;


        // fields for Log related elements
        public static System.Windows.Controls.TextBox? txtFilePath;
        public static System.Windows.Controls.Button? logPath;
        public static System.Windows.Controls.Primitives.ToggleButton? log;
        public static System.Windows.Controls.Viewbox? loggingViewBox;


        // fields for Offline-Mode related elements
        public static System.Windows.Controls.Grid? grid2;
        public static System.Windows.Controls.Primitives.ToggleButton? enableOfflineMode;
        public static System.Windows.Controls.Button? microsoftSecurityBaselineZipButton;
        public static System.Windows.Controls.TextBox? microsoftSecurityBaselineZipTextBox;
        public static System.Windows.Controls.Button? microsoft365AppsSecurityBaselineZipButton;
        public static System.Windows.Controls.TextBox? microsoft365AppsSecurityBaselineZipTextBox;
        public static System.Windows.Controls.Button? lgpoZipButton;
        public static System.Windows.Controls.TextBox? lgpoZipTextBox;

        /// <summary>
        /// Main method of the class called from the PowerShell code
        /// </summary>
        public static void LoadXaml()
        {
            // Defining the path to the XAML XML file
            if (HardenWindowsSecurity.GlobalVars.path == null)
            {
                throw new System.ArgumentNullException("GlobalVars.path cannot be null.");
            }

            GUI.xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "Main.xaml");
            // Read the content of the XML
            GUI.xamlContent = System.IO.File.ReadAllText(GUI.xamlPath);

            // Convert the text to XML document
            GUI.xamlDocument = new System.Xml.XmlDocument();
            GUI.xamlDocument.LoadXml(GUI.xamlContent);
            GUI.reader = new System.Xml.XmlNodeReader(GUI.xamlDocument);

            GUI.window = (System.Windows.Window)System.Windows.Markup.XamlReader.Load(GUI.reader);

            GUI.parentGrid = (System.Windows.Controls.Grid)GUI.window.FindName("ParentGrid");
            GUI.mainTabControlToggle = (System.Windows.Controls.Primitives.ToggleButton)GUI.parentGrid.FindName("MainTabControlToggle");
            GUI.mainContentControl = (System.Windows.Controls.ContentControl)GUI.mainTabControlToggle.FindName("MainContentControl");

            // Finding the progress bar
            GUI.mainProgressBar = (System.Windows.Controls.ProgressBar)GUI.parentGrid.FindName("MainProgressBar");

            // Set Main progress bar visibility initially to Collapsed
            GUI.mainProgressBar.Visibility = Visibility.Collapsed;

            // Assigning the icon for the Harden Windows Security GUI
            GUI.window.Icon = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "ProgramIcon.ico")));

            // Due to using ToggleButton as Tab Control element, this is now considered the parent of all inner elements
            GUI.mainContentControlStyle = (System.Windows.Style)GUI.mainContentControl.FindName("MainContentControlStyle");

            GUI.outputTextBlock = (System.Windows.Controls.TextBox)GUI.parentGrid.FindName("OutputTextBlock");
            GUI.scrollerForOutputTextBlock = (System.Windows.Controls.ScrollViewer)GUI.parentGrid.FindName("ScrollerForOutputTextBlock");

            // Assigning image source paths to the buttons
            // Need to cast the Style to the INameScope before using FindName method on it
            // more info: https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/interfaces/explicit-interface-implementation
            // in PowerShell this would simply work:
            //
            // [System.Windows.Style]$MainContentControlStyle = $MainContentControl.FindName('MainContentControlStyle')
            // $MainContentControlStyle.FindName('PathIcon1').Source
            ((System.Windows.Controls.Image)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("PathIcon1")).Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "path.png")));
            ((System.Windows.Controls.Image)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("PathIcon2")).Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "path.png")));
            ((System.Windows.Controls.Image)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("PathIcon3")).Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "path.png")));
            ((System.Windows.Controls.Image)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("LogButtonIcon")).Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "log.png")));
            ((System.Windows.Controls.Image)GUI.parentGrid.FindName("ExecuteButtonIcon")).Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "start.png")));

            GUI.categories = (System.Windows.Controls.ListView)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("Categories");
            GUI.subCategories = (System.Windows.Controls.ListView)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("SubCategories");
            GUI.selectAllCategories = (System.Windows.Controls.CheckBox)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("SelectAllCategories");
            GUI.selectAllSubCategories = (System.Windows.Controls.CheckBox)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("SelectAllSubCategories");

            // New initialization for Log related elements
            GUI.txtFilePath = (System.Windows.Controls.TextBox)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("txtFilePath");
            GUI.logPath = (System.Windows.Controls.Button)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("LogPath");
            GUI.log = (System.Windows.Controls.Primitives.ToggleButton)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("Log");
            GUI.loggingViewBox = (System.Windows.Controls.Viewbox)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("LoggingViewBox");


            // initializations for Offline-Mode related elements
            GUI.grid2 = (System.Windows.Controls.Grid)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("Grid2");
            GUI.enableOfflineMode = (System.Windows.Controls.Primitives.ToggleButton)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("EnableOfflineMode");
            GUI.microsoftSecurityBaselineZipButton = (System.Windows.Controls.Button)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("MicrosoftSecurityBaselineZipButton");
            GUI.microsoftSecurityBaselineZipTextBox = (System.Windows.Controls.TextBox)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("MicrosoftSecurityBaselineZipTextBox");
            GUI.microsoft365AppsSecurityBaselineZipButton = (System.Windows.Controls.Button)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("Microsoft365AppsSecurityBaselineZipButton");
            GUI.microsoft365AppsSecurityBaselineZipTextBox = (System.Windows.Controls.TextBox)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("Microsoft365AppsSecurityBaselineZipTextBox");
            GUI.lgpoZipButton = (System.Windows.Controls.Button)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("LGPOZipButton");
            GUI.lgpoZipTextBox = (System.Windows.Controls.TextBox)((System.Windows.Markup.INameScope)GUI.mainContentControlStyle).FindName("LGPOZipTextBox");

            // Initially set the visibility of the text area for the selected LogPath to Collapsed
            GUI.txtFilePath.Visibility = Visibility.Collapsed;

            // Initialize the LogPath button element as disabled
            GUI.logPath.IsEnabled = false;

            // Defining event handler
            // When the Log checkbox is checked, enable the LogPath button
            GUI.log.Checked += (sender, e) => GUI.logPath.IsEnabled = true;

            // Defining event handler
            // When the Log checkbox is unchecked, disable the LogPath button and set the visibility of the LogPath text area to Collapsed
            GUI.log.Unchecked += (sender, e) =>
            {
                GUI.logPath.IsEnabled = false;
                GUI.txtFilePath.Visibility = Visibility.Collapsed;
            };

            // Event handler for the Log Path button click to open a file path picker dialog
            GUI.logPath.Click += (sender, e) =>
            {
                using (SaveFileDialog dialog = new SaveFileDialog())
                {
                    // Defining the initial directory where the file picker GUI will be opened for the user
                    dialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    dialog.Filter = "Text files (*.txt)|*.txt";
                    dialog.Title = "Choose where to save the log file";

                    if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                    {
                        GUI.txtFilePath.Text = dialog.FileName;
                        GUI.txtFilePath.Visibility = Visibility.Visible;

                        HardenWindowsSecurity.Logger.LogMessage($"Logs will be saved in: {GUI.txtFilePath.Text}");
                    }
                }

                GUI.ShouldWriteLogs = true;
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
                GUI.enableOfflineMode.IsEnabled = false;

                // Display a message showing how to activate the offline mode

                // Add a new row definition for the text message
                System.Windows.Controls.RowDefinition offlineModeUnavailableRow = new System.Windows.Controls.RowDefinition
                {
                    Height = new System.Windows.GridLength(50)
                };
                GUI.grid2.RowDefinitions.Add(offlineModeUnavailableRow);

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
                GUI.grid2.Children.Add(offlineModeUnavailableNoticeBox);
            };
        }


        /// <summary>
        /// A method to update sub-category items based on the checked categories
        /// </summary>
        private static void UpdateSubCategories()
        {
            // Disable all sub-category items first
            foreach (var item in GUI.subCategories!.Items)
            {
                ((System.Windows.Controls.ListViewItem)item).IsEnabled = false;
            }

            // Get all checked categories
            var checkedCategories = GUI.categories!.Items
                .Cast<System.Windows.Controls.ListViewItem>()
                .Where(item => ((System.Windows.Controls.CheckBox)item.Content).IsChecked == true)
                .ToList();

            // Enable the corresponding sub-category items
            foreach (var categoryItem in checkedCategories)
            {
                string categoryContent = ((System.Windows.Controls.CheckBox)categoryItem.Content).Name;
                if (GUI.correlation.Contains(categoryContent))
                {
                    if (GUI.correlation[categoryContent] is string[] subCategoryNames)
                    {
                        foreach (string subCategoryName in subCategoryNames)
                        {
                            foreach (var item in GUI.subCategories.Items)
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
            }

            // Uncheck sub-category items whose category is not selected
            foreach (var item in GUI.subCategories.Items)
            {
                System.Windows.Controls.ListViewItem subCategoryItem = (System.Windows.Controls.ListViewItem)item;
                if (!subCategoryItem.IsEnabled)
                {
                    ((System.Windows.Controls.CheckBox)subCategoryItem.Content).IsChecked = false;
                }
            }

            if (HardenWindowsSecurity.GlobalVars.HardeningCategorieX == null)
            {
                throw new System.ArgumentNullException("GlobalVars.HardeningCategorieX cannot be null.");
            }

            // Disable categories that are not valid for the current session
            foreach (var item in GUI.categories.Items)
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
            GUI.microsoftSecurityBaselineZipButton!.IsEnabled = false;
            GUI.microsoftSecurityBaselineZipTextBox!.IsEnabled = false;
            GUI.microsoft365AppsSecurityBaselineZipButton!.IsEnabled = false;
            GUI.microsoft365AppsSecurityBaselineZipTextBox!.IsEnabled = false;
            GUI.lgpoZipButton!.IsEnabled = false;
            GUI.lgpoZipTextBox!.IsEnabled = false;
        }

        // The method that defines all of the event handlers for the UI elements
        private static void AddEventHandlers()
        {

            #region
            // null checks to make sure the elements are available to the AddEventHandlers method
            // LoadXaml method doesn't need the checks because these values are initialized in that method

            if (GUI.window == null)
            {
                throw new Exception("AddEventHandlers Method: Window object is empty!");
            }

            if (GUI.outputTextBlock == null)
            {
                throw new Exception("AddEventHandlers Method: outputTextBlock object is empty!");
            }

            if (GUI.categories == null)
            {
                throw new Exception("AddEventHandlers Method: categories object is empty!");
            }

            if (GUI.selectAllCategories == null)
            {
                throw new Exception("AddEventHandlers Method: selectAllCategories object is empty!");
            }

            if (GUI.subCategories == null)
            {
                throw new Exception("AddEventHandlers Method: subCategories object is empty!");
            }

            if (GUI.selectAllSubCategories == null)
            {
                throw new Exception("AddEventHandlers Method: selectAllSubCategories object is empty!");
            }

            if (GUI.microsoft365AppsSecurityBaselineZipTextBox == null)
            {
                throw new Exception("AddEventHandlers Method: microsoft365AppsSecurityBaselineZipTextBox object is empty!");
            }

            if (GUI.lgpoZipButton == null)
            {
                throw new Exception("AddEventHandlers Method: lgpoZipButton object is empty!");
            }

            if (GUI.lgpoZipTextBox == null)
            {
                throw new Exception("AddEventHandlers Method: lgpoZipTextBox object is empty!");
            }

            if (GUI.txtFilePath == null)
            {
                throw new Exception("AddEventHandlers Method: txtFilePath object is empty!");
            }

            if (GUI.enableOfflineMode == null)
            {
                throw new Exception("AddEventHandlers Method: enableOfflineMode object is empty!");
            }

            if (GUI.microsoftSecurityBaselineZipButton == null)
            {
                throw new Exception("AddEventHandlers Method: microsoftSecurityBaselineZipButton object is empty!");
            }

            if (GUI.microsoftSecurityBaselineZipTextBox == null)
            {
                throw new Exception("AddEventHandlers Method: microsoftSecurityBaselineZipTextBox object is empty!");
            }

            if (GUI.microsoft365AppsSecurityBaselineZipButton == null)
            {
                throw new Exception("AddEventHandlers Method: microsoft365AppsSecurityBaselineZipButton object is empty!");
            }
            #endregion


            // Add Checked and Unchecked event handlers to category checkboxes
            foreach (var item in GUI.categories.Items)
            {
                System.Windows.Controls.ListViewItem categoryItem = (System.Windows.Controls.ListViewItem)item;
                System.Windows.Controls.CheckBox checkBox = (System.Windows.Controls.CheckBox)categoryItem.Content;
                checkBox.DataContext = categoryItem;
                checkBox.Checked += (sender, e) => UpdateSubCategories();
                checkBox.Unchecked += (sender, e) => UpdateSubCategories();
            }

            // Register an event handler for the window size changed event
            GUI.window.SizeChanged += (sender, e) =>
            {
                // Calculate the max width based on the window width
                // Subtract 50 to account for the padding and margin
                long newMaxWidth = (long)GUI.window.ActualWidth - 50;

                // Update the main TextBox's MaxWidth property dynamically, instead of setting it to a fixed value in the XAML
                GUI.outputTextBlock.MaxWidth = newMaxWidth;
            };

            // event handler to make the GUI window draggable wherever it's empty
            GUI.window.MouseDown += (sender, e) =>
                        {
                            // Only allow dragging the window when the left mouse button (also includes touch) is clicked
                            if (e.ChangedButton == MouseButton.Left)
                            {
                                GUI.window.DragMove();
                            }
                        };

            // Add click event for 'Check All' button
            GUI.selectAllCategories.Checked += (sender, e) =>
            {

                if (HardenWindowsSecurity.GlobalVars.HardeningCategorieX == null)
                {
                    throw new System.ArgumentNullException("GlobalVars.HardeningCategorieX cannot be null.");
                }
                foreach (var item in GUI.categories.Items)
                {
                    System.Windows.Controls.ListViewItem categoryItem = (System.Windows.Controls.ListViewItem)item;
                    if (HardenWindowsSecurity.GlobalVars.HardeningCategorieX.Contains(((System.Windows.Controls.CheckBox)categoryItem.Content).Name))
                    {
                        ((System.Windows.Controls.CheckBox)categoryItem.Content).IsChecked = true;
                    }
                }
            };

            // Add click event for 'Uncheck All' button
            GUI.selectAllCategories.Unchecked += (sender, e) =>
            {
                foreach (var item in GUI.categories.Items)
                {
                    ((System.Windows.Controls.CheckBox)((System.Windows.Controls.ListViewItem)item).Content).IsChecked = false;
                }
            };

            // Add click event for 'Check All' button for enabled sub-categories
            GUI.selectAllSubCategories.Checked += (sender, e) =>
            {
                foreach (var item in GUI.subCategories.Items)
                {
                    System.Windows.Controls.ListViewItem subCategoryItem = (System.Windows.Controls.ListViewItem)item;
                    if (subCategoryItem.IsEnabled)
                    {
                        ((System.Windows.Controls.CheckBox)subCategoryItem.Content).IsChecked = true;
                    }
                }
            };

            // Add click event for 'Uncheck All' button from sub-categories, regardless of whether they are enabled or disabled
            GUI.selectAllSubCategories.Unchecked += (sender, e) =>
            {
                foreach (var item in GUI.subCategories.Items)
                {
                    ((System.Windows.Controls.CheckBox)((System.Windows.Controls.ListViewItem)item).Content).IsChecked = false;
                }
            };


            // Add Checked event handler to enable offline mode controls/buttons
            // When the Offline Mode button it toggled
            GUI.enableOfflineMode.Checked += (sender, e) =>
            {
                GUI.microsoftSecurityBaselineZipButton.IsEnabled = true;
                GUI.microsoftSecurityBaselineZipTextBox.IsEnabled = true;
                GUI.microsoft365AppsSecurityBaselineZipButton.IsEnabled = true;
                GUI.microsoft365AppsSecurityBaselineZipTextBox.IsEnabled = true;
                GUI.lgpoZipButton.IsEnabled = true;
                GUI.lgpoZipTextBox.IsEnabled = true;
            };

            // Add Unchecked event handler to disable offline mode controls/buttons
            GUI.enableOfflineMode.Unchecked += (sender, e) =>
            {
                DisableOfflineModeConfigInputs();
            };


            // Define the click event for the Microsoft Security Baseline Zip button
            GUI.microsoftSecurityBaselineZipButton.Click += (sender, e) =>
            {
                using (var dialog = new System.Windows.Forms.OpenFileDialog())
                {
                    dialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    dialog.Filter = "Zip files (*.zip)|*.zip";
                    dialog.Title = "Select the Microsoft Security Baseline Zip file";

                    if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
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
                                GUI.microsoftSecurityBaselineZipTextBox.Text = dialog.FileName;
                                // The actual value that will be used
                                GUI.MicrosoftSecurityBaselineZipPath = dialog.FileName;
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
            GUI.microsoft365AppsSecurityBaselineZipButton.Click += (sender, e) =>
            {
                using (var dialog = new System.Windows.Forms.OpenFileDialog())
                {
                    dialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    dialog.Filter = "Zip files (*.zip)|*.zip";
                    dialog.Title = "Select the Microsoft 365 Apps Security Baseline Zip file";

                    if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
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
                                GUI.microsoft365AppsSecurityBaselineZipTextBox.Text = dialog.FileName;
                                // The actual value that will be used
                                GUI.Microsoft365AppsSecurityBaselineZipPath = dialog.FileName;
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
            GUI.lgpoZipButton.Click += (sender, e) =>
            {
                using (var dialog = new System.Windows.Forms.OpenFileDialog())
                {
                    dialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    dialog.Filter = "Zip files (*.zip)|*.zip";
                    dialog.Title = "Select the LGPO Zip file";

                    if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
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
                                GUI.lgpoZipTextBox.Text = dialog.FileName;
                                // The actual value that will be used
                                GUI.LGPOZipPath = dialog.FileName;
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
            GUI.window.Closed += (sender, e) =>
            {
                // Only proceed further if user enabled logging
                if (GUI.ShouldWriteLogs)
                {

                    // Create the footer to the log file
                    string endOfLogFile = $"""
**********************
Harden Windows Security operation log end
End time: {DateTime.Now}
**********************
""";

                    // Add the footer to the log file
                    GUI.Logger.Add(endOfLogFile);

                    // Convert ArrayList to List<string>
                    List<string> logEntries = new List<string>();
                    foreach (string item in GUI.Logger)
                    {
                        logEntries.Add(item);
                    }

                    // Append log entries to the file
                    File.AppendAllLines(GUI.txtFilePath.Text, logEntries);
                };

            };
        }
    }
}
