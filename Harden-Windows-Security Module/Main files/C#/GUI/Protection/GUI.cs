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
using System.Windows.Threading;
using System.Runtime.CompilerServices;
using System.Diagnostics;
using System.ComponentModel;
using System.Threading;
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
using System.Threading.Tasks;
using System.Text;
using System.Reflection.PortableExecutable;
using static System.Windows.Forms.VisualStyles.VisualStyleElement.TrayNotify; // !

#nullable enable

namespace HardenWindowsSecurity
{
    /// <summary>
    /// A class to store all of the data that is related to the GUI and its operations
    /// </summary>
    public partial class GUIProtectWinSecurity
    {

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

            // Create and initialize the application - the WPF GUI uses the App context
            GUIProtectWinSecurity.app = new System.Windows.Application();

            #region Load Resource Dictionaries (First)
            // Define the path to the ResourceDictionaries folder
            string resourceFolder = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "ResourceDictionaries");

            // Get all of the XAML files in the folder
            var resourceFiles = Directory.GetFiles(resourceFolder, "*.xaml");

            // Load resource dictionaries from the ResourceDictionaries folder
            foreach (var file in resourceFiles)
            {
                using (FileStream fs = new FileStream(file, FileMode.Open, FileAccess.Read))
                {
                    // Load the resource dictionary from the XAML file
                    System.Windows.ResourceDictionary resourceDict = (System.Windows.ResourceDictionary)System.Windows.Markup.XamlReader.Load(fs);
                    GUIProtectWinSecurity.app.Resources.MergedDictionaries.Add(resourceDict);  // Add to application resources to ensure dictionaries are available to the whole application
                }
            }
            #endregion

            #region Load Main Window XAML (After Resource dictionaries have been loaded)
            // Define the path to the main Window XAML file
            GUIProtectWinSecurity.xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "Main.xaml");

            // Load the MainWindow.xaml
            using (FileStream fs = new FileStream(GUIProtectWinSecurity.xamlPath, FileMode.Open, FileAccess.Read))
            {
                // Load the main window from the XAML file
                GUIProtectWinSecurity.window = (System.Windows.Window)System.Windows.Markup.XamlReader.Load(fs);
            }
            #endregion

            // Set the MainWindow for the application
            GUIProtectWinSecurity.app.MainWindow = GUIProtectWinSecurity.window;

            #region parent border of the ProtectWindowsSecurity
            // Find the Border control by name
            System.Windows.Controls.Border border = (System.Windows.Controls.Border)GUIProtectWinSecurity.window.FindName("OuterMostBorder");

            // Access the ImageBrush from the Border's Background property
            ImageBrush imageBrush = (ImageBrush)border.Background;

            // Set the ImageSource property to the desired image path
            imageBrush.ImageSource = new System.Windows.Media.Imaging.BitmapImage(
                    new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "background.jpg"))
                );
            #endregion


            GUIProtectWinSecurity.parentGrid = (System.Windows.Controls.Grid)GUIProtectWinSecurity.window.FindName("ParentGrid");
            GUIProtectWinSecurity.mainTabControlToggle = (System.Windows.Controls.Primitives.ToggleButton)GUIProtectWinSecurity.parentGrid.FindName("MainTabControlToggle");
            GUIProtectWinSecurity.mainContentControl = (System.Windows.Controls.ContentControl)GUIProtectWinSecurity.mainTabControlToggle.FindName("MainContentControl");

            // Finding the progress bar
            GUIProtectWinSecurity.mainProgressBar = (System.Windows.Controls.ProgressBar)GUIProtectWinSecurity.parentGrid.FindName("MainProgressBar");

            // Set Main progress bar visibility initially to Collapsed
            GUIProtectWinSecurity.mainProgressBar.Visibility = Visibility.Collapsed;

            // Assigning the icon for the Harden Windows Security GUI
            GUIProtectWinSecurity.window.Icon = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "ProgramIcon.ico")));

            // Due to using ToggleButton as Tab Control element, this is now considered the parent of all inner elements
            GUIProtectWinSecurity.mainContentControlStyle = (System.Windows.Style)GUIProtectWinSecurity.mainContentControl.FindName("MainContentControlStyle");

            GUIProtectWinSecurity.outputTextBlock = (System.Windows.Controls.TextBox)GUIProtectWinSecurity.parentGrid.FindName("OutputTextBlock");
            GUIProtectWinSecurity.scrollerForOutputTextBlock = (System.Windows.Controls.ScrollViewer)GUIProtectWinSecurity.parentGrid.FindName("ScrollerForOutputTextBlock");

            // Assigning image source paths to the buttons
            // Need to cast the Style to the INameScope before using FindName method on it
            // more info: https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/interfaces/explicit-interface-implementation
            // in PowerShell this would simply work:
            //
            // [System.Windows.Style]$MainContentControlStyle = $MainContentControl.FindName('MainContentControlStyle')
            // $MainContentControlStyle.FindName('PathIcon1').Source
            ((System.Windows.Controls.Image)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("PathIcon1")).Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "path.png")));
            ((System.Windows.Controls.Image)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("PathIcon2")).Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "path.png")));
            ((System.Windows.Controls.Image)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("PathIcon3")).Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "path.png")));
            ((System.Windows.Controls.Image)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("LogButtonIcon")).Source = new System.Windows.Media.Imaging.BitmapImage(new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "log.png")));


            // Access the grid containing the Execute Button
            GUIProtectWinSecurity.ExecuteButtonGrid = GUIProtectWinSecurity.parentGrid.FindName("ExecuteButtonGrid") as System.Windows.Controls.Grid;

            // Access the Execute Button
            GUIProtectWinSecurity.ExecuteButton = (System.Windows.Controls.Primitives.ToggleButton)GUIProtectWinSecurity.ExecuteButtonGrid!.FindName("Execute");

            // Apply the template to make sure it's available
            GUIProtectWinSecurity.ExecuteButton.ApplyTemplate();

            // Access the image within the Execute Button's template
            GUIProtectWinSecurity.ExecuteButtonImage = ExecuteButton.Template.FindName("ExecuteIconImage", ExecuteButton) as System.Windows.Controls.Image;

            // Update the image source for the execute button
            GUIProtectWinSecurity.ExecuteButtonImage!.Source =
                new System.Windows.Media.Imaging.BitmapImage(
                    new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "ExecuteButton.png"))
                );

            GUIProtectWinSecurity.categories = (System.Windows.Controls.ListView)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("Categories");
            GUIProtectWinSecurity.subCategories = (System.Windows.Controls.ListView)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("SubCategories");
            GUIProtectWinSecurity.selectAllCategories = (System.Windows.Controls.CheckBox)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("SelectAllCategories");
            GUIProtectWinSecurity.selectAllSubCategories = (System.Windows.Controls.CheckBox)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("SelectAllSubCategories");

            // New initialization for Log related elements
            GUIProtectWinSecurity.txtFilePath = (System.Windows.Controls.TextBox)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("txtFilePath");
            GUIProtectWinSecurity.logPath = (System.Windows.Controls.Button)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("LogPath");
            GUIProtectWinSecurity.log = (System.Windows.Controls.Primitives.ToggleButton)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("Log");
            GUIProtectWinSecurity.loggingViewBox = (System.Windows.Controls.Viewbox)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("LoggingViewBox");


            // initializations for Offline-Mode related elements
            GUIProtectWinSecurity.grid2 = (System.Windows.Controls.Grid)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("Grid2");
            GUIProtectWinSecurity.enableOfflineMode = (System.Windows.Controls.Primitives.ToggleButton)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("EnableOfflineMode");
            GUIProtectWinSecurity.microsoftSecurityBaselineZipButton = (System.Windows.Controls.Button)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("MicrosoftSecurityBaselineZipButton");
            GUIProtectWinSecurity.microsoftSecurityBaselineZipTextBox = (System.Windows.Controls.TextBox)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("MicrosoftSecurityBaselineZipTextBox");
            GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipButton = (System.Windows.Controls.Button)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("Microsoft365AppsSecurityBaselineZipButton");
            GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipTextBox = (System.Windows.Controls.TextBox)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("Microsoft365AppsSecurityBaselineZipTextBox");
            GUIProtectWinSecurity.lgpoZipButton = (System.Windows.Controls.Button)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("LGPOZipButton");
            GUIProtectWinSecurity.lgpoZipTextBox = (System.Windows.Controls.TextBox)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("LGPOZipTextBox");

            // Initially set the text area for the selected LogPath to disabled
            GUIProtectWinSecurity.txtFilePath.IsEnabled = false;

            // Initialize the LogPath button element as disabled
            GUIProtectWinSecurity.logPath.IsEnabled = false;

            // Defining event handler
            // When the Log checkbox is checked, enable the LogPath button and log path text area
            GUIProtectWinSecurity.log.Checked += (sender, e) =>
            {
                GUIProtectWinSecurity.txtFilePath.IsEnabled = true;
                GUIProtectWinSecurity.logPath.IsEnabled = true;
            };

            // Defining event handler
            // When the Log checkbox is unchecked, disable the LogPath button and set the LogPath text area to disabled
            GUIProtectWinSecurity.log.Unchecked += (sender, e) =>
            {
                GUIProtectWinSecurity.logPath.IsEnabled = false;

                // Only disable the Log text file path element if it's not empty
                if (string.IsNullOrWhiteSpace(GUIProtectWinSecurity.txtFilePath.Text))
                {
                    GUIProtectWinSecurity.txtFilePath.IsEnabled = false;
                }
            };

            // Event handler for the Log Path button click to open a file path picker dialog
            GUIProtectWinSecurity.logPath.Click += (sender, e) =>
            {
                using (SaveFileDialog dialog = new SaveFileDialog())
                {
                    // Defining the initial directory where the file picker GUI will be opened for the user
                    dialog.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                    dialog.Filter = "Text files (*.txt)|*.txt";
                    dialog.Title = "Choose where to save the log file";

                    if (dialog.ShowDialog() == System.Windows.Forms.DialogResult.OK)
                    {
                        GUIProtectWinSecurity.txtFilePath.Text = dialog.FileName;
                        HardenWindowsSecurity.Logger.LogMessage($"Logs will be saved in: {GUIProtectWinSecurity.txtFilePath.Text}");
                    }
                }
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
                GUIProtectWinSecurity.enableOfflineMode.IsEnabled = false;

                // Display a message showing how to activate the offline mode

                // Add a new row definition for the text message
                System.Windows.Controls.RowDefinition offlineModeUnavailableRow = new System.Windows.Controls.RowDefinition
                {
                    Height = new System.Windows.GridLength(50)
                };
                GUIProtectWinSecurity.grid2.RowDefinitions.Add(offlineModeUnavailableRow);

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
                GUIProtectWinSecurity.grid2.Children.Add(offlineModeUnavailableNoticeBox);
            };
        }

    }
}
