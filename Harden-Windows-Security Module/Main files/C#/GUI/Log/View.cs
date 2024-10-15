using Microsoft.Win32;
using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Markup;
using System.Windows.Media.Imaging;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class GUIMain
    {

        // Partial class definition for handling navigation and view models
        public partial class NavigationVM : ViewModelBase
        {

            // Method to handle the Logs view, including loading
            private void Logs(object obj)
            {

                // Check if the view is already cached
                if (_viewCache.TryGetValue("LogsView", out var cachedView))
                {
                    CurrentView = cachedView;
                    return;
                }

                // Defining the path to the XAML XML file
                if (HardenWindowsSecurity.GlobalVars.path is null)
                {
                    throw new InvalidOperationException("GlobalVars.path cannot be null.");
                }

                // Construct the file path for the Logs view XAML
                string xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "Logs.xaml");

                // Read the XAML content from the file
                string xamlContent = File.ReadAllText(xamlPath);

                // Parse the XAML content to create a UserControl
                HardenWindowsSecurity.GUILogs.View = (UserControl)XamlReader.Parse(xamlContent);

                // Set the DataContext for Logs view
                HardenWindowsSecurity.GUILogs.View.DataContext = new LogsVM();

                // Find the Parent Grid
                HardenWindowsSecurity.GUILogs.ParentGrid = (Grid)HardenWindowsSecurity.GUILogs.View.FindName("ParentGrid");

                ToggleButton AutoScrollToggleButton = HardenWindowsSecurity.GUILogs.ParentGrid.FindName("AutoScrollToggleButton") as ToggleButton ?? throw new InvalidOperationException("AutoScrollToggleButton is null.");
                Button ExportLogsButton = HardenWindowsSecurity.GUILogs.ParentGrid.FindName("ExportLogsButton") as Button ?? throw new InvalidOperationException("ExportLogsButton is null.");
                HardenWindowsSecurity.GUILogs.MainLoggerTextBox = HardenWindowsSecurity.GUILogs.ParentGrid.FindName("MainLoggerTextBox") as TextBox ?? throw new InvalidOperationException("MainLoggerTextBox is null.");
                HardenWindowsSecurity.GUILogs.scrollerForOutputTextBox = HardenWindowsSecurity.GUILogs.ParentGrid.FindName("ScrollerForOutputTextBox") as ScrollViewer ?? throw new InvalidOperationException("ScrollerForOutputTextBox is null.");
                Image ExportLogsIcon = GUILogs.ParentGrid.FindName("ExportLogsIcon") as Image ?? throw new InvalidOperationException("ExportLogsIcon is null.");
                Button ClearLogsButton = HardenWindowsSecurity.GUILogs.ParentGrid.FindName("ClearLogsButton") as Button ?? throw new InvalidOperationException("ClearLogsButton is null.");
                Image ClearLogsIcon = GUILogs.ParentGrid.FindName("ClearLogsIcon") as Image ?? throw new InvalidOperationException("ClearLogsIcon is null.");


                // Add image to the ExportLogsIcon
                var ExportLogsIconBitmapImage = new BitmapImage();
                ExportLogsIconBitmapImage.BeginInit();
                ExportLogsIconBitmapImage.UriSource = new System.Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "ExportIconBlack.png"));
                ExportLogsIconBitmapImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                ExportLogsIconBitmapImage.EndInit();
                ExportLogsIcon.Source = ExportLogsIconBitmapImage;


                // Add image to the ClearLogsIcon
                var ClearLogsIconBitmapImage = new BitmapImage();
                ClearLogsIconBitmapImage.BeginInit();
                ClearLogsIconBitmapImage.UriSource = new System.Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "ClearLogsIcon.png"));
                ClearLogsIconBitmapImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                ClearLogsIconBitmapImage.EndInit();
                ClearLogsIcon.Source = ClearLogsIconBitmapImage;


                // Need to apply the template before we can set the toggle button to true
                _ = AutoScrollToggleButton.ApplyTemplate();

                // Set the AutoScrollToggleButton to checked initially when the view is loaded
                AutoScrollToggleButton.IsChecked = true;

                AutoScrollToggleButton.Checked += (sender, e) =>
                {
                    GUILogs.AutoScroll = true;
                };

                AutoScrollToggleButton.Unchecked += (sender, e) =>
                {
                    GUILogs.AutoScroll = false;
                };


                // Event handler for ExportLogsButton
                ExportLogsButton.Click += (sender, e) =>
                {
                    // Create a SaveFileDialog
                    SaveFileDialog saveFileDialog = new()
                    {
                        Filter = "Text files (*.txt)|*.txt|All files (*.*)|*.*",
                        Title = "Save Log File",
                        FileName = $"Harden Windows Security App Logs Export At {DateTime.Now:yyyy-MM-dd HH-mm-ss}.txt"
                    };

                    // Show the dialog and check if the user clicked "Save"
                    if (saveFileDialog.ShowDialog() == true)
                    {
                        // Get the file path selected by the user
                        string filePath = saveFileDialog.FileName;

                        // Write the text content from the TextBox to the file
                        File.WriteAllText(filePath, GUILogs.MainLoggerTextBox.Text);

                        _ = MessageBox.Show("Logs successfully saved.", "Success", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                };


                // Event handler for ClearLogsButton
                ClearLogsButton.Click += (sender, e) =>
                {
                    // Set the logs text box to an empty string, clearing all the logs from the GUI logger
                    GUILogs.MainLoggerTextBox.Text = string.Empty;
                };


                // Cache the view before setting it as the CurrentView
                _viewCache["LogsView"] = HardenWindowsSecurity.GUILogs.View;

                // Set the CurrentView to the Protect view
                CurrentView = HardenWindowsSecurity.GUILogs.View;
            }
        }
    }
}
