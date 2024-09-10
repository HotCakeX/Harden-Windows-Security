using Microsoft.Win32;
using System;
using System.IO;
using System.Windows;
using System.Windows.Markup;

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
                if (HardenWindowsSecurity.GlobalVars.path == null)
                {
                    throw new InvalidOperationException("GlobalVars.path cannot be null.");
                }

                // Construct the file path for the Logs view XAML
                string xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "Logs.xaml");

                // Read the XAML content from the file
                string xamlContent = File.ReadAllText(xamlPath);

                // Parse the XAML content to create a UserControl
                HardenWindowsSecurity.GUILogs.View = (System.Windows.Controls.UserControl)XamlReader.Parse(xamlContent);

                // Set the DataContext for Logs view
                HardenWindowsSecurity.GUILogs.View.DataContext = new LogsVM();

                // Find the Parent Grid
                HardenWindowsSecurity.GUILogs.ParentGrid = (System.Windows.Controls.Grid)HardenWindowsSecurity.GUILogs.View.FindName("ParentGrid");

                System.Windows.Controls.Primitives.ToggleButton AutoScrollToggleButton = HardenWindowsSecurity.GUILogs.ParentGrid.FindName("AutoScrollToggleButton") as System.Windows.Controls.Primitives.ToggleButton ?? throw new InvalidOperationException("AutoScrollToggleButton is null.");
                System.Windows.Controls.Button ExportLogsButton = HardenWindowsSecurity.GUILogs.ParentGrid.FindName("ExportLogsButton") as System.Windows.Controls.Button ?? throw new InvalidOperationException("ExportLogsButton is null.");
                HardenWindowsSecurity.GUILogs.MainLoggerTextBox = HardenWindowsSecurity.GUILogs.ParentGrid.FindName("MainLoggerTextBox") as System.Windows.Controls.TextBox ?? throw new InvalidOperationException("MainLoggerTextBox is null.");
                HardenWindowsSecurity.GUILogs.scrollerForOutputTextBox = HardenWindowsSecurity.GUILogs.ParentGrid.FindName("ScrollerForOutputTextBox") as System.Windows.Controls.ScrollViewer ?? throw new InvalidOperationException("ScrollerForOutputTextBox is null.");
                System.Windows.Controls.Image ExportLogsIcon = GUILogs.ParentGrid.FindName("ExportLogsIcon") as System.Windows.Controls.Image ?? throw new InvalidOperationException("ExportLogsIcon is null.");

                // Add image to the ExportLogsIcon
                var ExportLogsIconBitmapImage = new System.Windows.Media.Imaging.BitmapImage();
                ExportLogsIconBitmapImage.BeginInit();
                ExportLogsIconBitmapImage.UriSource = new System.Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "ExportIconBlack.png"));
                ExportLogsIconBitmapImage.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad; // Load the image data into memory
                ExportLogsIconBitmapImage.EndInit();
                ExportLogsIcon.Source = ExportLogsIconBitmapImage;

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


                // Cache the view before setting it as the CurrentView
                _viewCache["LogsView"] = HardenWindowsSecurity.GUILogs.View;

                // Set the CurrentView to the Protect view
                CurrentView = HardenWindowsSecurity.GUILogs.View;
            }
        }
    }
}
