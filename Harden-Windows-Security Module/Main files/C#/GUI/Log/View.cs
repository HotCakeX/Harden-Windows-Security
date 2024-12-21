using Microsoft.Win32;
using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Markup;
using System.Windows.Media.Imaging;

namespace HardenWindowsSecurity;

    public partial class GUIMain
    {

        // Partial class definition for handling navigation and view models
        public partial class NavigationVM : ViewModelBase
        {

            // Method to handle the Logs view, including loading
            private void LogsView(object obj)
            {

                // Check if the view is already cached
                if (_viewCache.TryGetValue("LogsView", out var cachedView))
                {
                    CurrentView = cachedView;
                    return;
                }

                if (GlobalVars.path is null)
                {
                    throw new InvalidOperationException("GlobalVars.path cannot be null.");
                }

                // Construct the file path for the Logs view XAML
                string xamlPath = Path.Combine(GlobalVars.path, "Resources", "XAML", "Logs.xaml");

                // Read the XAML content from the file
                string xamlContent = File.ReadAllText(xamlPath);

                // Parse the XAML content to create a UserControl
                GUILogs.View = (UserControl)XamlReader.Parse(xamlContent);

                // Find the Parent Grid
                GUILogs.ParentGrid = (Grid)GUILogs.View.FindName("ParentGrid");

                ToggleButton AutoScrollToggleButton = GUILogs.ParentGrid.FindName("AutoScrollToggleButton") as ToggleButton ?? throw new InvalidOperationException("AutoScrollToggleButton is null.");
                Button ExportLogsButton = GUILogs.ParentGrid.FindName("ExportLogsButton") as Button ?? throw new InvalidOperationException("ExportLogsButton is null.");
                GUILogs.MainLoggerTextBox = GUILogs.ParentGrid.FindName("MainLoggerTextBox") as TextBox ?? throw new InvalidOperationException("MainLoggerTextBox is null.");
                GUILogs.scrollerForOutputTextBox = GUILogs.ParentGrid.FindName("ScrollerForOutputTextBox") as ScrollViewer ?? throw new InvalidOperationException("ScrollerForOutputTextBox is null.");
                Image ExportLogsIcon = GUILogs.ParentGrid.FindName("ExportLogsIcon") as Image ?? throw new InvalidOperationException("ExportLogsIcon is null.");
                Button ClearLogsButton = GUILogs.ParentGrid.FindName("ClearLogsButton") as Button ?? throw new InvalidOperationException("ClearLogsButton is null.");
                Image ClearLogsIcon = GUILogs.ParentGrid.FindName("ClearLogsIcon") as Image ?? throw new InvalidOperationException("ClearLogsIcon is null.");


                // Add image to the ExportLogsIcon
                BitmapImage ExportLogsIconBitmapImage = new();
                ExportLogsIconBitmapImage.BeginInit();
                ExportLogsIconBitmapImage.UriSource = new Uri(Path.Combine(GlobalVars.path!, "Resources", "Media", "ExportIconBlack.png"));
                ExportLogsIconBitmapImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                ExportLogsIconBitmapImage.EndInit();
                ExportLogsIcon.Source = ExportLogsIconBitmapImage;


                // Add image to the ClearLogsIcon
                BitmapImage ClearLogsIconBitmapImage = new();
                ClearLogsIconBitmapImage.BeginInit();
                ClearLogsIconBitmapImage.UriSource = new Uri(Path.Combine(GlobalVars.path!, "Resources", "Media", "ClearLogsIcon.png"));
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
                _viewCache["LogsView"] = GUILogs.View;

                // Set the CurrentView to the Protect view
                CurrentView = GUILogs.View;
            }
        }
    }
