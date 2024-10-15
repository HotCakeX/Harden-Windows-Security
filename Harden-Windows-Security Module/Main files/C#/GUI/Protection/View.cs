using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Markup;
using System.Windows.Media.Imaging;

#nullable disable

namespace HardenWindowsSecurity
{
    public partial class GUIMain
    {

        // NavigationVM class
        public partial class NavigationVM : ViewModelBase
        {

            // Method to handle the Protect view, including loading
            private void Protect(object obj)
            {
                // Check if the view is already cached
                if (_viewCache.TryGetValue("ProtectView", out var cachedView))
                {
                    CurrentView = cachedView;
                    return;
                }

                // Defining the path to the XAML XML file
                if (HardenWindowsSecurity.GlobalVars.path is null)
                {
                    throw new InvalidOperationException("GlobalVars.path cannot be null.");
                }

                // Construct the file path for the Protect view XAML
                string xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "Protect.xaml");

                // Read the XAML content from the file
                string xamlContent = File.ReadAllText(xamlPath);

                // Parse the XAML content to create a UserControl
                GUIProtectWinSecurity.View = (UserControl)XamlReader.Parse(xamlContent);

                // Set the DataContext for Protect view
                GUIProtectWinSecurity.View.DataContext = new ProtectVM();

                GUIProtectWinSecurity.parentGrid = (Grid)GUIProtectWinSecurity.View.FindName("ParentGrid");
                GUIProtectWinSecurity.mainTabControlToggle = (ToggleButton)GUIProtectWinSecurity.parentGrid.FindName("MainTabControlToggle");
                GUIProtectWinSecurity.mainContentControl = (ContentControl)GUIProtectWinSecurity.mainTabControlToggle.FindName("MainContentControl");


                // Due to using ToggleButton as Tab Control element, this is now considered the parent of all inner elements
                GUIProtectWinSecurity.mainContentControlStyle = (System.Windows.Style)GUIProtectWinSecurity.mainContentControl.FindName("MainContentControlStyle");

                // Assigning image source paths to the buttons
                // Need to cast the Style to the INameScope before using FindName method on it
                // more info: https://learn.microsoft.com/en-us/dotnet/csharp/programming-guide/interfaces/explicit-interface-implementation
                // in PowerShell this would simply work:
                //
                // [System.Windows.Style]$MainContentControlStyle = $MainContentControl.FindName('MainContentControlStyle')
                // $MainContentControlStyle.FindName('PathIcon1').Source

                // PathIcon1
                BitmapImage PathIcon1Image = new();
                PathIcon1Image.BeginInit();
                PathIcon1Image.UriSource = new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "path.png"));
                PathIcon1Image.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                PathIcon1Image.EndInit();
                ((Image)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("PathIcon1")).Source = PathIcon1Image;

                // PathIcon2
                var PathIcon2Image = new BitmapImage();
                PathIcon2Image.BeginInit();
                PathIcon2Image.UriSource = new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "path.png"));
                PathIcon2Image.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                PathIcon2Image.EndInit();
                ((Image)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("PathIcon2")).Source = PathIcon2Image;

                // PathIcon3
                var PathIcon3Image = new BitmapImage();
                PathIcon3Image.BeginInit();
                PathIcon3Image.UriSource = new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "path.png"));
                PathIcon3Image.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                PathIcon3Image.EndInit();
                ((Image)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("PathIcon3")).Source = PathIcon3Image;

                // LogButtonIcon
                var LogButtonIconImage = new BitmapImage();
                LogButtonIconImage.BeginInit();
                LogButtonIconImage.UriSource = new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "Media", "log.png"));
                LogButtonIconImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                LogButtonIconImage.EndInit();
                ((Image)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("LogButtonIcon")).Source = LogButtonIconImage;

                #region Combobox
                GUIProtectWinSecurity.ProtectionPresetComboBox = GUIProtectWinSecurity.parentGrid.FindName("ProtectionPresetComboBox") as ComboBox;


                // Attach the event handler using a lambda expression
                GUIProtectWinSecurity.ProtectionPresetComboBox.SelectionChanged += (sender, args) =>
                {
                    // Cast the sender back to a ComboBox
                    if (sender is ComboBox comboBox)
                    {
                        // Get the selected item as a ComboBoxItem
                        if (comboBox.SelectedItem is ComboBoxItem selectedItem)
                        {
                            // Assign the selected content to the SelectedProtectionPreset property
                            GUIProtectWinSecurity.SelectedProtectionPreset = selectedItem.Content.ToString();

                            // Uncheck all categories first
                            foreach (var item in GUIProtectWinSecurity.categories.Items)
                            {
                                ((CheckBox)((ListViewItem)item).Content).IsChecked = false;
                            }

                            // Uncheck all sub-categories first
                            foreach (var item in GUIProtectWinSecurity.subCategories.Items)
                            {
                                ((CheckBox)((ListViewItem)item).Content).IsChecked = false;
                            }

                            // Check the categories and sub-categories based on the preset configurations
                            switch (GUIProtectWinSecurity.SelectedProtectionPreset?.ToLowerInvariant())
                            {
                                case "preset: basic":
                                    {
                                        GUIMain.app.Dispatcher.Invoke(() =>
                                         {

                                             string presetName = "preset: basic";

                                             // Check if the preset exists in the dictionary
                                             if (GUIProtectWinSecurity.PresetsIntel.TryGetValue(presetName, out var categoriesAndSubcategories))
                                             {
                                                 // Access the categories and subcategories
                                                 List<string> categories = categoriesAndSubcategories["Categories"];
                                                 List<string> subcategories = categoriesAndSubcategories["SubCategories"];

                                                 // Loop over each category in the dictionary
                                                 foreach (string category in categories)
                                                 {

                                                     // Loop over each category in the GUI
                                                     foreach (var item in GUIProtectWinSecurity.categories.Items)
                                                     {
                                                         // Get the category item list view item
                                                         ListViewItem categoryItem = (ListViewItem)item;

                                                         // get the name of the list view item as string
                                                         string categoryItemName = ((CheckBox)categoryItem.Content).Name.ToString();

                                                         // if the category is authorized to be available
                                                         if (HardenWindowsSecurity.GlobalVars.HardeningCategorieX.Contains(categoryItemName))
                                                         {
                                                             // If the name of the current checkbox list view item in the loop is the same as the category name in the outer loop, then set the category on the GUI to checked
                                                             if (string.Equals(categoryItemName, category, StringComparison.OrdinalIgnoreCase))
                                                             {
                                                                 ((CheckBox)categoryItem.Content).IsChecked = true;
                                                             }

                                                         }
                                                     }
                                                 }

                                                 foreach (string subcategory in subcategories)
                                                 {

                                                     // Loop over each sub-category in the GUI
                                                     foreach (var item in GUIProtectWinSecurity.subCategories.Items)
                                                     {
                                                         // Get the sub-category item list view item
                                                         ListViewItem SubCategoryItem = (ListViewItem)item;

                                                         // get the name of the list view item as string
                                                         string SubcategoryItemName = ((CheckBox)SubCategoryItem.Content).Name.ToString();

                                                         // If the name of the current checkbox list view item in the loop is the same as the sub-category name in the outer loop, then set the sub-category on the GUI to checked
                                                         if (string.Equals(SubcategoryItemName, subcategory, StringComparison.OrdinalIgnoreCase))
                                                         {
                                                             ((CheckBox)SubCategoryItem.Content).IsChecked = true;
                                                         }

                                                     }


                                                 }
                                             }
                                             else
                                             {
                                                 Logger.LogMessage($"Preset '{presetName}' not found.", LogTypeIntel.Error);
                                             }


                                         });
                                        break;
                                    }
                                case "preset: recommended":
                                    {
                                        GUIMain.app.Dispatcher.Invoke(() =>
                                        {

                                            string presetName = "preset: recommended";

                                            // Check if the preset exists in the dictionary
                                            if (GUIProtectWinSecurity.PresetsIntel.TryGetValue(presetName, out var categoriesAndSubcategories))
                                            {
                                                // Access the categories and subcategories
                                                List<string> categories = categoriesAndSubcategories["Categories"];
                                                List<string> subcategories = categoriesAndSubcategories["SubCategories"];

                                                // Loop over each category in the dictionary
                                                foreach (string category in categories)
                                                {

                                                    // Loop over each category in the GUI
                                                    foreach (var item in GUIProtectWinSecurity.categories.Items)
                                                    {
                                                        // Get the category item list view item
                                                        ListViewItem categoryItem = (ListViewItem)item;

                                                        // get the name of the list view item as string
                                                        string categoryItemName = ((CheckBox)categoryItem.Content).Name.ToString();

                                                        // if the category is authorized to be available
                                                        if (HardenWindowsSecurity.GlobalVars.HardeningCategorieX.Contains(categoryItemName))
                                                        {
                                                            // If the name of the current checkbox list view item in the loop is the same as the category name in the outer loop, then set the category on the GUI to checked
                                                            if (string.Equals(categoryItemName, category, StringComparison.OrdinalIgnoreCase))
                                                            {
                                                                ((CheckBox)categoryItem.Content).IsChecked = true;
                                                            }

                                                        }
                                                    }
                                                }

                                                foreach (string subcategory in subcategories)
                                                {

                                                    // Loop over each sub-category in the GUI
                                                    foreach (var item in GUIProtectWinSecurity.subCategories.Items)
                                                    {
                                                        // Get the sub-category item list view item
                                                        ListViewItem SubCategoryItem = (ListViewItem)item;

                                                        // get the name of the list view item as string
                                                        string SubcategoryItemName = ((CheckBox)SubCategoryItem.Content).Name.ToString();

                                                        // If the name of the current checkbox list view item in the loop is the same as the sub-category name in the outer loop, then set the sub-category on the GUI to checked
                                                        if (string.Equals(SubcategoryItemName, subcategory, StringComparison.OrdinalIgnoreCase))
                                                        {
                                                            ((CheckBox)SubCategoryItem.Content).IsChecked = true;
                                                        }

                                                    }


                                                }
                                            }
                                            else
                                            {
                                                Logger.LogMessage($"Preset '{presetName}' not found.", LogTypeIntel.Error);
                                            }

                                        });
                                        break;
                                    }
                                case "preset: complete":
                                    {

                                        string presetName = "preset: complete";

                                        // Check if the preset exists in the dictionary
                                        if (GUIProtectWinSecurity.PresetsIntel.TryGetValue(presetName, out var categoriesAndSubcategories))
                                        {
                                            // Access the categories and subcategories
                                            List<string> categories = categoriesAndSubcategories["Categories"];
                                            List<string> subcategories = categoriesAndSubcategories["SubCategories"];

                                            // Loop over each category in the dictionary
                                            foreach (string category in categories)
                                            {

                                                // Loop over each category in the GUI
                                                foreach (var item in GUIProtectWinSecurity.categories.Items)
                                                {
                                                    // Get the category item list view item
                                                    ListViewItem categoryItem = (ListViewItem)item;

                                                    // get the name of the list view item as string
                                                    string categoryItemName = ((CheckBox)categoryItem.Content).Name.ToString();

                                                    // if the category is authorized to be available
                                                    if (HardenWindowsSecurity.GlobalVars.HardeningCategorieX.Contains(categoryItemName))
                                                    {
                                                        // If the name of the current checkbox list view item in the loop is the same as the category name in the outer loop, then set the category on the GUI to checked
                                                        if (string.Equals(categoryItemName, category, StringComparison.OrdinalIgnoreCase))
                                                        {
                                                            ((CheckBox)categoryItem.Content).IsChecked = true;
                                                        }

                                                    }
                                                }
                                            }

                                            foreach (string subcategory in subcategories)
                                            {

                                                // Loop over each sub-category in the GUI
                                                foreach (var item in GUIProtectWinSecurity.subCategories.Items)
                                                {
                                                    // Get the sub-category item list view item
                                                    ListViewItem SubCategoryItem = (ListViewItem)item;

                                                    // get the name of the list view item as string
                                                    string SubcategoryItemName = ((CheckBox)SubCategoryItem.Content).Name.ToString();

                                                    // If the name of the current checkbox list view item in the loop is the same as the sub-category name in the outer loop, then set the sub-category on the GUI to checked
                                                    if (string.Equals(SubcategoryItemName, subcategory, StringComparison.OrdinalIgnoreCase))
                                                    {
                                                        ((CheckBox)SubCategoryItem.Content).IsChecked = true;
                                                    }

                                                }


                                            }
                                        }
                                        else
                                        {
                                            Logger.LogMessage($"Preset '{presetName}' not found.", LogTypeIntel.Error);
                                        }
                                        break;
                                    }

                                default:
                                    break;
                            }


                        }
                    }
                };

                #endregion

                // Access the grid containing the Execute Button
                GUIProtectWinSecurity.ExecuteButtonGrid = GUIProtectWinSecurity.parentGrid.FindName("ExecuteButtonGrid") as Grid;

                // Access the Execute Button
                GUIProtectWinSecurity.ExecuteButton = (ToggleButton)GUIProtectWinSecurity.ExecuteButtonGrid!.FindName("Execute");

                // Apply the template to make sure it's available
                _ = GUIProtectWinSecurity.ExecuteButton.ApplyTemplate();

                // Access the image within the Execute Button's template
                GUIProtectWinSecurity.ExecuteButtonImage = GUIProtectWinSecurity.ExecuteButton.Template.FindName("ExecuteIconImage", GUIProtectWinSecurity.ExecuteButton) as Image;

                // Update the image source for the execute button
                // Load the Execute button image into memory and set it as the source
                var ExecuteButtonBitmapImage = new BitmapImage();
                ExecuteButtonBitmapImage.BeginInit();
                ExecuteButtonBitmapImage.UriSource = new Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "ExecuteButton.png"));
                ExecuteButtonBitmapImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                ExecuteButtonBitmapImage.EndInit();

                GUIProtectWinSecurity.ExecuteButtonImage!.Source = ExecuteButtonBitmapImage;


                GUIProtectWinSecurity.categories = (System.Windows.Controls.ListView)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("Categories");
                GUIProtectWinSecurity.subCategories = (System.Windows.Controls.ListView)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("SubCategories");
                GUIProtectWinSecurity.selectAllCategories = (CheckBox)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("SelectAllCategories");
                GUIProtectWinSecurity.selectAllSubCategories = (CheckBox)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("SelectAllSubCategories");

                // New initialization for Log related elements
                GUIProtectWinSecurity.txtFilePath = (TextBox)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("txtFilePath");
                GUIProtectWinSecurity.logPath = (Button)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("LogPath");
                GUIProtectWinSecurity.log = (ToggleButton)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("Log");
                GUIProtectWinSecurity.EventLogging = (ToggleButton)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("EventLogging");

                // initializations for Offline-Mode related elements
                GUIProtectWinSecurity.grid2 = (Grid)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("Grid2");
                GUIProtectWinSecurity.enableOfflineMode = (ToggleButton)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("EnableOfflineMode");
                GUIProtectWinSecurity.microsoftSecurityBaselineZipButton = (Button)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("MicrosoftSecurityBaselineZipButton");
                GUIProtectWinSecurity.microsoftSecurityBaselineZipTextBox = (TextBox)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("MicrosoftSecurityBaselineZipTextBox");
                GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipButton = (Button)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("Microsoft365AppsSecurityBaselineZipButton");
                GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipTextBox = (TextBox)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("Microsoft365AppsSecurityBaselineZipTextBox");
                GUIProtectWinSecurity.lgpoZipButton = (Button)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("LGPOZipButton");
                GUIProtectWinSecurity.lgpoZipTextBox = (TextBox)((System.Windows.Markup.INameScope)GUIProtectWinSecurity.mainContentControlStyle).FindName("LGPOZipTextBox");

                // Initially set the text area for the selected LogPath to disabled
                GUIProtectWinSecurity.txtFilePath.IsEnabled = false;

                // Defining event handler
                // When the Log checkbox is checked, enable the log path text area
                GUIProtectWinSecurity.log.Checked += (sender, e) =>
                {
                    GUIProtectWinSecurity.txtFilePath.IsEnabled = true;
                };

                // Defining event handler
                // When the Log checkbox is unchecked, set the LogPath text area to disabled
                GUIProtectWinSecurity.log.Unchecked += (sender, e) =>
                {
                    // Only disable the Log text file path element if it's not empty
                    if (string.IsNullOrWhiteSpace(GUIProtectWinSecurity.txtFilePath.Text))
                    {
                        GUIProtectWinSecurity.txtFilePath.IsEnabled = false;
                    }
                };

                // Event handler for the Log Path button click to open a file path picker dialog
                GUIProtectWinSecurity.logPath.Click += (sender, e) =>
                {
                    SaveFileDialog dialog = new()
                    {
                        // Defining the initial directory where the file picker GUI will be opened for the user
                        InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                        Filter = "Text files (*.txt)|*.txt",
                        Title = "Choose where to save the log file",
                        FileName = $"Harden Windows Security App Logs Export At {DateTime.Now:yyyy-MM-dd HH-mm-ss}.txt" // Default file name
                    };

                    // Show the dialog and process the result
                    if (dialog.ShowDialog() == true)
                    {
                        // Set the chosen file path in the text box
                        GUIProtectWinSecurity.txtFilePath.Text = dialog.FileName;
                        // Log a message to indicate where the logs will be saved
                        HardenWindowsSecurity.Logger.LogMessage($"Logs will be saved in: {GUIProtectWinSecurity.txtFilePath.Text}", LogTypeIntel.Information);
                    }
                };

                // Initially disable the Offline Mode configuration inputs until the Offline Mode checkbox is checked
                GUIProtectWinSecurity.DisableOfflineModeConfigInputs();

                // Implement the event handlers for the UI elements
                GUIProtectWinSecurity.AddEventHandlers();

                // Update the sub-categories based on the initial unchecked state of the categories
                GUIProtectWinSecurity.UpdateSubCategories();


                // If not running as Admin, disable the event logging since it requires Administrator privileges
                // To write to the event source
                if (!HardenWindowsSecurity.UserPrivCheck.IsAdmin())
                {
                    GUIProtectWinSecurity.EventLogging.IsEnabled = false;
                }

                if (!HardenWindowsSecurity.GlobalVars.Offline)
                {
                    // Disable the Offline mode toggle button if -Offline parameter was not used with the function
                    GUIProtectWinSecurity.enableOfflineMode.IsEnabled = false;

                    // Display a message showing how to activate the offline mode

                    // Add a new row definition for the text message
                    System.Windows.Controls.RowDefinition offlineModeUnavailableRow = new()
                    {
                        Height = new System.Windows.GridLength(50)
                    };
                    GUIProtectWinSecurity.grid2.RowDefinitions.Add(offlineModeUnavailableRow);

                    // Create a new text box
                    TextBox offlineModeUnavailableNoticeBox = new()
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
                    offlineModeUnavailableNoticeBox.SetValue(Grid.ColumnSpanProperty, 2);
                    offlineModeUnavailableNoticeBox.SetValue(Grid.RowProperty, 4);

                    // Create a gradient brush for the text color
                    System.Windows.Media.LinearGradientBrush gradientBrush = new();
                    gradientBrush.GradientStops.Add(new System.Windows.Media.GradientStop(System.Windows.Media.Colors.Purple, 0));
                    gradientBrush.GradientStops.Add(new System.Windows.Media.GradientStop(System.Windows.Media.Colors.Blue, 1));
                    offlineModeUnavailableNoticeBox.Foreground = gradientBrush;

                    // Add the text box to the grid
                    _ = GUIProtectWinSecurity.grid2.Children.Add(offlineModeUnavailableNoticeBox);
                };

                // Register the Execute button to be enabled/disabled based on global activity
                HardenWindowsSecurity.ActivityTracker.RegisterUIElement(GUIProtectWinSecurity.ExecuteButton);

                // Register additional elements for automatic enablement/disablement
                HardenWindowsSecurity.ActivityTracker.RegisterUIElement(GUIProtectWinSecurity.logPath);
                HardenWindowsSecurity.ActivityTracker.RegisterUIElement(GUIProtectWinSecurity.log);

                // Cache the view before setting it as the CurrentView
                _viewCache["ProtectView"] = GUIProtectWinSecurity.View;

                // Set the CurrentView to the Protect view
                CurrentView = GUIProtectWinSecurity.View;
            }

        }
    }
}
