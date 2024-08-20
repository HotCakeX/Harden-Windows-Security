using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Markup;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Xml.Linq;

#nullable disable

namespace HardenWindowsSecurity
{
    public partial class GUIMain
    {
        // Define the SecOp class, representing an individual security option in the data grid
        public class SecOp : System.ComponentModel.INotifyPropertyChanged
        {
            // Private fields to hold property values

            // Stores whether the security option is compliant
            private bool _Compliant;

            // Stores the security option's character image
            private System.Windows.Media.ImageSource _characterImage;

            // Stores the background color for the security option
            private System.Windows.Media.Brush _bgColor;

            // Event to notify listeners when a property value changes
            public event System.ComponentModel.PropertyChangedEventHandler PropertyChanged;

            // Public property to get or set the security option's character image
            public System.Windows.Media.ImageSource CharacterImage
            {
                get => _characterImage;
                set
                {
                    _characterImage = value;

                    // Notify that the CharacterImage property has changed
                    OnPropertyChanged(nameof(CharacterImage));
                }
            }

            // Public property to get or set the background color
            public System.Windows.Media.Brush BgColor
            {
                get => _bgColor;
                set
                {
                    _bgColor = value;

                    // Notify that the BgColor property has changed
                    OnPropertyChanged(nameof(BgColor));
                }
            }

            // Public properties for security option details
            public string FriendlyName { get; set; }
            public string Value { get; set; }
            public string Name { get; set; }
            public string Category { get; set; }
            public string Method { get; set; }

            // Public property to get or set whether the security option is compliant
            public bool Compliant
            {
                get => _Compliant;
                set
                {
                    _Compliant = value;

                    // Update CharacterImage based on compliance
                    CharacterImage = LoadImage(_Compliant ? "ConfirmationTrue.png" : "ConfirmationFalse.png");

                    // Notify that the Compliant property has changed
                    OnPropertyChanged(nameof(Compliant));
                }
            }

            // Method to notify listeners that a property value has changed
            protected void OnPropertyChanged(string propertyName)
            {
                PropertyChanged?.Invoke(this, new System.ComponentModel.PropertyChangedEventArgs(propertyName));
            }

            // Private method to load an image from the specified file name
            private System.Windows.Media.ImageSource LoadImage(string fileName)
            {
                // Construct the full path to the image file
                string imagePath = System.IO.Path.Combine(GlobalVars.path, "Resources", "Media", fileName);
                // Return the loaded image as a BitmapImage
                return new System.Windows.Media.Imaging.BitmapImage(new System.Uri(imagePath, System.UriKind.Absolute));
            }
        }

        // Partial class definition for handling navigation and view models
        public partial class NavigationVM : ViewModelBase
        {
            // Method to get the background color based on the category
            private System.Windows.Media.Brush GetCategoryColor(string category)
            {
                // Determine the background color for each category
                switch (category)
                {
                    // Light Pastel Sky Blue
                    case "MicrosoftDefender":
                        return new System.Windows.Media.BrushConverter().ConvertFromString("#B3E5FC") as System.Windows.Media.Brush;

                    // Light Pastel Coral
                    case "AttackSurfaceReductionRules":
                        return new System.Windows.Media.BrushConverter().ConvertFromString("#FFDAB9") as System.Windows.Media.Brush;

                    // Light Pastel Green (unchanged)
                    case "BitLockerSettings":
                        return new System.Windows.Media.BrushConverter().ConvertFromString("#C3FDB8") as System.Windows.Media.Brush;

                    // Light Pastel Lemon (unchanged)
                    case "TLSSecurity":
                        return new System.Windows.Media.BrushConverter().ConvertFromString("#FFFACD") as System.Windows.Media.Brush;

                    // Light Pastel Lavender
                    case "LockScreen":
                        return new System.Windows.Media.BrushConverter().ConvertFromString("#E6E6FA") as System.Windows.Media.Brush;

                    // Light Pastel Aqua
                    case "UserAccountControl":
                        return new System.Windows.Media.BrushConverter().ConvertFromString("#C1F0F6") as System.Windows.Media.Brush;

                    // Light Pastel Teal (unchanged)
                    case "DeviceGuard":
                        return new System.Windows.Media.BrushConverter().ConvertFromString("#B2DFDB") as System.Windows.Media.Brush;

                    // Light Pastel Pink
                    case "WindowsFirewall":
                        return new System.Windows.Media.BrushConverter().ConvertFromString("#F8BBD0") as System.Windows.Media.Brush;

                    // Light Pastel Peach (unchanged)
                    case "OptionalWindowsFeatures":
                        return new System.Windows.Media.BrushConverter().ConvertFromString("#FFE4E1") as System.Windows.Media.Brush;

                    // Light Pastel Mint
                    case "WindowsNetworking":
                        return new System.Windows.Media.BrushConverter().ConvertFromString("#F5FFFA") as System.Windows.Media.Brush;

                    // Light Pastel Gray (unchanged)
                    default:
                        return new System.Windows.Media.BrushConverter().ConvertFromString("#EDEDED") as System.Windows.Media.Brush;
                }
            }

            // Method to update the total count of security options displayed
            private void UpdateTotalCount()
            {
                var totalCount = _membersView.Cast<SecOp>().Count(); // Get the total count of security options
                if (CurrentView is System.Windows.Controls.UserControl confirmView)
                {
                    // Find the TextBlock used to display the total count
                    var TotalCountTextBlock = (System.Windows.Controls.TextBlock)confirmView.FindName("TotalCountTextBlock");
                    if (TotalCountTextBlock != null)
                    {
                        // Update the text of the TextBlock to show the total count
                        TotalCountTextBlock.Text = $"{totalCount} verifiable security checks";
                    }
                }
            }

            // Private fields to hold the collection view and security options collection

            // Collection view for filtering and sorting
            private ICollectionView _membersView;

            // Collection of SecOp objects
            private System.Collections.ObjectModel.ObservableCollection<SecOp> _members;

            // Method to handle the "Confirm" view, including loading and modifying it
            private void Confirm(object obj)
            {
                // Check if the Confirm view is already cached
                if (_viewCache.TryGetValue("ConfirmView", out var cachedView))
                {
                    // Use the cached view if available
                    CurrentView = cachedView;
                    return;
                }

                // Construct the full file path to the Confirm view XAML file
                string xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "Confirm.xaml");

                // Read the XAML content from the file
                string xamlContent = System.IO.File.ReadAllText(xamlPath);

                // Parse the XAML content to create a UserControl object
                System.Windows.Controls.UserControl confirmView = (System.Windows.Controls.UserControl)System.Windows.Markup.XamlReader.Parse(xamlContent);

                // Initialize an empty security options collection
                _members = new System.Collections.ObjectModel.ObservableCollection<SecOp>();

                // Create a collection view based on the security options collection
                _membersView = System.Windows.Data.CollectionViewSource.GetDefaultView(_members);

                // Find the DataGrid in the Confirm view and set its ItemsSource to the collection view
                var membersDataGrid = (System.Windows.Controls.DataGrid)confirmView.FindName("membersDataGrid");
                if (membersDataGrid != null)
                {
                    // Bind the DataGrid to the collection view
                    membersDataGrid.ItemsSource = _membersView;
                }

                // Handle the TextBox filter using a lambda expression
                var textBoxFilter = (System.Windows.Controls.TextBox)confirmView.FindName("textBoxFilter");
                if (textBoxFilter != null)
                {
                    textBoxFilter.TextChanged += (sender, e) =>
                    {
                        // Get the filter text from the TextBox
                        string filterText = textBoxFilter.Text;
                        if (_membersView != null)
                        {
                            // Apply a filter to the collection view based on the filter text
                            _membersView.Filter = memberObj =>
                            {
                                if (memberObj is SecOp member)
                                {
                                    // Check if any of the security option properties contain the filter text
                                    return (member.FriendlyName?.Contains(filterText, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                           (member.Value?.Contains(filterText, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                           (member.Name?.Contains(filterText, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                           (member.Category?.Contains(filterText, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                           (member.Method?.Contains(filterText, StringComparison.OrdinalIgnoreCase) ?? false);
                                }
                                return false;
                            };
                            _membersView.Refresh(); // Refresh the collection view to apply the filter
                        }
                    };
                }

                #region ExecuteButton
                // Find the Refresh button and attach the Click event handler

                // Access the grid containing the Execute Button
                System.Windows.Controls.Grid RefreshButtonGrid = confirmView.FindName("RefreshButtonGrid") as System.Windows.Controls.Grid;

                // Access the Execute Button
                System.Windows.Controls.Primitives.ToggleButton RefreshButton = (System.Windows.Controls.Primitives.ToggleButton)RefreshButtonGrid.FindName("RefreshButton");

                // Apply the template to make sure it's available
                RefreshButton.ApplyTemplate();

                // Access the image within the Execute Button's template
                System.Windows.Controls.Image RefreshIconImage = RefreshButton.Template.FindName("RefreshIconImage", RefreshButton) as System.Windows.Controls.Image;

                // Update the image source for the execute button
                RefreshIconImage.Source =
                    new System.Windows.Media.Imaging.BitmapImage(
                        new System.Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "ExecuteButton.png"))
                    );

                #endregion

                // Set up the Click event handler for the Refresh button
                RefreshButton.Click += async (sender, e) =>
                {
                    // Disable the Refresh button while processing
                    RefreshButton.Dispatcher.Invoke(() =>
                    {
                        RefreshButton.IsEnabled = false;
                    });

                    // Clear the current security options before starting data generation
                    _members.Clear();
                    _membersView.Refresh(); // Refresh the collection view to clear the DataGrid

                    // Run the method asynchronously in a different thread
                    await System.Threading.Tasks.Task.Run(() =>
                    {
                        HardenWindowsSecurity.InvokeConfirmation.Invoke(null);
                    });

                    // After InvokeConfirmation is completed, update the security options collection
                    await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                    {
                        LoadMembers(); // Load updated security options
                        RefreshButton.IsChecked = false; // Uncheck the Refresh button
                        RefreshButton.IsEnabled = true; // Re-enable the Refresh button
                    });
                };

                // Cache the Confirm view for future use
                _viewCache["ConfirmView"] = confirmView;

                // Set the CurrentView to the modified Confirm view
                CurrentView = confirmView;
            }

            // Method to load security options from the FinalMegaObject and update the DataGrid
            private void LoadMembers()
            {
                // Clear the current security options
                _members.Clear();

                // Retrieve data from GlobalVars.FinalMegaObject and populate the security options collection
                if (HardenWindowsSecurity.GlobalVars.FinalMegaObject != null)
                {
                    foreach (var kvp in HardenWindowsSecurity.GlobalVars.FinalMegaObject)
                    {
                        var category = kvp.Key; // Get the category of results
                        var results = kvp.Value; // Get the results for the category

                        foreach (var result in results)
                        {
                            var compliant = string.Equals(result.Compliant, "true", System.StringComparison.OrdinalIgnoreCase);

                            // Add each result as a new SecOp object to the collection
                            _members.Add(new SecOp
                            {
                                FriendlyName = result.FriendlyName,
                                Value = result.Value,
                                Name = result.Name,
                                Category = result.Category,
                                Method = result.Method,
                                Compliant = compliant, // Set the compliance status
                                BgColor = GetCategoryColor(result.Category) // Set the background color based on the category
                            });
                        }
                    }
                }

                // Refresh the collection view to update the DataGrid
                _membersView.Refresh();

                // Update the total count display
                UpdateTotalCount();
            }
        }
    }
}
