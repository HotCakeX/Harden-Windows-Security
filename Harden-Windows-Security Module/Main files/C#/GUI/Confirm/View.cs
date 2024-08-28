using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
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
using static HardenWindowsSecurity.NewToastNotification;
using System.Collections.Generic;

#nullable disable

namespace HardenWindowsSecurity
{
    public partial class GUIMain
    {

        // Partial class definition for handling navigation and view models
        public partial class NavigationVM : ViewModelBase
        {

            // Private fields to hold the collection view and security options collection

            // Collection view for filtering and sorting
            private ICollectionView _SecOpsCollectionView;

            // Collection of SecOp objects
            private System.Collections.ObjectModel.ObservableCollection<SecOp> __SecOpses;

            // Method to handle the "Confirm" view, including loading and modifying it
            private void Confirm(object obj)
            {
                // Check if the Confirm view is already cached
                if (_viewCache.TryGetValue("ConfirmView", out var cachedView))
                {
                    // Use the cached view if available
                    CurrentView = cachedView;

                    // Only update the UI if work is not being done (i.e. the confirmation job is not already active)
                    if (HardenWindowsSecurity.ActivityTracker.IsActive == false)
                    {
                        // Update the UI every time the user switches to Confirm tab but do not display toast notification when it happens because it won't make sense
                        UpdateTotalCount(false);
                    }

                    return;
                }

                // Construct the full file path to the Confirm view XAML file
                string xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "Confirm.xaml");

                // Read the XAML content from the file
                string xamlContent = System.IO.File.ReadAllText(xamlPath);

                // Parse the XAML content to create a UserControl object
                System.Windows.Controls.UserControl confirmView = (System.Windows.Controls.UserControl)System.Windows.Markup.XamlReader.Parse(xamlContent);

                // Find the SecOpsDataGrid
                HardenWindowsSecurity.GUIConfirmSystemCompliance.SecOpsDataGrid = (System.Windows.Controls.DataGrid)confirmView.FindName("SecOpsDataGrid");

                // Initialize an empty security options collection
                __SecOpses = new System.Collections.ObjectModel.ObservableCollection<SecOp>();

                // Create a collection view based on the security options collection
                _SecOpsCollectionView = System.Windows.Data.CollectionViewSource.GetDefaultView(__SecOpses);

                // Set the ItemSource of the DataGrid in the Confirm view to the collection view
                if (HardenWindowsSecurity.GUIConfirmSystemCompliance.SecOpsDataGrid != null)
                {
                    // Bind the DataGrid to the collection view
                    HardenWindowsSecurity.GUIConfirmSystemCompliance.SecOpsDataGrid.ItemsSource = _SecOpsCollectionView;
                }

                // Handle the TextBox filter using a lambda expression
                var textBoxFilter = (System.Windows.Controls.TextBox)confirmView.FindName("textBoxFilter");
                if (textBoxFilter != null)
                {
                    textBoxFilter.TextChanged += (sender, e) =>
                    {
                        // Get the filter text from the TextBox
                        string filterText = textBoxFilter.Text;
                        if (_SecOpsCollectionView != null)
                        {
                            // Apply a filter to the collection view based on the filter text
                            _SecOpsCollectionView.Filter = memberObj =>
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
                            _SecOpsCollectionView.Refresh(); // Refresh the collection view to apply the filter
                        }
                    };
                }

                #region RefreshButton
                // Find the Refresh button and attach the Click event handler

                // Access the grid containing the Refresh Button
                System.Windows.Controls.Grid RefreshButtonGrid = confirmView.FindName("RefreshButtonGrid") as System.Windows.Controls.Grid;

                // Access the Refresh Button
                System.Windows.Controls.Primitives.ToggleButton RefreshButton = (System.Windows.Controls.Primitives.ToggleButton)RefreshButtonGrid.FindName("RefreshButton");

                // Register the RefreshButton as an element that will be enabled/disabled based on current activity
                HardenWindowsSecurity.ActivityTracker.RegisterUIElement(RefreshButton);

                // Apply the template to make sure it's available
                RefreshButton.ApplyTemplate();

                // Access the image within the Refresh Button's template
                System.Windows.Controls.Image RefreshIconImage = RefreshButton.Template.FindName("RefreshIconImage", RefreshButton) as System.Windows.Controls.Image;

                // Update the image source for the Refresh button
                RefreshIconImage.Source =
                    new System.Windows.Media.Imaging.BitmapImage(
                        new System.Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "ExecuteButton.png"))
                    );

                #endregion


                // perform the compliance check only if user has Admin privileges
                if (!HardenWindowsSecurity.UserPrivCheck.IsAdmin())
                {
                    // Disable the refresh button
                    RefreshButton.IsEnabled = false;
                    HardenWindowsSecurity.Logger.LogMessage("You need Administrator privileges to perform compliance check on the system.");
                }

                // Set up the Click event handler for the Refresh button
                RefreshButton.Click += async (sender, e) =>
                {

                    // Only continue if there is no activity other places
                    if (HardenWindowsSecurity.ActivityTracker.IsActive == false)
                    {
                        // mark as activity started
                        HardenWindowsSecurity.ActivityTracker.IsActive = true;

                        // Disable the Refresh button while processing
                        // Set text blocks to empty while new data is being generated
                        System.Windows.Application.Current.Dispatcher.Invoke(() =>
                            {
                                var CompliantItemsTextBlock = (System.Windows.Controls.TextBlock)confirmView.FindName("CompliantItemsTextBlock");
                                var NonCompliantItemsTextBlock = (System.Windows.Controls.TextBlock)confirmView.FindName("NonCompliantItemsTextBlock");
                                CompliantItemsTextBlock.Text = "";
                                NonCompliantItemsTextBlock.Text = "";

                                var TotalCountTextBlock = (System.Windows.Controls.TextBlock)confirmView.FindName("TotalCountTextBlock");

                                if (TotalCountTextBlock != null)
                                {
                                    // Update the text of the TextBlock to show the total count
                                    TotalCountTextBlock.Text = "Loading...";
                                }

                            });

                        // Clear the current security options before starting data generation
                        __SecOpses.Clear();
                        _SecOpsCollectionView.Refresh(); // Refresh the collection view to clear the DataGrid

                        // Run the method asynchronously in a different thread
                        await System.Threading.Tasks.Task.Run(() =>
                            {
                                // Get fresh data for compliance checking
                                HardenWindowsSecurity.Initializer.Initialize(null, true);

                                // Perform the compliance check
                                HardenWindowsSecurity.InvokeConfirmation.Invoke(null);
                            });

                        // After InvokeConfirmation is completed, update the security options collection
                        await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                            {
                                LoadMembers(); // Load updated security options
                                RefreshButton.IsChecked = false; // Uncheck the Refresh button
                            });

                        // mark as activity completed
                        HardenWindowsSecurity.ActivityTracker.IsActive = false;
                    }
                };

                // Cache the Confirm view for future use
                _viewCache["ConfirmView"] = confirmView;

                // Set the CurrentView to the modified Confirm view
                CurrentView = confirmView;
            }


            /// <summary>
            /// Method that returns background color based on the category
            /// Used by the LoadMembers() method only
            /// </summary>
            /// <param name="category">Name of the category</param>
            /// <returns>The color of the category to be used for display purposes on the DataGrid GUI</returns>
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

            /// <summary>
            /// Method to update the total count of security options displayed on the Text Block
            /// In the Confirmation page view
            /// </summary>
            /// <param name="ShowNotification">If set to true, this method will display end of confirmation toast notification</param>
            private void UpdateTotalCount(bool ShowNotification)
            {
                // Get the total count of security options
                int totalCount = _SecOpsCollectionView.Cast<SecOp>().Count();
                if (CurrentView is System.Windows.Controls.UserControl confirmView)
                {
                    // Find the TextBlock used to display the total count
                    System.Windows.Controls.TextBlock TotalCountTextBlock = (System.Windows.Controls.TextBlock)confirmView.FindName("TotalCountTextBlock");
                    if (TotalCountTextBlock != null)
                    {
                        // Update the text of the TextBlock to show the total count
                        TotalCountTextBlock.Text = $"{totalCount} Total Verifiable Security Checks";
                    }

                    // Get the count of the compliant items
                    string CompliantItemsCount = _SecOpsCollectionView.SourceCollection
                        .Cast<SecOp>()
                        .Where(item => item.Compliant)
                        .Count()
                        .ToString(CultureInfo.InvariantCulture);

                    // Get the count of the Non-compliant items
                    string NonCompliantItemsCount = _SecOpsCollectionView.SourceCollection
                        .Cast<SecOp>()
                        .Where(item => !item.Compliant)
                        .Count()
                        .ToString(CultureInfo.InvariantCulture);

                    // Find the text blocks that display counts of true/false items
                    var CompliantItemsTextBlock = (System.Windows.Controls.TextBlock)confirmView.FindName("CompliantItemsTextBlock");
                    var NonCompliantItemsTextBlock = (System.Windows.Controls.TextBlock)confirmView.FindName("NonCompliantItemsTextBlock");

                    if (CompliantItemsTextBlock != null)
                    {
                        // Set the text block's text
                        CompliantItemsTextBlock.Text = $"{CompliantItemsCount} Compliant Items";
                    }

                    if (NonCompliantItemsTextBlock != null)
                    {
                        // Set the text block's text
                        NonCompliantItemsTextBlock.Text = $"{NonCompliantItemsCount} Non-Compliant Items";
                    }

                    // Display a notification if it's allowed to do so, and ShowNotification is set to true
                    if (HardenWindowsSecurity.GlobalVars.UseNewNotificationsExp == true && ShowNotification == true)
                    {
                        HardenWindowsSecurity.NewToastNotification.Show(ToastNotificationType.EndOfConfirmation, CompliantItemsCount, NonCompliantItemsCount);
                    }
                }
            }

            /// <summary>
            /// Method to load security options from the FinalMegaObject and update the DataGrid
            /// Also sets custom background colors for each category
            /// </summary>
            private void LoadMembers()
            {
                // Clear the current security options
                __SecOpses.Clear();

                // Retrieve data from GlobalVars.FinalMegaObject and populate the security options collection
                if (HardenWindowsSecurity.GlobalVars.FinalMegaObject != null)
                {
                    foreach (KeyValuePair<string, List<IndividualResult>> kvp in HardenWindowsSecurity.GlobalVars.FinalMegaObject)
                    {
                        string category = kvp.Key; // Get the category of results
                        List<IndividualResult> results = kvp.Value; // Get the results for the category

                        foreach (IndividualResult result in results)
                        {
                            // Add each result as a new SecOp object to the collection
                            __SecOpses.Add(new SecOp
                            {
                                FriendlyName = result.FriendlyName,
                                Value = result.Value,
                                Name = result.Name,
                                Category = result.Category,
                                Method = result.Method,
                                Compliant = result.Compliant,
                                BgColor = GetCategoryColor(result.Category) // Set the background color based on the category
                            });
                        }
                    }
                }

                // Refresh the collection view to update the DataGrid
                _SecOpsCollectionView.Refresh();

                // Update the total count display
                UpdateTotalCount(true);
            }
        }
    }
}
