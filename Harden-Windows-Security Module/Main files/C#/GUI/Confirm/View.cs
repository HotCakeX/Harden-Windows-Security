using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media.Imaging;
using static HardenWindowsSecurity.NewToastNotification;

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
                    if (!HardenWindowsSecurity.ActivityTracker.IsActive)
                    {
                        // Update the UI every time the user switches to Confirm tab but do not display toast notification when it happens because it won't make sense
                        UpdateTotalCount(false);
                    }

                    return;
                }

                // if Admin privileges are not available, return and do not proceed any further
                // Will prevent the page from being loaded since the CurrentView won't be set/changed
                if (!HardenWindowsSecurity.UserPrivCheck.IsAdmin())
                {
                    Logger.LogMessage("Confirmation page can only be used when running the Harden Windows Security Application with Administrator privileges", LogTypeIntel.ErrorInteractionRequired);
                    return;
                }

                // Construct the full file path to the Confirm view XAML file
                string xamlPath = System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path, "Resources", "XAML", "Confirm.xaml");

                // Read the XAML content from the file
                string xamlContent = System.IO.File.ReadAllText(xamlPath);

                // Parse the XAML content to create a UserControl object
                GUIConfirmSystemCompliance.View = (UserControl)System.Windows.Markup.XamlReader.Parse(xamlContent);

                // Set the DataContext for the Confirm view
                GUIConfirmSystemCompliance.View.DataContext = new ConfirmVM();

                // Find the SecOpsDataGrid
                HardenWindowsSecurity.GUIConfirmSystemCompliance.SecOpsDataGrid = (DataGrid)GUIConfirmSystemCompliance.View.FindName("SecOpsDataGrid");

                TextBlock TotalCurrentlyDisplayedSecOpsTextBlock = (TextBlock)GUIConfirmSystemCompliance.View.FindName("TotalCurrentlyDisplayedSecOps");

                #region ToggleButtons
                ToggleButton CompliantItemsToggleButton = (ToggleButton)GUIConfirmSystemCompliance.View.FindName("CompliantItemsToggleButton");
                ToggleButton NonCompliantItemsToggleButton = (ToggleButton)GUIConfirmSystemCompliance.View.FindName("NonCompliantItemsToggleButton");

                // Apply the templates so that we can set the IsChecked property to true
                _ = CompliantItemsToggleButton.ApplyTemplate();
                _ = NonCompliantItemsToggleButton.ApplyTemplate();

                CompliantItemsToggleButton.IsChecked = true;
                NonCompliantItemsToggleButton.IsChecked = true;
                #endregion

                // Method to update the text block showing the total count of currently displayed items in the GUI
                void UpdateCurrentVisibleItemsTextBlock()
                {
                    // Get the count of all of the current items in the CollectionView
                    string totalDisplayedItemsCount = _SecOpsCollectionView.Cast<SecOp>().Count().ToString(CultureInfo.InvariantCulture);
                    // Display the count in a text box in the GUI
                    TotalCurrentlyDisplayedSecOpsTextBlock.Text = $"Showing {totalDisplayedItemsCount} Items";
                }

                // A Method to apply filters on the DataGrid based on the filter text and toggle buttons
                void ApplyFilters(string filterText, bool includeCompliant, bool includeNonCompliant)
                {
                    // Make sure the collection has data and is not null
                    if (_SecOpsCollectionView is not null)
                    {
                        // Apply a filter to the collection view based on the filter text and toggle buttons
                        _SecOpsCollectionView.Filter = memberObj =>
                        {
                            if (memberObj is SecOp member)
                            {
                                // Check if the item passes the text filter
                                bool passesTextFilter =
                                       (member.FriendlyName?.Contains(filterText, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                       (member.Value?.Contains(filterText, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                       (member.Name?.Contains(filterText, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                       (member.Category?.Contains(filterText, StringComparison.OrdinalIgnoreCase) ?? false) ||
                                       (member.Method?.Contains(filterText, StringComparison.OrdinalIgnoreCase) ?? false);

                                // Check if the item passes the compliant toggle buttons filters
                                bool passesCompliantFilter = (includeCompliant && member.Compliant) ||
                                                             (includeNonCompliant && !member.Compliant);

                                // Return true if the item passes all filters
                                return passesTextFilter && passesCompliantFilter;
                            }
                            return false;
                        };

                        _SecOpsCollectionView.Refresh(); // Refresh the collection view to apply the filter

                        UpdateCurrentVisibleItemsTextBlock();
                    }
                }

                // Initialize an empty security options collection
                __SecOpses = [];

                // Create a collection view based on the security options collection
                _SecOpsCollectionView = System.Windows.Data.CollectionViewSource.GetDefaultView(__SecOpses);

                // Set the ItemSource of the DataGrid in the Confirm view to the collection view
                if (HardenWindowsSecurity.GUIConfirmSystemCompliance.SecOpsDataGrid is not null)
                {
                    // Bind the DataGrid to the collection view
                    HardenWindowsSecurity.GUIConfirmSystemCompliance.SecOpsDataGrid.ItemsSource = _SecOpsCollectionView;
                }

                // Finding the textboxFilter element
                var textBoxFilter = (TextBox)GUIConfirmSystemCompliance.View.FindName("textBoxFilter");

                #region event handlers for data filtration
                // Attach event handlers to the text box filter and toggle buttons
                textBoxFilter.TextChanged += (sender, e) => ApplyFilters(textBoxFilter.Text, CompliantItemsToggleButton.IsChecked ?? false, NonCompliantItemsToggleButton.IsChecked ?? false);

                CompliantItemsToggleButton.Checked += (sender, e) => ApplyFilters(textBoxFilter.Text, CompliantItemsToggleButton.IsChecked ?? false, NonCompliantItemsToggleButton.IsChecked ?? false);
                CompliantItemsToggleButton.Unchecked += (sender, e) => ApplyFilters(textBoxFilter.Text, CompliantItemsToggleButton.IsChecked ?? false, NonCompliantItemsToggleButton.IsChecked ?? false);

                NonCompliantItemsToggleButton.Checked += (sender, e) => ApplyFilters(textBoxFilter.Text, CompliantItemsToggleButton.IsChecked ?? false, NonCompliantItemsToggleButton.IsChecked ?? false);
                NonCompliantItemsToggleButton.Unchecked += (sender, e) => ApplyFilters(textBoxFilter.Text, CompliantItemsToggleButton.IsChecked ?? false, NonCompliantItemsToggleButton.IsChecked ?? false);
                #endregion

                #region RefreshButton
                // Find the Refresh button and attach the Click event handler

                // Access the grid containing the Refresh Button
                Grid RefreshButtonGrid = GUIConfirmSystemCompliance.View.FindName("RefreshButtonGrid") as Grid;

                // Access the Refresh Button
                ToggleButton RefreshButton = (ToggleButton)RefreshButtonGrid.FindName("RefreshButton");

                // Apply the template to make sure it's available
                _ = RefreshButton.ApplyTemplate();

                // Access the image within the Refresh Button's template
                Image RefreshIconImage = RefreshButton.Template.FindName("RefreshIconImage", RefreshButton) as Image;

                // Update the image source for the Refresh button
                // Load the Refresh icon image into memory and set it as the source
                var RefreshIconBitmapImage = new BitmapImage();
                RefreshIconBitmapImage.BeginInit();
                RefreshIconBitmapImage.UriSource = new System.Uri(System.IO.Path.Combine(HardenWindowsSecurity.GlobalVars.path!, "Resources", "Media", "ExecuteButton.png"));
                RefreshIconBitmapImage.CacheOption = BitmapCacheOption.OnLoad; // Load the image data into memory
                RefreshIconBitmapImage.EndInit();

                RefreshIconImage.Source = RefreshIconBitmapImage;


                #endregion


                #region ComboBox
                // Finding the ComplianceCategoriesSelectionComboBox ComboBox
                ComboBox ComplianceCategoriesSelectionComboBox = GUIConfirmSystemCompliance.View.FindName("ComplianceCategoriesSelectionComboBox") as ComboBox;

                // Create an instance of the class
                var cats = new ComplianceCategoriex();

                // Get the valid compliance checking categories
                string[] catsStrings = cats.GetValidValues();

                // Convert the array to a list to easily add items
                List<string> catsList = new(catsStrings);

                // Add an empty item to the list at the beginning
                // Add an empty string as the first item
                catsList.Insert(0, "");

                // Set the ComboBox's ItemsSource to the updated list
                ComplianceCategoriesSelectionComboBox.ItemsSource = catsList;

                #endregion


                // Register the RefreshButton as an element that will be enabled/disabled based on current activity
                HardenWindowsSecurity.ActivityTracker.RegisterUIElement(RefreshButton);


                // Set up the Click event handler for the Refresh button
                RefreshButton.Click += async (sender, e) =>
                {

                    // Only continue if there is no activity other places
                    if (!HardenWindowsSecurity.ActivityTracker.IsActive)
                    {
                        // mark as activity started
                        HardenWindowsSecurity.ActivityTracker.IsActive = true;

                        // Clear the current security options before starting data generation
                        __SecOpses.Clear();
                        _SecOpsCollectionView.Refresh(); // Refresh the collection view to clear the DataGrid

                        // Disable the Refresh button while processing
                        // Set text blocks to empty while new data is being generated
                        System.Windows.Application.Current.Dispatcher.Invoke(() =>
                            {
                                // Finding the elements
                                var CompliantItemsTextBlock = (TextBlock)GUIConfirmSystemCompliance.View.FindName("CompliantItemsTextBlock");
                                var NonCompliantItemsTextBlock = (TextBlock)GUIConfirmSystemCompliance.View.FindName("NonCompliantItemsTextBlock");

                                // Setting these texts the same as the text in the XAML for these text blocks so that every time Refresh button is pressed, they lose their numbers until the new data is generated and new counts are calculated
                                CompliantItemsTextBlock.Text = "Compliant Items";
                                NonCompliantItemsTextBlock.Text = "Non-Compliant Items";

                                var TotalCountTextBlock = (TextBlock)GUIConfirmSystemCompliance.View.FindName("TotalCountTextBlock");

                                if (TotalCountTextBlock is not null)
                                {
                                    // Update the text of the TextBlock to show the total count
                                    TotalCountTextBlock.Text = "Loading...";
                                }

                                UpdateCurrentVisibleItemsTextBlock();
                            });

                        // Run the method asynchronously in a different thread
                        await System.Threading.Tasks.Task.Run(() =>
                            {
                                // Get fresh data for compliance checking
                                HardenWindowsSecurity.Initializer.Initialize(null, true);

                                // initialize the variable to null
                                string SelectedCategory = string.Empty;

                                // Use the App dispatcher since this is being done in a different thread
                                GUIMain.app.Dispatcher.Invoke(() =>
                                {

                                    if (ComplianceCategoriesSelectionComboBox.SelectedItem is not null)
                                    {
                                        // Get the currently selected value in the Compliance Checking category ComboBox if it exists
                                        var SelectedComplianceCategories = ComplianceCategoriesSelectionComboBox.SelectedItem;

                                        // Get the currently selected compliance category
                                        SelectedCategory = SelectedComplianceCategories?.ToString();
                                    }

                                });

                                // if user selected a category for compliance checking
                                if (SelectedCategory is not null && !string.IsNullOrEmpty(SelectedCategory))
                                {
                                    // Perform the compliance check using the selected compliance category
                                    HardenWindowsSecurity.InvokeConfirmation.Invoke([SelectedCategory]);
                                }
                                else
                                {
                                    // Perform the compliance check for all categories
                                    HardenWindowsSecurity.InvokeConfirmation.Invoke(null);
                                }
                            });

                        // After InvokeConfirmation is completed, update the security options collection
                        await System.Windows.Application.Current.Dispatcher.InvokeAsync(() =>
                            {
                                LoadMembers(); // Load updated security options
                                RefreshButton.IsChecked = false; // Uncheck the Refresh button

                                UpdateCurrentVisibleItemsTextBlock();
                            });

                        // mark as activity completed
                        HardenWindowsSecurity.ActivityTracker.IsActive = false;
                    }
                };

                // Cache the Confirm view for future use
                _viewCache["ConfirmView"] = GUIConfirmSystemCompliance.View;

                // Set the CurrentView to the modified Confirm view
                CurrentView = GUIConfirmSystemCompliance.View;
            }


            /// <summary>
            /// Method that returns background color based on the category
            /// Used by the LoadMembers() method only
            /// </summary>
            /// <param name="category">Name of the category</param>
            /// <returns>The color of the category to be used for display purposes on the DataGrid GUI</returns>
            static private System.Windows.Media.Brush GetCategoryColor(string category)
            {
                // Determine the background color for each category
                return category switch
                {
                    // Light Pastel Sky Blue
                    "MicrosoftDefender" => new System.Windows.Media.BrushConverter().ConvertFromString("#B3E5FC") as System.Windows.Media.Brush,
                    // Light Pastel Coral
                    "AttackSurfaceReductionRules" => new System.Windows.Media.BrushConverter().ConvertFromString("#FFDAB9") as System.Windows.Media.Brush,
                    // Light Pastel Green
                    "BitLockerSettings" => new System.Windows.Media.BrushConverter().ConvertFromString("#C3FDB8") as System.Windows.Media.Brush,
                    // Light Pastel Lemon
                    "TLSSecurity" => new System.Windows.Media.BrushConverter().ConvertFromString("#FFFACD") as System.Windows.Media.Brush,
                    // Light Pastel Lavender
                    "LockScreen" => new System.Windows.Media.BrushConverter().ConvertFromString("#E6E6FA") as System.Windows.Media.Brush,
                    // Light Pastel Aqua
                    "UserAccountControl" => new System.Windows.Media.BrushConverter().ConvertFromString("#C1F0F6") as System.Windows.Media.Brush,
                    // Light Pastel Teal
                    "DeviceGuard" => new System.Windows.Media.BrushConverter().ConvertFromString("#B2DFDB") as System.Windows.Media.Brush,
                    // Light Pastel Pink
                    "WindowsFirewall" => new System.Windows.Media.BrushConverter().ConvertFromString("#F8BBD0") as System.Windows.Media.Brush,
                    // Light Pastel Peach
                    "OptionalWindowsFeatures" => new System.Windows.Media.BrushConverter().ConvertFromString("#FFE4E1") as System.Windows.Media.Brush,
                    // Light Pastel Mint
                    "WindowsNetworking" => new System.Windows.Media.BrushConverter().ConvertFromString("#F5FFFA") as System.Windows.Media.Brush,
                    // Light Pastel Gray
                    _ => new System.Windows.Media.BrushConverter().ConvertFromString("#EDEDED") as System.Windows.Media.Brush,
                };
            }

            /// <summary>
            /// Method to update the total count of security options displayed on the Text Block
            /// In the Confirmation page view
            /// </summary>
            /// <param name="ShowNotification">If set to true, this method will display end of confirmation toast notification</param>
            private void UpdateTotalCount(bool ShowNotification)
            {

                // calculates the total number of all security options across all lists, so all the items in each category that exist in the values of the main dictionary object
                int totalCount = HardenWindowsSecurity.GlobalVars.FinalMegaObject?.Values.Sum(list => list.Count) ?? 0;

                // Find the TextBlock used to display the total count
                TextBlock TotalCountTextBlock = (TextBlock)GUIConfirmSystemCompliance.View.FindName("TotalCountTextBlock");
                if (TotalCountTextBlock is not null)
                {
                    // Update the text of the TextBlock to show the total count
                    TotalCountTextBlock.Text = $"{totalCount} Total Verifiable Security Checks";
                }

                // Get the count of the compliant items
                string CompliantItemsCount = _SecOpsCollectionView.SourceCollection
                    .Cast<SecOp>()
                    .Count(item => item.Compliant).ToString(CultureInfo.InvariantCulture);

                // Get the count of the Non-compliant items
                string NonCompliantItemsCount = _SecOpsCollectionView.SourceCollection
                    .Cast<SecOp>()
                    .Count(item => !item.Compliant).ToString(CultureInfo.InvariantCulture);

                // Find the text blocks that display counts of true/false items
                var CompliantItemsTextBlock = (TextBlock)GUIConfirmSystemCompliance.View.FindName("CompliantItemsTextBlock");
                var NonCompliantItemsTextBlock = (TextBlock)GUIConfirmSystemCompliance.View.FindName("NonCompliantItemsTextBlock");

                if (CompliantItemsTextBlock is not null)
                {
                    // Set the text block's text
                    CompliantItemsTextBlock.Text = $"{CompliantItemsCount} Compliant Items";
                }

                if (NonCompliantItemsTextBlock is not null)
                {
                    // Set the text block's text
                    NonCompliantItemsTextBlock.Text = $"{NonCompliantItemsCount} Non-Compliant Items";
                }

                // Display a notification if it's allowed to do so, and ShowNotification is set to true
                if (HardenWindowsSecurity.GlobalVars.UseNewNotificationsExp && ShowNotification)
                {
                    HardenWindowsSecurity.NewToastNotification.Show(ToastNotificationType.EndOfConfirmation, CompliantItemsCount, NonCompliantItemsCount, null, null);
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
                if (HardenWindowsSecurity.GlobalVars.FinalMegaObject is not null)
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
