using AppControlManager.IntelGathering;
using CommunityToolkit.WinUI.UI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Windows.ApplicationModel.DataTransfer;

// To learn more about WinUI, the WinUI project structure,
// and more about our project templates, see: http://aka.ms/winui-project-info.

namespace AppControlManager.Pages
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class AllowNewAppsLocalFilesDataGrid : Page
    {

        // A static instance of the AllowNewAppsLocalFilesDataGrid class which will hold the single, shared instance of the page
        private static AllowNewAppsLocalFilesDataGrid? _instance;

        public AllowNewAppsLocalFilesDataGrid()
        {
            this.InitializeComponent();

            // Make sure navigating to/from this page maintains its state
            this.NavigationCacheMode = NavigationCacheMode.Enabled;

            // Assign this instance to the static field
            _instance = this;

        }

        // Public property to access the singleton instance from other classes
        // It's okay it's nullable, null check will happen before accessing it
        public static AllowNewAppsLocalFilesDataGrid? Instance => _instance;


        #region

        // Without the following steps, when the user begins data fetching process and then navigates away from this page
        // Upon arrival at this page again, the DataGrid loses its virtualization, causing the UI to hang for extended periods of time
        // But after nullifying DataGrid's ItemsSource when page is navigated from and reassigning it when page is navigated to,
        // We tackle that problem. Data will sill be stored in the ObservableCollection when page is not in focus,
        // But DataGrid's source will pick them up only when page is navigated to.
        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);
            FileIdentitiesDataGrid.ItemsSource = AllowNewAppsStart.Instance.LocalFilesFileIdentities;

            // Update the logs when user switches to this page
            UpdateTotalLogs();
        }

        protected override void OnNavigatedFrom(NavigationEventArgs e)
        {
            base.OnNavigatedFrom(e);
            FileIdentitiesDataGrid.ItemsSource = null;
        }

        #endregion


        /// <summary>
        /// Event handler for the SearchBox text change
        /// </summary>
        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            ApplyFilters();
        }


        /// <summary>
        /// Applies the date and search filters to the data grid
        /// </summary>
        private void ApplyFilters()
        {

            // Get the search term from the SearchBox, converting it to lowercase for case-insensitive searching
            string searchTerm = SearchBox.Text.Trim().ToLowerInvariant();

            // Start with all items from the complete list, 'AllFileIdentities'
            // This list is used as the base set for filtering to preserve original data
            IEnumerable<FileIdentity> filteredResults = AllowNewAppsStart.Instance.LocalFilesAllFileIdentities.AsEnumerable();

            // Apply the search filter if there is a non-empty search term
            if (!string.IsNullOrWhiteSpace(searchTerm))
            {

                // Filter results further to match the search term across multiple properties, case-insensitively
                filteredResults = filteredResults.Where(output =>
                    (output.FileName is not null && output.FileName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (output.SignatureStatus.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (output.Action.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (output.OriginalFileName is not null && output.OriginalFileName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (output.InternalName is not null && output.InternalName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (output.FileDescription is not null && output.FileDescription.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (output.ProductName is not null && output.ProductName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (output.FileVersion is not null && output.FileVersion.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (output.PackageFamilyName is not null && output.PackageFamilyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (output.SHA1PageHash is not null && output.SHA1PageHash.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (output.FilePath is not null && output.FilePath.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (output.SHA256FlatHash is not null && output.SHA256FlatHash.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (output.SHA256Hash is not null && output.SHA256Hash.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    output.FilePublishersToDisplay.Contains(searchTerm)
                );
            }

            // Clear the current contents of the ObservableCollection
            AllowNewAppsStart.Instance.LocalFilesFileIdentities.Clear();

            // Populate the ObservableCollection with the filtered results
            // This triggers the UI to update the DataGrid based on the filtered data
            foreach (FileIdentity result in filteredResults)
            {
                AllowNewAppsStart.Instance.LocalFilesFileIdentities.Add(result);
            }

            // Explicitly set the DataGrid's ItemsSource to ensure the data refreshes
            FileIdentitiesDataGrid.ItemsSource = AllowNewAppsStart.Instance.LocalFilesFileIdentities;

            // Update any visual or text element showing the total logs count
            UpdateTotalLogs();
        }


        /// <summary>
        /// Event handler for the Clear Data button
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ClearDataButton_Click(object sender, RoutedEventArgs e)
        {
            AllowNewAppsStart.Instance.LocalFilesFileIdentities.Clear();
            AllowNewAppsStart.Instance.LocalFilesAllFileIdentities.Clear();

            UpdateTotalLogs(true);
        }




        // https://learn.microsoft.com/en-us/windows/communitytoolkit/controls/datagrid_guidance/group_sort_filter
        // Column sorting logic for the entire DataGrid
        private void FileIdentitiesDataGrid_Sorting(object sender, DataGridColumnEventArgs e)
        {
            // Sort the column based on its tag and current sort direction
            if (string.Equals(e.Column.Tag?.ToString(), "FileName", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.FileName);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "SignatureStatus", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.SignatureStatus);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "Action", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.Action);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "OriginalFileName", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.OriginalFileName);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "InternalName", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.InternalName);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "FileDescription", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.FileDescription);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "ProductName", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.ProductName);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "FileVersion", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.FileVersion);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "PackageFamilyName", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.PackageFamilyName);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "SHA256Hash", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.SHA256Hash);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "SHA1Hash", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.SHA1Hash);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "SHA256FlatHash", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.SHA256FlatHash);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "SHA1FlatHash", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.SHA1FlatHash);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "SISigningScenario", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.SISigningScenario);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "FilePath", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.FilePath);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "SHA1PageHash", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.SHA1PageHash);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "SHA256PageHash", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.SHA256PageHash);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "HasWHQLSigner", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.HasWHQLSigner);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "FilePublishersToDisplay", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.FilePublishersToDisplay);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "IsECCSigned", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.IsECCSigned);
            }

            // Clear SortDirection for other columns
            foreach (DataGridColumn column in FileIdentitiesDataGrid.Columns)
            {
                if (column != e.Column)
                {
                    column.SortDirection = null;
                }
            }
        }


        /// <summary>
        /// Helper method for sorting any column on the DataGird
        /// </summary>
        /// <typeparam name="T"></typeparam>
        /// <param name="e"></param>
        /// <param name="keySelector"></param>
        private void SortColumn<T>(DataGridColumnEventArgs e, Func<FileIdentity, T> keySelector)
        {
            // Check if the search box is empty or not
            bool isSearchEmpty = string.IsNullOrWhiteSpace(SearchBox.Text);

            // Get the collection to sort based on the search box status
            // Allowing us to sort only the items in the search results
            List<FileIdentity> collectionToSort = isSearchEmpty ? AllowNewAppsStart.Instance.LocalFilesAllFileIdentities : [.. AllowNewAppsStart.Instance.LocalFilesFileIdentities];

            // Perform the sorting based on the current SortDirection (ascending or descending)
            if (e.Column.SortDirection is null || e.Column.SortDirection == DataGridSortDirection.Ascending)
            {
                // Descending: custom order depending on column type
                AllowNewAppsStart.Instance.LocalFilesFileIdentities = [.. collectionToSort.OrderByDescending(keySelector)];

                // Set the column direction to Descending
                e.Column.SortDirection = DataGridSortDirection.Descending;
            }
            else
            {
                // Ascending: custom order depending on column type
                AllowNewAppsStart.Instance.LocalFilesFileIdentities = [.. collectionToSort.OrderBy(keySelector)];
                e.Column.SortDirection = DataGridSortDirection.Ascending;
            }

            // Update the ItemsSource of the DataGrid
            // Required for sort + search to work properly, even though binding to the ObservableCollection already happens in XAML
            FileIdentitiesDataGrid.ItemsSource = AllowNewAppsStart.Instance.LocalFilesFileIdentities;
        }


        /// <summary>
        /// Selects all of the displayed rows on the DataGrid
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void SelectAll_Click(object sender, RoutedEventArgs e)
        {
            _ = DispatcherQueue.TryEnqueue(() =>
            {
                // Clear existing selections
                FileIdentitiesDataGrid.SelectedItems.Clear();

                foreach (FileIdentity fileIdentity in AllowNewAppsStart.Instance.LocalFilesFileIdentities)
                {
                    _ = FileIdentitiesDataGrid.SelectedItems.Add(fileIdentity); // Select each item
                }

            });
        }


        /// <summary>
        /// De-selects all of the displayed rows on the DataGrid
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void DeSelectAll_Click(object sender, RoutedEventArgs e)
        {
            FileIdentitiesDataGrid.SelectedItems.Clear(); // Deselect all rows by clearing SelectedItems
        }



        /// <summary>
        /// Deletes the selected row from the results
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void DataGridFlyoutMenuDelete_Click(object sender, RoutedEventArgs e)
        {
            // Collect the selected items to delete
            List<FileIdentity> itemsToDelete = [.. FileIdentitiesDataGrid.SelectedItems.Cast<FileIdentity>()];

            // Remove each selected item from the FileIdentities collection
            foreach (FileIdentity item in itemsToDelete)
            {
                _ = AllowNewAppsStart.Instance.LocalFilesFileIdentities.Remove(item);
            }

            UpdateTotalLogs();
        }



        /// <summary>
        /// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
        /// </summary>
        /// <param name="sender">The event sender.</param>
        /// <param name="e">The event arguments.</param>
        private void DataGridFlyoutMenuCopy_Click(object sender, RoutedEventArgs e)
        {
            // Check if there are selected items in the DataGrid
            if (FileIdentitiesDataGrid.SelectedItems.Count > 0)
            {
                // Initialize StringBuilder to store all selected rows' data with labels
                StringBuilder dataBuilder = new();

                // Loop through each selected item in the DataGrid
                foreach (var selectedItem in FileIdentitiesDataGrid.SelectedItems)
                {
                    if (selectedItem is FileIdentity selectedRow)
                    {
                        // Append each row's formatted data to the StringBuilder
                        _ = dataBuilder.AppendLine(ConvertRowToText(selectedRow));

                        // Add a separator between rows for readability in multi-row copies
                        _ = dataBuilder.AppendLine(new string('-', 50));
                    }
                }

                // Create a DataPackage to hold the text data
                DataPackage dataPackage = new();

                // Set the formatted text as the content of the DataPackage
                dataPackage.SetText(dataBuilder.ToString());

                // Copy the DataPackage content to the clipboard
                Clipboard.SetContent(dataPackage);
            }
        }

        /// <summary>
        /// Converts the properties of a FileIdentity row into a labeled, formatted string for copying to clipboard.
        /// </summary>
        /// <param name="row">The selected FileIdentity row from the DataGrid.</param>
        /// <returns>A formatted string of the row's properties with labels.</returns>
        private static string ConvertRowToText(FileIdentity row)
        {
            // Use StringBuilder to format each property with its label for easy reading
            return new StringBuilder()
                .AppendLine($"File Name: {row.FileName}")
                .AppendLine($"Signature Status: {row.SignatureStatus}")
                .AppendLine($"Action: {row.Action}")
                .AppendLine($"Original File Name: {row.OriginalFileName}")
                .AppendLine($"Internal Name: {row.InternalName}")
                .AppendLine($"File Description: {row.FileDescription}")
                .AppendLine($"Product Name: {row.ProductName}")
                .AppendLine($"File Version: {row.FileVersion}")
                .AppendLine($"Package Family Name: {row.PackageFamilyName}")
                .AppendLine($"SHA256 Hash: {row.SHA256Hash}")
                .AppendLine($"SHA1 Hash: {row.SHA1Hash}")
                .AppendLine($"SHA256 Flat Hash: {row.SHA256FlatHash}")
                .AppendLine($"SHA1 Flat Hash: {row.SHA1FlatHash}")
                .AppendLine($"Signing Scenario: {row.SISigningScenario}")
                .AppendLine($"File Path: {row.FilePath}")
                .AppendLine($"SHA1 Page Hash: {row.SHA1PageHash}")
                .AppendLine($"SHA256 Page Hash: {row.SHA256PageHash}")
                .AppendLine($"Has WHQL Signer: {row.HasWHQLSigner}")
                .AppendLine($"File Publishers: {row.FilePublishersToDisplay}")
                .AppendLine($"Is ECC Signed: {row.IsECCSigned}")
                .ToString();
        }



        /// <summary>
        /// Event handler for the Copy Individual Items SubMenu. It will populate the submenu items in the flyout of the data grid.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void FileIdentitiesDataGrid_Loaded(object sender, RoutedEventArgs e)
        {
            // Ensure the CopyIndividualItemsSubMenu is available
            if (CopyIndividualItemsSubMenu is null)
            {
                return;
            }

            // Clear any existing items to avoid duplication if reloaded
            CopyIndividualItemsSubMenu.Items.Clear();

            // Create a dictionary to map headers to their specific click event methods
            Dictionary<string, RoutedEventHandler> copyActions = new()
            {
                { "File Name", CopyFileName_Click },
                { "Signature Status", CopySignatureStatus_Click },
                { "Action", CopyAction_Click },
                { "Original File Name", CopyOriginalFileName_Click },
                { "Internal Name", CopyInternalName_Click },
                { "File Description", CopyFileDescription_Click },
                { "Product Name", CopyProductName_Click },
                { "File Version", CopyFileVersion_Click },
                { "Package Family Name", CopyPackageFamilyName_Click },
                { "SHA256 Hash", CopySHA256Hash_Click },
                { "SHA1 Hash", CopySHA1Hash_Click },
                { "SHA256 Flat Hash", CopySHA256FlatHash_Click },
                { "SHA1 Flat Hash", CopySHA1FlatHash_Click },
                { "Signing Scenario", CopySigningScenario_Click },
                { "File Path", CopyFilePath_Click },
                { "SHA1 Page Hash", CopySHA1PageHash_Click },
                { "SHA256 Page Hash", CopySHA256PageHash_Click },
                { "Has WHQL Signer", CopyHasWHQLSigner_Click },
                { "File Publishers", CopyFilePublishersToDisplay_Click },
                { "Is ECC Signed", CopyIsECCSigned_Click }
            };

            // Add menu items with specific click events for each column
            foreach (DataGridColumn column in FileIdentitiesDataGrid.Columns)
            {
                string headerText = column.Header.ToString()!;

                if (copyActions.TryGetValue(headerText, out RoutedEventHandler? value))
                {
                    // Create a new MenuFlyout Item
                    MenuFlyoutItem menuItem = new() { Text = $"Copy {headerText}" };

                    // Set the click event for the menu item
                    menuItem.Click += value;

                    // Add the menu item to the submenu
                    CopyIndividualItemsSubMenu.Items.Add(menuItem);
                }
            }
        }

        // Click event handlers for each property
        private void CopyFileName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FileName);
        private void CopySignatureStatus_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SignatureStatus.ToString());
        private void CopyAction_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.Action.ToString());
        private void CopyOriginalFileName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.OriginalFileName);
        private void CopyInternalName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.InternalName);
        private void CopyFileDescription_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FileDescription);
        private void CopyProductName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.ProductName);
        private void CopyFileVersion_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FileVersion?.ToString());
        private void CopyPackageFamilyName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.PackageFamilyName);
        private void CopySHA256Hash_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SHA256Hash);
        private void CopySHA1Hash_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SHA1Hash);
        private void CopySHA256FlatHash_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SHA256FlatHash);
        private void CopySHA1FlatHash_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SHA1FlatHash);
        private void CopySigningScenario_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SISigningScenario.ToString());
        private void CopyFilePath_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FilePath);
        private void CopySHA1PageHash_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SHA1PageHash);
        private void CopySHA256PageHash_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SHA256PageHash);
        private void CopyHasWHQLSigner_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.HasWHQLSigner.ToString());
        private void CopyFilePublishersToDisplay_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FilePublishersToDisplay.ToString());
        private void CopyIsECCSigned_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.IsECCSigned.ToString());


        /// <summary>
        /// Helper method to copy a specified property to clipboard without reflection
        /// </summary>
        /// <param name="getProperty">Function that retrieves the desired property value as a string</param>
        private void CopyToClipboard(Func<FileIdentity, string?> getProperty)
        {
            if (FileIdentitiesDataGrid.SelectedItem is FileIdentity selectedItem)
            {
                string? propertyValue = getProperty(selectedItem);
                if (propertyValue is not null)
                {
                    DataPackage dataPackage = new();
                    dataPackage.SetText(propertyValue);
                    Clipboard.SetContent(dataPackage);
                }
            }
        }



        /// <summary>
        /// Updates the total logs count displayed on the UI
        /// </summary>
        internal void UpdateTotalLogs(bool? Zero = null)
        {
            if (Zero == true)
            {
                TotalCountOfTheFilesTextBox.Text = $"Total logs: 0";

                // Update the InfoBadge for the top menu
                AllowNewApps.Instance.UpdateLocalFilesInfoBadge(0, 1);
            }
            else
            {
                TotalCountOfTheFilesTextBox.Text = $"Total logs: {AllowNewAppsStart.Instance.LocalFilesFileIdentities.Count}";

                // Update the InfoBadge for the top menu
                AllowNewApps.Instance.UpdateLocalFilesInfoBadge(AllowNewAppsStart.Instance.LocalFilesFileIdentities.Count, 1);
            }


        }


    }
}
