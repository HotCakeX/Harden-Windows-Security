using AppControlManager.IntelGathering;
using AppControlManager.Logging;
using CommunityToolkit.WinUI.UI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.DataTransfer;


namespace AppControlManager.Pages
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class EventLogsPolicyCreation : Page
    {

        // To store the FileIdentities displayed on the DataGrid
        // Binding happens on the XAML but methods related to search update the ItemSource of the DataGrid from code behind otherwise there will not be an expected result
        public ObservableCollection<FileIdentity> FileIdentities { get; set; }

        // Store all outputs for searching, used as a temporary storage for filtering
        // If ObservableCollection were used directly, any filtering or modification could remove items permanently
        // from the collection, making it difficult to reset or apply different filters without re-fetching data.
        private readonly List<FileIdentity> AllFileIdentities;

        private string? CodeIntegrityEVTX; // To store the Code Integrity EVTX file path
        private string? AppLockerEVTX; // To store the AppLocker EVTX file path

        // The user selected scan level
        private ScanLevels scanLevel = ScanLevels.FilePublisher;


        // Variables to hold the data supplied by the UI elements
        private Guid? BasePolicyGUID;
        private string? PolicyToAddLogsTo;
        private string? BasePolicyXMLFile;


        public EventLogsPolicyCreation()
        {
            this.InitializeComponent();

            // Make sure navigating to/from this page maintains its state
            this.NavigationCacheMode = NavigationCacheMode.Enabled;

            // Initialize the lists
            FileIdentities = [];
            AllFileIdentities = [];

            // Add the DateChanged event handler
            FilterByDateCalendarPicker.DateChanged += FilterByDateCalendarPicker_DateChanged;
        }


        #region

        // Without the following steps, when the user begins data fetching process and then navigates away from this page
        // Upon arrival at this page again, the DataGrid loses its virtualization, causing the UI to hang for extended periods of time
        // But after nullifying DataGrid's ItemsSource when page is navigated from and reassigning it when page is navigated to,
        // We tackle that problem. Data will sill be stored in the ObservableCollection when page is not in focus,
        // But DataGrid's source will pick them up only when page is navigated to.
        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);
            FileIdentitiesDataGrid.ItemsSource = FileIdentities;
        }

        protected override void OnNavigatedFrom(NavigationEventArgs e)
        {
            base.OnNavigatedFrom(e);
            FileIdentitiesDataGrid.ItemsSource = null;
        }

        #endregion


        /// <summary>
        /// Event handler for the CalendarDatePicker date changed event
        /// </summary>
        private void FilterByDateCalendarPicker_DateChanged(CalendarDatePicker sender, CalendarDatePickerDateChangedEventArgs args)
        {
            ApplyFilters();
        }


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
            // Get the selected date from the CalendarDatePicker (if any)
            DateTimeOffset? selectedDate = FilterByDateCalendarPicker.Date;

            // Get the search term from the SearchBox, converting it to lowercase for case-insensitive searching
            string searchTerm = SearchBox.Text.Trim().ToLowerInvariant();

            // Start with all items from the complete list, 'AllFileIdentities'
            // This list is used as the base set for filtering to preserve original data
            IEnumerable<FileIdentity> filteredResults = AllFileIdentities.AsEnumerable();

            // Apply the date filter if a date is selected in the CalendarDatePicker
            if (selectedDate.HasValue)
            {
                // Filter results to include only items where 'TimeCreated' is greater than or equal to the selected date
                filteredResults = filteredResults.Where(item => item.TimeCreated >= selectedDate.Value);
            }

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
                    (output.PolicyName is not null && output.PolicyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (output.ComputerName is not null && output.ComputerName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (output.FilePath is not null && output.FilePath.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (output.SHA256FlatHash is not null && output.SHA256FlatHash.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    (output.SHA256Hash is not null && output.SHA256Hash.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                    output.FilePublishersToDisplay.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)
                );
            }

            // Clear the current contents of the ObservableCollection
            FileIdentities.Clear();

            // Populate the ObservableCollection with the filtered results
            // This triggers the UI to update the DataGrid based on the filtered data
            foreach (FileIdentity result in filteredResults)
            {
                FileIdentities.Add(result);
            }

            // Explicitly set the DataGrid's ItemsSource to ensure the data refreshes
            FileIdentitiesDataGrid.ItemsSource = FileIdentities;

            // Update any visual or text element showing the total logs count
            UpdateTotalLogs();
        }




        /// <summary>
        /// Event handler for the ScanLogs click
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private async void ScanLogs_Click(object sender, RoutedEventArgs e)
        {

            try
            {
                // Disable the scan button initially
                ScanLogs.IsEnabled = false;

                // Display the progress ring on the ScanLogs button
                ScanLogsProgressRing.IsActive = true;
                ScanLogsProgressRing.Visibility = Visibility.Visible;


                // Disable the Policy creator button while scan is being performed
                CreatePolicyButton.IsEnabled = false;

                // Clear the FileIdentities before getting and showing the new ones
                FileIdentities.Clear();
                AllFileIdentities.Clear();

                UpdateTotalLogs(true);

                // Grab the App Control Logs
                HashSet<FileIdentity> Output = await GetEventLogsData.GetAppControlEvents(CodeIntegrityEvtxFilePath: CodeIntegrityEVTX, AppLockerEvtxFilePath: AppLockerEVTX);

                // Store all of the data in the ObservableCollection and List
                foreach (FileIdentity fileIdentity in Output)
                {
                    AllFileIdentities.Add(fileIdentity);

                    FileIdentities.Add(fileIdentity);
                }

                UpdateTotalLogs();
            }

            finally
            {
                // Enable the button again
                ScanLogs.IsEnabled = true;

                // Clear the selected file paths
                CodeIntegrityEVTX = null;
                AppLockerEVTX = null;

                // Stop displaying the Progress Ring
                ScanLogsProgressRing.IsActive = false;
                ScanLogsProgressRing.Visibility = Visibility.Collapsed;


                // Enable the Policy creator button again
                CreatePolicyButton.IsEnabled = true;
            }
        }



        /// <summary>
        /// Event handler for the select Code Integrity EVTX file path button
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void SelectCodeIntegrityEVTXFiles_Click(object sender, RoutedEventArgs e)
        {

            string filter = "EVTX log file|*.evtx";

            string? selectedFile = FileDialogHelper.ShowFilePickerDialog(filter);

            if (!string.IsNullOrEmpty(selectedFile))
            {
                // Store the selected evtx file path
                CodeIntegrityEVTX = selectedFile;

                Logger.Write($"Selected {selectedFile} for Code Integrity EVTX log scanning");
            }
        }


        /// <summary>
        /// Event handler for the select AppLocker EVTX file path button
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void SelectAppLockerEVTXFiles_Click(object sender, RoutedEventArgs e)
        {

            string filter = "EVTX log file|*.evtx";

            string? selectedFile = FileDialogHelper.ShowFilePickerDialog(filter);

            if (!string.IsNullOrEmpty(selectedFile))
            {
                // Store the selected EVTX file path
                AppLockerEVTX = selectedFile;

                Logger.Write($"Selected {selectedFile} for AppLocker EVTX log scanning");
            }
        }



        /// <summary>
        /// Event handler for the Clear Data button
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ClearDataButton_Click(object sender, RoutedEventArgs e)
        {
            FileIdentities.Clear();
            AllFileIdentities.Clear();

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
            else if (string.Equals(e.Column.Tag?.ToString(), "TimeCreated", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.TimeCreated);
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
            else if (string.Equals(e.Column.Tag?.ToString(), "ComputerName", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.ComputerName);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "PolicyGUID", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.PolicyGUID);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "PolicyName", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.PolicyName);
            }
            else if (string.Equals(e.Column.Tag?.ToString(), "FilePublishersToDisplay", StringComparison.OrdinalIgnoreCase))
            {
                SortColumn(e, output => output.FilePublishersToDisplay);
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
            List<FileIdentity> collectionToSort = isSearchEmpty ? AllFileIdentities : [.. FileIdentities];

            // Perform the sorting based on the current SortDirection (ascending or descending)
            if (e.Column.SortDirection is null || e.Column.SortDirection == DataGridSortDirection.Ascending)
            {
                // Descending: custom order depending on column type
                FileIdentities = [.. collectionToSort.OrderByDescending(keySelector)];

                // Set the column direction to Descending
                e.Column.SortDirection = DataGridSortDirection.Descending;
            }
            else
            {
                // Ascending: custom order depending on column type
                FileIdentities = [.. collectionToSort.OrderBy(keySelector)];
                e.Column.SortDirection = DataGridSortDirection.Ascending;
            }

            // Update the ItemsSource of the DataGrid
            // Required for sort + search to work properly, even though binding to the ObservableCollection already happens in XAML
            FileIdentitiesDataGrid.ItemsSource = FileIdentities;
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

                foreach (FileIdentity fileIdentity in FileIdentities)
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
            List<FileIdentity> itemsToDelete = FileIdentitiesDataGrid.SelectedItems.Cast<FileIdentity>().ToList();

            // Remove each selected item from the FileIdentities collection
            foreach (FileIdentity item in itemsToDelete)
            {
                _ = FileIdentities.Remove(item);
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
                .AppendLine($"Time Created: {row.TimeCreated}")
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
                .AppendLine($"Computer Name: {row.ComputerName}")
                .AppendLine($"Policy GUID: {row.PolicyGUID}")
                .AppendLine($"Policy Name: {row.PolicyName}")
                .AppendLine($"File Publishers: {row.FilePublishersToDisplay}")
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
                { "Time Created", CopyTimeCreated_Click },
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
                { "Computer Name", CopyComputerName_Click },
                { "Policy GUID", CopyPolicyGUID_Click },
                { "Policy Name", CopyPolicyName_Click },
                { "File Publishers", CopyFilePublishersToDisplay_Click }
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
        private void CopyTimeCreated_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.TimeCreated.ToString());
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
        private void CopyComputerName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.ComputerName);
        private void CopyPolicyGUID_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.PolicyGUID.ToString());
        private void CopyPolicyName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.PolicyName);
        private void CopyFilePublishersToDisplay_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FilePublishersToDisplay.ToString());


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
        private void UpdateTotalLogs(bool? Zero = null)
        {
            if (Zero == true)
            {
                TotalCountOfTheFilesTextBox.Text = $"Total logs: 0";
            }
            else
            {
                TotalCountOfTheFilesTextBox.Text = $"Total logs: {FileIdentities.Count}";
            }
        }


        /// <summary>
        /// Changes the main button's text that creates the policy, based on the selected method of creation
        /// </summary>
        /// <param name="text"></param>
        private void CreatePolicyButtonTextChange(string text)
        {
            CreatePolicyButton.Content = text;
        }


        /// <summary>
        /// The button that browses for XML file the logs will be added to
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void AddToPolicyButton_Click(object sender, RoutedEventArgs e)
        {

            string filter = "XML file|*.xml";

            string? selectedFile = FileDialogHelper.ShowFilePickerDialog(filter);

            if (!string.IsNullOrEmpty(selectedFile))
            {
                // Store the selected XML file path
                PolicyToAddLogsTo = selectedFile;

                Logger.Write($"Selected {PolicyToAddLogsTo} to add the logs to.");

                CreatePolicyButtonTextChange("Add logs to the selected policy");
            }

        }


        /// <summary>
        /// The button to browse for the XML file the supplemental policy that will be created will belong to
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void BasePolicyFileButton_Click(object sender, RoutedEventArgs e)
        {

            string filter = "XML file|*.xml";

            string? selectedFile = FileDialogHelper.ShowFilePickerDialog(filter);

            if (!string.IsNullOrEmpty(selectedFile))
            {
                // Store the selected XML file path
                BasePolicyXMLFile = selectedFile;

                Logger.Write($"Selected {BasePolicyXMLFile} to associate the Supplemental policy with.");

                CreatePolicyButtonTextChange("Create Policy for Selected Base");
            }

        }



        /// <summary>
        /// The button to submit a base policy GUID that will be used to set the base policy ID in the Supplemental policy file that will be created.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        /// <exception cref="ArgumentException"></exception>
        private void BaseGUIDSubmitButton_Click(object sender, RoutedEventArgs e)
        {
            if (Guid.TryParse(BaseGUIDTextBox.Text, out Guid guid))
            {
                BasePolicyGUID = guid;

                CreatePolicyButtonTextChange("Create Policy for Base GUID");
            }
            else
            {
                throw new ArgumentException("Invalid GUID");
            }

        }


        /// <summary>
        /// When the main button responsible for creating policy is pressed
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        private async void CreatePolicyButton_Click(SplitButton sender, SplitButtonClickEventArgs args)
        {

            try
            {

                // Disable the policy creator button
                CreatePolicyButton.IsEnabled = false;

                // Disable the scan logs button
                ScanLogs.IsEnabled = false;

                // Display the progress ring on the ScanLogs button
                ScanLogsProgressRing.IsActive = true;
                ScanLogsProgressRing.Visibility = Visibility.Visible;


                if (FileIdentities.Count == 0)
                {
                    throw new InvalidOperationException("There are no logs. Use the scan button first.");
                }


                if (PolicyToAddLogsTo is null && BasePolicyXMLFile is null && BasePolicyGUID is null)
                {
                    throw new InvalidOperationException("You must select an option from the policy creation list");
                }


                // Create a policy name if it wasn't provided
                DateTime now = DateTime.Now;
                string formattedDate = now.ToString("MM-dd-yyyy 'at' HH-mm-ss");


                // Get the policy name from the UI text box
                string? policyName = PolicyNameTextBox.Text;

                // If the UI text box was empty or whitespace then set policy name manually
                if (string.IsNullOrWhiteSpace(policyName))
                {
                    policyName = $"Supplemental policy from event logs - {formattedDate}";
                }



                // All of the File Identities that will be used to put in the policy XML file
                List<FileIdentity> SelectedLogs = [];

                // Check if there are selected items in the DataGrid
                if (FileIdentitiesDataGrid.SelectedItems.Count > 0)
                {
                    // convert every selected item to FileIdentity and store it in the list
                    foreach (FileIdentity item in FileIdentitiesDataGrid.SelectedItems)
                    {
                        SelectedLogs.Add(item);
                    }
                }

                // If no item was selected from the DataGrid, use everything in the ObservableCollection
                else
                {
                    SelectedLogs = [.. FileIdentities];
                }



                // If user selected to deploy the policy
                // Need to retrieve it while we're still at the UI thread
                bool DeployAtTheEnd = DeployPolicyToggle.IsChecked;


                await Task.Run(() =>
                {

                    // Create a new Staging Area
                    DirectoryInfo stagingArea = StagingArea.NewStagingArea("PolicyCreator");

                    // Get the path to an empty policy file
                    string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

                    // Separate the signed and unsigned data
                    FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: SelectedLogs, level: scanLevel);

                    // Insert the data into the empty policy file
                    XMLOps.Initiate(DataPackage, EmptyPolicyPath);



                    if (PolicyToAddLogsTo is not null)
                    {

                        // Backup any possible Macros so they won't be lost during merge operations
                        var MacrosBackup = Macros.Backup(PolicyToAddLogsTo);

                        // Set policy name and reset the policy ID of our new policy
                        string supplementalPolicyID = SetCiPolicyInfo.Set(EmptyPolicyPath, true, policyName, null, null);

                        // Remove all policy rule options prior to merging the policies since we don't need to add/remove any policy rule options to/from the user input policy
                        CiRuleOptions.Set(filePath: EmptyPolicyPath, RemoveAll: true);

                        // Merge the created policy with the user-selected policy which will result in adding the new rules to it
                        SiPolicy.Merger.Merge(PolicyToAddLogsTo, [EmptyPolicyPath]);

                        UpdateHvciOptions.Update(PolicyToAddLogsTo);

                        // Restore any possible Macros
                        Macros.Restore(PolicyToAddLogsTo, MacrosBackup);


                        // If user selected to deploy the policy
                        if (DeployAtTheEnd)
                        {

                            string CIPPath = Path.Combine(stagingArea.FullName, $"{supplementalPolicyID}.cip");

                            PolicyToCIPConverter.Convert(PolicyToAddLogsTo, CIPPath);

                            CiToolHelper.UpdatePolicy(CIPPath);

                        }
                    }

                    else if (BasePolicyXMLFile is not null)
                    {
                        string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{policyName}.xml");

                        // Instantiate the user selected Base policy - To get its BasePolicyID
                        CodeIntegrityPolicy codeIntegrityPolicy = new(BasePolicyXMLFile, null);

                        // Set the BasePolicyID of our new policy to the one from user selected policy
                        string supplementalPolicyID = SetCiPolicyInfo.Set(EmptyPolicyPath, true, policyName, codeIntegrityPolicy.BasePolicyID, null);

                        // Configure policy rule options
                        CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental);

                        // Set policy version
                        SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

                        // Copying the policy file to the User Config directory - outside of the temporary staging area
                        File.Copy(EmptyPolicyPath, OutputPath, true);


                        // If user selected to deploy the policy
                        if (DeployAtTheEnd)
                        {

                            string CIPPath = Path.Combine(stagingArea.FullName, $"{supplementalPolicyID}.cip");

                            PolicyToCIPConverter.Convert(OutputPath, CIPPath);

                            CiToolHelper.UpdatePolicy(CIPPath);

                        }

                    }
                    else if (BasePolicyGUID is not null)
                    {
                        string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{policyName}.xml");


                        // Set the BasePolicyID of our new policy to the one supplied by user
                        string supplementalPolicyID = SetCiPolicyInfo.Set(EmptyPolicyPath, true, policyName, BasePolicyGUID.ToString(), null);


                        // Configure policy rule options
                        CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental);


                        // Set policy version
                        SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

                        // Copying the policy file to the User Config directory - outside of the temporary staging area
                        File.Copy(EmptyPolicyPath, OutputPath, true);


                        // If user selected to deploy the policy
                        if (DeployAtTheEnd)
                        {

                            string CIPPath = Path.Combine(stagingArea.FullName, $"{supplementalPolicyID}.cip");

                            PolicyToCIPConverter.Convert(OutputPath, CIPPath);

                            CiToolHelper.UpdatePolicy(CIPPath);

                        }

                    }


                });

            }

            finally
            {

                // Enable the policy creator button again
                CreatePolicyButton.IsEnabled = true;


                // enable the scan logs button again
                ScanLogs.IsEnabled = true;

                // Display the progress ring on the ScanLogs button
                ScanLogsProgressRing.IsActive = false;
                ScanLogsProgressRing.Visibility = Visibility.Collapsed;

            }

        }


        /// <summary>
        /// Scan level selection event handler for ComboBox
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        /// <exception cref="InvalidOperationException"></exception>
        private void ScanLevelComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (ScanLevelComboBox.SelectedItem is ComboBoxItem selectedItem)
            {
                string selectedText = selectedItem.Content.ToString()!;

                if (!Enum.TryParse(selectedText, out scanLevel))
                {
                    throw new InvalidOperationException($"{selectedText} is not a valid Scan Level");
                }
            }
        }

    }
}
