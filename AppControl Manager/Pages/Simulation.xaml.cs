using CommunityToolkit.WinUI.Controls;
using CommunityToolkit.WinUI.UI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Navigation;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Windows.ApplicationModel.DataTransfer;

namespace WDACConfig.Pages
{
    public sealed partial class Simulation : Page
    {
        public ObservableCollection<SimulationOutput> SimulationOutputs { get; set; }
        private readonly List<SimulationOutput> AllSimulationOutputs; // Store all outputs for searching
        private List<string> filePaths; // For selected file paths
        private readonly List<string> folderPaths; // For selected folder paths
        private string? xmlFilePath; // For selected XML file path
        private List<string> catRootPaths; // For selected Cat Root paths

        public Simulation()
        {
            this.InitializeComponent();
            this.NavigationCacheMode = NavigationCacheMode.Enabled;

            SimulationOutputs = [];
            AllSimulationOutputs = [];
            filePaths = [];
            folderPaths = [];
            catRootPaths = [];

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
            SimulationDataGrid.ItemsSource = SimulationOutputs;
        }

        protected override void OnNavigatedFrom(NavigationEventArgs e)
        {
            base.OnNavigatedFrom(e);
            SimulationDataGrid.ItemsSource = null;
        }

        #endregion




        // Event handler for the Begin Simulation button
        private async void BeginSimulationButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Collect values from UI elements
                bool noCatRootScanning = (NoCatRootScanningToggle.IsChecked);
                double radialGaugeValue = ScalabilityRadialGauge.Value; // Value from radial gauge
                bool CSVOutput = (CSVOutputToggle.IsChecked);

                BeginSimulationButton.IsEnabled = false;
                ScalabilityRadialGauge.IsEnabled = false;

                // Run the simulation
                ConcurrentDictionary<string, SimulationOutput> result = await Task.Run(() =>
                {
                    return InvokeWDACSimulation.Invoke(
                        filePaths,
                        folderPaths,
                        xmlFilePath,
                        noCatRootScanning,
                        CSVOutput,
                        catRootPaths,
                        (ushort)radialGaugeValue,
                        SimulationProgressBar
                    );
                });

                // Clear the current ObservableCollection and backup the full data set
                SimulationOutputs.Clear();
                AllSimulationOutputs.Clear();

                // Update the TextBox with the total count of files
                TotalCountOfTheFilesTextBox.Text = result.Count.ToString(CultureInfo.InvariantCulture);

                // Update the ObservableCollection on the UI thread
                foreach (KeyValuePair<string, SimulationOutput> entry in result)
                {
                    SimulationOutput simOutput = entry.Value;

                    SimulationOutput simulationOutput = new(
                        simOutput.Path,
                        simOutput.Source,
                        simOutput.IsAuthorized,
                        simOutput.SignerID,
                        simOutput.SignerName,
                        simOutput.SignerCertRoot,
                        simOutput.SignerCertPublisher,
                        simOutput.SignerScope,
                        simOutput.SignerFileAttributeIDs,
                        simOutput.MatchCriteria,
                        simOutput.SpecificFileNameLevelMatchCriteria,
                        simOutput.CertSubjectCN,
                        simOutput.CertIssuerCN,
                        simOutput.CertNotAfter,
                        simOutput.CertTBSValue,
                        simOutput.FilePath
                    );

                    // Add to the full list and observable collection
                    AllSimulationOutputs.Add(simulationOutput);

                    // Add to the ObservableCollection bound to the UI
                    _ = DispatcherQueue.TryEnqueue(() =>
                    {
                        SimulationOutputs.Add(simulationOutput);
                    });
                }
            }
            finally
            {
                BeginSimulationButton.IsEnabled = true;
                ScalabilityRadialGauge.IsEnabled = true;
            }
        }

        // Event handler for the Select XML File button
        private void SelectXmlFileButton_Click(object sender, RoutedEventArgs e)
        {
            string? selectedFile = FileSystemPicker.ShowFilePicker(
            "Select an XML file",
            ("XML Files", "*.xml"));

            if (!string.IsNullOrEmpty(selectedFile))
            {
                // Store the selected XML file path
                xmlFilePath = selectedFile;

                // Update the TextBox with the selected XML file path
                XmlFilePathTextBox.Text = selectedFile;
            }
        }

        // Event handler for the Select Files button
        private void SelectFilesButton_Click(object sender, RoutedEventArgs e)
        {
            List<string>? selectedFiles = FileSystemPicker.ShowMultiFilePicker();
            if (selectedFiles is not null && selectedFiles.Count != 0)
            {
                filePaths = [.. selectedFiles];
            }
        }

        // Event handler for the Select Folders button
        private void SelectFoldersButton_Click(object sender, RoutedEventArgs e)
        {
            string? selectedFolder = FileSystemPicker.ShowDirectoryPicker();
            if (!string.IsNullOrEmpty(selectedFolder))
            {
                folderPaths.Add(selectedFolder);
            }
        }

        // Event handler for the Cat Root Paths button
        private void CatRootPathsButton_Click(object sender, RoutedEventArgs e)
        {
            List<string>? selectedCatRoots = FileSystemPicker.ShowMultiFilePicker();
            if (selectedCatRoots is not null && selectedCatRoots.Count != 0)
            {
                catRootPaths = [.. selectedCatRoots];
            }
        }

        // Event handler for RadialGauge ValueChanged
        private void ScalabilityRadialGauge_ValueChanged(object sender, RangeBaseValueChangedEventArgs e)
        {
            if (sender is RadialGauge gauge)
            {
                // Update the button content with the current value of the gauge
                ScalabilityButton.Content = $"Scalability: {gauge.Value:N0}";
            }
        }

        // Event handler for the Clear Data button
        private void ClearDataButton_Click(object sender, RoutedEventArgs e)
        {
            // Clear the ObservableCollection
            SimulationOutputs.Clear();
            // Clear the full data
            AllSimulationOutputs.Clear();

            // set the total count to 0 after clearing all the data
            TotalCountOfTheFilesTextBox.Text = "0";
        }

        // Event handler for the SearchBox text change
        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            string searchTerm = SearchBox.Text.Trim().ToLowerInvariant();

            // Perform a case-insensitive search in all relevant fields
            List<SimulationOutput> filteredResults = AllSimulationOutputs.Where(output =>
                (output.Path is not null && output.Path.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                (output.Source is not null && output.Source.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                (output.MatchCriteria is not null && output.MatchCriteria.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                (output.SpecificFileNameLevelMatchCriteria is not null && output.SpecificFileNameLevelMatchCriteria.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                (output.CertSubjectCN is not null && output.CertSubjectCN.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                (output.SignerName is not null && output.SignerName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
                (output.FilePath is not null && output.FilePath.Contains(searchTerm, StringComparison.OrdinalIgnoreCase))
            ).ToList();


            // Update the ObservableCollection on the UI thread with the filtered results
            SimulationOutputs.Clear();
            foreach (SimulationOutput result in filteredResults)
            {
                SimulationOutputs.Add(result);
            }
        }


        // https://learn.microsoft.com/en-us/windows/communitytoolkit/controls/datagrid_guidance/group_sort_filter

        // Column sorting logic for the entire DataGrid
        private void SimulationDataGrid_Sorting(object sender, DataGridColumnEventArgs e)
        {
            // Check if the column being sorted is the "IsAuthorized" column
            if (string.Equals(e.Column.Tag?.ToString(), "IsAuthorized", StringComparison.OrdinalIgnoreCase))
            {
                // Perform the sorting based on the current SortDirection (ascending or descending)
                // At first it is null since no direction has been chosen for the column
                if (e.Column.SortDirection is null || e.Column.SortDirection is DataGridSortDirection.Ascending)
                {
                    // Descending: First True, then False
                    SimulationOutputs = [.. AllSimulationOutputs.OrderBy(output => !output.IsAuthorized)];

                    // Set the column direction to Descending
                    e.Column.SortDirection = DataGridSortDirection.Descending;
                }
                else
                {
                    // Ascending: First False, then True
                    SimulationOutputs = [.. AllSimulationOutputs.OrderBy(output => output.IsAuthorized)];
                    e.Column.SortDirection = DataGridSortDirection.Ascending;
                }

                // Update the ItemsSource of the DataGrid
                SimulationDataGrid.ItemsSource = SimulationOutputs;

                // Clear SortDirection for other columns
                foreach (DataGridColumn column in SimulationDataGrid.Columns)
                {
                    if (column != e.Column)
                    {
                        column.SortDirection = null;
                    }
                }
            }
        }





        /// <summary>
        /// Populates the "Copy Individual Items" submenu in the flyout when the DataGrid is loaded.
        /// </summary>
        private void SimulationDataGrid_Loaded(object sender, RoutedEventArgs e)
        {
            if (CopyIndividualItemsSubMenu is null)
            {
                return;
            }

            // Clear any existing items to avoid duplicates if reloaded
            CopyIndividualItemsSubMenu.Items.Clear();

            // Define headers and their associated click events for individual copy actions
            Dictionary<string, RoutedEventHandler> copyActions = new()
            {
                { "Path", CopyPath_Click },
                { "Source", CopySource_Click },
                { "Is Authorized", CopyIsAuthorized_Click },
                { "Match Criteria", CopyMatchCriteria_Click },
                { "Specific File Name Criteria", CopySpecificFileNameCriteria_Click },
                { "Signer ID", CopySignerID_Click },
                { "Signer Name", CopySignerName_Click },
                { "Signer Cert Root", CopySignerCertRoot_Click },
                { "Signer Cert Publisher", CopySignerCertPublisher_Click },
                { "Signer Scope", CopySignerScope_Click },
                { "Cert Subject CN", CopyCertSubjectCN_Click },
                { "Cert Issuer CN", CopyCertIssuerCN_Click },
                { "Cert Not After", CopyCertNotAfter_Click },
                { "Cert TBS Value", CopyCertTBSValue_Click },
                { "File Path", CopyFilePath_Click }
            };

            // Add each column header as an individual copy option in the flyout submenu
            foreach (KeyValuePair<string, RoutedEventHandler> action in copyActions)
            {
                // Create a new menu item for each column header
                MenuFlyoutItem menuItem = new() { Text = $"Copy {action.Key}" };

                // Set the click event for the menu item
                menuItem.Click += action.Value;

                // Add the menu item to the submenu
                CopyIndividualItemsSubMenu.Items.Add(menuItem);
            }
        }

        // Event handlers for each column copy action
        private void CopyPath_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard(nameof(SimulationOutput.Path));
        private void CopySource_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard(nameof(SimulationOutput.Source));
        private void CopyIsAuthorized_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard(nameof(SimulationOutput.IsAuthorized));
        private void CopyMatchCriteria_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard(nameof(SimulationOutput.MatchCriteria));
        private void CopySpecificFileNameCriteria_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard(nameof(SimulationOutput.SpecificFileNameLevelMatchCriteria));
        private void CopySignerID_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard(nameof(SimulationOutput.SignerID));
        private void CopySignerName_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard(nameof(SimulationOutput.SignerName));
        private void CopySignerCertRoot_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard(nameof(SimulationOutput.SignerCertRoot));
        private void CopySignerCertPublisher_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard(nameof(SimulationOutput.SignerCertPublisher));
        private void CopySignerScope_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard(nameof(SimulationOutput.SignerScope));
        private void CopyCertSubjectCN_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard(nameof(SimulationOutput.CertSubjectCN));
        private void CopyCertIssuerCN_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard(nameof(SimulationOutput.CertIssuerCN));
        private void CopyCertNotAfter_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard(nameof(SimulationOutput.CertNotAfter));
        private void CopyCertTBSValue_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard(nameof(SimulationOutput.CertTBSValue));
        private void CopyFilePath_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard(nameof(SimulationOutput.FilePath));

        /// <summary>
        /// Copies the specified property of the selected row to the clipboard.
        /// </summary>
        /// <param name="propertyName">Name of the property to copy</param>
        private void CopyPropertyToClipboard(string propertyName)
        {
            // Get the currently selected item in the DataGrid
            if (SimulationDataGrid.SelectedItem is not SimulationOutput selectedItem)
            {
                return;
            }

            // Retrieve the property value directly based on the property name
            string? propertyValue = propertyName switch
            {
                nameof(SimulationOutput.Path) => selectedItem.Path,
                nameof(SimulationOutput.Source) => selectedItem.Source,
                nameof(SimulationOutput.IsAuthorized) => selectedItem.IsAuthorized.ToString(),
                nameof(SimulationOutput.MatchCriteria) => selectedItem.MatchCriteria,
                nameof(SimulationOutput.SpecificFileNameLevelMatchCriteria) => selectedItem.SpecificFileNameLevelMatchCriteria,
                nameof(SimulationOutput.SignerID) => selectedItem.SignerID,
                nameof(SimulationOutput.SignerName) => selectedItem.SignerName,
                nameof(SimulationOutput.SignerCertRoot) => selectedItem.SignerCertRoot,
                nameof(SimulationOutput.SignerCertPublisher) => selectedItem.SignerCertPublisher,
                nameof(SimulationOutput.SignerScope) => selectedItem.SignerScope,
                nameof(SimulationOutput.CertSubjectCN) => selectedItem.CertSubjectCN,
                nameof(SimulationOutput.CertIssuerCN) => selectedItem.CertIssuerCN,
                nameof(SimulationOutput.CertNotAfter) => selectedItem.CertNotAfter,
                nameof(SimulationOutput.CertTBSValue) => selectedItem.CertTBSValue,
                nameof(SimulationOutput.FilePath) => selectedItem.FilePath,
                _ => null
            };

            if (!string.IsNullOrEmpty(propertyValue))
            {
                DataPackage dataPackage = new();
                dataPackage.SetText(propertyValue);
                Clipboard.SetContent(dataPackage);
            }
        }


        /// <summary>
        /// Copies all column values of the selected row to the clipboard.
        /// </summary>
        private void SimulationDataGrid_CopyRow_Click(object sender, RoutedEventArgs e)
        {
            if (SimulationDataGrid.SelectedItem is not SimulationOutput selectedItem)
            {
                return;
            }

            string rowData = new StringBuilder()
                .AppendLine($"Path: {selectedItem.Path}")
                .AppendLine($"Source: {selectedItem.Source}")
                .AppendLine($"Is Authorized: {selectedItem.IsAuthorized}")
                .AppendLine($"Match Criteria: {selectedItem.MatchCriteria}")
                .AppendLine($"Specific File Name Criteria: {selectedItem.SpecificFileNameLevelMatchCriteria}")
                .AppendLine($"Signer ID: {selectedItem.SignerID}")
                .AppendLine($"Signer Name: {selectedItem.SignerName}")
                .AppendLine($"Signer Cert Root: {selectedItem.SignerCertRoot}")
                .AppendLine($"Signer Cert Publisher: {selectedItem.SignerCertPublisher}")
                .AppendLine($"Signer Scope: {selectedItem.SignerScope}")
                .AppendLine($"Cert Subject CN: {selectedItem.CertSubjectCN}")
                .AppendLine($"Cert Issuer CN: {selectedItem.CertIssuerCN}")
                .AppendLine($"Cert Not After: {selectedItem.CertNotAfter}")
                .AppendLine($"Cert TBS Value: {selectedItem.CertTBSValue}")
                .AppendLine($"File Path: {selectedItem.FilePath}")
                .ToString();

            DataPackage dataPackage = new();
            dataPackage.SetText(rowData);
            Clipboard.SetContent(dataPackage);
        }


    }
}
