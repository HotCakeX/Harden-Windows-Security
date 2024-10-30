using CommunityToolkit.WinUI.Controls;
using CommunityToolkit.WinUI.UI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;
using System;

namespace WDACConfig.Pages
{
    public sealed partial class Simulation : Page
    {
        public ObservableCollection<SimulationOutput> SimulationOutputs { get; set; }
        private List<SimulationOutput> AllSimulationOutputs; // Store all outputs for searching
        private List<string> filePaths; // For selected file paths
        private List<string> folderPaths; // For selected folder paths
        private string? xmlFilePath; // For selected XML file path
        private List<string> catRootPaths; // For selected Cat Root paths

        public Simulation()
        {
            this.InitializeComponent();
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Enabled;

            SimulationOutputs = [];
            AllSimulationOutputs = [];
            filePaths = [];
            folderPaths = [];
            catRootPaths = [];
        }

        // Event handler for the Begin Simulation button
        private async void BeginSimulationButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                // Collect values from UI elements
                bool noCatRootScanning = (NoCatRootScanningToggle.IsChecked == true);
                double radialGaugeValue = ScalabilityRadialGauge.Value; // Value from radial gauge
                bool CSVOutput = (CSVOutputToggle.IsChecked == true);

                BeginSimulationButton.IsEnabled = false;
                ScalabilityRadialGauge.IsEnabled = false;

                // Run the simulation
                var result = await Task.Run(() =>
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
                foreach (var entry in result)
                {
                    var simOutput = entry.Value;

                    var simulationOutput = new SimulationOutput(
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
            string? selectedFile = FileSystemPicker.ShowFilePicker();
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
            if (selectedFiles != null && selectedFiles.Count != 0)
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
            if (selectedCatRoots != null && selectedCatRoots.Count != 0)
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
        }

        // Event handler for the SearchBox text change
        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            string searchTerm = SearchBox.Text.Trim().ToLowerInvariant();

            // Perform a case-insensitive search in all relevant fields
            List<SimulationOutput> filteredResults = AllSimulationOutputs.Where(output =>
                (output.Path != null && output.Path.Contains(searchTerm, StringComparison.InvariantCultureIgnoreCase)) ||
                (output.Source != null && output.Source.Contains(searchTerm, StringComparison.InvariantCultureIgnoreCase)) ||
                (output.MatchCriteria != null && output.MatchCriteria.Contains(searchTerm, StringComparison.InvariantCultureIgnoreCase)) ||
                (output.SpecificFileNameLevelMatchCriteria != null && output.SpecificFileNameLevelMatchCriteria.Contains(searchTerm, StringComparison.InvariantCultureIgnoreCase)) ||
                (output.CertSubjectCN != null && output.CertSubjectCN.Contains(searchTerm, StringComparison.InvariantCultureIgnoreCase)) ||
                (output.SignerName != null && output.SignerName.Contains(searchTerm, StringComparison.InvariantCultureIgnoreCase)) ||
                (output.FilePath != null && output.FilePath.Contains(searchTerm, StringComparison.InvariantCultureIgnoreCase))
            ).ToList();


            // Update the ObservableCollection on the UI thread with the filtered results
            SimulationOutputs.Clear();
            foreach (var result in filteredResults)
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
                    SimulationOutputs = new ObservableCollection<SimulationOutput>(
                        AllSimulationOutputs.OrderBy(output => !output.IsAuthorized)
                    );

                    // Set the column direction to Descending
                    e.Column.SortDirection = DataGridSortDirection.Descending;
                }
                else
                {
                    // Ascending: First False, then True
                    SimulationOutputs = new ObservableCollection<SimulationOutput>(
                        AllSimulationOutputs.OrderBy(output => output.IsAuthorized)
                    );
                    e.Column.SortDirection = DataGridSortDirection.Ascending;
                }

                // Update the ItemsSource of the DataGrid
                SimulationDataGrid.ItemsSource = SimulationOutputs;

                // Clear SortDirection for other columns
                foreach (var column in SimulationDataGrid.Columns)
                {
                    if (column != e.Column)
                    {
                        column.SortDirection = null;
                    }
                }
            }
        }

    }
}
