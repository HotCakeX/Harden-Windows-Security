using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using AppControlManager.IntelGathering;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;
using WinRT;

namespace AppControlManager.Pages;

// Since the columns for data in the ItemTemplate use "Binding" instead of "x:Bind", we need to use [GeneratedBindableCustomProperty] for them to work properly
[GeneratedBindableCustomProperty]
public sealed partial class StrictKernelPolicyScanResults : Page, INotifyPropertyChanged
{

	private static StrictKernelPolicyScanResults? _instance;

	internal ListView UIListView { get; private set; }

	#region LISTVIEW IMPLEMENTATIONS

	public event PropertyChangedEventHandler? PropertyChanged;
	private void OnPropertyChanged(string propertyName) =>
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

	// Properties to hold each columns' width.
	private GridLength _columnWidth1;
	public GridLength ColumnWidth1
	{
		get => _columnWidth1;
		set { _columnWidth1 = value; OnPropertyChanged(nameof(ColumnWidth1)); }
	}

	private GridLength _columnWidth2;
	public GridLength ColumnWidth2
	{
		get => _columnWidth2;
		set { _columnWidth2 = value; OnPropertyChanged(nameof(ColumnWidth2)); }
	}

	private GridLength _columnWidth3;
	public GridLength ColumnWidth3
	{
		get => _columnWidth3;
		set { _columnWidth3 = value; OnPropertyChanged(nameof(ColumnWidth3)); }
	}

	private GridLength _columnWidth4;
	public GridLength ColumnWidth4
	{
		get => _columnWidth4;
		set { _columnWidth4 = value; OnPropertyChanged(nameof(ColumnWidth4)); }
	}

	private GridLength _columnWidth5;
	public GridLength ColumnWidth5
	{
		get => _columnWidth5;
		set { _columnWidth5 = value; OnPropertyChanged(nameof(ColumnWidth5)); }
	}

	private GridLength _columnWidth6;
	public GridLength ColumnWidth6
	{
		get => _columnWidth6;
		set { _columnWidth6 = value; OnPropertyChanged(nameof(ColumnWidth6)); }
	}

	private GridLength _columnWidth7;
	public GridLength ColumnWidth7
	{
		get => _columnWidth7;
		set { _columnWidth7 = value; OnPropertyChanged(nameof(ColumnWidth7)); }
	}

	private GridLength _columnWidth8;
	public GridLength ColumnWidth8
	{
		get => _columnWidth8;
		set { _columnWidth8 = value; OnPropertyChanged(nameof(ColumnWidth8)); }
	}

	private GridLength _columnWidth9;
	public GridLength ColumnWidth9
	{
		get => _columnWidth9;
		set { _columnWidth9 = value; OnPropertyChanged(nameof(ColumnWidth9)); }
	}

	private GridLength _columnWidth10;
	public GridLength ColumnWidth10
	{
		get => _columnWidth10;
		set { _columnWidth10 = value; OnPropertyChanged(nameof(ColumnWidth10)); }
	}

	private GridLength _columnWidth11;
	public GridLength ColumnWidth11
	{
		get => _columnWidth11;
		set { _columnWidth11 = value; OnPropertyChanged(nameof(ColumnWidth11)); }
	}

	private GridLength _columnWidth12;
	public GridLength ColumnWidth12
	{
		get => _columnWidth12;
		set { _columnWidth12 = value; OnPropertyChanged(nameof(ColumnWidth12)); }
	}

	private GridLength _columnWidth13;
	public GridLength ColumnWidth13
	{
		get => _columnWidth13;
		set { _columnWidth13 = value; OnPropertyChanged(nameof(ColumnWidth13)); }
	}

	private GridLength _columnWidth14;
	public GridLength ColumnWidth14
	{
		get => _columnWidth14;
		set { _columnWidth14 = value; OnPropertyChanged(nameof(ColumnWidth14)); }
	}

	private GridLength _columnWidth15;
	public GridLength ColumnWidth15
	{
		get => _columnWidth15;
		set { _columnWidth15 = value; OnPropertyChanged(nameof(ColumnWidth15)); }
	}

	private GridLength _columnWidth16;
	public GridLength ColumnWidth16
	{
		get => _columnWidth16;
		set { _columnWidth16 = value; OnPropertyChanged(nameof(ColumnWidth16)); }
	}

	private GridLength _columnWidth17;
	public GridLength ColumnWidth17
	{
		get => _columnWidth17;
		set { _columnWidth17 = value; OnPropertyChanged(nameof(ColumnWidth17)); }
	}

	private GridLength _columnWidth18;
	public GridLength ColumnWidth18
	{
		get => _columnWidth18;
		set { _columnWidth18 = value; OnPropertyChanged(nameof(ColumnWidth18)); }
	}

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidths()
	{

		// Measure header text widths first.
		double maxWidth1 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("FileNameHeader/Text"));
		double maxWidth2 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("SignatureStatusHeader/Text"));
		double maxWidth3 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("OriginalFileNameHeader/Text"));
		double maxWidth4 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("InternalNameHeader/Text"));
		double maxWidth5 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("FileDescriptionHeader/Text"));
		double maxWidth6 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("ProductNameHeader/Text"));
		double maxWidth7 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("FileVersionHeader/Text"));
		double maxWidth8 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("PackageFamilyNameHeader/Text"));
		double maxWidth9 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA256HashHeader/Text"));
		double maxWidth10 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA1HashHeader/Text"));
		double maxWidth11 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("SigningScenarioHeader/Text"));
		double maxWidth12 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("FilePathHeader/Text"));
		double maxWidth13 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA1PageHashHeader/Text"));
		double maxWidth14 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA256PageHashHeader/Text"));
		double maxWidth15 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("HasWHQLSignerHeader/Text"));
		double maxWidth16 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("FilePublishersHeader/Text"));
		double maxWidth17 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("IsECCSignedHeader/Text"));
		double maxWidth18 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("OpusDataHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (FileIdentity item in CreateSupplementalPolicy.Instance.ScanResults)
		{
			double w1 = ListViewUIHelpers.MeasureTextWidth(item.FileName);
			if (w1 > maxWidth1) maxWidth1 = w1;

			double w2 = ListViewUIHelpers.MeasureTextWidth(item.SignatureStatus.ToString());
			if (w2 > maxWidth2) maxWidth2 = w2;

			double w3 = ListViewUIHelpers.MeasureTextWidth(item.OriginalFileName);
			if (w3 > maxWidth3) maxWidth3 = w3;

			double w4 = ListViewUIHelpers.MeasureTextWidth(item.InternalName);
			if (w4 > maxWidth4) maxWidth4 = w4;

			double w5 = ListViewUIHelpers.MeasureTextWidth(item.FileDescription);
			if (w5 > maxWidth5) maxWidth5 = w5;

			double w6 = ListViewUIHelpers.MeasureTextWidth(item.ProductName);
			if (w6 > maxWidth6) maxWidth6 = w6;

			double w7 = ListViewUIHelpers.MeasureTextWidth(item.FileVersion?.ToString());
			if (w7 > maxWidth7) maxWidth7 = w7;

			double w8 = ListViewUIHelpers.MeasureTextWidth(item.PackageFamilyName);
			if (w8 > maxWidth8) maxWidth8 = w8;

			double w9 = ListViewUIHelpers.MeasureTextWidth(item.SHA256Hash);
			if (w9 > maxWidth9) maxWidth9 = w9;

			double w10 = ListViewUIHelpers.MeasureTextWidth(item.SHA1Hash);
			if (w10 > maxWidth10) maxWidth10 = w10;

			double w11 = ListViewUIHelpers.MeasureTextWidth(item.SISigningScenario.ToString());
			if (w11 > maxWidth11) maxWidth11 = w11;

			double w12 = ListViewUIHelpers.MeasureTextWidth(item.FilePath);
			if (w12 > maxWidth12) maxWidth12 = w12;

			double w13 = ListViewUIHelpers.MeasureTextWidth(item.SHA1PageHash);
			if (w13 > maxWidth13) maxWidth13 = w13;

			double w14 = ListViewUIHelpers.MeasureTextWidth(item.SHA256PageHash);
			if (w14 > maxWidth14) maxWidth14 = w14;

			double w15 = ListViewUIHelpers.MeasureTextWidth(item.HasWHQLSigner.ToString());
			if (w15 > maxWidth15) maxWidth15 = w15;

			double w16 = ListViewUIHelpers.MeasureTextWidth(item.FilePublishersToDisplay);
			if (w16 > maxWidth16) maxWidth16 = w16;

			double w17 = ListViewUIHelpers.MeasureTextWidth(item.IsECCSigned.ToString());
			if (w17 > maxWidth17) maxWidth17 = w17;

			double w18 = ListViewUIHelpers.MeasureTextWidth(item.Opus);
			if (w18 > maxWidth18) maxWidth18 = w18;
		}

		// Set the column width properties.
		ColumnWidth1 = new GridLength(maxWidth1);
		ColumnWidth2 = new GridLength(maxWidth2);
		ColumnWidth3 = new GridLength(maxWidth3);
		ColumnWidth4 = new GridLength(maxWidth4);
		ColumnWidth5 = new GridLength(maxWidth5);
		ColumnWidth6 = new GridLength(maxWidth6);
		ColumnWidth7 = new GridLength(maxWidth7);
		ColumnWidth8 = new GridLength(maxWidth8);
		ColumnWidth9 = new GridLength(maxWidth9);
		ColumnWidth10 = new GridLength(maxWidth10);
		ColumnWidth11 = new GridLength(maxWidth11);
		ColumnWidth12 = new GridLength(maxWidth12);
		ColumnWidth13 = new GridLength(maxWidth13);
		ColumnWidth14 = new GridLength(maxWidth14);
		ColumnWidth15 = new GridLength(maxWidth15);
		ColumnWidth16 = new GridLength(maxWidth16);
		ColumnWidth17 = new GridLength(maxWidth17);
		ColumnWidth18 = new GridLength(maxWidth18);
	}


	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	/// <param name="sender">The event sender.</param>
	/// <param name="e">The event arguments.</param>
	private void ListViewFlyoutMenuCopy_Click(object sender, RoutedEventArgs e)
	{
		// Check if there are selected items in the ListView
		if (FileIdentitiesListView.SelectedItems.Count > 0)
		{
			// Initialize StringBuilder to store all selected rows' data with labels
			StringBuilder dataBuilder = new();

			// Loop through each selected item in the ListView
			foreach (var selectedItem in FileIdentitiesListView.SelectedItems)
			{
				if (selectedItem is FileIdentity obj)

					// Append each row's formatted data to the StringBuilder
					_ = dataBuilder.AppendLine(ListViewUIHelpers.ConvertRowToText(obj));

				// Add a separator between rows for readability in multi-row copies
				_ = dataBuilder.AppendLine(new string('-', 50));
			}

			// Create a DataPackage to hold the text data
			DataPackage dataPackage = new();

			// Set the formatted text as the content of the DataPackage
			dataPackage.SetText(dataBuilder.ToString());

			// Copy the DataPackage content to the clipboard
			Clipboard.SetContent(dataPackage);
		}
	}


	// Click event handlers for each property
	private void CopyFileName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FileName);
	private void CopySignatureStatus_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SignatureStatus.ToString());
	private void CopyOriginalFileName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.OriginalFileName);
	private void CopyInternalName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.InternalName);
	private void CopyFileDescription_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FileDescription);
	private void CopyProductName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.ProductName);
	private void CopyFileVersion_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FileVersion?.ToString());
	private void CopyPackageFamilyName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.PackageFamilyName);
	private void CopySHA256Hash_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SHA256Hash);
	private void CopySHA1Hash_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SHA1Hash);
	private void CopySigningScenario_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SISigningScenario.ToString());
	private void CopyFilePath_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FilePath);
	private void CopySHA1PageHash_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SHA1PageHash);
	private void CopySHA256PageHash_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SHA256PageHash);
	private void CopyHasWHQLSigner_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.HasWHQLSigner.ToString());
	private void CopyFilePublishers_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FilePublishersToDisplay);
	private void CopyIsECCSigned_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.IsECCSigned.ToString());
	private void CopyOpusData_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.Opus);

	/// <summary>
	/// Helper method to copy a specified property to clipboard without reflection
	/// </summary>
	/// <param name="getProperty">Function that retrieves the desired property value as a string</param>
	private void CopyToClipboard(Func<FileIdentity, string?> getProperty)
	{
		if (FileIdentitiesListView.SelectedItem is FileIdentity selectedItem)
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

	// Event handlers for each sort button
	private void ColumnSortingButton_FileName_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.FileName);
	}
	private void ColumnSortingButton_SignatureStatus_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.SignatureStatus);
	}
	private void ColumnSortingButton_OriginalFileName_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.OriginalFileName);
	}
	private void ColumnSortingButton_InternalName_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.InternalName);
	}
	private void ColumnSortingButton_FileDescription_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.FileDescription);
	}
	private void ColumnSortingButton_ProductName_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.ProductName);
	}
	private void ColumnSortingButton_FileVersion_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.FileVersion);
	}
	private void ColumnSortingButton_PackageFamilyName_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.PackageFamilyName);
	}
	private void ColumnSortingButton_SHA256Hash_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.SHA256Hash);
	}
	private void ColumnSortingButton_SHA1Hash_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.SHA1Hash);
	}
	private void ColumnSortingButton_SigningScenario_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.SISigningScenario);
	}
	private void ColumnSortingButton_FilePath_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.FilePath);
	}
	private void ColumnSortingButton_SHA1PageHash_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.SHA1PageHash);
	}
	private void ColumnSortingButton_SHA256PageHash_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.SHA256PageHash);
	}
	private void ColumnSortingButton_HasWHQLSigner_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.HasWHQLSigner);
	}
	private void ColumnSortingButton_FilePublishers_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.FilePublishersToDisplay);
	}
	private void ColumnSortingButton_IsECCSigned_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.IsECCSigned);
	}
	private void ColumnSortingButton_OpusData_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.Opus);
	}

	/// <summary>
	/// Performs data sorting
	/// </summary>
	/// <typeparam name="T"></typeparam>
	/// <param name="keySelector"></param>
	private void SortColumn<T>(Func<FileIdentity, T> keySelector)
	{
		// Determine if a search filter is active.
		bool isSearchEmpty = string.IsNullOrWhiteSpace(SearchBox.Text);
		// Use either the full list (CreateSupplementalPolicy.Instance.ScanResultsList) or the current display list.
		List<FileIdentity> collectionToSort = isSearchEmpty ? CreateSupplementalPolicy.Instance.ScanResultsList : [.. CreateSupplementalPolicy.Instance.ScanResults];

		if (SortingDirectionToggle.IsChecked)
		{
			// Sort in descending order.
			CreateSupplementalPolicy.Instance.ScanResults = [.. collectionToSort.OrderByDescending(keySelector)];
		}
		else
		{
			// Sort in ascending order.
			CreateSupplementalPolicy.Instance.ScanResults = [.. collectionToSort.OrderBy(keySelector)];
		}

		// Refresh the ItemsSource so the UI updates.
		FileIdentitiesListView.ItemsSource = CreateSupplementalPolicy.Instance.ScanResults;
	}

	#endregion

	public StrictKernelPolicyScanResults()
	{
		this.InitializeComponent();

		UIListView = FileIdentitiesListView;

		// Assign this instance to the static field
		_instance = this;
	}

	// Public property to access the singleton instance from other classes
	public static StrictKernelPolicyScanResults Instance => _instance ?? throw new InvalidOperationException("StrictKernelPolicyScanResults is not initialized.");


	#region
	protected override void OnNavigatedTo(NavigationEventArgs e)
	{
		base.OnNavigatedTo(e);

		// Update the logs when user switches to this page
		UpdateTotalFiles();

		// Assign the ItemsSource of the ListView only once
		// We cannot do it after column width calculation because initialization is not guaranteed at that moment
		if (CreateSupplementalPolicy.Instance.StrictKernelModeDataProcessed)
		{
			CalculateColumnWidths();

			FileIdentitiesListView.ItemsSource = CreateSupplementalPolicy.Instance.ScanResults;

			CreateSupplementalPolicy.Instance.StrictKernelModeDataProcessed = false;
		}
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
		IEnumerable<FileIdentity> filteredResults = CreateSupplementalPolicy.Instance.ScanResultsList.AsEnumerable();

		// Apply the search filter if there is a non-empty search term
		if (!string.IsNullOrWhiteSpace(searchTerm))
		{

			// Filter results further to match the search term across multiple properties, case-insensitively
			filteredResults = filteredResults.Where(output =>
				(output.FileName is not null && output.FileName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.SignatureStatus.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.OriginalFileName is not null && output.OriginalFileName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.InternalName is not null && output.InternalName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FileDescription is not null && output.FileDescription.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.ProductName is not null && output.ProductName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FileVersion is not null && output.FileVersion.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.PackageFamilyName is not null && output.PackageFamilyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.SHA1PageHash is not null && output.SHA1PageHash.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.FilePath is not null && output.FilePath.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				(output.SHA256Hash is not null && output.SHA256Hash.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
				output.FilePublishersToDisplay.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				output.Opus.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)
			);
		}

		// Populate the ObservableCollection with the filtered results		
		CreateSupplementalPolicy.Instance.ScanResults = [.. filteredResults];

		// Explicitly set the ListView's ItemsSource to ensure the data refreshes
		FileIdentitiesListView.ItemsSource = CreateSupplementalPolicy.Instance.ScanResults;

		// Update any visual or text element showing the total logs count
		UpdateTotalFiles();
	}


	/// <summary>
	/// Event handler for the Clear Data button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void ClearDataButton_Click(object sender, RoutedEventArgs e)
	{
		CreateSupplementalPolicy.Instance.ScanResults.Clear();
		CreateSupplementalPolicy.Instance.ScanResultsList.Clear();

		UpdateTotalFiles(true);
	}


	/// <summary>
	/// Selects all of the displayed rows on the ListView
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SelectAll_Click(object sender, RoutedEventArgs e)
	{
		// Clear existing selections
		FileIdentitiesListView.SelectedItems.Clear();

		foreach (FileIdentity fileIdentity in CreateSupplementalPolicy.Instance.ScanResults)
		{
			FileIdentitiesListView.SelectedItems.Add(fileIdentity); // Select each item
		}
	}

	/// <summary>
	/// De-selects all of the displayed rows on the ListView
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void DeSelectAll_Click(object sender, RoutedEventArgs e)
	{
		FileIdentitiesListView.SelectedItems.Clear(); // Deselect all rows by clearing SelectedItems
	}

	/// <summary>
	/// Updates the total logs count displayed on the UI
	/// </summary>
	internal void UpdateTotalFiles(bool? Zero = null)
	{
		if (Zero == true)
		{
			TotalCountOfTheFilesTextBox.Text = $"Total files: 0";
		}
		else
		{
			TotalCountOfTheFilesTextBox.Text = $"Total files: {CreateSupplementalPolicy.Instance.ScanResults.Count}";
		}
	}

	/// <summary>
	/// Deletes the selected row from the results
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void ListViewFlyoutMenuDelete_Click(object sender, RoutedEventArgs e)
	{
		// Collect the selected items to delete
		List<FileIdentity> itemsToDelete = [.. FileIdentitiesListView.SelectedItems.Cast<FileIdentity>()];

		// Remove each selected item from the FileIdentities collection
		foreach (FileIdentity item in itemsToDelete)
		{
			_ = CreateSupplementalPolicy.Instance.ScanResults.Remove(item);
			_ = CreateSupplementalPolicy.Instance.ScanResultsList?.Remove(item);
		}

		UpdateTotalFiles();
	}


	#region Ensuring right-click on rows behaves better and normally on ListView

	// When right-clicking on an unselected row, first it becomes selected and then the context menu will be shown for the selected row
	// This is a much more expected behavior. Without this, the right-click would be meaningless on the ListView unless user left-clicks on the row first

	private void ListView_ContainerContentChanging(ListViewBase sender, ContainerContentChangingEventArgs args)
	{
		// When the container is being recycled, detach the handler.
		if (args.InRecycleQueue)
		{
			args.ItemContainer.RightTapped -= ListViewItem_RightTapped;
		}
		else
		{
			// Detach first to avoid multiple subscriptions, then attach the handler.
			args.ItemContainer.RightTapped -= ListViewItem_RightTapped;
			args.ItemContainer.RightTapped += ListViewItem_RightTapped;
		}
	}

	private void ListViewItem_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (sender is ListViewItem item)
		{
			// If the item is not already selected, clear previous selections and select this one.
			if (!item.IsSelected)
			{
				//clear for exclusive selection
				FileIdentitiesListView.SelectedItems.Clear();
				item.IsSelected = true;
			}
		}
	}

	#endregion


	/// <summary>
	/// CTRL + C shortcuts event handler
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void CtrlC_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		ListViewFlyoutMenuCopy_Click(sender, new RoutedEventArgs());
		args.Handled = true;
	}

}
