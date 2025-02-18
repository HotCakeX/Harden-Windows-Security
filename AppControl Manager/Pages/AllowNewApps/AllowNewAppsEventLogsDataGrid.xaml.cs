using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using AppControlManager.IntelGathering;
using AppControlManager.Others;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;
using WinRT;

namespace AppControlManager.Pages;

// Since the columns for data in the ItemTemplate use "Binding" instead of "x:Bind", we need to use [GeneratedBindableCustomProperty] for them to work properly
[GeneratedBindableCustomProperty]
public sealed partial class AllowNewAppsEventLogsDataGrid : Page, INotifyPropertyChanged
{

	// A static instance of the AllowNewAppsEventLogsDataGrid class which will hold the single, shared instance of the page
	private static AllowNewAppsEventLogsDataGrid? _instance;

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

	private GridLength _columnWidth19;
	public GridLength ColumnWidth19
	{
		get => _columnWidth19;
		set { _columnWidth19 = value; OnPropertyChanged(nameof(ColumnWidth19)); }
	}

	private GridLength _columnWidth20;
	public GridLength ColumnWidth20
	{
		get => _columnWidth20;
		set { _columnWidth20 = value; OnPropertyChanged(nameof(ColumnWidth20)); }
	}

	private GridLength _columnWidth21;
	public GridLength ColumnWidth21
	{
		get => _columnWidth21;
		set { _columnWidth21 = value; OnPropertyChanged(nameof(ColumnWidth21)); }
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
		double maxWidth2 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("TimeCreatedHeader/Text"));
		double maxWidth3 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("SignatureStatusHeader/Text"));
		double maxWidth4 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("ActionHeader/Text"));
		double maxWidth5 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("OriginalFileNameHeader/Text"));
		double maxWidth6 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("InternalNameHeader/Text"));
		double maxWidth7 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("FileDescriptionHeader/Text"));
		double maxWidth8 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("ProductNameHeader/Text"));
		double maxWidth9 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("FileVersionHeader/Text"));
		double maxWidth10 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("PackageFamilyNameHeader/Text"));
		double maxWidth11 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA256HashHeader/Text"));
		double maxWidth12 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA1HashHeader/Text"));
		double maxWidth13 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("SigningScenarioHeader/Text"));
		double maxWidth14 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("FilePathHeader/Text"));
		double maxWidth15 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA1PageHashHeader/Text"));
		double maxWidth16 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA256PageHashHeader/Text"));
		double maxWidth17 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("HasWHQLSignerHeader/Text"));
		double maxWidth18 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("FilePublishersHeader/Text"));
		double maxWidth19 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("OpusDataHeader/Text"));
		double maxWidth20 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("PolicyGUIDHeader/Text"));
		double maxWidth21 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("PolicyNameHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (FileIdentity item in AllowNewAppsStart.Instance.LocalFilesFileIdentities)
		{
			double w1 = ListViewUIHelpers.MeasureTextWidth(item.FileName);
			if (w1 > maxWidth1) maxWidth1 = w1;

			double w2 = ListViewUIHelpers.MeasureTextWidth(item.TimeCreated.ToString());
			if (w2 > maxWidth2) maxWidth2 = w2;

			double w3 = ListViewUIHelpers.MeasureTextWidth(item.SignatureStatus.ToString());
			if (w3 > maxWidth3) maxWidth3 = w3;

			double w4 = ListViewUIHelpers.MeasureTextWidth(item.Action.ToString());
			if (w4 > maxWidth4) maxWidth4 = w4;

			double w5 = ListViewUIHelpers.MeasureTextWidth(item.OriginalFileName);
			if (w5 > maxWidth5) maxWidth5 = w5;

			double w6 = ListViewUIHelpers.MeasureTextWidth(item.InternalName);
			if (w6 > maxWidth6) maxWidth6 = w6;

			double w7 = ListViewUIHelpers.MeasureTextWidth(item.FileDescription);
			if (w7 > maxWidth7) maxWidth7 = w7;

			double w8 = ListViewUIHelpers.MeasureTextWidth(item.ProductName);
			if (w8 > maxWidth8) maxWidth8 = w8;

			double w9 = ListViewUIHelpers.MeasureTextWidth(item.FileVersion?.ToString());
			if (w9 > maxWidth9) maxWidth9 = w9;

			double w10 = ListViewUIHelpers.MeasureTextWidth(item.PackageFamilyName);
			if (w10 > maxWidth10) maxWidth10 = w10;

			double w11 = ListViewUIHelpers.MeasureTextWidth(item.SHA256Hash);
			if (w11 > maxWidth11) maxWidth11 = w11;

			double w12 = ListViewUIHelpers.MeasureTextWidth(item.SHA1Hash);
			if (w12 > maxWidth12) maxWidth12 = w12;

			double w13 = ListViewUIHelpers.MeasureTextWidth(item.SISigningScenario.ToString());
			if (w13 > maxWidth13) maxWidth13 = w13;

			double w14 = ListViewUIHelpers.MeasureTextWidth(item.FilePath);
			if (w14 > maxWidth14) maxWidth14 = w14;

			double w15 = ListViewUIHelpers.MeasureTextWidth(item.SHA1PageHash);
			if (w15 > maxWidth15) maxWidth15 = w15;

			double w16 = ListViewUIHelpers.MeasureTextWidth(item.SHA256PageHash);
			if (w16 > maxWidth16) maxWidth16 = w16;

			double w17 = ListViewUIHelpers.MeasureTextWidth(item.HasWHQLSigner.ToString());
			if (w17 > maxWidth17) maxWidth17 = w17;

			double w18 = ListViewUIHelpers.MeasureTextWidth(item.FilePublishersToDisplay);
			if (w18 > maxWidth18) maxWidth18 = w18;

			double w19 = ListViewUIHelpers.MeasureTextWidth(item.Opus);
			if (w19 > maxWidth19) maxWidth19 = w19;

			double w20 = ListViewUIHelpers.MeasureTextWidth(item.PolicyGUID.ToString());
			if (w20 > maxWidth20) maxWidth20 = w20;

			double w21 = ListViewUIHelpers.MeasureTextWidth(item.PolicyName);
			if (w21 > maxWidth21) maxWidth21 = w21;
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
		ColumnWidth19 = new GridLength(maxWidth19);
		ColumnWidth20 = new GridLength(maxWidth20);
		ColumnWidth21 = new GridLength(maxWidth21);
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
		// Use either the full list (AllowNewAppsStart.Instance.EventLogsAllFileIdentities) or the current display list.
		var collectionToSort = isSearchEmpty ? AllowNewAppsStart.Instance.EventLogsAllFileIdentities : [.. AllowNewAppsStart.Instance.EventLogsFileIdentities];

		if (SortingDirectionToggle.IsChecked)
		{
			// Sort in descending order.
			AllowNewAppsStart.Instance.EventLogsFileIdentities = [.. collectionToSort.OrderByDescending(keySelector)];
		}
		else
		{
			// Sort in ascending order.
			AllowNewAppsStart.Instance.EventLogsFileIdentities = [.. collectionToSort.OrderBy(keySelector)];
		}

		// Refresh the ItemsSource so the UI updates.
		FileIdentitiesListView.ItemsSource = AllowNewAppsStart.Instance.EventLogsFileIdentities;
	}


	/// <summary>
	/// Converts the properties of a FileIdentity row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	/// <param name="row">The selected FileIdentity row from the ListView.</param>
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
	#endregion


	public AllowNewAppsEventLogsDataGrid()
	{
		this.InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Enabled;

		// Assign this instance to the static field
		_instance = this;

		UIListView = FileIdentitiesListView;
	}


	// Public property to access the singleton instance from other classes
	// It's okay it's nullable, null check will happen before accessing it
	public static AllowNewAppsEventLogsDataGrid Instance => _instance ?? throw new InvalidOperationException("AllowNewAppsEventLogsDataGrid is not initialized");

	#region
	protected override void OnNavigatedTo(NavigationEventArgs e)
	{
		base.OnNavigatedTo(e);
		FileIdentitiesListView.ItemsSource = AllowNewAppsStart.Instance.EventLogsFileIdentities;

		// Update the logs when user switches to this page
		UpdateTotalLogs();

		// Assign the ItemsSource of the ListView only once
		// We cannot do it after column width calculation because initialization is not guaranteed at that moment
		if (AllowNewAppsStart.Instance.EventLogsDataProcessed)
		{
			CalculateColumnWidths();

			FileIdentitiesListView.ItemsSource = AllowNewAppsStart.Instance.EventLogsFileIdentities;

			AllowNewAppsStart.Instance.EventLogsDataProcessed = false;
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

		// Start with all items from the complete list, 'AllowNewAppsStart.Instance.EventLogsAllFileIdentities'
		// This list is used as the base set for filtering to preserve original data
		IEnumerable<FileIdentity> filteredResults = AllowNewAppsStart.Instance.EventLogsAllFileIdentities.AsEnumerable();

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
		AllowNewAppsStart.Instance.EventLogsFileIdentities.Clear();

		// Populate the ObservableCollection with the filtered results
		// This triggers the UI to update the ListView based on the filtered data
		foreach (FileIdentity result in filteredResults)
		{
			AllowNewAppsStart.Instance.EventLogsFileIdentities.Add(result);
		}

		// Explicitly set the ListView's ItemsSource to ensure the data refreshes
		FileIdentitiesListView.ItemsSource = AllowNewAppsStart.Instance.EventLogsFileIdentities;

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
		AllowNewAppsStart.Instance.EventLogsFileIdentities.Clear();
		AllowNewAppsStart.Instance.EventLogsAllFileIdentities.Clear();

		UpdateTotalLogs(true);
	}

	/// <summary>
	/// Selects all of the displayed rows on the ListView
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SelectAll_Click(object sender, RoutedEventArgs e)
	{
		_ = DispatcherQueue.TryEnqueue(() =>
		{
			// Clear existing selections
			FileIdentitiesListView.SelectedItems.Clear();

			foreach (FileIdentity fileIdentity in AllowNewAppsStart.Instance.EventLogsFileIdentities)
			{
				FileIdentitiesListView.SelectedItems.Add(fileIdentity); // Select each item
			}
		});
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
	/// Deletes the selected row from the results
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void DataGridFlyoutMenuDelete_Click(object sender, RoutedEventArgs e)
	{
		// Collect the selected items to delete
		List<FileIdentity> itemsToDelete = [.. FileIdentitiesListView.SelectedItems.Cast<FileIdentity>()];

		// Remove each selected item from the FileIdentities collection
		foreach (FileIdentity item in itemsToDelete)
		{
			_ = AllowNewAppsStart.Instance.EventLogsFileIdentities.Remove(item);
			_ = AllowNewAppsStart.Instance.EventLogsAllFileIdentities?.Remove(item);
		}

		UpdateTotalLogs();
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
			AllowNewApps.Instance.UpdateEventLogsInfoBadge(0, 1);
		}
		else
		{
			TotalCountOfTheFilesTextBox.Text = $"Total logs: {AllowNewAppsStart.Instance.EventLogsFileIdentities.Count}";

			// Update the InfoBadge for the top menu
			AllowNewApps.Instance.UpdateEventLogsInfoBadge(AllowNewAppsStart.Instance.EventLogsFileIdentities.Count, 1);
		}
	}
}
