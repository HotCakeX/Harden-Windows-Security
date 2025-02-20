using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.XMLOps;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;
using WinRT;

namespace AppControlManager.Pages;

// Since the columns for data in the ItemTemplate use "Binding" instead of "x:Bind", we need to use [GeneratedBindableCustomProperty] for them to work properly
[GeneratedBindableCustomProperty]
public sealed partial class EventLogsPolicyCreation : Page, INotifyPropertyChanged
{

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
		foreach (FileIdentity item in FileIdentities)
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
	private void CopySigningScenario_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SISigningScenario.ToString());
	private void CopyFilePath_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FilePath);
	private void CopySHA1PageHash_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SHA1PageHash);
	private void CopySHA256PageHash_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SHA256PageHash);
	private void CopyHasWHQLSigner_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.HasWHQLSigner.ToString());
	private void CopyFilePublishers_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.FilePublishersToDisplay);
	private void CopyOpusData_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.Opus);
	private void CopyPolicyGUID_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.PolicyGUID.ToString());
	private void CopyPolicyName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.PolicyName);

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
	private void ColumnSortingButton_TimeCreated_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.TimeCreated);
	}
	private void ColumnSortingButton_SignatureStatus_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.SignatureStatus);
	}
	private void ColumnSortingButton_Action_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.Action);
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
	private void ColumnSortingButton_OpusData_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.Opus);
	}
	private void ColumnSortingButton_PolicyID_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.PolicyGUID);
	}
	private void ColumnSortingButton_PolicyName_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(fileIden => fileIden.PolicyName);
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
		// Use either the full list AllFileIdentities or the current display list.
		List<FileIdentity> collectionToSort = isSearchEmpty ? AllFileIdentities : [.. FileIdentities];

		if (SortingDirectionToggle.IsChecked)
		{
			// Sort in descending order.
			FileIdentities = [.. collectionToSort.OrderByDescending(keySelector)];
		}
		else
		{
			// Sort in ascending order.
			FileIdentities = [.. collectionToSort.OrderBy(keySelector)];
		}

		// Refresh the ItemsSource so the UI updates.
		FileIdentitiesListView.ItemsSource = FileIdentities;
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


	// To store the FileIdentities displayed on the ListView
	// Binding happens on the XAML but methods related to search update the ItemSource of the ListView from code behind otherwise there will not be an expected result
	internal ObservableCollection<FileIdentity> FileIdentities { get; set; }

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
		// This triggers the UI to update the ListView based on the filtered data
		foreach (FileIdentity result in filteredResults)
		{
			FileIdentities.Add(result);
		}

		// Explicitly set the ListView's ItemsSource to ensure the data refreshes
		FileIdentitiesListView.ItemsSource = FileIdentities;

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

			CalculateColumnWidths();
			FileIdentitiesListView.ItemsSource = FileIdentities;
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
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.EVTXPickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected evtx file path
			CodeIntegrityEVTX = selectedFile;

			Logger.Write($"Selected {selectedFile} for Code Integrity EVTX log scanning");

			SelectedCodeIntegrityEVTXFilesFlyout_TextBox.Text = selectedFile;

			SelectedCodeIntegrityEVTXFilesFlyout.ShowAt(BrowseForEVTXDropDownButton);
		}
	}


	private void SelectedCodeIntegrityEVTXFilesFlyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		SelectedCodeIntegrityEVTXFilesFlyout_TextBox.Text = null;
		CodeIntegrityEVTX = null;
	}


	/// <summary>
	/// Event handler for the select AppLocker EVTX file path button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SelectAppLockerEVTXFiles_Click(object sender, RoutedEventArgs e)
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.EVTXPickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected EVTX file path
			AppLockerEVTX = selectedFile;

			Logger.Write($"Selected {selectedFile} for AppLocker EVTX log scanning");

			SelectedAppLockerEVTXFilesFlyout_TextBox.Text = selectedFile;

			SelectedAppLockerEVTXFilesFlyout.ShowAt(BrowseForEVTXDropDownButton);
		}
	}


	private void SelectedAppLockerEVTXFilesFlyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		SelectedAppLockerEVTXFilesFlyout_TextBox.Text = null;
		AppLockerEVTX = null;
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

			foreach (FileIdentity fileIdentity in FileIdentities)
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
			_ = FileIdentities.Remove(item);
			_ = AllFileIdentities.Remove(item); // Removing it from the other list so that when user deletes data when search filtering is applied, after removing the search, the deleted data won't be restored
		}

		UpdateTotalLogs();
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
	/// The button that browses for XML file the logs will be added to
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void AddToPolicyButton_Click(object sender, RoutedEventArgs e)
	{

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			PolicyToAddLogsTo = selectedFile;

			Logger.Write($"Selected {PolicyToAddLogsTo} to add the logs to.");
		}

	}


	/// <summary>
	/// The button to browse for the XML file the supplemental policy that will be created will belong to
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BasePolicyFileButton_Click(object sender, RoutedEventArgs e)
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			BasePolicyXMLFile = selectedFile;

			Logger.Write($"Selected {BasePolicyXMLFile} to associate the Supplemental policy with.");
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


			if (FileIdentities.Count is 0)
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

			// Check if there are selected items in the ListView
			if (FileIdentitiesListView.SelectedItems.Count > 0)
			{
				// convert every selected item to FileIdentity and store it in the list
				foreach (var item in FileIdentitiesListView.SelectedItems)
				{
					if (item is FileIdentity item1)
					{
						SelectedLogs.Add(item1);
					}
				}
			}
			// If no item was selected from the ListView, use everything in the ObservableCollection
			else
			{
				SelectedLogs = [.. FileIdentities];
			}

			// If user selected to deploy the policy
			// Need to retrieve it while we're still at the UI thread
			bool DeployAtTheEnd = DeployPolicyToggle.IsChecked;

			// See which section of the Segmented control is selected for policy creation
			int selectedCreationMethod = segmentedControl.SelectedIndex;

			await Task.Run(() =>
			{

				// Create a new Staging Area
				DirectoryInfo stagingArea = StagingArea.NewStagingArea("PolicyCreator");

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: SelectedLogs, level: scanLevel);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, SiPolicyIntel.Authorization.Allow);

				switch (selectedCreationMethod)
				{
					case 0:
						{
							if (PolicyToAddLogsTo is not null)
							{

								// Set policy name and reset the policy ID of our new policy
								string supplementalPolicyID = SetCiPolicyInfo.Set(EmptyPolicyPath, true, policyName, null, null);

								// Remove all policy rule options prior to merging the policies since we don't need to add/remove any policy rule options to/from the user input policy
								CiRuleOptions.Set(filePath: EmptyPolicyPath, RemoveAll: true);

								// Merge the created policy with the user-selected policy which will result in adding the new rules to it
								SiPolicy.Merger.Merge(PolicyToAddLogsTo, [EmptyPolicyPath]);

								UpdateHvciOptions.Update(PolicyToAddLogsTo);

								// If user selected to deploy the policy
								if (DeployAtTheEnd)
								{
									string CIPPath = Path.Combine(stagingArea.FullName, $"{supplementalPolicyID}.cip");

									PolicyToCIPConverter.Convert(PolicyToAddLogsTo, CIPPath);

									CiToolHelper.UpdatePolicy(CIPPath);
								}
							}
							else
							{
								throw new InvalidOperationException("No policy file was selected to add the logs to.");
							}

							break;
						}
					case 1:
						{
							if (BasePolicyXMLFile is not null)
							{
								string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{policyName}.xml");

								// Instantiate the user selected Base policy
								SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(BasePolicyXMLFile, null);

								// Set the BasePolicyID of our new policy to the one from user selected policy
								string supplementalPolicyID = SetCiPolicyInfo.Set(EmptyPolicyPath, true, policyName, policyObj.BasePolicyID, null);

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
							else
							{
								throw new InvalidOperationException("No policy file was selected to associate the Supplemental policy with.");
							}

							break;
						}
					case 2:
						{

							if (BasePolicyGUID is not null)
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
							else
							{
								throw new InvalidOperationException("No Base Policy GUID was provided to use as the BasePolicyID of the supplemental policy.");
							}

							break;
						}
					default:
						{
							break;
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
		// Get the ComboBox that triggered the event
		ComboBox comboBox = (ComboBox)sender;

		// Get the selected item from the ComboBox
		string selectedText = (string)comboBox.SelectedItem;

		scanLevel = Enum.Parse<ScanLevels>(selectedText);
	}


	private void BrowseForCodeIntegrityEVTXFilesButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!SelectedCodeIntegrityEVTXFilesFlyout.IsOpen)
			SelectedCodeIntegrityEVTXFilesFlyout.ShowAt(BrowseForEVTXDropDownButton);
	}

	private void BrowseForCodeIntegrityEVTXFilesButton_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!SelectedCodeIntegrityEVTXFilesFlyout.IsOpen)
				SelectedCodeIntegrityEVTXFilesFlyout.ShowAt(BrowseForEVTXDropDownButton);
	}

	private void BrowseForAppLockerEVTXFilesButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!SelectedAppLockerEVTXFilesFlyout.IsOpen)
			SelectedAppLockerEVTXFilesFlyout.ShowAt(BrowseForEVTXDropDownButton);
	}

	private void BrowseForAppLockerEVTXFilesButton_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!SelectedAppLockerEVTXFilesFlyout.IsOpen)
				SelectedAppLockerEVTXFilesFlyout.ShowAt(BrowseForEVTXDropDownButton);
	}


	/// <summary>
	/// Event handler for for the segmented button's selection change
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SegmentedControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		CreatePolicyButton.Content = segmentedControl.SelectedIndex switch
		{
			0 => "Add logs to the selected policy",
			1 => "Create Policy for Selected Base",
			2 => "Create Policy for Base GUID",
			_ => "Create Policy"
		};

	}
}
