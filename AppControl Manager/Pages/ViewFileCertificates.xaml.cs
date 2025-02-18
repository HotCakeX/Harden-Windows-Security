using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SimulationMethods;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;
using WinRT;

namespace AppControlManager.Pages;

// Since the columns for data in the ItemTemplate use "Binding" instead of "x:Bind", we need to use [GeneratedBindableCustomProperty] for them to work properly
[GeneratedBindableCustomProperty]
public sealed partial class ViewFileCertificates : Page, INotifyPropertyChanged
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

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// </summary>
	private void CalculateColumnWidths()
	{
		// Measure header text widths first.
		double maxWidth1 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("SignerNumberHeader/Text"));
		double maxWidth2 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("TypeHeader/Text"));
		double maxWidth3 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("SubjectCommonNameHeader/Text"));
		double maxWidth4 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("IssuerCommonNameHeader/Text"));
		double maxWidth5 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("NotBeforeHeader/Text"));
		double maxWidth6 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("NotAfterHeader/Text"));
		double maxWidth7 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("HashingAlgorithmHeader/Text"));
		double maxWidth8 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("SerialNumberHeader/Text"));
		double maxWidth9 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("ThumbprintHeader/Text"));
		double maxWidth10 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("TBSHashHeader/Text"));
		double maxWidth11 = ListViewUIHelpers.MeasureTextWidth(GlobalVars.Rizz.GetString("ExtensionOIDsHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (FileCertificateInfoCol item in FileCertificates)
		{
			double w1 = ListViewUIHelpers.MeasureTextWidth(item.SignerNumber.ToString());
			if (w1 > maxWidth1) maxWidth1 = w1;

			double w2 = ListViewUIHelpers.MeasureTextWidth(item.Type.ToString());
			if (w2 > maxWidth2) maxWidth2 = w2;

			double w3 = ListViewUIHelpers.MeasureTextWidth(item.SubjectCN);
			if (w3 > maxWidth3) maxWidth3 = w3;

			double w4 = ListViewUIHelpers.MeasureTextWidth(item.IssuerCN);
			if (w4 > maxWidth4) maxWidth4 = w4;

			double w5 = ListViewUIHelpers.MeasureTextWidth(item.NotBefore.ToString());
			if (w5 > maxWidth5) maxWidth5 = w5;

			double w6 = ListViewUIHelpers.MeasureTextWidth(item.NotAfter.ToString());
			if (w6 > maxWidth6) maxWidth6 = w6;

			double w7 = ListViewUIHelpers.MeasureTextWidth(item.HashingAlgorithm);
			if (w7 > maxWidth7) maxWidth7 = w7;

			double w8 = ListViewUIHelpers.MeasureTextWidth(item.SerialNumber);
			if (w8 > maxWidth8) maxWidth8 = w8;

			double w9 = ListViewUIHelpers.MeasureTextWidth(item.Thumbprint);
			if (w9 > maxWidth9) maxWidth9 = w9;

			double w10 = ListViewUIHelpers.MeasureTextWidth(item.TBSHash);
			if (w10 > maxWidth10) maxWidth10 = w10;

			double w11 = ListViewUIHelpers.MeasureTextWidth(item.OIDs);
			if (w11 > maxWidth11) maxWidth11 = w11;
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
	}

	/// <summary>
	/// Converts the properties of a FileCertificateInfoCol row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	/// <param name="row">The selected FileCertificateInfoCol row from the ListView.</param>
	/// <returns>A formatted string of the row's properties with labels.</returns>
	private static string ConvertRowToText(FileCertificateInfoCol row)
	{
		// Use StringBuilder to format each property with its label for easy reading
		return new StringBuilder()
			.AppendLine(GlobalVars.Rizz.GetString("SignerNumberHeader/Text") + row.SignerNumber)
			.AppendLine(GlobalVars.Rizz.GetString("TypeHeader/Text") + row.Type)
			.AppendLine(GlobalVars.Rizz.GetString("SubjectCommonNameHeader/Text") + row.SubjectCN)
			.AppendLine(GlobalVars.Rizz.GetString("IssuerCommonNameHeader/Text") + row.IssuerCN)
			.AppendLine(GlobalVars.Rizz.GetString("NotBeforeHeader/Text") + row.NotBefore)
			.AppendLine(GlobalVars.Rizz.GetString("NotAfterHeader/Text") + row.NotAfter)
			.AppendLine(GlobalVars.Rizz.GetString("HashingAlgorithmHeader/Text") + row.HashingAlgorithm)
			.AppendLine(GlobalVars.Rizz.GetString("SerialNumberHeader/Text") + row.SerialNumber)
			.AppendLine(GlobalVars.Rizz.GetString("ThumbprintHeader/Text") + row.Thumbprint)
			.AppendLine(GlobalVars.Rizz.GetString("TBSHashHeader/Text") + row.TBSHash)
			.AppendLine(GlobalVars.Rizz.GetString("ExtensionOIDsHeader/Text") + row.OIDs)
			.ToString();
	}


	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	/// <param name="sender">The event sender.</param>
	/// <param name="e">The event arguments.</param>
	private void ListViewFlyoutMenuCopy_Click(object sender, RoutedEventArgs e)
	{
		// Check if there are selected items in the ListView
		if (FileCertificatesListView.SelectedItems.Count > 0)
		{
			// Initialize StringBuilder to store all selected rows' data with labels
			StringBuilder dataBuilder = new();

			// Loop through each selected item in the ListView
			foreach (var selectedItem in FileCertificatesListView.SelectedItems)
			{

				if (selectedItem is FileCertificateInfoCol obj)

					// Append each row's formatted data to the StringBuilder
					_ = dataBuilder.AppendLine(ConvertRowToText(obj));

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
	private void CopySignerNumber_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SignerNumber.ToString());
	private void CopyType_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.Type.ToString());
	private void CopySubjectCommonName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SubjectCN);
	private void CopyIssuerCommonName_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.IssuerCN);
	private void CopyNotBefore_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.NotBefore.ToString());
	private void CopyNotAfter_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.NotAfter.ToString());
	private void CopyHashingAlgorithm_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.HashingAlgorithm);
	private void CopySerialNumber_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.SerialNumber);
	private void CopyThumbprint_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.Thumbprint);
	private void CopyTBSHash_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.TBSHash);
	private void CopyExtensionOIDs_Click(object sender, RoutedEventArgs e) => CopyToClipboard((item) => item.OIDs);

	/// <summary>
	/// Helper method to copy a specified property to clipboard without reflection
	/// </summary>
	/// <param name="getProperty">Function that retrieves the desired property value as a string</param>
	private void CopyToClipboard(Func<FileCertificateInfoCol, string?> getProperty)
	{
		if (FileCertificatesListView.SelectedItem is FileCertificateInfoCol selectedItem)
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
	private void ColumnSortingButton_SignerNumber_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.SignerNumber);
	}
	private void ColumnSortingButton_Type_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.Type);
	}
	private void ColumnSortingButton_SubjectCommonName_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.SubjectCN);
	}
	private void ColumnSortingButton_IssuerCommonName_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.IssuerCN);
	}
	private void ColumnSortingButton_NotBefore_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.NotBefore);
	}
	private void ColumnSortingButton_NotAfter_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.NotAfter);
	}
	private void ColumnSortingButton_HashingAlgorithm_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.HashingAlgorithm);
	}
	private void ColumnSortingButton_SerialNumber_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.SerialNumber);
	}
	private void ColumnSortingButton_Thumbprint_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.Thumbprint);
	}
	private void ColumnSortingButton_TBSHash_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.TBSHash);
	}
	private void ColumnSortingButton_ExtensionOIDs_Click(object sender, RoutedEventArgs e)
	{
		SortColumn(policy => policy.OIDs);
	}

	/// <summary>
	/// Performs data sorting
	/// </summary>
	/// <typeparam name="T"></typeparam>
	/// <param name="keySelector"></param>
	private void SortColumn<T>(Func<FileCertificateInfoCol, T> keySelector)
	{
		// Determine if a search filter is active.
		bool isSearchEmpty = string.IsNullOrWhiteSpace(SearchBox.Text);
		// Use either the full list (FilteredCertificates) or the current display list.
		var collectionToSort = isSearchEmpty ? FilteredCertificates : [.. FileCertificates];

		if (SortingDirectionToggle.IsChecked)
		{
			// Sort in descending order.
			FileCertificates = [.. collectionToSort.OrderByDescending(keySelector)];
		}
		else
		{
			// Sort in ascending order.
			FileCertificates = [.. collectionToSort.OrderBy(keySelector)];
		}

		// Refresh the ItemsSource so the UI updates.
		FileCertificatesListView.ItemsSource = FileCertificates;
	}

	#endregion


	public ViewFileCertificates()
	{
		this.InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Required;
	}

	// Main collection assigned to the ListView
	private ObservableCollection<FileCertificateInfoCol> FileCertificates = [];

	// Collection used during search
	private ObservableCollection<FileCertificateInfoCol> FilteredCertificates = [];

	// A dictionary where each key is a hash and value is the .Cat file path where the hash was found in
	private readonly Dictionary<string, string> AllSecurityCatalogHashes = [];

	private bool SecurityCatalogsWereCached;

	private void GatherSecurityCatalogs()
	{

		// Get the .cat files in the CatRoot directory
		List<FileInfo> detectedCatFiles = FileUtility.GetFilesFast([new DirectoryInfo(@"C:\Windows\System32\CatRoot")], null, [".cat"]);

		Logger.Write($"Including {detectedCatFiles.Count} Security Catalogs in the file certificate acquisition process");

		foreach (FileInfo file in detectedCatFiles)
		{
			// Get the hashes of the security catalog file
			HashSet<string> catHashes = MeowParser.GetHashes(file.FullName);

			// If the security catalog file has hashes, then add them to the dictionary
			if (catHashes.Count > 0)
			{
				foreach (string hash in catHashes)
				{
					_ = AllSecurityCatalogHashes.TryAdd(hash, file.FullName);
				}
			}
		}
	}

	/// <summary>
	/// Event handler for the Browse button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void BrowseForFilesButton_Click(object sender, RoutedEventArgs e)
	{

		try
		{
			BrowseForFilesSettingsCard.IsEnabled = false;
			BrowseForFilesButton.IsEnabled = false;

			string? selectedFiles = FileDialogHelper.ShowFilePickerDialog(GlobalVars.AnyFilePickerFilter);

			if (!string.IsNullOrWhiteSpace(selectedFiles))
			{
				// Clear the data grid variables before starting
				FileCertificates.Clear();
				FilteredCertificates.Clear();

				// Get the results
				List<FileCertificateInfoCol> result = await Fetch(selectedFiles);

				// Add the results to the collection
				foreach (FileCertificateInfoCol item in result)
				{
					FileCertificates.Add(item);
				}

				// Initialize filtered collection with all certificates
				FilteredCertificates = [.. FileCertificates];

				CalculateColumnWidths();

				FileCertificatesListView.ItemsSource = FilteredCertificates;
			}
		}
		finally
		{
			BrowseForFilesSettingsCard.IsEnabled = true;
			BrowseForFilesButton.IsEnabled = true;
		}
	}

	/// <summary>
	/// Event handler for the Settings Card click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void BrowseForFilesSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			BrowseForFilesSettingsCard.IsEnabled = false;
			BrowseForFilesButton.IsEnabled = false;

			string? selectedFiles = FileDialogHelper.ShowFilePickerDialog(GlobalVars.AnyFilePickerFilter);

			if (!string.IsNullOrWhiteSpace(selectedFiles))
			{
				// Clear the data grid variables before starting
				FileCertificates.Clear();
				FilteredCertificates.Clear();

				// To store the results that will be added to the Observable Collections
				List<FileCertificateInfoCol> result;

				// Get the file's extension
				string fileExtension = Path.GetExtension(selectedFiles);

				// Perform different operations for .CIP files
				if (String.Equals(fileExtension, ".cip", StringComparison.OrdinalIgnoreCase))
				{
					// Get the results
					result = await FetchForCIP(selectedFiles);
				}

				else if (String.Equals(fileExtension, ".cer", StringComparison.OrdinalIgnoreCase))
				{
					// Get the results
					result = await FetchForCER(selectedFiles);
				}

				// For any other files
				else
				{
					// Get the results
					result = await Fetch(selectedFiles);
				}

				// Add the results to the collection
				foreach (FileCertificateInfoCol item in result)
				{
					FileCertificates.Add(item);
				}

				// Initialize filtered collection with all certificates
				FilteredCertificates = [.. FileCertificates];

				CalculateColumnWidths();

				FileCertificatesListView.ItemsSource = FilteredCertificates;
			}

		}
		finally
		{
			BrowseForFilesSettingsCard.IsEnabled = true;
			BrowseForFilesButton.IsEnabled = true;
		}
	}

	/// <summary>
	/// Get the certificates of the .CIP files
	/// </summary>
	/// <param name="file"></param>
	/// <returns></returns>
	private static async Task<List<FileCertificateInfoCol>> FetchForCIP(string file)
	{
		List<FileCertificateInfoCol> output = [];

		await Task.Run(() =>
		{

			// Create a new SignedCms object to store the signed message
			SignedCms signedCms = new();

			// Decode the signed message from the file specified by cipFilePath
			// The file is read as a byte array because the SignedCms.Decode() method expects a byte array as input
			// https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.signedcms.decode
			signedCms.Decode(File.ReadAllBytes(file));

			X509Certificate2Collection certificates = signedCms.Certificates;
			X509Certificate2[] certificateArray = new X509Certificate2[certificates.Count];
			certificates.CopyTo(certificateArray, 0);

			// Counter (in case the CIP file is signed by multiple certificates)
			int i = 1;

			// Loop over the array of X509Certificate2 objects that represent the certificates used to sign the message
			foreach (X509Certificate2 signer in certificateArray)
			{
				output.Add(new FileCertificateInfoCol
				{
					SignerNumber = i,
					Type = CertificateType.Leaf,
					SubjectCN = CryptoAPI.GetNameString(signer.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false), // SubjectCN
					IssuerCN = CryptoAPI.GetNameString(signer.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true), // IssuerCN
					NotBefore = signer.NotBefore,
					NotAfter = signer.NotAfter,
					HashingAlgorithm = signer.SignatureAlgorithm.FriendlyName,
					SerialNumber = signer.SerialNumber,
					Thumbprint = signer.Thumbprint,
					TBSHash = CertificateHelper.GetTBSCertificate(signer),
					OIDs = string.Join(", ", signer.Extensions
							.Select(ext =>
								ext.Oid is not null ? $"{ext.Oid.Value} ({ext.Oid.FriendlyName})" : ext?.Oid?.Value)
							.Where(oid => !string.IsNullOrWhiteSpace(oid)))
				});

				i++;
			}

		});

		return output;
	}


	/// <summary>
	/// Fetch for the .cer files
	/// </summary>
	/// <param name="file"></param>
	/// <returns></returns>
	private static async Task<List<FileCertificateInfoCol>> FetchForCER(string file)
	{
		List<FileCertificateInfoCol> output = [];

		await Task.Run(() =>
		{
			// Create a certificate object from the .cer file
			X509Certificate2 CertObject = X509CertificateLoader.LoadCertificateFromFile(file);

			// Add the certificate as leaf certificate
			output.Add(new FileCertificateInfoCol
			{
				SignerNumber = 1,
				Type = CertificateType.Leaf,
				SubjectCN = CryptoAPI.GetNameString(CertObject.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false), // SubjectCN
				IssuerCN = CryptoAPI.GetNameString(CertObject.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true), // IssuerCN
				NotBefore = CertObject.NotBefore,
				NotAfter = CertObject.NotAfter,
				HashingAlgorithm = CertObject.SignatureAlgorithm.FriendlyName,
				SerialNumber = CertObject.SerialNumber,
				Thumbprint = CertObject.Thumbprint,
				TBSHash = CertificateHelper.GetTBSCertificate(CertObject),
				OIDs = string.Join(", ", CertObject.Extensions
						.Select(ext =>
							ext.Oid is not null ? $"{ext.Oid.Value} ({ext.Oid.FriendlyName})" : ext?.Oid?.Value)
						.Where(oid => !string.IsNullOrWhiteSpace(oid)))
			});

		});

		return output;
	}


	/// <summary>
	/// The main method that performs data collection task
	/// </summary>
	/// <param name="file"></param>
	/// <returns></returns>
	private async Task<List<FileCertificateInfoCol>> Fetch(string file)
	{
		// A List to return at the end
		List<FileCertificateInfoCol> output = [];

		// Query the UI toggle switch
		bool shouldProcessSecurityCats = IncludeSecurityCatalogsToggleSwitch.IsOn;

		await Task.Run(() =>
		{
			// Get all of the file's certificates
			List<AllFileSigners> signerDetails = AllCertificatesGrabber.GetAllFileSigners(file);

			// If the file has no signers and the user wants to include security catalogs
			if (signerDetails.Count is 0 && shouldProcessSecurityCats)
			{
				// Process the security catalogs if they haven't been processed
				if (!SecurityCatalogsWereCached)
				{
					GatherSecurityCatalogs();
					SecurityCatalogsWereCached = true;
				}

				// Grab the file's Code Integrity hashes
				CodeIntegrityHashes fileHashes = CiFileHash.GetCiFileHashes(file);


				if (AllSecurityCatalogHashes.TryGetValue(fileHashes.SHa1Authenticode!, out string? CurrentFilePathHashSHA1CatResult))
				{
					try
					{
						signerDetails = AllCertificatesGrabber.GetAllFileSigners(CurrentFilePathHashSHA1CatResult);
					}
					catch (HashMismatchInCertificateException)
					{
						Logger.Write($"The file '{file}' has hash mismatch.");
					}
				}
				else if (AllSecurityCatalogHashes.TryGetValue(fileHashes.SHA256Authenticode!, out string? CurrentFilePathHashSHA256CatResult))
				{
					try
					{
						signerDetails = AllCertificatesGrabber.GetAllFileSigners(CurrentFilePathHashSHA256CatResult);
					}
					catch (HashMismatchInCertificateException)
					{
						Logger.Write($"The file '{file}' has hash mismatch.");
					}
				}

			}

			// Get full chains of all of the file's certificates
			List<ChainPackage> result = GetCertificateDetails.Get([.. signerDetails]);

			// Start the counter with 1 instead of 0 for better display
			int i = 1;

			// Loop over every signer of the file
			foreach (ChainPackage signer in result)
			{
				// If the signer has Leaf certificate
				if (signer.LeafCertificate is not null)
				{
					output.Add(new FileCertificateInfoCol
					{
						SignerNumber = i,
						Type = CertificateType.Leaf,
						SubjectCN = signer.LeafCertificate.SubjectCN,
						IssuerCN = signer.LeafCertificate.IssuerCN,
						NotBefore = signer.LeafCertificate.NotBefore,
						NotAfter = signer.LeafCertificate.NotAfter,
						HashingAlgorithm = signer.LeafCertificate.Certificate.SignatureAlgorithm.FriendlyName,
						SerialNumber = signer.LeafCertificate.Certificate.SerialNumber,
						Thumbprint = signer.LeafCertificate.Certificate.Thumbprint,
						TBSHash = signer.LeafCertificate.TBSValue,
						OIDs = string.Join(", ", signer.LeafCertificate.Certificate.Extensions
							.Select(ext =>
								ext.Oid is not null ? $"{ext.Oid.Value} ({ext.Oid.FriendlyName})" : ext?.Oid?.Value)
							.Where(oid => !string.IsNullOrWhiteSpace(oid)))
					});
				}

				// If the signer has any Intermediate Certificates
				if (signer.IntermediateCertificates is not null)
				{
					// Loop over Intermediate certificates of the file
					foreach (ChainElement intermediate in signer.IntermediateCertificates)
					{
						output.Add(new FileCertificateInfoCol
						{
							SignerNumber = i,
							Type = CertificateType.Intermediate,
							SubjectCN = intermediate.SubjectCN,
							IssuerCN = intermediate.IssuerCN,
							NotBefore = intermediate.NotBefore,
							NotAfter = intermediate.NotAfter,
							HashingAlgorithm = intermediate.Certificate.SignatureAlgorithm.FriendlyName,
							SerialNumber = intermediate.Certificate.SerialNumber,
							Thumbprint = intermediate.Certificate.Thumbprint,
							TBSHash = intermediate.TBSValue,
							OIDs = string.Join(", ", intermediate.Certificate.Extensions
								.Select(ext =>
									ext.Oid is not null ? $"{ext.Oid.Value} ({ext.Oid.FriendlyName})" : ext?.Oid?.Value)
								.Where(oid => !string.IsNullOrWhiteSpace(oid)))
						});
					}
				}

				// Add the root certificate
				output.Add(new FileCertificateInfoCol
				{
					SignerNumber = i,
					Type = CertificateType.Root,
					SubjectCN = signer.RootCertificate.SubjectCN,
					IssuerCN = signer.RootCertificate.SubjectCN, // Issuer is itself for Root certificate type
					NotBefore = signer.RootCertificate.NotBefore,
					NotAfter = signer.RootCertificate.NotAfter,
					HashingAlgorithm = signer.RootCertificate.Certificate.SignatureAlgorithm.FriendlyName,
					SerialNumber = signer.RootCertificate.Certificate.SerialNumber,
					Thumbprint = signer.RootCertificate.Certificate.Thumbprint,
					TBSHash = signer.RootCertificate.TBSValue,
					OIDs = string.Join(", ", signer.RootCertificate.Certificate.Extensions
						.Select(ext =>
							ext.Oid is not null ? $"{ext.Oid.Value} ({ext.Oid.FriendlyName})" : ext?.Oid?.Value)
						.Where(oid => !string.IsNullOrWhiteSpace(oid)))
				});

				// Increase the counter
				i++;
			}

		});

		return output;
	}

	/// <summary>
	/// Event handler for the search box
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		// Get the search term from the search box
		string query = SearchBox.Text.Trim();

		if (string.IsNullOrWhiteSpace(query))
		{
			FilteredCertificates = [.. FileCertificates];
		}
		else
		{
			FilteredCertificates = [.. FileCertificates.Where(cert =>
					(cert.SubjectCN is not null && cert.SubjectCN.Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					(cert.IssuerCN is not null && cert.IssuerCN.Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					(cert.TBSHash is not null && cert.TBSHash.Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					(cert.OIDs is not null && cert.OIDs.Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					cert.SignerNumber.ToString().Contains(query, StringComparison.OrdinalIgnoreCase) ||
					cert.Type.ToString().Contains(query, StringComparison.OrdinalIgnoreCase) ||
					cert.NotAfter.ToString().Contains(query, StringComparison.OrdinalIgnoreCase) ||
					cert.NotBefore.ToString().Contains(query, StringComparison.OrdinalIgnoreCase) ||
					(cert.HashingAlgorithm is not null && cert.HashingAlgorithm.Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					(cert.SerialNumber is not null && cert.SerialNumber.Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					(cert.Thumbprint is not null && cert.Thumbprint.Contains(query, StringComparison.OrdinalIgnoreCase))
				)];
		}

		FileCertificatesListView.ItemsSource = FilteredCertificates;
	}


	private void IncludeSecurityCatalogsSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		IncludeSecurityCatalogsToggleSwitch.IsOn = !IncludeSecurityCatalogsToggleSwitch.IsOn;
	}
}
