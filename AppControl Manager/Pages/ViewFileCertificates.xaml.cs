using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;

namespace AppControlManager.Pages;

public sealed partial class ViewFileCertificates : Page
{
	public ViewFileCertificates()
	{
		this.InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Enabled;
	}

	// a class that represents each certificate in a chain
	public sealed class FileCertificateInfoCol
	{
		public int SignerNumber { get; set; }
		public CertificateType Type { get; set; }
		public string? SubjectCN { get; set; }
		public string? IssuerCN { get; set; }
		public DateTime NotBefore { get; set; }
		public DateTime NotAfter { get; set; }
		public string? HashingAlgorithm { get; set; }
		public string? SerialNumber { get; set; }
		public string? Thumbprint { get; set; }
		public string? TBSHash { get; set; }
		public string? OIDs { get; set; }
	}

	// Main collection assigned to the DataGrid
	private readonly ObservableCollection<FileCertificateInfoCol> FileCertificates = [];

	// Collection used during search
	private ObservableCollection<FileCertificateInfoCol> FilteredCertificates = [];


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
				FileCertificatesDataGrid.ItemsSource = FilteredCertificates;
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
				FileCertificatesDataGrid.ItemsSource = FilteredCertificates;
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
	private static async Task<List<FileCertificateInfoCol>> Fetch(string file)
	{
		// A List to return at the end
		List<FileCertificateInfoCol> output = [];

		await Task.Run(() =>
		{
			// Get all of the file's certificates
			List<AllFileSigners> signerDetails = AllCertificatesGrabber.GetAllFileSigners(file);

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
	/// Copies the selected rows to the clipboard, formatting each property with its value.
	/// </summary>
	/// <param name="sender">The event sender.</param>
	/// <param name="e">The event arguments.</param>
	private void DataGridFlyoutMenuCopy_Click(object sender, RoutedEventArgs e)
	{
		if (FileCertificatesDataGrid.SelectedItems.Count > 0)
		{
			StringBuilder dataBuilder = new();

			foreach (FileCertificateInfoCol selectedItem in FileCertificatesDataGrid.SelectedItems)
			{
				_ = dataBuilder.AppendLine(ConvertRowToText(selectedItem));
				_ = dataBuilder.AppendLine(new string('-', 50));
			}

			DataPackage dataPackage = new();
			dataPackage.SetText(dataBuilder.ToString());
			Clipboard.SetContent(dataPackage);
		}
	}

	/// <summary>
	/// Converts a row's properties and values into a formatted string for clipboard copy.
	/// </summary>
	/// <param name="row">The selected row from the DataGrid.</param>
	/// <returns>A formatted string of the row's properties and values.</returns>
	private static string ConvertRowToText(FileCertificateInfoCol row)
	{
		return new StringBuilder()
			.AppendLine($"Signer Number: {row.SignerNumber}")
			.AppendLine($"Type: {row.Type}")
			.AppendLine($"Subject Common Name: {row.SubjectCN}")
			.AppendLine($"Issuer Common Name: {row.IssuerCN}")
			.AppendLine($"Not Before: {row.NotBefore}")
			.AppendLine($"Not After: {row.NotAfter}")
			.AppendLine($"Hashing Algorithm: {row.HashingAlgorithm}")
			.AppendLine($"Serial Number: {row.SerialNumber}")
			.AppendLine($"Thumbprint: {row.Thumbprint}")
			.AppendLine($"TBS Hash: {row.TBSHash}")
			.AppendLine($"Extension OIDs: {row.OIDs}")
			.ToString();
	}

	/// <summary>
	/// Event handler for the Copy Individual Items SubMenu. Populates items in the flyout of the data grid.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void FileCertificatesDataGrid_Loaded(object sender, RoutedEventArgs e)
	{
		if (CopyIndividualItemsSubMenu is null)
		{
			return;
		}

		CopyIndividualItemsSubMenu.Items.Clear();

		Dictionary<string, RoutedEventHandler> copyActions = new()
		{
			{ "Signer Number", CopySignerNumber_Click },
			{ "Type", CopyType_Click },
			{ "Subject Common Name", CopySubjectCN_Click },
			{ "Issuer Common Name", CopyIssuerCN_Click },
			{ "Not Before", CopyNotBefore_Click },
			{ "Not After", CopyNotAfter_Click },
			{ "Hashing Algorithm", CopyHashingAlgorithm_Click },
			{ "Serial Number", CopySerialNumber_Click },
			{ "Thumbprint", CopyThumbprint_Click },
			{ "TBS Hash", CopyTBSHash_Click },
			{ "Extension OIDs", CopyOIDs_Click }
		};

		foreach (KeyValuePair<string, RoutedEventHandler> action in copyActions)
		{
			MenuFlyoutItem menuItem = new() { Text = $"Copy {action.Key}" };
			menuItem.Click += action.Value;
			CopyIndividualItemsSubMenu.Items.Add(menuItem);
		}
	}

	// Click event handlers for each property
	private void CopySignerNumber_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard("CertificateNumber");
	private void CopyType_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard("Type");
	private void CopySubjectCN_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard("SubjectCN");
	private void CopyIssuerCN_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard("IssuerCN");
	private void CopyNotBefore_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard("NotBefore");
	private void CopyNotAfter_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard("NotAfter");
	private void CopyHashingAlgorithm_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard("HashingAlgorithm");
	private void CopySerialNumber_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard("SerialNumber");
	private void CopyThumbprint_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard("Thumbprint");
	private void CopyTBSHash_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard("TBSValue");
	private void CopyOIDs_Click(object sender, RoutedEventArgs e) => CopyPropertyToClipboard("OIDs");

	/// <summary>
	/// Helper method to copy a specified property value to the clipboard.
	/// </summary>
	/// <param name="propertyName"></param>
	private void CopyPropertyToClipboard(string propertyName)
	{
		if (FileCertificatesDataGrid.SelectedItem is not FileCertificateInfoCol selectedItem)
		{
			return;
		}

		string? propertyValue = propertyName switch
		{
			"CertificateNumber" => selectedItem.SignerNumber.ToString(),
			"Type" => selectedItem.Type.ToString(),
			"SubjectCN" => selectedItem.SubjectCN,
			"IssuerCN" => selectedItem.IssuerCN,
			"NotBefore" => selectedItem.NotBefore.ToString(),
			"NotAfter" => selectedItem.NotAfter.ToString(),
			"HashingAlgorithm" => selectedItem.HashingAlgorithm,
			"SerialNumber" => selectedItem.SerialNumber,
			"Thumbprint" => selectedItem.Thumbprint,
			"TBSValue" => selectedItem.TBSHash,
			"OIDs" => selectedItem.OIDs,
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

		FileCertificatesDataGrid.ItemsSource = FilteredCertificates;
	}

}
