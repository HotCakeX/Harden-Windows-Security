// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SimulationMethods;
using AppControlManager.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;
using Windows.ApplicationModel.DataTransfer;

namespace AppControlManager.Pages;

/// <summary>
/// Represents a page for viewing file certificates, managing their display, and facilitating clipboard
/// operations.
/// </summary>
internal sealed partial class ViewFileCertificates : Page
{

#pragma warning disable CA1822
	private ViewFileCertificatesVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<ViewFileCertificatesVM>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
#pragma warning restore CA1822

	/// <summary>
	/// Constructor for the ViewFileCertificates class. Initializes components, sets navigation cache mode, and assigns the
	/// data context.
	/// </summary>
	internal ViewFileCertificates()
	{
		this.InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Required;

		this.DataContext = ViewModel;
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
					_ = dataBuilder.AppendLine(ViewModel.ConvertRowToText(obj));

				// Add a separator between rows for readability in multi-row copies
				_ = dataBuilder.AppendLine(ListViewHelper.DefaultDelimiter);
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


	private async void BrowseForFilesSettingsCard_Click()
	{
		try
		{
			BrowseForFilesSettingsCard.IsEnabled = false;
			BrowseForFilesButton.IsEnabled = false;

			string? selectedFiles = FileDialogHelper.ShowFilePickerDialog(GlobalVars.AnyFilePickerFilter);

			if (!string.IsNullOrWhiteSpace(selectedFiles))
			{

				// To store the results that will be added to the Observable Collections
				List<FileCertificateInfoCol> result;

				// Get the file's extension
				string fileExtension = Path.GetExtension(selectedFiles);

				// Perform different operations for .CIP files
				if (string.Equals(fileExtension, ".cip", StringComparison.OrdinalIgnoreCase))
				{
					// Get the results
					result = await FetchForCIP(selectedFiles);
				}

				else if (string.Equals(fileExtension, ".cer", StringComparison.OrdinalIgnoreCase))
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
				ViewModel.FileCertificates.Clear();
				ViewModel.FilteredCertificates.Clear();

				ViewModel.FilteredCertificates.AddRange(result);

				foreach (FileCertificateInfoCol item in result)
				{
					item.ParentViewModel = ViewModel;
					ViewModel.FileCertificates.Add(item);
				}

				ViewModel.CalculateColumnWidths();
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
			// https://learn.microsoft.com/dotnet/api/system.security.cryptography.pkcs.signedcms.decode
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
				// Get the security catalog data to include in the scan
				ConcurrentDictionary<string, string> AllSecurityCatalogHashes = CatRootScanner.Scan(null, 5);

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
			List<ChainPackage> result = GetCertificateDetails.Get(signerDetails);

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
