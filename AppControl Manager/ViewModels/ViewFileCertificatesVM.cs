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
using System.Collections.ObjectModel;
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
using CommunityToolkit.WinUI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace AppControlManager.ViewModels;

internal sealed partial class ViewFileCertificatesVM : ViewModelBase
{
	internal ViewFileCertificatesVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			null, null);
	}

	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the UI elements are enabled or disabled.
	/// </summary>
	internal bool AreElementsEnabled { get; set => SP(ref field, value); } = true;

	internal bool IncludeSecurityCatalogsToggleSwitch { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Main collection assigned to the ListView
	/// </summary>
	internal readonly ObservableCollection<FileCertificateInfoCol> FileCertificates = [];

	/// <summary>
	/// Collection used during search
	/// </summary>
	internal readonly List<FileCertificateInfoCol> FilteredCertificates = [];

	/// <summary>
	/// The file being analyzed for certificates.
	/// </summary>
	private string? selectedFile;

	/// <summary>
	/// Text for the search.
	/// </summary>
	internal string? SearchBoxTextBox
	{
		get; set
		{
			if (SP(ref field, value))
			{
				SearchBox_TextChanged();
			}
		}
	}

	#region LISTVIEW IMPLEMENTATIONS

	// Properties to hold each columns' width.
	internal GridLength ColumnWidth1 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth2 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth3 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth4 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth5 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth6 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth7 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth8 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth9 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth10 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth11 { get; set => SP(ref field, value); }

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// </summary>
	internal void CalculateColumnWidths()
	{
		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.GetStr("SignerNumberHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.GetStr("TypeHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.GetStr("SubjectCommonNameHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.GetStr("IssuerCommonNameHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.GetStr("NotBeforeHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(GlobalVars.GetStr("NotAfterHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureText(GlobalVars.GetStr("HashingAlgorithmHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureText(GlobalVars.GetStr("SerialNumberHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureText(GlobalVars.GetStr("ThumbprintHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureText(GlobalVars.GetStr("TBSHashHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureText(GlobalVars.GetStr("ExtensionOIDsHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (FileCertificateInfoCol item in FileCertificates)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.SignerNumber.ToString(), maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.Type.ToString(), maxWidth2);
			maxWidth3 = ListViewHelper.MeasureText(item.SubjectCN, maxWidth3);
			maxWidth4 = ListViewHelper.MeasureText(item.IssuerCN, maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.NotBefore.ToString(), maxWidth5);
			maxWidth6 = ListViewHelper.MeasureText(item.NotAfter.ToString(), maxWidth6);
			maxWidth7 = ListViewHelper.MeasureText(item.HashingAlgorithm, maxWidth7);
			maxWidth8 = ListViewHelper.MeasureText(item.SerialNumber, maxWidth8);
			maxWidth9 = ListViewHelper.MeasureText(item.Thumbprint, maxWidth9);
			maxWidth10 = ListViewHelper.MeasureText(item.TBSHash, maxWidth10);
			maxWidth11 = ListViewHelper.MeasureText(item.OIDs, maxWidth11);
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

	#endregion

	private void SearchBox_TextChanged()
	{
		// Get the search term from the search box
		string? query = SearchBoxTextBox?.Trim();

		if (query is null)
			return;

		// Get the ListView ScrollViewer info
		ScrollViewer? Sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.Locally_Deployed_Policies);

		double? savedHorizontal = null;
		if (Sv != null)
		{
			savedHorizontal = Sv.HorizontalOffset;
		}

		List<FileCertificateInfoCol> results = [];

		results = FilteredCertificates.Where(cert =>
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
				).ToList();

		FileCertificates.Clear();

		foreach (FileCertificateInfoCol item in results)
		{
			FileCertificates.Add(item);
		}

		if (Sv != null && savedHorizontal.HasValue)
		{
			// restore horizontal scroll position
			_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
		}
	}


	#region Sort

	/// <summary>
	/// Enum representing the sort columns for certificate items.
	/// </summary>
	private enum CertificateSortColumn
	{
		SignerNumber,
		Type,
		SubjectCommonName,
		IssuerCommonName,
		NotBefore,
		NotAfter,
		HashingAlgorithm,
		SerialNumber,
		Thumbprint,
		TBSHash,
		ExtensionOIDs
	}

	// Sorting state: current column and sort direction.
	private CertificateSortColumn? _currentSortColumn;
	private bool _isDescending = true; // column defaults to descending.

	/// <summary>
	/// Common sort method that determines sort column and toggles direction.
	/// </summary>
	/// <param name="newSortColumn">The column to sort by.</param>
	private async void Sort(CertificateSortColumn newSortColumn)
	{
		try
		{

			// Get the ListView ScrollViewer info
			ScrollViewer? Sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.Locally_Deployed_Policies);

			double? savedHorizontal = null;
			if (Sv != null)
			{
				savedHorizontal = Sv.HorizontalOffset;
			}


			// Toggle sort order if the same column is clicked.
			if (_currentSortColumn.HasValue && _currentSortColumn.Value == newSortColumn)
			{
				_isDescending = !_isDescending;
			}
			else
			{
				_currentSortColumn = newSortColumn;
				_isDescending = true;
			}

			// Determine if there is active search text.
			bool isSearchEmpty = string.IsNullOrWhiteSpace(SearchBoxTextBox);
			List<FileCertificateInfoCol> sourceData = isSearchEmpty
				? FilteredCertificates
				: FileCertificates.ToList();

			List<FileCertificateInfoCol> sortedData = [];

			switch (newSortColumn)
			{
				case CertificateSortColumn.SignerNumber:
					sortedData = _isDescending
						? sourceData.OrderByDescending(c => c.SignerNumber).ToList()
						: sourceData.OrderBy(c => c.SignerNumber).ToList();
					break;
				case CertificateSortColumn.Type:
					sortedData = _isDescending
						? sourceData.OrderByDescending(c => c.Type).ToList()
						: sourceData.OrderBy(c => c.Type).ToList();
					break;
				case CertificateSortColumn.SubjectCommonName:
					sortedData = _isDescending
						? sourceData.OrderByDescending(c => c.SubjectCN).ToList()
						: sourceData.OrderBy(c => c.SubjectCN).ToList();
					break;
				case CertificateSortColumn.IssuerCommonName:
					sortedData = _isDescending
						? sourceData.OrderByDescending(c => c.IssuerCN).ToList()
						: sourceData.OrderBy(c => c.IssuerCN).ToList();
					break;
				case CertificateSortColumn.NotBefore:
					sortedData = _isDescending
						? sourceData.OrderByDescending(c => c.NotBefore).ToList()
						: sourceData.OrderBy(c => c.NotBefore).ToList();
					break;
				case CertificateSortColumn.NotAfter:
					sortedData = _isDescending
						? sourceData.OrderByDescending(c => c.NotAfter).ToList()
						: sourceData.OrderBy(c => c.NotAfter).ToList();
					break;
				case CertificateSortColumn.HashingAlgorithm:
					sortedData = _isDescending
						? sourceData.OrderByDescending(c => c.HashingAlgorithm).ToList()
						: sourceData.OrderBy(c => c.HashingAlgorithm).ToList();
					break;
				case CertificateSortColumn.SerialNumber:
					sortedData = _isDescending
						? sourceData.OrderByDescending(c => c.SerialNumber).ToList()
						: sourceData.OrderBy(c => c.SerialNumber).ToList();
					break;
				case CertificateSortColumn.Thumbprint:
					sortedData = _isDescending
						? sourceData.OrderByDescending(c => c.Thumbprint).ToList()
						: sourceData.OrderBy(c => c.Thumbprint).ToList();
					break;
				case CertificateSortColumn.TBSHash:
					sortedData = _isDescending
						? sourceData.OrderByDescending(c => c.TBSHash).ToList()
						: sourceData.OrderBy(c => c.TBSHash).ToList();
					break;
				case CertificateSortColumn.ExtensionOIDs:
					sortedData = _isDescending
						? sourceData.OrderByDescending(c => c.OIDs).ToList()
						: sourceData.OrderBy(c => c.OIDs).ToList();
					break;
				default:
					break;
			}

			// Update the observable collection on the UI thread.
			await Dispatcher.EnqueueAsync(() =>
			{
				FileCertificates.Clear();
				foreach (var item in sortedData)
				{
					FileCertificates.Add(item);
				}

				if (Sv != null && savedHorizontal.HasValue)
				{
					// restore horizontal scroll position
					_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
				}
			});
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	// Methods bound to each header button's Click events.
	internal void SortBySignerNumber()
	{
		Sort(CertificateSortColumn.SignerNumber);
	}

	internal void SortByType()
	{
		Sort(CertificateSortColumn.Type);
	}

	internal void SortBySubjectCommonName()
	{
		Sort(CertificateSortColumn.SubjectCommonName);
	}

	internal void SortByIssuerCommonName()
	{
		Sort(CertificateSortColumn.IssuerCommonName);
	}

	internal void SortByNotBefore()
	{
		Sort(CertificateSortColumn.NotBefore);
	}

	internal void SortByNotAfter()
	{
		Sort(CertificateSortColumn.NotAfter);
	}

	internal void SortByHashingAlgorithm()
	{
		Sort(CertificateSortColumn.HashingAlgorithm);
	}

	internal void SortBySerialNumber()
	{
		Sort(CertificateSortColumn.SerialNumber);
	}

	internal void SortByThumbprint()
	{
		Sort(CertificateSortColumn.Thumbprint);
	}

	internal void SortByTBSHash()
	{
		Sort(CertificateSortColumn.TBSHash);
	}

	internal void SortByExtensionOIDs()
	{
		Sort(CertificateSortColumn.ExtensionOIDs);
	}

	#endregion


	#region Copy

	/// <summary>
	/// Converts the properties of a FileCertificateInfoCol row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	/// <param name="row">The selected FileCertificateInfoCol row from the ListView.</param>
	/// <returns>A formatted string of the row's properties with labels.</returns>
	private string ConvertRowToText(FileCertificateInfoCol row)
	{
		// Use StringBuilder to format each property with its label for easy reading
		return new StringBuilder()
			.AppendLine(GlobalVars.GetStr("SignerNumberHeader/Text") + ": " + row.SignerNumber)
			.AppendLine(GlobalVars.GetStr("TypeHeader/Text") + ": " + row.Type)
			.AppendLine(GlobalVars.GetStr("SubjectCommonNameHeader/Text") + ": " + row.SubjectCN)
			.AppendLine(GlobalVars.GetStr("IssuerCommonNameHeader/Text") + ": " + row.IssuerCN)
			.AppendLine(GlobalVars.GetStr("NotBeforeHeader/Text") + ": " + row.NotBefore)
			.AppendLine(GlobalVars.GetStr("NotAfterHeader/Text") + ": " + row.NotAfter)
			.AppendLine(GlobalVars.GetStr("HashingAlgorithmHeader/Text") + ": " + row.HashingAlgorithm)
			.AppendLine(GlobalVars.GetStr("SerialNumberHeader/Text") + ": " + row.SerialNumber)
			.AppendLine(GlobalVars.GetStr("ThumbprintHeader/Text") + ": " + row.Thumbprint)
			.AppendLine(GlobalVars.GetStr("TBSHashHeader/Text") + ": " + row.TBSHash)
			.AppendLine(GlobalVars.GetStr("ExtensionOIDsHeader/Text") + ": " + row.OIDs)
			.ToString();
	}

	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	internal void ListViewFlyoutMenuCopy_Click()
	{
		// Get the ListView ScrollViewer info
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.View_File_Certificates);

		if (lv is null) return;

		// Check if there are selected items in the ListView
		if (lv.SelectedItems.Count > 0)
		{
			// Initialize StringBuilder to store all selected rows' data with labels
			StringBuilder dataBuilder = new();

			// Loop through each selected item in the ListView
			foreach (var selectedItem in lv.SelectedItems)
			{
				if (selectedItem is FileCertificateInfoCol obj)

					// Append each row's formatted data to the StringBuilder
					_ = dataBuilder.AppendLine(ConvertRowToText(obj));

				// Add a separator between rows for readability in multi-row copies
				_ = dataBuilder.AppendLine(ListViewHelper.DefaultDelimiter);
			}

			ClipboardManagement.CopyText(dataBuilder.ToString());
		}
	}

	/// <summary>
	/// Helper method to copy a specified property to clipboard without reflection
	/// </summary>
	/// <param name="getProperty">Function that retrieves the desired property value as a string</param>
	private void CopyToClipboard(Func<FileCertificateInfoCol, string?> getProperty)
	{
		// Get the ListView ScrollViewer info
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.View_File_Certificates);

		if (lv is null) return;

		if (lv.SelectedItem is FileCertificateInfoCol selectedItem)
		{
			string? propertyValue = getProperty(selectedItem);
			if (propertyValue is not null)
			{
				ClipboardManagement.CopyText(propertyValue);
			}
		}
	}

	// Click event handlers for each property
	internal void CopySignerNumber_Click() => CopyToClipboard((item) => item.SignerNumber.ToString());
	internal void CopyType_Click() => CopyToClipboard((item) => item.Type.ToString());
	internal void CopySubjectCommonName_Click() => CopyToClipboard((item) => item.SubjectCN);
	internal void CopyIssuerCommonName_Click() => CopyToClipboard((item) => item.IssuerCN);
	internal void CopyNotBefore_Click() => CopyToClipboard((item) => item.NotBefore.ToString());
	internal void CopyNotAfter_Click() => CopyToClipboard((item) => item.NotAfter.ToString());
	internal void CopyHashingAlgorithm_Click() => CopyToClipboard((item) => item.HashingAlgorithm);
	internal void CopySerialNumber_Click() => CopyToClipboard((item) => item.SerialNumber);
	internal void CopyThumbprint_Click() => CopyToClipboard((item) => item.Thumbprint);
	internal void CopyTBSHash_Click() => CopyToClipboard((item) => item.TBSHash);
	internal void CopyExtensionOIDs_Click() => CopyToClipboard((item) => item.OIDs);

	#endregion


	/// <summary>
	/// Get the certificates of the .CIP files
	/// </summary>
	/// <param name="file"></param>
	/// <returns></returns>
	private async Task<List<FileCertificateInfoCol>> FetchForCIP(string file)
	{
		List<FileCertificateInfoCol> output = [];

		try
		{
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
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);

			return output;
		}
	}


	/// <summary>
	/// Fetch for the .cer files
	/// </summary>
	/// <param name="file"></param>
	/// <returns></returns>
	private async Task<List<FileCertificateInfoCol>> FetchForCER(string file)
	{
		List<FileCertificateInfoCol> output = [];

		try
		{
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
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);

			return output;
		}
	}

	/// <summary>
	/// The main method that performs data collection task
	/// </summary>
	/// <param name="file"></param>
	/// <returns></returns>
	private async Task Fetch()
	{
		if (string.IsNullOrWhiteSpace(selectedFile))
		{
			return;
		}

		MainInfoBarIsClosable = false;

		AreElementsEnabled = false;

		// A List to return at the end
		List<FileCertificateInfoCol> output = [];

		try
		{
			MainInfoBar.WriteInfo(GlobalVars.GetStr("CheckingForFileSignatures"));

			// Get the file's extension
			string fileExtension = Path.GetExtension(selectedFile);

			// Perform different operations for .CIP files
			if (string.Equals(fileExtension, ".cip", StringComparison.OrdinalIgnoreCase))
			{
				// Get the results
				output = await FetchForCIP(selectedFile);
			}

			else if (string.Equals(fileExtension, ".cer", StringComparison.OrdinalIgnoreCase))
			{
				// Get the results
				output = await FetchForCER(selectedFile);
			}

			// For any other files
			else
			{
				await Task.Run(() =>
				{
					// Get all of the file's certificates
					List<AllFileSigners> signerDetails = AllCertificatesGrabber.GetAllFileSigners(selectedFile);

					// If the file has no signers and the user wants to include security catalogs
					if (signerDetails.Count is 0 && IncludeSecurityCatalogsToggleSwitch)
					{
						// Get the security catalog data to include in the scan
						ConcurrentDictionary<string, string> AllSecurityCatalogHashes = CatRootScanner.Scan(null, 5);

						// Grab the file's Code Integrity hashes
						CodeIntegrityHashes fileHashes = CiFileHash.GetCiFileHashes(selectedFile);

						if (AllSecurityCatalogHashes.TryGetValue(fileHashes.SHa1Authenticode!, out string? CurrentFilePathHashSHA1CatResult))
						{
							try
							{
								signerDetails = AllCertificatesGrabber.GetAllFileSigners(CurrentFilePathHashSHA1CatResult);
							}
							catch (HashMismatchInCertificateException)
							{
								Logger.Write(
									string.Format(
										GlobalVars.GetStr("FileHasHashMismatchMessage"),
										selectedFile
									)
								);
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
								Logger.Write(
									string.Format(
										GlobalVars.GetStr("FileHasHashMismatchMessage"),
										selectedFile
									)
								);
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
			}

			// Add the results to the collection
			FileCertificates.Clear();
			FilteredCertificates.Clear();

			FilteredCertificates.AddRange(output);

			foreach (FileCertificateInfoCol item in output)
			{
				item.ParentViewModel = this;
				FileCertificates.Add(item);
			}

			CalculateColumnWidths();

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("FileCertificatesScanResultMessage"), selectedFile, (FilteredCertificates.Count > 0 ? FilteredCertificates.Max(x => x.SignerNumber) : 0), (IncludeSecurityCatalogsToggleSwitch ? GlobalVars.GetStr("IncludedText") : GlobalVars.GetStr("NotIncludedText"))));

			await PublishUserActivityAsync(LaunchProtocolActions.FileSignature,
				selectedFile,
				GlobalVars.GetStr("UserActivityNameForFileSignature"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			AreElementsEnabled = true;
			MainInfoBarIsClosable = true;
		}
	}

	/// <summary>
	/// Called by the UI element in the page.
	/// </summary>
	internal async void BrowseForFilesSettingsCard_Click()
	{
		selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.AnyFilePickerFilter);

		await Fetch();
	}

	/// <summary>
	/// Used by any code from the app to use the functionalities in this VM.
	/// </summary>
	/// <param name="filePath"></param>
	/// <returns></returns>
	internal async Task OpenInViewFileCertificatesVM(string filePath)
	{
		try
		{
			// Navigate to the View File Certificates page
			App._nav.Navigate(typeof(Pages.ViewFileCertificates), null);

			selectedFile = filePath;

			await Fetch();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// CTRL + C shortcuts event handler
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	internal void CtrlC_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		ListViewFlyoutMenuCopy_Click();
		args.Handled = true;
	}
}
