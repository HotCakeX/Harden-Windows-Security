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
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SimulationMethods;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

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

		CalculateColumnWidths();
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
			if (SPT(ref field, value))
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
		ScrollViewer? Sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.View_File_Certificates);

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

	private ListViewHelper.SortState SortState { get; set; } = new();

	// Pre‑computed property getters for high performance.
	// Used for column sorting and column copying (single cell and entire row), for all ListViews that display FileCertificateInfoCol data type
	private static readonly FrozenDictionary<string, (string Label, Func<FileCertificateInfoCol, object?> Getter)> FileCertificateInfoColPropertyMappings
		= new Dictionary<string, (string Label, Func<FileCertificateInfoCol, object?> Getter)>
		{
			{ "SignerNumber",      (GlobalVars.GetStr("SignerNumberHeader/Text") + ": ",      fc => fc.SignerNumber) },
			{ "Type",              (GlobalVars.GetStr("TypeHeader/Text") + ": ",              fc => fc.Type) },
			{ "SubjectCN",         (GlobalVars.GetStr("SubjectCommonNameHeader/Text") + ": ", fc => fc.SubjectCN) },
			{ "IssuerCN",          (GlobalVars.GetStr("IssuerCommonNameHeader/Text") + ": ",  fc => fc.IssuerCN) },
			{ "NotBefore",         (GlobalVars.GetStr("NotBeforeHeader/Text") + ": ",         fc => fc.NotBefore) },
			{ "NotAfter",          (GlobalVars.GetStr("NotAfterHeader/Text") + ": ",          fc => fc.NotAfter) },
			{ "HashingAlgorithm",  (GlobalVars.GetStr("HashingAlgorithmHeader/Text") + ": ",  fc => fc.HashingAlgorithm) },
			{ "SerialNumber",      (GlobalVars.GetStr("SerialNumberHeader/Text") + ": ",      fc => fc.SerialNumber) },
			{ "Thumbprint",        (GlobalVars.GetStr("ThumbprintHeader/Text") + ": ",        fc => fc.Thumbprint) },
			{ "TBSHash",           (GlobalVars.GetStr("TBSHashHeader/Text") + ": ",           fc => fc.TBSHash) },
			{ "OIDs",              (GlobalVars.GetStr("ExtensionOIDsHeader/Text") + ": ",     fc => fc.OIDs) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	internal void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			// Look up the mapping in the reusable property mappings dictionary.
			if (FileCertificateInfoColPropertyMappings.TryGetValue(key, out (string Label, Func<FileCertificateInfoCol, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					mapping.Getter,
					SearchBoxTextBox,
					FilteredCertificates,
					FileCertificates,
					SortState,
					key,
					regKey: ListViewHelper.ListViewsRegistry.View_File_Certificates);
			}
		}
	}

	#endregion


	#region Copy

	/// <summary>
	/// Converts the properties of a FileCertificateInfoCol row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	internal void CopySelectedPolicies_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.View_File_Certificates);

		if (lv is null) return;

		if (lv.SelectedItems.Count > 0)
		{
			// SelectedItems is an IList, and contains FileCertificateInfoCol
			ListViewHelper.ConvertRowToText(lv.SelectedItems, FileCertificateInfoColPropertyMappings);
		}
	}

	/// <summary>
	/// Copy a single property of the current selection
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void CopyPolicyProperty_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;
		string key = (string)menuItem.Tag;

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.View_File_Certificates);

		if (lv is null) return;

		if (FileCertificateInfoColPropertyMappings.TryGetValue(key, out var map))
		{
			// TElement = FileCertificateInfoCol, copy just that one property
			ListViewHelper.CopyToClipboard<FileCertificateInfoCol>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}

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
}
