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

using System.Collections.Concurrent;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SimulationMethods;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.ApplicationModel.DataTransfer;
using Windows.Storage;

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
			Dispatcher, null, null);

		// To adjust the initial width of the columns, giving them nice paddings.
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

	// Properties for the CMS section
	internal int RawCmsDataLength { get; set => SP(ref field, value); }
	internal int ContentInfoDataLength { get; set => SP(ref field, value); }
	internal int CmsVersion { get; set => SP(ref field, value); }
	internal bool IsDetached { get; set => SP(ref field, value); }
	internal string? ContentTypeOid { get; set => SP(ref field, value); }
	internal string? ContentTypeFriendlyName { get; set => SP(ref field, value); }

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
	internal GridLength ColumnWidth12 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth13 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth14 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth15 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth16 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth17 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth18 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth19 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth20 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth21 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth22 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth23 { get; set => SP(ref field, value); }

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
		double maxWidth12 = ListViewHelper.MeasureText(GlobalVars.GetStr("VersionHeader/Text"));
		double maxWidth13 = ListViewHelper.MeasureText(GlobalVars.GetStr("HasPrivateKeyHeader/Text"));
		double maxWidth14 = ListViewHelper.MeasureText(GlobalVars.GetStr("ArchivedHeader/Text"));
		double maxWidth15 = ListViewHelper.MeasureText(GlobalVars.GetStr("CertificatePoliciesHeader/Text"));
		double maxWidth16 = ListViewHelper.MeasureText(GlobalVars.GetStr("AuthorityInformationAccessHeader/Text"));
		double maxWidth17 = ListViewHelper.MeasureText(GlobalVars.GetStr("CRLDistributionPointsHeader/Text"));
		double maxWidth18 = ListViewHelper.MeasureText(GlobalVars.GetStr("BasicConstraintsHeader/Text"));
		double maxWidth19 = ListViewHelper.MeasureText(GlobalVars.GetStr("KeyUsageHeader/Text"));
		double maxWidth20 = ListViewHelper.MeasureText(GlobalVars.GetStr("AuthorityKeyIdentifierHeader/Text"));
		double maxWidth21 = ListViewHelper.MeasureText(GlobalVars.GetStr("SubjectKeyIdentifierHeader/Text"));
		double maxWidth22 = ListViewHelper.MeasureText(GlobalVars.GetStr("RawDataLengthHeader/Text"));
		double maxWidth23 = ListViewHelper.MeasureText(GlobalVars.GetStr("PublicKeyLengthHeader/Text"));

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
			maxWidth12 = ListViewHelper.MeasureText(item.Version?.ToString(), maxWidth12);
			maxWidth13 = ListViewHelper.MeasureText(item.HasPrivateKey?.ToString(), maxWidth13);
			maxWidth14 = ListViewHelper.MeasureText(item.Archived?.ToString(), maxWidth14);
			maxWidth15 = ListViewHelper.MeasureText(item.CertificatePolicies, maxWidth15);
			maxWidth16 = ListViewHelper.MeasureText(item.AuthorityInformationAccess, maxWidth16);
			maxWidth17 = ListViewHelper.MeasureText(item.CRLDistributionPoints, maxWidth17);
			maxWidth18 = ListViewHelper.MeasureText(item.BasicConstraints, maxWidth18);
			maxWidth19 = ListViewHelper.MeasureText(item.KeyUsage, maxWidth19);
			maxWidth20 = ListViewHelper.MeasureText(item.AuthorityKeyIdentifier, maxWidth20);
			maxWidth21 = ListViewHelper.MeasureText(item.SubjectKeyIdentifier, maxWidth21);
			maxWidth22 = ListViewHelper.MeasureText(item.RawDataLength.ToString(), maxWidth22);
			maxWidth23 = ListViewHelper.MeasureText(item.PublicKeyLength.ToString(), maxWidth23);
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
		ColumnWidth22 = new GridLength(maxWidth22);
		ColumnWidth23 = new GridLength(maxWidth23);
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
					(cert.Thumbprint is not null && cert.Thumbprint.Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					(cert.Version?.ToString() is not null && cert.Version.Value.ToString().Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					(cert.HasPrivateKey?.ToString() is not null && cert.HasPrivateKey.Value.ToString().Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					(cert.Archived?.ToString() is not null && cert.Archived.Value.ToString().Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					(cert.CertificatePolicies is not null && cert.CertificatePolicies.Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					(cert.AuthorityInformationAccess is not null && cert.AuthorityInformationAccess.Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					(cert.CRLDistributionPoints is not null && cert.CRLDistributionPoints.Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					(cert.BasicConstraints is not null && cert.BasicConstraints.Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					(cert.KeyUsage is not null && cert.KeyUsage.Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					(cert.AuthorityKeyIdentifier is not null && cert.AuthorityKeyIdentifier.Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					(cert.SubjectKeyIdentifier is not null && cert.SubjectKeyIdentifier.Contains(query, StringComparison.OrdinalIgnoreCase)) ||
					cert.RawDataLength.ToString().Contains(query, StringComparison.OrdinalIgnoreCase) ||
					cert.PublicKeyLength.ToString().Contains(query, StringComparison.OrdinalIgnoreCase)
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
			{ "OIDs",              (GlobalVars.GetStr("ExtensionOIDsHeader/Text") + ": ",     fc => fc.OIDs) },
			{ "Version",           (GlobalVars.GetStr("VersionHeader/Text") + ": ",           fc => fc.Version) },
			{ "HasPrivateKey",     (GlobalVars.GetStr("HasPrivateKeyHeader/Text") + ": ",     fc => fc.HasPrivateKey) },
			{ "Archived",          (GlobalVars.GetStr("ArchivedHeader/Text") + ": ",          fc => fc.Archived) },
			{ "CertificatePolicies",(GlobalVars.GetStr("CertificatePoliciesHeader/Text") + ": ", fc => fc.CertificatePolicies) },
			{ "AuthorityInformationAccess", (GlobalVars.GetStr("AuthorityInformationAccessHeader/Text") + ": ", fc => fc.AuthorityInformationAccess) },
			{ "CRLDistributionPoints", (GlobalVars.GetStr("CRLDistributionPointsHeader/Text") + ": ", fc => fc.CRLDistributionPoints) },
			{ "BasicConstraints",  (GlobalVars.GetStr("BasicConstraintsHeader/Text") + ": ",  fc => fc.BasicConstraints) },
			{ "KeyUsage",          (GlobalVars.GetStr("KeyUsageHeader/Text") + ": ",          fc => fc.KeyUsage) },
			{ "AuthorityKeyIdentifier", (GlobalVars.GetStr("AuthorityKeyIdentifierHeader/Text") + ": ", fc => fc.AuthorityKeyIdentifier) },
			{ "SubjectKeyIdentifier", (GlobalVars.GetStr("SubjectKeyIdentifierHeader/Text") + ": ", fc => fc.SubjectKeyIdentifier) },
			{ "RawDataLength",     (GlobalVars.GetStr("RawDataLengthHeader/Text") + ": ",     fc => fc.RawDataLength) },
			{ "PublicKeyLength",   (GlobalVars.GetStr("PublicKeyLengthHeader/Text") + ": ",   fc => fc.PublicKeyLength) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	internal void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			// Look up the mapping in the reusable property mappings dictionary.
			if (FileCertificateInfoColPropertyMappings.TryGetValue(key, out (string Label, Func<FileCertificateInfoCol, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					keySelector: mapping.Getter,
					searchBoxText: SearchBoxTextBox,
					originalList: FilteredCertificates,
					observableCollection: FileCertificates,
					sortState: SortState,
					newKey: key,
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
					// Extract additional details similar to the comparer
					(int? Version, bool? HasPrivateKey, bool? Archived, string? CertificatePolicies, string? AuthorityInformationAccess, string? CrlDistributionPoints, string? BasicConstraints, string? KeyUsage, string? AuthorityKeyIdentifier, string? SubjectKeyIdentifier, int RawDataLength, int PublicKeyLength) det
						= ExtractDetailedFields(signer);

					output.Add(new FileCertificateInfoCol
					(
						signerNumber: i,
						type: CertificateType.Leaf,
						subjectCN: CryptoAPI.GetNameString(signer.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false), // SubjectCN
						issuerCN: CryptoAPI.GetNameString(signer.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true), // IssuerCN
						notBefore: signer.NotBefore,
						notAfter: signer.NotAfter,
						hashingAlgorithm: signer.SignatureAlgorithm.FriendlyName,
						serialNumber: signer.SerialNumber,
						thumbprint: signer.Thumbprint,
						tBSHash: CertificateHelper.GetTBSCertificate(signer),
						oIDs: string.Join(", ", signer.Extensions
								.Select(ext =>
									ext.Oid is not null ? $"{ext.Oid.Value} ({ext.Oid.FriendlyName})" : ext?.Oid?.Value)
								.Where(oid => !string.IsNullOrWhiteSpace(oid))),
						version: det.Version,
						hasPrivateKey: det.HasPrivateKey,
						archived: det.Archived,
						certificatePolicies: det.CertificatePolicies,
						authorityInformationAccess: det.AuthorityInformationAccess,
						crlDistributionPoints: det.CrlDistributionPoints,
						basicConstraints: det.BasicConstraints,
						keyUsage: det.KeyUsage,
						authorityKeyIdentifier: det.AuthorityKeyIdentifier,
						subjectKeyIdentifier: det.SubjectKeyIdentifier,
						rawDataLength: det.RawDataLength,
						publicKeyLength: det.PublicKeyLength
					));

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

				// Extract additional details similar to the comparer
				(int? Version, bool? HasPrivateKey, bool? Archived, string? CertificatePolicies, string? AuthorityInformationAccess, string? CrlDistributionPoints, string? BasicConstraints, string? KeyUsage, string? AuthorityKeyIdentifier, string? SubjectKeyIdentifier, int RawDataLength, int PublicKeyLength) det
					= ExtractDetailedFields(CertObject);

				// Add the certificate as leaf certificate
				output.Add(new FileCertificateInfoCol
				(
					signerNumber: 1,
					type: CertificateType.Leaf,
					subjectCN: CryptoAPI.GetNameString(CertObject.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false), // SubjectCN
					issuerCN: CryptoAPI.GetNameString(CertObject.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, true), // IssuerCN
					notBefore: CertObject.NotBefore,
					notAfter: CertObject.NotAfter,
					hashingAlgorithm: CertObject.SignatureAlgorithm.FriendlyName,
					serialNumber: CertObject.SerialNumber,
					thumbprint: CertObject.Thumbprint,
					tBSHash: CertificateHelper.GetTBSCertificate(CertObject),
					oIDs: string.Join(", ", CertObject.Extensions
							.Select(ext =>
								ext.Oid is not null ? $"{ext.Oid.Value} ({ext.Oid.FriendlyName})" : ext?.Oid?.Value)
							.Where(oid => !string.IsNullOrWhiteSpace(oid))),
					version: det.Version,
					hasPrivateKey: det.HasPrivateKey,
					archived: det.Archived,
					certificatePolicies: det.CertificatePolicies,
					authorityInformationAccess: det.AuthorityInformationAccess,
					crlDistributionPoints: det.CrlDistributionPoints,
					basicConstraints: det.BasicConstraints,
					keyUsage: det.KeyUsage,
					authorityKeyIdentifier: det.AuthorityKeyIdentifier,
					subjectKeyIdentifier: det.SubjectKeyIdentifier,
					rawDataLength: det.RawDataLength,
					publicKeyLength: det.PublicKeyLength
				));

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

				try
				{
					byte[] bytes = await File.ReadAllBytesAsync(selectedFile);
					SignedCms cms = new();
					cms.Decode(bytes.AsSpan());
					RawCmsDataLength = bytes.Length;
					ContentInfoDataLength = cms.ContentInfo.Content.Length;
					CmsVersion = cms.Version;
					IsDetached = cms.Detached;
					ContentTypeOid = cms.ContentInfo.ContentType.Value;
					ContentTypeFriendlyName = cms.ContentInfo.ContentType.FriendlyName;
				}
				catch
				{
					RawCmsDataLength = 0;
					ContentInfoDataLength = 0;
					CmsVersion = 0;
					IsDetached = false;
					ContentTypeOid = null;
					ContentTypeFriendlyName = null;
				}
			}

			else if (string.Equals(fileExtension, ".cer", StringComparison.OrdinalIgnoreCase))
			{
				// Get the results
				output = await FetchForCER(selectedFile);

				RawCmsDataLength = 0;
				ContentInfoDataLength = 0;
				CmsVersion = 0;
				IsDetached = false;
				ContentTypeOid = null;
				ContentTypeFriendlyName = null;
			}

			// For any other files
			else
			{
				await Task.Run(() =>
				{
					List<AllFileSigners> signerDetails = [];
					try
					{
						// Get all of the file's certificates
						signerDetails = AllCertificatesGrabber.GetAllFileSigners(selectedFile);

						// If the file has no signers and the user wants to include security catalogs
						if (signerDetails.Count is 0 && IncludeSecurityCatalogsToggleSwitch)
						{
							// Get the security catalog data to include in the scan
							ConcurrentDictionary<string, string> AllSecurityCatalogHashes = CatRootScanner.Scan(null, 5);

							// Grab the file's Code Integrity hashes
							CodeIntegrityHashes fileHashes = CiFileHash.GetCiFileHashes(selectedFile);

							if (AllSecurityCatalogHashes.TryGetValue(fileHashes.SHA1Authenticode!, out string? CurrentFilePathHashSHA1CatResult))
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
								X509Certificate2 LeafCert = signer.LeafCertificate.Certificate;

								(int? Version, bool? HasPrivateKey, bool? Archived, string? CertificatePolicies, string? AuthorityInformationAccess, string? CrlDistributionPoints, string? BasicConstraints, string? KeyUsage, string? AuthorityKeyIdentifier, string? SubjectKeyIdentifier, int RawDataLength, int PublicKeyLength) det
									= ExtractDetailedFields(LeafCert);

								output.Add(new FileCertificateInfoCol
								(
									signerNumber: i,
									type: CertificateType.Leaf,
									subjectCN: signer.LeafCertificate.SubjectCN,
									issuerCN: signer.LeafCertificate.IssuerCN,
									notBefore: signer.LeafCertificate.NotBefore,
									notAfter: signer.LeafCertificate.NotAfter,
									hashingAlgorithm: LeafCert.SignatureAlgorithm.FriendlyName,
									serialNumber: LeafCert.SerialNumber,
									thumbprint: LeafCert.Thumbprint,
									tBSHash: signer.LeafCertificate.TBSValue,
									oIDs: string.Join(", ", LeafCert.Extensions
										.Select(ext =>
											ext.Oid is not null ? $"{ext.Oid.Value} ({ext.Oid.FriendlyName})" : ext?.Oid?.Value)
										.Where(oid => !string.IsNullOrWhiteSpace(oid))),
									version: det.Version,
									hasPrivateKey: det.HasPrivateKey,
									archived: det.Archived,
									certificatePolicies: det.CertificatePolicies,
									authorityInformationAccess: det.AuthorityInformationAccess,
									crlDistributionPoints: det.CrlDistributionPoints,
									basicConstraints: det.BasicConstraints,
									keyUsage: det.KeyUsage,
									authorityKeyIdentifier: det.AuthorityKeyIdentifier,
									subjectKeyIdentifier: det.SubjectKeyIdentifier,
									rawDataLength: det.RawDataLength,
									publicKeyLength: det.PublicKeyLength
								));
							}

							// If the signer has any Intermediate Certificates
							if (signer.IntermediateCertificates is not null)
							{
								// Loop over Intermediate certificates of the file
								foreach (ChainElement intermediate in signer.IntermediateCertificates)
								{
									X509Certificate2 IntCert = intermediate.Certificate;

									(int? Version, bool? HasPrivateKey, bool? Archived, string? CertificatePolicies, string? AuthorityInformationAccess, string? CrlDistributionPoints, string? BasicConstraints, string? KeyUsage, string? AuthorityKeyIdentifier, string? SubjectKeyIdentifier, int RawDataLength, int PublicKeyLength) det
										= ExtractDetailedFields(IntCert);

									output.Add(new FileCertificateInfoCol
									(
										signerNumber: i,
										type: CertificateType.Intermediate,
										subjectCN: intermediate.SubjectCN,
										issuerCN: intermediate.IssuerCN,
										notBefore: intermediate.NotBefore,
										notAfter: intermediate.NotAfter,
										hashingAlgorithm: IntCert.SignatureAlgorithm.FriendlyName,
										serialNumber: IntCert.SerialNumber,
										thumbprint: IntCert.Thumbprint,
										tBSHash: intermediate.TBSValue,
										oIDs: string.Join(", ", IntCert.Extensions
											.Select(ext =>
												ext.Oid is not null ? $"{ext.Oid.Value} ({ext.Oid.FriendlyName})" : ext?.Oid?.Value)
											.Where(oid => !string.IsNullOrWhiteSpace(oid))),
										version: det.Version,
										hasPrivateKey: det.HasPrivateKey,
										archived: det.Archived,
										certificatePolicies: det.CertificatePolicies,
										authorityInformationAccess: det.AuthorityInformationAccess,
										crlDistributionPoints: det.CrlDistributionPoints,
										basicConstraints: det.BasicConstraints,
										keyUsage: det.KeyUsage,
										authorityKeyIdentifier: det.AuthorityKeyIdentifier,
										subjectKeyIdentifier: det.SubjectKeyIdentifier,
										rawDataLength: det.RawDataLength,
										publicKeyLength: det.PublicKeyLength
									));
								}
							}

							// Add the root certificate
							{
								X509Certificate2 RootCert = signer.RootCertificate.Certificate;

								(int? Version, bool? HasPrivateKey, bool? Archived, string? CertificatePolicies, string? AuthorityInformationAccess, string? CrlDistributionPoints, string? BasicConstraints, string? KeyUsage, string? AuthorityKeyIdentifier, string? SubjectKeyIdentifier, int RawDataLength, int PublicKeyLength) det
									= ExtractDetailedFields(RootCert);

								output.Add(new FileCertificateInfoCol
								(
									signerNumber: i,
									type: CertificateType.Root,
									subjectCN: signer.RootCertificate.SubjectCN,
									issuerCN: signer.RootCertificate.SubjectCN, // Issuer is itself for Root certificate type
									notBefore: signer.RootCertificate.NotBefore,
									notAfter: signer.RootCertificate.NotAfter,
									hashingAlgorithm: RootCert.SignatureAlgorithm.FriendlyName,
									serialNumber: RootCert.SerialNumber,
									thumbprint: RootCert.Thumbprint,
									tBSHash: signer.RootCertificate.TBSValue,
									oIDs: string.Join(", ", RootCert.Extensions
									.Select(ext =>
										ext.Oid is not null ? $"{ext.Oid.Value} ({ext.Oid.FriendlyName})" : ext?.Oid?.Value)
									.Where(oid => !string.IsNullOrWhiteSpace(oid))),
									version: det.Version,
									hasPrivateKey: det.HasPrivateKey,
									archived: det.Archived,
									certificatePolicies: det.CertificatePolicies,
									authorityInformationAccess: det.AuthorityInformationAccess,
									crlDistributionPoints: det.CrlDistributionPoints,
									basicConstraints: det.BasicConstraints,
									keyUsage: det.KeyUsage,
									authorityKeyIdentifier: det.AuthorityKeyIdentifier,
									subjectKeyIdentifier: det.SubjectKeyIdentifier,
									rawDataLength: det.RawDataLength,
									publicKeyLength: det.PublicKeyLength
								));
							}

							// Increase the counter
							i++;
						}
					}
					finally
					{
						// Disposing AllFileSigners to release X509Chain native resources
						// after extracting all needed certificate/chain information.
						foreach (AllFileSigners signer in signerDetails)
						{
							signer.Dispose();
						}
					}
				});

				RawCmsDataLength = 0;
				ContentInfoDataLength = 0;
				CmsVersion = 0;
				IsDetached = false;
				ContentTypeOid = null;
				ContentTypeFriendlyName = null;
			}

			// Add the results to the collection
			FileCertificates.Clear();
			FilteredCertificates.Clear();

			FilteredCertificates.AddRange(output);

			foreach (FileCertificateInfoCol item in output)
			{
				FileCertificates.Add(item);
			}

			CalculateColumnWidths();

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("FileCertificatesScanResultMessage"), selectedFile, FilteredCertificates.Count > 0 ? FilteredCertificates.Max(x => x.SignerNumber) : 0, IncludeSecurityCatalogsToggleSwitch ? GlobalVars.GetStr("IncludedText") : GlobalVars.GetStr("NotIncludedText")));

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
	/// DragOver handler.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void OnDragOver(object sender, DragEventArgs e)
	{
		if (e.DataView.Contains(StandardDataFormats.StorageItems))
		{
			e.AcceptedOperation = DataPackageOperation.Copy;
			e.DragUIOverride.Caption = GlobalVars.GetStr("DragAndDropHintViewFileCertificatesCaption");
			e.DragUIOverride.IsCaptionVisible = true;
			e.DragUIOverride.IsContentVisible = true;
		}
		else
		{
			e.AcceptedOperation = DataPackageOperation.None;
		}
	}

	/// <summary>
	/// Drop handler, triggers Fetch().
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal async void OnDrop(object sender, DragEventArgs e)
	{
		if (e.DataView.Contains(StandardDataFormats.StorageItems))
		{
			try
			{
				IReadOnlyList<IStorageItem> items = await e.DataView.GetStorageItemsAsync();

				if (items.Count > 0 && items[0] is StorageFile file)
				{
					selectedFile = file.Path;
					await Fetch();
				}
			}
			catch (Exception ex)
			{
				MainInfoBar.WriteError(ex);
			}
		}
	}

	/// <summary>
	/// Used by any code from the app to use the functionalities in this VM.
	/// </summary>
	/// <param name="filePath"></param>
	/// <returns></returns>
	internal async Task OpenInViewFileCertificatesVM(string? filePath)
	{
		try
		{
			// Navigate to the View File Certificates page
			ViewModelProvider.NavigationService.Navigate(typeof(Pages.ViewFileCertificates), null);

			selectedFile = filePath;

			await Fetch();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Retrieves detailed fields from an X509Certificate2 object.
	/// </summary>
	/// <param name="cert"></param>
	/// <returns></returns>
	private static (int? Version, bool? HasPrivateKey, bool? Archived, string? CertificatePolicies, string? AuthorityInformationAccess, string? CrlDistributionPoints, string? BasicConstraints, string? KeyUsage, string? AuthorityKeyIdentifier, string? SubjectKeyIdentifier, int RawDataLength, int PublicKeyLength) ExtractDetailedFields(X509Certificate2 cert)
	{
		int? version = cert?.Version;
		bool? hasPrivateKey = cert?.HasPrivateKey;
		bool? archived = cert?.Archived;
		string? certificatePolicies = null;
		string? authorityInformationAccess = null;
		string? crlDistributionPoints = null;
		string? basicConstraints = null;
		string? keyUsage = null;
		string? authorityKeyIdentifier = null;
		string? subjectKeyIdentifier = null;
		int rawDataLength = cert?.RawData?.Length ?? 0;

		int publicKeyLength = 0;
		try
		{
			if (cert?.PublicKey?.Oid?.Value == "1.2.840.113549.1.1.1")
			{
				using RSA? rsa = cert.GetRSAPublicKey();
				if (rsa != null)
				{
					publicKeyLength = rsa.KeySize;
				}
			}
			else if (cert?.PublicKey?.Oid?.Value == "1.2.840.10045.2.1")
			{
				using ECDsa? ecdsa = cert.GetECDsaPublicKey();
				if (ecdsa != null)
				{
					publicKeyLength = ecdsa.KeySize;
				}
			}
			else
			{
				using DSA? dsa = cert?.GetDSAPublicKey();
				if (dsa != null)
				{
					publicKeyLength = dsa.KeySize;
				}

				if (publicKeyLength == 0)
				{
					using ECDiffieHellman? ecdh = cert?.GetECDiffieHellmanPublicKey();
					if (ecdh != null)
					{
						publicKeyLength = ecdh.KeySize;
					}
				}
			}
		}
		catch
		{
			publicKeyLength = 0;
		}

		try
		{
			if (cert is not null)
			{
				foreach (X509Extension ext in cert.Extensions)
				{
					if (ext.Oid?.Value is null)
					{
						continue;
					}

					if (string.Equals(ext.Oid.Value, "2.5.29.37", StringComparison.OrdinalIgnoreCase))
					{
						try
						{
							X509EnhancedKeyUsageExtension ekuExt = new(ext, ext.Critical);
							keyUsage = ekuExt.Format(false);
						}
						catch { }
					}
					else if (string.Equals(ext.Oid.Value, "2.5.29.15", StringComparison.OrdinalIgnoreCase))
					{
						try
						{
							X509KeyUsageExtension kuExt = new(ext, ext.Critical);
							keyUsage = kuExt.Format(false);
						}
						catch { }
					}
					else if (string.Equals(ext.Oid.Value, "2.5.29.19", StringComparison.OrdinalIgnoreCase))
					{
						try
						{
							X509BasicConstraintsExtension bcExt = new(ext, ext.Critical);
							basicConstraints = $"CA: {bcExt.CertificateAuthority}, PathLengthConstraint: {(bcExt.HasPathLengthConstraint ? bcExt.PathLengthConstraint.ToString() : "None")}";
						}
						catch { }
					}
					else if (string.Equals(ext.Oid.Value, "2.5.29.35", StringComparison.OrdinalIgnoreCase))
					{
						try
						{
							authorityKeyIdentifier = Convert.ToHexString(ext.RawData);
						}
						catch { }
					}
					else if (string.Equals(ext.Oid.Value, "2.5.29.14", StringComparison.OrdinalIgnoreCase))
					{
						try
						{
							X509SubjectKeyIdentifierExtension skiExt = new(ext, ext.Critical);
							subjectKeyIdentifier = skiExt.SubjectKeyIdentifier;
						}
						catch { }
					}
					else if (string.Equals(ext.Oid.Value, "2.5.29.31", StringComparison.OrdinalIgnoreCase))
					{
						try
						{
							crlDistributionPoints = ext.Format(false);
						}
						catch { }
					}
					else if (string.Equals(ext.Oid.Value, "1.3.6.1.5.5.7.1.1", StringComparison.OrdinalIgnoreCase))
					{
						try
						{
							authorityInformationAccess = ext.Format(false);
						}
						catch { }
					}
					else if (string.Equals(ext.Oid.Value, "2.5.29.32", StringComparison.OrdinalIgnoreCase))
					{
						try
						{
							certificatePolicies = ext.Format(false);
						}
						catch { }
					}
				}
			}
		}
		catch { }

		return (version, hasPrivateKey, archived, certificatePolicies, authorityInformationAccess, crlDistributionPoints, basicConstraints, keyUsage, authorityKeyIdentifier, subjectKeyIdentifier, rawDataLength, publicKeyLength);
	}

	/// <summary>
	/// Exports the displayed data to JSON.
	/// </summary>
	internal async void ExportToJSON()
	{
		try
		{
			AreElementsEnabled = false;
			MainInfoBarIsClosable = false;

			DateTime now = DateTime.Now;
			string formattedDateTime = now.ToString("yyyy-MM-dd_HH-mm-ss");
			string fileName = $"AppControlManager_SignerDataExport_{formattedDateTime}.json";

			string? savePath = FileDialogHelper.ShowSaveFileDialog(GlobalVars.JSONPickerFilter, fileName);

			if (savePath is null)
				return;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("ExportingToJSONMsg"));

			await Task.Run(() =>
			{
				string jsonString = JsonSerializer.Serialize(
					FilteredCertificates,
					FileCertificateInfoColJsonSerializationContext.Default.ListFileCertificateInfoCol);

				File.WriteAllText(savePath, jsonString);
			});

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyExportedDataToJSON"), FilteredCertificates.Count, savePath));
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
}
