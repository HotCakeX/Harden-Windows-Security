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
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using AppControlManager.Others;
using CommunityToolkit.WinUI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812, CA1822 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.
internal sealed partial class ViewFileCertificatesVM : ViewModelBase
{

	// Main collection assigned to the ListView
	internal readonly ObservableCollection<FileCertificateInfoCol> FileCertificates = [];

	// Collection used during search
	internal readonly List<FileCertificateInfoCol> FilteredCertificates = [];


	#region UI-Bound Properties

	internal string? SearchBoxTextBox { get; set => SP(ref field, value); }

	#endregion

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
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SignerNumberHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("TypeHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SubjectCommonNameHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("IssuerCommonNameHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("NotBeforeHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("NotAfterHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("HashingAlgorithmHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SerialNumberHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("ThumbprintHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("TBSHashHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("ExtensionOIDsHeader/Text"));

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


	/// <summary>
	/// Event handler for the search box
	/// </summary>
	internal void SearchBox_TextChanged()
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

		results = [.. FilteredCertificates.Where(cert =>
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

	// Methods bound to each header button’s Click events.
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


	/// <summary>
	/// Converts the properties of a FileCertificateInfoCol row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	/// <param name="row">The selected FileCertificateInfoCol row from the ListView.</param>
	/// <returns>A formatted string of the row's properties with labels.</returns>
	internal string ConvertRowToText(FileCertificateInfoCol row)
	{
		// Use StringBuilder to format each property with its label for easy reading
		return new StringBuilder()
			.AppendLine(GlobalVars.Rizz.GetString("SignerNumberHeader/Text") + ": " + row.SignerNumber)
			.AppendLine(GlobalVars.Rizz.GetString("TypeHeader/Text") + ": " + row.Type)
			.AppendLine(GlobalVars.Rizz.GetString("SubjectCommonNameHeader/Text") + ": " + row.SubjectCN)
			.AppendLine(GlobalVars.Rizz.GetString("IssuerCommonNameHeader/Text") + ": " + row.IssuerCN)
			.AppendLine(GlobalVars.Rizz.GetString("NotBeforeHeader/Text") + ": " + row.NotBefore)
			.AppendLine(GlobalVars.Rizz.GetString("NotAfterHeader/Text") + ": " + row.NotAfter)
			.AppendLine(GlobalVars.Rizz.GetString("HashingAlgorithmHeader/Text") + ": " + row.HashingAlgorithm)
			.AppendLine(GlobalVars.Rizz.GetString("SerialNumberHeader/Text") + ": " + row.SerialNumber)
			.AppendLine(GlobalVars.Rizz.GetString("ThumbprintHeader/Text") + ": " + row.Thumbprint)
			.AppendLine(GlobalVars.Rizz.GetString("TBSHashHeader/Text") + ": " + row.TBSHash)
			.AppendLine(GlobalVars.Rizz.GetString("ExtensionOIDsHeader/Text") + ": " + row.OIDs)
			.ToString();
	}


	/// <summary>
	/// Get the certificates of the .CIP files
	/// </summary>
	/// <param name="file"></param>
	/// <returns></returns>
	internal static async Task<List<FileCertificateInfoCol>> FetchForCIP(string file)
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
	internal static async Task<List<FileCertificateInfoCol>> FetchForCER(string file)
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
}
