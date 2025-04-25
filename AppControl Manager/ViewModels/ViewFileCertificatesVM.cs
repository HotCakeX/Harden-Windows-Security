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
using System.Linq;
using AppControlManager.Others;
using CommunityToolkit.WinUI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.
internal sealed partial class ViewFileCertificatesVM : ViewModelBase
{

	// Main collection assigned to the ListView
	internal readonly ObservableCollection<FileCertificateInfoCol> FileCertificates = [];

	// Collection used during search
	internal readonly List<FileCertificateInfoCol> FilteredCertificates = [];


	#region UI-Bound Properties

	internal string? SearchBoxTextBox
	{
		get; set => SetProperty(ref field, value);
	}

	#endregion

	#region LISTVIEW IMPLEMENTATIONS

	// Properties to hold each columns' width.
	internal GridLength ColumnWidth1
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth2
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth3
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth4
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth5
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth6
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth7
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth8
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth9
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth10
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth11
	{
		get; set => SetProperty(ref field, value);
	}

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// </summary>
	internal void CalculateColumnWidths()
	{
		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SignerNumberHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("TypeHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SubjectCommonNameHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("IssuerCommonNameHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("NotBeforeHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("NotAfterHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("HashingAlgorithmHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SerialNumberHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("ThumbprintHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("TBSHashHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("ExtensionOIDsHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (FileCertificateInfoCol item in FileCertificates)
		{
			double w1 = ListViewHelper.MeasureTextWidth(item.SignerNumber.ToString());
			if (w1 > maxWidth1) maxWidth1 = w1;

			double w2 = ListViewHelper.MeasureTextWidth(item.Type.ToString());
			if (w2 > maxWidth2) maxWidth2 = w2;

			double w3 = ListViewHelper.MeasureTextWidth(item.SubjectCN);
			if (w3 > maxWidth3) maxWidth3 = w3;

			double w4 = ListViewHelper.MeasureTextWidth(item.IssuerCN);
			if (w4 > maxWidth4) maxWidth4 = w4;

			double w5 = ListViewHelper.MeasureTextWidth(item.NotBefore.ToString());
			if (w5 > maxWidth5) maxWidth5 = w5;

			double w6 = ListViewHelper.MeasureTextWidth(item.NotAfter.ToString());
			if (w6 > maxWidth6) maxWidth6 = w6;

			double w7 = ListViewHelper.MeasureTextWidth(item.HashingAlgorithm);
			if (w7 > maxWidth7) maxWidth7 = w7;

			double w8 = ListViewHelper.MeasureTextWidth(item.SerialNumber);
			if (w8 > maxWidth8) maxWidth8 = w8;

			double w9 = ListViewHelper.MeasureTextWidth(item.Thumbprint);
			if (w9 > maxWidth9) maxWidth9 = w9;

			double w10 = ListViewHelper.MeasureTextWidth(item.TBSHash);
			if (w10 > maxWidth10) maxWidth10 = w10;

			double w11 = ListViewHelper.MeasureTextWidth(item.OIDs);
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

}
