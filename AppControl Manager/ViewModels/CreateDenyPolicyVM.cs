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

using System.Collections.Generic;
using System.Collections.ObjectModel;
using AppControlManager.IntelGathering;
using AppControlManager.Others;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.
internal sealed partial class CreateDenyPolicyVM : ViewModelBase
{
	// Used to store the scan results and as the source for the results ListViews
	internal ObservableCollection<FileIdentity> FilesAndFoldersScanResults
	{
		get; set => SetProperty(ref field, value);
	} = [];

	internal readonly List<FileIdentity> filesAndFoldersScanResultsList = [];

	internal ListViewHelper.SortState SortStateFilesAndFolders { get; set; } = new();

	#region UI-Bound Properties

	internal Visibility FilesAndFoldersInfoBarActionButtonVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;

	internal Visibility PFNInfoBarActionButtonVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;

	internal Visibility CustomFilePathRulesInfoBarActionButtonVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;

	internal string TotalCountOfTheFilesTextBox
	{
		get; set => SetProperty(ref field, value);
	} = "Total files: 0";

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

	internal GridLength ColumnWidth12
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth13
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth14
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth15
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth16
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth17
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidth18
	{
		get; set => SetProperty(ref field, value);
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
		double maxWidth1 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FileNameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SignatureStatusHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("OriginalFileNameHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("InternalNameHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FileDescriptionHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("ProductNameHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FileVersionHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("PackageFamilyNameHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA256HashHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA1HashHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SigningScenarioHeader/Text"));
		double maxWidth12 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FilePathHeader/Text"));
		double maxWidth13 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA1PageHashHeader/Text"));
		double maxWidth14 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA256PageHashHeader/Text"));
		double maxWidth15 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("HasWHQLSignerHeader/Text"));
		double maxWidth16 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FilePublishersHeader/Text"));
		double maxWidth17 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("IsECCSignedHeader/Text"));
		double maxWidth18 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("OpusDataHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (FileIdentity item in FilesAndFoldersScanResults)
		{
			double w1 = ListViewHelper.MeasureTextWidth(item.FileName);
			if (w1 > maxWidth1) maxWidth1 = w1;

			double w2 = ListViewHelper.MeasureTextWidth(item.SignatureStatus.ToString());
			if (w2 > maxWidth2) maxWidth2 = w2;

			double w3 = ListViewHelper.MeasureTextWidth(item.OriginalFileName);
			if (w3 > maxWidth3) maxWidth3 = w3;

			double w4 = ListViewHelper.MeasureTextWidth(item.InternalName);
			if (w4 > maxWidth4) maxWidth4 = w4;

			double w5 = ListViewHelper.MeasureTextWidth(item.FileDescription);
			if (w5 > maxWidth5) maxWidth5 = w5;

			double w6 = ListViewHelper.MeasureTextWidth(item.ProductName);
			if (w6 > maxWidth6) maxWidth6 = w6;

			double w7 = ListViewHelper.MeasureTextWidth(item.FileVersion?.ToString());
			if (w7 > maxWidth7) maxWidth7 = w7;

			double w8 = ListViewHelper.MeasureTextWidth(item.PackageFamilyName);
			if (w8 > maxWidth8) maxWidth8 = w8;

			double w9 = ListViewHelper.MeasureTextWidth(item.SHA256Hash);
			if (w9 > maxWidth9) maxWidth9 = w9;

			double w10 = ListViewHelper.MeasureTextWidth(item.SHA1Hash);
			if (w10 > maxWidth10) maxWidth10 = w10;

			double w11 = ListViewHelper.MeasureTextWidth(item.SISigningScenario.ToString());
			if (w11 > maxWidth11) maxWidth11 = w11;

			double w12 = ListViewHelper.MeasureTextWidth(item.FilePath);
			if (w12 > maxWidth12) maxWidth12 = w12;

			double w13 = ListViewHelper.MeasureTextWidth(item.SHA1PageHash);
			if (w13 > maxWidth13) maxWidth13 = w13;

			double w14 = ListViewHelper.MeasureTextWidth(item.SHA256PageHash);
			if (w14 > maxWidth14) maxWidth14 = w14;

			double w15 = ListViewHelper.MeasureTextWidth(item.HasWHQLSigner.ToString());
			if (w15 > maxWidth15) maxWidth15 = w15;

			double w16 = ListViewHelper.MeasureTextWidth(item.FilePublishersToDisplay);
			if (w16 > maxWidth16) maxWidth16 = w16;

			double w17 = ListViewHelper.MeasureTextWidth(item.IsECCSigned.ToString());
			if (w17 > maxWidth17) maxWidth17 = w17;

			double w18 = ListViewHelper.MeasureTextWidth(item.Opus);
			if (w18 > maxWidth18) maxWidth18 = w18;
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
	}

	#endregion


	/// <summary>
	/// Updates the total logs count displayed on the UI
	/// </summary>
	internal void UpdateTotalFiles(bool? Zero = null)
	{
		if (Zero == true)
		{
			TotalCountOfTheFilesTextBox = "Total files: 0";
		}
		else
		{
			TotalCountOfTheFilesTextBox = $"Total files: {FilesAndFoldersScanResults.Count}";
		}
	}
}
