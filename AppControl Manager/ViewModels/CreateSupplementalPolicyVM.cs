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
internal sealed partial class CreateSupplementalPolicyVM : ViewModelBase
{


	#region Files and Folders scan


	#region LISTVIEW IMPLEMENTATIONS Files And Folders

	// Properties to hold each columns' width.
	private GridLength _ColumnWidthFilesAndFolders1;
	internal GridLength ColumnWidthFilesAndFolders1
	{
		get => _ColumnWidthFilesAndFolders1;
		set { _ColumnWidthFilesAndFolders1 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders1)); }
	}

	private GridLength _ColumnWidthFilesAndFolders2;
	internal GridLength ColumnWidthFilesAndFolders2
	{
		get => _ColumnWidthFilesAndFolders2;
		set { _ColumnWidthFilesAndFolders2 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders2)); }
	}

	private GridLength _ColumnWidthFilesAndFolders3;
	internal GridLength ColumnWidthFilesAndFolders3
	{
		get => _ColumnWidthFilesAndFolders3;
		set { _ColumnWidthFilesAndFolders3 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders3)); }
	}

	private GridLength _ColumnWidthFilesAndFolders4;
	internal GridLength ColumnWidthFilesAndFolders4
	{
		get => _ColumnWidthFilesAndFolders4;
		set { _ColumnWidthFilesAndFolders4 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders4)); }
	}

	private GridLength _ColumnWidthFilesAndFolders5;
	internal GridLength ColumnWidthFilesAndFolders5
	{
		get => _ColumnWidthFilesAndFolders5;
		set { _ColumnWidthFilesAndFolders5 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders5)); }
	}

	private GridLength _ColumnWidthFilesAndFolders6;
	internal GridLength ColumnWidthFilesAndFolders6
	{
		get => _ColumnWidthFilesAndFolders6;
		set { _ColumnWidthFilesAndFolders6 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders6)); }
	}

	private GridLength _ColumnWidthFilesAndFolders7;
	internal GridLength ColumnWidthFilesAndFolders7
	{
		get => _ColumnWidthFilesAndFolders7;
		set { _ColumnWidthFilesAndFolders7 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders7)); }
	}

	private GridLength _ColumnWidthFilesAndFolders8;
	internal GridLength ColumnWidthFilesAndFolders8
	{
		get => _ColumnWidthFilesAndFolders8;
		set { _ColumnWidthFilesAndFolders8 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders8)); }
	}

	private GridLength _ColumnWidthFilesAndFolders9;
	internal GridLength ColumnWidthFilesAndFolders9
	{
		get => _ColumnWidthFilesAndFolders9;
		set { _ColumnWidthFilesAndFolders9 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders9)); }
	}

	private GridLength _ColumnWidthFilesAndFolders10;
	internal GridLength ColumnWidthFilesAndFolders10
	{
		get => _ColumnWidthFilesAndFolders10;
		set { _ColumnWidthFilesAndFolders10 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders10)); }
	}

	private GridLength _ColumnWidthFilesAndFolders11;
	internal GridLength ColumnWidthFilesAndFolders11
	{
		get => _ColumnWidthFilesAndFolders11;
		set { _ColumnWidthFilesAndFolders11 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders11)); }
	}

	private GridLength _ColumnWidthFilesAndFolders12;
	internal GridLength ColumnWidthFilesAndFolders12
	{
		get => _ColumnWidthFilesAndFolders12;
		set { _ColumnWidthFilesAndFolders12 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders12)); }
	}

	private GridLength _ColumnWidthFilesAndFolders13;
	internal GridLength ColumnWidthFilesAndFolders13
	{
		get => _ColumnWidthFilesAndFolders13;
		set { _ColumnWidthFilesAndFolders13 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders13)); }
	}

	private GridLength _ColumnWidthFilesAndFolders14;
	internal GridLength ColumnWidthFilesAndFolders14
	{
		get => _ColumnWidthFilesAndFolders14;
		set { _ColumnWidthFilesAndFolders14 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders14)); }
	}

	private GridLength _ColumnWidthFilesAndFolders15;
	internal GridLength ColumnWidthFilesAndFolders15
	{
		get => _ColumnWidthFilesAndFolders15;
		set { _ColumnWidthFilesAndFolders15 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders15)); }
	}

	private GridLength _ColumnWidthFilesAndFolders16;
	internal GridLength ColumnWidthFilesAndFolders16
	{
		get => _ColumnWidthFilesAndFolders16;
		set { _ColumnWidthFilesAndFolders16 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders16)); }
	}

	private GridLength _ColumnWidthFilesAndFolders17;
	internal GridLength ColumnWidthFilesAndFolders17
	{
		get => _ColumnWidthFilesAndFolders17;
		set { _ColumnWidthFilesAndFolders17 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders17)); }
	}

	private GridLength _ColumnWidthFilesAndFolders18;
	internal GridLength ColumnWidthFilesAndFolders18
	{
		get => _ColumnWidthFilesAndFolders18;
		set { _ColumnWidthFilesAndFolders18 = value; OnPropertyChanged(nameof(ColumnWidthFilesAndFolders18)); }
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
		ColumnWidthFilesAndFolders1 = new GridLength(maxWidth1);
		ColumnWidthFilesAndFolders2 = new GridLength(maxWidth2);
		ColumnWidthFilesAndFolders3 = new GridLength(maxWidth3);
		ColumnWidthFilesAndFolders4 = new GridLength(maxWidth4);
		ColumnWidthFilesAndFolders5 = new GridLength(maxWidth5);
		ColumnWidthFilesAndFolders6 = new GridLength(maxWidth6);
		ColumnWidthFilesAndFolders7 = new GridLength(maxWidth7);
		ColumnWidthFilesAndFolders8 = new GridLength(maxWidth8);
		ColumnWidthFilesAndFolders9 = new GridLength(maxWidth9);
		ColumnWidthFilesAndFolders10 = new GridLength(maxWidth10);
		ColumnWidthFilesAndFolders11 = new GridLength(maxWidth11);
		ColumnWidthFilesAndFolders12 = new GridLength(maxWidth12);
		ColumnWidthFilesAndFolders13 = new GridLength(maxWidth13);
		ColumnWidthFilesAndFolders14 = new GridLength(maxWidth14);
		ColumnWidthFilesAndFolders15 = new GridLength(maxWidth15);
		ColumnWidthFilesAndFolders16 = new GridLength(maxWidth16);
		ColumnWidthFilesAndFolders17 = new GridLength(maxWidth17);
		ColumnWidthFilesAndFolders18 = new GridLength(maxWidth18);
	}

	#endregion


	/// <summary>
	/// Controls enabled/disabled states of the elements that allow browsing for base policy file path
	/// </summary>
	private bool _FilesAndFoldersBrowseForBasePolicyIsEnabled = true;
	internal bool FilesAndFoldersBrowseForBasePolicyIsEnabled
	{
		get => _FilesAndFoldersBrowseForBasePolicyIsEnabled;
		set => SetProperty(_FilesAndFoldersBrowseForBasePolicyIsEnabled, value, newValue => _FilesAndFoldersBrowseForBasePolicyIsEnabled = newValue);
	}

	/// <summary>
	/// Used to store the scan results and as the source for the results ListViews
	/// </summary>
	private ObservableCollection<FileIdentity> _filesAndFoldersScanResults = [];
	internal ObservableCollection<FileIdentity> FilesAndFoldersScanResults
	{
		get => _filesAndFoldersScanResults;
		set => SetProperty(_filesAndFoldersScanResults, value, newValue => _filesAndFoldersScanResults = newValue);
	}

	internal readonly List<FileIdentity> filesAndFoldersScanResultsList = [];

	internal ListViewHelper.SortState SortStateFilesAndFolders { get; set; } = new();


	private Visibility _FilesAndFoldersInfoBarActionButtonVisibility = Visibility.Collapsed;
	internal Visibility FilesAndFoldersInfoBarActionButtonVisibility
	{
		get => _FilesAndFoldersInfoBarActionButtonVisibility;
		set => SetProperty(_FilesAndFoldersInfoBarActionButtonVisibility, value, newValue => _FilesAndFoldersInfoBarActionButtonVisibility = newValue);
	}


	/// <summary>
	/// Updates the total logs count displayed on the UI
	/// </summary>
	internal void UpdateTotalFilesFilesAndFolders(bool? Zero = null)
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

	private string _TotalCountOfTheFilesTextBox = "Total files: 0";
	internal string TotalCountOfTheFilesTextBox
	{
		get => _TotalCountOfTheFilesTextBox;
		set => SetProperty(_TotalCountOfTheFilesTextBox, value, newValue => _TotalCountOfTheFilesTextBox = newValue);
	}

	#endregion

	#region Certificates scan

	/// <summary>
	/// Controls enabled/disabled states of the elements that allow browsing for base policy file path
	/// </summary>
	private bool _CertificatesBrowseForBasePolicyIsEnabled = true;
	internal bool CertificatesBrowseForBasePolicyIsEnabled
	{
		get => _CertificatesBrowseForBasePolicyIsEnabled;
		set => SetProperty(_CertificatesBrowseForBasePolicyIsEnabled, value, newValue => _CertificatesBrowseForBasePolicyIsEnabled = newValue);
	}

	private Visibility _CertificatesInfoBarActionButtonVisibility = Visibility.Collapsed;
	internal Visibility CertificatesInfoBarActionButtonVisibility
	{
		get => _CertificatesInfoBarActionButtonVisibility;
		set => SetProperty(_CertificatesInfoBarActionButtonVisibility, value, newValue => _CertificatesInfoBarActionButtonVisibility = newValue);
	}

	#endregion

	#region ISG

	/// <summary>
	/// Controls enabled/disabled states of the elements that allow browsing for base policy file path
	/// </summary>
	private bool _ISGBrowseForBasePolicyIsEnabled = true;
	internal bool ISGBrowseForBasePolicyIsEnabled
	{
		get => _ISGBrowseForBasePolicyIsEnabled;
		set => SetProperty(_ISGBrowseForBasePolicyIsEnabled, value, newValue => _ISGBrowseForBasePolicyIsEnabled = newValue);
	}

	private Visibility _ISGInfoBarActionButtonVisibility = Visibility.Collapsed;
	internal Visibility ISGInfoBarActionButtonVisibility
	{
		get => _ISGInfoBarActionButtonVisibility;
		set => SetProperty(_ISGInfoBarActionButtonVisibility, value, newValue => _ISGInfoBarActionButtonVisibility = newValue);
	}

	#endregion

	#region Strict Kernel-Mode Supplemental Policy

	/// <summary>
	/// Controls enabled/disabled states of the elements that allow browsing for base policy file path
	/// </summary>
	private bool _StrictKernelModeBrowseForBasePolicyIsEnabled = true;
	internal bool StrictKernelModeBrowseForBasePolicyIsEnabled
	{
		get => _StrictKernelModeBrowseForBasePolicyIsEnabled;
		set => SetProperty(_StrictKernelModeBrowseForBasePolicyIsEnabled, value, newValue => _StrictKernelModeBrowseForBasePolicyIsEnabled = newValue);
	}


	#region LISTVIEW IMPLEMENTATIONS Strict Kernel Mode

	// Properties to hold each columns' width.
	private GridLength _ColumnWidthStrictKernelMode1;
	internal GridLength ColumnWidthStrictKernelMode1
	{
		get => _ColumnWidthStrictKernelMode1;
		set { _ColumnWidthStrictKernelMode1 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode1)); }
	}

	private GridLength _ColumnWidthStrictKernelMode2;
	internal GridLength ColumnWidthStrictKernelMode2
	{
		get => _ColumnWidthStrictKernelMode2;
		set { _ColumnWidthStrictKernelMode2 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode2)); }
	}

	private GridLength _ColumnWidthStrictKernelMode3;
	internal GridLength ColumnWidthStrictKernelMode3
	{
		get => _ColumnWidthStrictKernelMode3;
		set { _ColumnWidthStrictKernelMode3 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode3)); }
	}

	private GridLength _ColumnWidthStrictKernelMode4;
	internal GridLength ColumnWidthStrictKernelMode4
	{
		get => _ColumnWidthStrictKernelMode4;
		set { _ColumnWidthStrictKernelMode4 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode4)); }
	}

	private GridLength _ColumnWidthStrictKernelMode5;
	internal GridLength ColumnWidthStrictKernelMode5
	{
		get => _ColumnWidthStrictKernelMode5;
		set { _ColumnWidthStrictKernelMode5 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode5)); }
	}

	private GridLength _ColumnWidthStrictKernelMode6;
	internal GridLength ColumnWidthStrictKernelMode6
	{
		get => _ColumnWidthStrictKernelMode6;
		set { _ColumnWidthStrictKernelMode6 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode6)); }
	}

	private GridLength _ColumnWidthStrictKernelMode7;
	internal GridLength ColumnWidthStrictKernelMode7
	{
		get => _ColumnWidthStrictKernelMode7;
		set { _ColumnWidthStrictKernelMode7 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode7)); }
	}

	private GridLength _ColumnWidthStrictKernelMode8;
	internal GridLength ColumnWidthStrictKernelMode8
	{
		get => _ColumnWidthStrictKernelMode8;
		set { _ColumnWidthStrictKernelMode8 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode8)); }
	}

	private GridLength _ColumnWidthStrictKernelMode9;
	internal GridLength ColumnWidthStrictKernelMode9
	{
		get => _ColumnWidthStrictKernelMode9;
		set { _ColumnWidthStrictKernelMode9 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode9)); }
	}

	private GridLength _ColumnWidthStrictKernelMode10;
	internal GridLength ColumnWidthStrictKernelMode10
	{
		get => _ColumnWidthStrictKernelMode10;
		set { _ColumnWidthStrictKernelMode10 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode10)); }
	}

	private GridLength _ColumnWidthStrictKernelMode11;
	internal GridLength ColumnWidthStrictKernelMode11
	{
		get => _ColumnWidthStrictKernelMode11;
		set { _ColumnWidthStrictKernelMode11 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode11)); }
	}

	private GridLength _ColumnWidthStrictKernelMode12;
	internal GridLength ColumnWidthStrictKernelMode12
	{
		get => _ColumnWidthStrictKernelMode12;
		set { _ColumnWidthStrictKernelMode12 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode12)); }
	}

	private GridLength _ColumnWidthStrictKernelMode13;
	internal GridLength ColumnWidthStrictKernelMode13
	{
		get => _ColumnWidthStrictKernelMode13;
		set { _ColumnWidthStrictKernelMode13 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode13)); }
	}

	private GridLength _ColumnWidthStrictKernelMode14;
	internal GridLength ColumnWidthStrictKernelMode14
	{
		get => _ColumnWidthStrictKernelMode14;
		set { _ColumnWidthStrictKernelMode14 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode14)); }
	}

	private GridLength _ColumnWidthStrictKernelMode15;
	internal GridLength ColumnWidthStrictKernelMode15
	{
		get => _ColumnWidthStrictKernelMode15;
		set { _ColumnWidthStrictKernelMode15 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode15)); }
	}

	private GridLength _ColumnWidthStrictKernelMode16;
	internal GridLength ColumnWidthStrictKernelMode16
	{
		get => _ColumnWidthStrictKernelMode16;
		set { _ColumnWidthStrictKernelMode16 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode16)); }
	}

	private GridLength _ColumnWidthStrictKernelMode17;
	internal GridLength ColumnWidthStrictKernelMode17
	{
		get => _ColumnWidthStrictKernelMode17;
		set { _ColumnWidthStrictKernelMode17 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode17)); }
	}

	private GridLength _ColumnWidthStrictKernelMode18;
	internal GridLength ColumnWidthStrictKernelMode18
	{
		get => _ColumnWidthStrictKernelMode18;
		set { _ColumnWidthStrictKernelMode18 = value; OnPropertyChanged(nameof(ColumnWidthStrictKernelMode18)); }
	}

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidthsStrictKernelMode()
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
		foreach (FileIdentity item in StrictKernelModeScanResults)
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
		ColumnWidthStrictKernelMode1 = new GridLength(maxWidth1);
		ColumnWidthStrictKernelMode2 = new GridLength(maxWidth2);
		ColumnWidthStrictKernelMode3 = new GridLength(maxWidth3);
		ColumnWidthStrictKernelMode4 = new GridLength(maxWidth4);
		ColumnWidthStrictKernelMode5 = new GridLength(maxWidth5);
		ColumnWidthStrictKernelMode6 = new GridLength(maxWidth6);
		ColumnWidthStrictKernelMode7 = new GridLength(maxWidth7);
		ColumnWidthStrictKernelMode8 = new GridLength(maxWidth8);
		ColumnWidthStrictKernelMode9 = new GridLength(maxWidth9);
		ColumnWidthStrictKernelMode10 = new GridLength(maxWidth10);
		ColumnWidthStrictKernelMode11 = new GridLength(maxWidth11);
		ColumnWidthStrictKernelMode12 = new GridLength(maxWidth12);
		ColumnWidthStrictKernelMode13 = new GridLength(maxWidth13);
		ColumnWidthStrictKernelMode14 = new GridLength(maxWidth14);
		ColumnWidthStrictKernelMode15 = new GridLength(maxWidth15);
		ColumnWidthStrictKernelMode16 = new GridLength(maxWidth16);
		ColumnWidthStrictKernelMode17 = new GridLength(maxWidth17);
		ColumnWidthStrictKernelMode18 = new GridLength(maxWidth18);
	}

	#endregion



	private ObservableCollection<FileIdentity> _StrictKernelModeScanResults = [];
	internal ObservableCollection<FileIdentity> StrictKernelModeScanResults
	{
		get => _StrictKernelModeScanResults;
		set => SetProperty(_StrictKernelModeScanResults, value, newValue => _StrictKernelModeScanResults = newValue);
	}

	internal readonly List<FileIdentity> StrictKernelModeScanResultsList = [];

	internal ListViewHelper.SortState SortStateStrictKernelMode { get; set; } = new();


	private Visibility _StrictKernelModeInfoBarActionButtonVisibility = Visibility.Collapsed;
	internal Visibility StrictKernelModeInfoBarActionButtonVisibility
	{
		get => _StrictKernelModeInfoBarActionButtonVisibility;
		set => SetProperty(_StrictKernelModeInfoBarActionButtonVisibility, value, newValue => _StrictKernelModeInfoBarActionButtonVisibility = newValue);
	}


	private string _TotalCountOfTheFilesStrictKernelModeTextBox = "Total files: 0";
	internal string TotalCountOfTheFilesStrictKernelModeTextBox
	{
		get => _TotalCountOfTheFilesStrictKernelModeTextBox;
		set => SetProperty(_TotalCountOfTheFilesStrictKernelModeTextBox, value, newValue => _TotalCountOfTheFilesStrictKernelModeTextBox = newValue);
	}


	/// <summary>
	/// Updates the total logs count displayed on the UI
	/// </summary>
	internal void UpdateTotalFilesStrictKernelMode(bool? Zero = null)
	{
		if (Zero == true)
		{
			TotalCountOfTheFilesStrictKernelModeTextBox = "Total files: 0";
		}
		else
		{
			TotalCountOfTheFilesStrictKernelModeTextBox = $"Total files: {StrictKernelModeScanResults.Count}";
		}
	}

	#endregion

	#region Package Family Names

	/// <summary>
	/// Controls enabled/disabled states of the elements that allow browsing for base policy file path
	/// </summary>
	private bool _PFNBrowseForBasePolicyIsEnabled = true;
	internal bool PFNBrowseForBasePolicyIsEnabled
	{
		get => _PFNBrowseForBasePolicyIsEnabled;
		set => SetProperty(_PFNBrowseForBasePolicyIsEnabled, value, newValue => _PFNBrowseForBasePolicyIsEnabled = newValue);
	}


	private Visibility _PFNInfoBarActionButtonVisibility = Visibility.Collapsed;
	internal Visibility PFNInfoBarActionButtonVisibility
	{
		get => _PFNInfoBarActionButtonVisibility;
		set => SetProperty(_PFNInfoBarActionButtonVisibility, value, newValue => _PFNInfoBarActionButtonVisibility = newValue);
	}

	#endregion

	#region Custom Pattern-based File Rule

	/// <summary>
	/// Controls enabled/disabled states of the elements that allow browsing for base policy file path
	/// </summary>
	private bool _CustomPatternBasedFileRuleBrowseForBasePolicyIsEnabled = true;
	internal bool CustomPatternBasedFileRuleBrowseForBasePolicyIsEnabled
	{
		get => _CustomPatternBasedFileRuleBrowseForBasePolicyIsEnabled;
		set => SetProperty(_CustomPatternBasedFileRuleBrowseForBasePolicyIsEnabled, value, newValue => _CustomPatternBasedFileRuleBrowseForBasePolicyIsEnabled = newValue);
	}


	private Visibility _CustomFilePathRulesInfoBarActionButtonVisibility = Visibility.Collapsed;
	internal Visibility CustomFilePathRulesInfoBarActionButtonVisibility
	{
		get => _CustomFilePathRulesInfoBarActionButtonVisibility;
		set => SetProperty(_CustomFilePathRulesInfoBarActionButtonVisibility, value, newValue => _CustomFilePathRulesInfoBarActionButtonVisibility = newValue);
	}

	#endregion



	/// <summary>
	/// The path to the policy file that user selected to add the new rules to.
	/// </summary>
	private string? _PolicyFileToMergeWith;
	internal string? PolicyFileToMergeWith
	{
		get => _PolicyFileToMergeWith;
		set => SetProperty(_PolicyFileToMergeWith, value, newValue => _PolicyFileToMergeWith = newValue);
	}


	/// <summary>
	/// Whether the button that allows for picking a policy file to add the rules to is enabled or disabled.
	/// </summary>
	private bool _PolicyFileToMergeWithPickerButtonIsEnabled;
	internal bool PolicyFileToMergeWithPickerButtonIsEnabled
	{
		get => _PolicyFileToMergeWithPickerButtonIsEnabled;
		set => SetProperty(_PolicyFileToMergeWithPickerButtonIsEnabled, value, newValue => _PolicyFileToMergeWithPickerButtonIsEnabled = newValue);
	}

	/// <summary>
	/// Controls the visibility of all of the elements related to browsing for base policy file.
	/// </summary>
	private Visibility _BasePolicyElementsVisibility = Visibility.Visible;
	internal Visibility BasePolicyElementsVisibility
	{
		get => _BasePolicyElementsVisibility;
		set => SetProperty(_BasePolicyElementsVisibility, value, newValue => _BasePolicyElementsVisibility = newValue);
	}


	/// <summary>
	/// The mode of operation for the Supplemental creation page.
	/// Set to 0 (Creating New Policies) by default.
	/// </summary>
	private int _OperationModeComboBoxSelectedIndex;
	internal int OperationModeComboBoxSelectedIndex
	{
		get => _OperationModeComboBoxSelectedIndex;
		set
		{
			// Update the operation mode property
			_ = SetProperty(_OperationModeComboBoxSelectedIndex, value, newValue => _OperationModeComboBoxSelectedIndex = newValue);

			// Automate the update of elements responsible for accepting base policy path.
			// If this is set to 0, they should be visible, otherwise they should be collapsed.
			BasePolicyElementsVisibility = value == 0 ? Visibility.Visible : Visibility.Collapsed;

			PolicyFileToMergeWithPickerButtonIsEnabled = value == 1;
		}
	}

	/// <summary>
	/// Clears the PolicyFileToMergeWith
	/// </summary>
	internal void ClearPolicyFileToMergeWith()
	{
		PolicyFileToMergeWith = null;
	}

}
