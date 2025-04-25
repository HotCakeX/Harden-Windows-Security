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
	internal GridLength ColumnWidthFilesAndFolders1
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders2
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders3
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders4
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders5
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders6
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders7
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders8
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders9
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders10
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders11
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders12
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders13
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders14
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders15
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders16
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders17
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthFilesAndFolders18
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
	internal bool FilesAndFoldersBrowseForBasePolicyIsEnabled
	{
		get; set => SetProperty(ref field, value);
	} = true;

	/// <summary>
	/// Used to store the scan results and as the source for the results ListViews
	/// </summary>
	internal ObservableCollection<FileIdentity> FilesAndFoldersScanResults
	{
		get; set => SetProperty(ref field, value);
	} = [];

	internal readonly List<FileIdentity> filesAndFoldersScanResultsList = [];

	internal ListViewHelper.SortState SortStateFilesAndFolders { get; set; } = new();

	internal Visibility FilesAndFoldersInfoBarActionButtonVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;


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

	internal string TotalCountOfTheFilesTextBox
	{
		get; set => SetProperty(ref field, value);
	} = "Total files: 0";

	#endregion

	#region Certificates scan

	/// <summary>
	/// Controls enabled/disabled states of the elements that allow browsing for base policy file path
	/// </summary>
	internal bool CertificatesBrowseForBasePolicyIsEnabled
	{
		get; set => SetProperty(ref field, value);
	} = true;

	internal Visibility CertificatesInfoBarActionButtonVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;

	#endregion

	#region ISG

	/// <summary>
	/// Controls enabled/disabled states of the elements that allow browsing for base policy file path
	/// </summary>
	internal bool ISGBrowseForBasePolicyIsEnabled
	{
		get; set => SetProperty(ref field, value);
	} = true;

	internal Visibility ISGInfoBarActionButtonVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;

	#endregion

	#region Strict Kernel-Mode Supplemental Policy

	/// <summary>
	/// Controls enabled/disabled states of the elements that allow browsing for base policy file path
	/// </summary>
	internal bool StrictKernelModeBrowseForBasePolicyIsEnabled
	{
		get; set => SetProperty(ref field, value);
	} = true;


	#region LISTVIEW IMPLEMENTATIONS Strict Kernel Mode

	// Properties to hold each columns' width.
	internal GridLength ColumnWidthStrictKernelMode1
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode2
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode3
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode4
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode5
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode6
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode7
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode8
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode9
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode10
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode11
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode12
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode13
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode14
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode15
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode16
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode17
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthStrictKernelMode18
	{
		get; set => SetProperty(ref field, value);
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

	internal ObservableCollection<FileIdentity> StrictKernelModeScanResults
	{
		get; set => SetProperty(ref field, value);
	} = [];

	internal readonly List<FileIdentity> StrictKernelModeScanResultsList = [];

	internal ListViewHelper.SortState SortStateStrictKernelMode { get; set; } = new();

	internal Visibility StrictKernelModeInfoBarActionButtonVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;


	internal string TotalCountOfTheFilesStrictKernelModeTextBox
	{
		get; set => SetProperty(ref field, value);
	} = "Total files: 0";


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
	internal bool PFNBrowseForBasePolicyIsEnabled
	{
		get; set => SetProperty(ref field, value);
	} = true;

	internal Visibility PFNInfoBarActionButtonVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;

	#endregion

	#region Custom Pattern-based File Rule

	/// <summary>
	/// Controls enabled/disabled states of the elements that allow browsing for base policy file path
	/// </summary>
	internal bool CustomPatternBasedFileRuleBrowseForBasePolicyIsEnabled
	{
		get; set => SetProperty(ref field, value);
	} = true;

	internal Visibility CustomFilePathRulesInfoBarActionButtonVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;

	#endregion

	/// <summary>
	/// The path to the policy file that user selected to add the new rules to.
	/// </summary>
	internal string? PolicyFileToMergeWith
	{
		get; set => SetProperty(ref field, value);
	}

	/// <summary>
	/// Whether the button that allows for picking a policy file to add the rules to is enabled or disabled.
	/// </summary>
	internal bool PolicyFileToMergeWithPickerButtonIsEnabled
	{
		get; set => SetProperty(ref field, value);
	}

	/// <summary>
	/// Controls the visibility of all of the elements related to browsing for base policy file.
	/// </summary>
	internal Visibility BasePolicyElementsVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Visible;


	/// <summary>
	/// The mode of operation for the Supplemental creation page.
	/// Set to 0 (Creating New Policies) by default.
	/// </summary>
	internal int OperationModeComboBoxSelectedIndex
	{
		get;
		set
		{
			// Update the operation mode property
			_ = SetProperty(ref field, value);

			// Automate the update of elements responsible for accepting base policy path.
			// If this is set to 0, they should be visible, otherwise they should be collapsed.
			BasePolicyElementsVisibility = field == 0 ? Visibility.Visible : Visibility.Collapsed;

			PolicyFileToMergeWithPickerButtonIsEnabled = field == 1;
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
