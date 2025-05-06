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
using AppControlManager.IntelGathering;
using AppControlManager.Others;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.
internal sealed partial class CreateSupplementalPolicyVM : ViewModelBase
{

	internal CreateSupplementalPolicyVM()
	{
		FilesAndFoldersProgressRingValueProgress = new Progress<double>(p => FilesAndFoldersProgressRingValue = p);
		DriverAutoDetectionProgressRingValueProgress = new Progress<double>(p => DriverAutoDetectionProgressRingValue = p);
	}


	internal double FilesAndFoldersProgressRingValue { get; set => SP(ref field, value); }
	internal double DriverAutoDetectionProgressRingValue { get; set => SP(ref field, value); }

	// A Progress<double> so Report() callbacks run on the UI thread
	internal IProgress<double> FilesAndFoldersProgressRingValueProgress;
	internal IProgress<double> DriverAutoDetectionProgressRingValueProgress;

	internal Visibility FilesAndFoldersBasePolicyLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility CertificatesBasePolicyPathLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility ISGBasePolicyPathLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility StrictKernelModeBasePolicyLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility PFNBasePolicyPathLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;


	#region Files and Folders scan


	#region LISTVIEW IMPLEMENTATIONS Files And Folders

	// Properties to hold each columns' width.
	internal GridLength ColumnWidthFilesAndFolders1 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders2 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders3 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders4 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders5 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders6 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders7 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders8 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders9 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders10 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders11 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders12 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders13 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders14 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders15 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders16 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders17 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthFilesAndFolders18 { get; set => SP(ref field, value); }

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidths()
	{

		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FileNameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SignatureStatusHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("OriginalFileNameHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("InternalNameHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FileDescriptionHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("ProductNameHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FileVersionHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("PackageFamilyNameHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA256HashHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA1HashHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SigningScenarioHeader/Text"));
		double maxWidth12 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FilePathHeader/Text"));
		double maxWidth13 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA1PageHashHeader/Text"));
		double maxWidth14 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA256PageHashHeader/Text"));
		double maxWidth15 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("HasWHQLSignerHeader/Text"));
		double maxWidth16 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FilePublishersHeader/Text"));
		double maxWidth17 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("IsECCSignedHeader/Text"));
		double maxWidth18 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("OpusDataHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (FileIdentity item in FilesAndFoldersScanResults)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.FileName, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.SignatureStatus.ToString(), maxWidth2);
			maxWidth3 = ListViewHelper.MeasureText(item.OriginalFileName, maxWidth3);
			maxWidth4 = ListViewHelper.MeasureText(item.InternalName, maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.FileDescription, maxWidth5);
			maxWidth6 = ListViewHelper.MeasureText(item.ProductName, maxWidth6);
			maxWidth7 = ListViewHelper.MeasureText(item.FileVersion?.ToString(), maxWidth7);
			maxWidth8 = ListViewHelper.MeasureText(item.PackageFamilyName, maxWidth8);
			maxWidth9 = ListViewHelper.MeasureText(item.SHA256Hash, maxWidth9);
			maxWidth10 = ListViewHelper.MeasureText(item.SHA1Hash, maxWidth10);
			maxWidth11 = ListViewHelper.MeasureText(item.SISigningScenario.ToString(), maxWidth11);
			maxWidth12 = ListViewHelper.MeasureText(item.FilePath, maxWidth12);
			maxWidth13 = ListViewHelper.MeasureText(item.SHA1PageHash, maxWidth13);
			maxWidth14 = ListViewHelper.MeasureText(item.SHA256PageHash, maxWidth14);
			maxWidth15 = ListViewHelper.MeasureText(item.HasWHQLSigner.ToString(), maxWidth15);
			maxWidth16 = ListViewHelper.MeasureText(item.FilePublishersToDisplay, maxWidth16);
			maxWidth17 = ListViewHelper.MeasureText(item.IsECCSigned.ToString(), maxWidth17);
			maxWidth18 = ListViewHelper.MeasureText(item.Opus, maxWidth18);
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
		get; set => SP(ref field, value);
	} = true;

	/// <summary>
	/// Used to store the scan results and as the source for the results ListViews
	/// </summary>
	internal ObservableCollection<FileIdentity> FilesAndFoldersScanResults
	{
		get; set => SP(ref field, value);
	} = [];

	internal readonly List<FileIdentity> filesAndFoldersScanResultsList = [];

	internal ListViewHelper.SortState SortStateFilesAndFolders { get; set; } = new();

	internal Visibility FilesAndFoldersInfoBarActionButtonVisibility
	{
		get; set => SP(ref field, value);
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
		get; set => SP(ref field, value);
	} = "Total files: 0";

	#endregion

	#region Certificates scan

	/// <summary>
	/// Controls enabled/disabled states of the elements that allow browsing for base policy file path
	/// </summary>
	internal bool CertificatesBrowseForBasePolicyIsEnabled
	{
		get; set => SP(ref field, value);
	} = true;

	internal Visibility CertificatesInfoBarActionButtonVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	#endregion

	#region ISG

	/// <summary>
	/// Controls enabled/disabled states of the elements that allow browsing for base policy file path
	/// </summary>
	internal bool ISGBrowseForBasePolicyIsEnabled
	{
		get; set => SP(ref field, value);
	} = true;

	internal Visibility ISGInfoBarActionButtonVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	#endregion

	#region Strict Kernel-Mode Supplemental Policy

	/// <summary>
	/// Controls enabled/disabled states of the elements that allow browsing for base policy file path
	/// </summary>
	internal bool StrictKernelModeBrowseForBasePolicyIsEnabled
	{
		get; set => SP(ref field, value);
	} = true;


	#region LISTVIEW IMPLEMENTATIONS Strict Kernel Mode

	// Properties to hold each columns' width.
	internal GridLength ColumnWidthStrictKernelMode1 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode2 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode3 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode4 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode5 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode6 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode7 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode8 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode9 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode10 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode11 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode12 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode13 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode14 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode15 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode16 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode17 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthStrictKernelMode18 { get; set => SP(ref field, value); }

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidthsStrictKernelMode()
	{

		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FileNameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SignatureStatusHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("OriginalFileNameHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("InternalNameHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FileDescriptionHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("ProductNameHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FileVersionHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("PackageFamilyNameHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA256HashHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA1HashHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SigningScenarioHeader/Text"));
		double maxWidth12 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FilePathHeader/Text"));
		double maxWidth13 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA1PageHashHeader/Text"));
		double maxWidth14 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA256PageHashHeader/Text"));
		double maxWidth15 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("HasWHQLSignerHeader/Text"));
		double maxWidth16 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FilePublishersHeader/Text"));
		double maxWidth17 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("IsECCSignedHeader/Text"));
		double maxWidth18 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("OpusDataHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (FileIdentity item in StrictKernelModeScanResults)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.FileName, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.SignatureStatus.ToString(), maxWidth2);
			maxWidth3 = ListViewHelper.MeasureText(item.OriginalFileName, maxWidth3);
			maxWidth4 = ListViewHelper.MeasureText(item.InternalName, maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.FileDescription, maxWidth5);
			maxWidth6 = ListViewHelper.MeasureText(item.ProductName, maxWidth6);
			maxWidth7 = ListViewHelper.MeasureText(item.FileVersion?.ToString(), maxWidth7);
			maxWidth8 = ListViewHelper.MeasureText(item.PackageFamilyName, maxWidth8);
			maxWidth9 = ListViewHelper.MeasureText(item.SHA256Hash, maxWidth9);
			maxWidth10 = ListViewHelper.MeasureText(item.SHA1Hash, maxWidth10);
			maxWidth11 = ListViewHelper.MeasureText(item.SISigningScenario.ToString(), maxWidth11);
			maxWidth12 = ListViewHelper.MeasureText(item.FilePath, maxWidth12);
			maxWidth13 = ListViewHelper.MeasureText(item.SHA1PageHash, maxWidth13);
			maxWidth14 = ListViewHelper.MeasureText(item.SHA256PageHash, maxWidth14);
			maxWidth15 = ListViewHelper.MeasureText(item.HasWHQLSigner.ToString(), maxWidth15);
			maxWidth16 = ListViewHelper.MeasureText(item.FilePublishersToDisplay, maxWidth16);
			maxWidth17 = ListViewHelper.MeasureText(item.IsECCSigned.ToString(), maxWidth17);
			maxWidth18 = ListViewHelper.MeasureText(item.Opus, maxWidth18);
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
		get; set => SP(ref field, value);
	} = [];

	internal readonly List<FileIdentity> StrictKernelModeScanResultsList = [];

	internal ListViewHelper.SortState SortStateStrictKernelMode { get; set; } = new();

	internal Visibility StrictKernelModeInfoBarActionButtonVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;


	internal string TotalCountOfTheFilesStrictKernelModeTextBox
	{
		get; set => SP(ref field, value);
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
		get; set => SP(ref field, value);
	} = true;

	internal Visibility PFNInfoBarActionButtonVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	#endregion

	#region Custom Pattern-based File Rule

	/// <summary>
	/// Controls enabled/disabled states of the elements that allow browsing for base policy file path
	/// </summary>
	internal bool CustomPatternBasedFileRuleBrowseForBasePolicyIsEnabled
	{
		get; set => SP(ref field, value);
	} = true;

	internal Visibility CustomFilePathRulesInfoBarActionButtonVisibility
	{
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	#endregion

	/// <summary>
	/// The path to the policy file that user selected to add the new rules to.
	/// </summary>
	internal string? PolicyFileToMergeWith { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the button that allows for picking a policy file to add the rules to is enabled or disabled.
	/// </summary>
	internal bool PolicyFileToMergeWithPickerButtonIsEnabled { get; set => SP(ref field, value); }

	/// <summary>
	/// Controls the visibility of all of the elements related to browsing for base policy file.
	/// </summary>
	internal Visibility BasePolicyElementsVisibility
	{
		get; set => SP(ref field, value);
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
			_ = SP(ref field, value);

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
