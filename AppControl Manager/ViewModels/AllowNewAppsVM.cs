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
internal sealed partial class AllowNewAppsVM : ViewModelBase
{

	#region

	// To store the FileIdentities displayed on the Local Files ListView
	internal ObservableCollection<FileIdentity> LocalFilesFileIdentities
	{
		get; set => SetProperty(ref field, value);
	} = [];


	// Store all outputs for searching, used as a temporary storage for filtering
	// If ObservableCollection were used directly, any filtering or modification could remove items permanently
	// from the collection, making it difficult to reset or apply different filters without re-fetching data.
	internal readonly List<FileIdentity> LocalFilesAllFileIdentities = [];

	internal ListViewHelper.SortState SortStateLocalFiles { get; set; } = new();


	// To store the FileIdentities displayed on the Event Logs ListView
	internal readonly ObservableCollection<FileIdentity> EventLogsFileIdentities = [];

	// Store all outputs for searching, used as a temporary storage for filtering
	// If ObservableCollection were used directly, any filtering or modification could remove items permanently
	// from the collection, making it difficult to reset or apply different filters without re-fetching data.
	internal readonly List<FileIdentity> EventLogsAllFileIdentities = [];

	internal ListViewHelper.SortState SortStateEventLogs { get; set; } = new();

	#endregion


	#region UI-Bound Properties

	internal Visibility OpenInPolicyEditorInfoBarActionButtonVisibility
	{
		get; set => SetProperty(ref field, value);
	} = Visibility.Collapsed;

	/// <summary>
	/// Holds the state of the Event Logs menu item, indicating whether it is enabled or disabled.
	/// </summary>
	internal bool EventLogsMenuItemState
	{
		get; set => SetProperty(ref field, value);
	}

	/// <summary>
	/// Stores the state of the local files menu item as a boolean value. Indicates whether the local files menu item is
	/// enabled or disabled.
	/// </summary>
	internal bool LocalFilesMenuItemState
	{
		get; set => SetProperty(ref field, value);
	}

	/// <summary>
	/// Stores the count of local files for display in an info badge. Used to track and indicate the number of local files.
	/// </summary>
	internal int LocalFilesCountInfoBadgeValue
	{
		get; set => SetProperty(ref field, value);
	}

	/// <summary>
	/// Stores the opacity level for the local files count info badge. It is a double value representing transparency.
	/// </summary>
	internal double LocalFilesCountInfoBadgeOpacity
	{
		get; set => SetProperty(ref field, value);
	}

	/// <summary>
	/// Stores the count of event logs for the info badge. Used to track the number of events for display purposes.
	/// </summary>
	internal int EventLogsCountInfoBadgeValue
	{
		get; set => SetProperty(ref field, value);
	}

	/// <summary>
	/// Stores the opacity level for the event logs count info badge. It is a double value representing transparency.
	/// </summary>
	internal double EventLogsCountInfoBadgeOpacity
	{
		get; set => SetProperty(ref field, value);
	}

	/// <summary>
	/// Toggle button to determine whether the new Supplemental policy should be deployed on the system after creation or not
	/// </summary>
	internal bool DeployPolicy
	{
		get; set => SetProperty(ref field, value);
	}

	internal bool DeployPolicyState
	{
		get; set => SetProperty(ref field, value);
	}

	#endregion


	#region LISTVIEW IMPLEMENTATIONS FOR EVENT LOGS

	// Properties to hold each columns' width.
	internal GridLength ColumnWidthEventLogs1
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs2
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs3
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs4
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs5
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs6
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs7
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs8
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs9
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs10
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs11
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs12
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs13
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs14
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs15
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs16
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs17
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs18
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs19
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs20
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthEventLogs21
	{
		get; set => SetProperty(ref field, value);
	}

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidthEventLogs()
	{
		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FileNameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("TimeCreatedHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SignatureStatusHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("ActionHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("OriginalFileNameHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("InternalNameHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FileDescriptionHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("ProductNameHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FileVersionHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("PackageFamilyNameHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA256HashHeader/Text"));
		double maxWidth12 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA1HashHeader/Text"));
		double maxWidth13 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SigningScenarioHeader/Text"));
		double maxWidth14 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FilePathHeader/Text"));
		double maxWidth15 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA1FlatHashHeader/Text"));
		double maxWidth16 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("SHA256FlatHashHeader/Text"));
		double maxWidth17 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FilePublishersHeader/Text"));
		double maxWidth18 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("OpusDataHeader/Text"));
		double maxWidth19 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("PolicyGUIDHeader/Text"));
		double maxWidth20 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("PolicyNameHeader/Text"));
		double maxWidth21 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("ComputerNameHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (FileIdentity item in EventLogsFileIdentities)
		{
			double w1 = ListViewHelper.MeasureTextWidth(item.FileName);
			if (w1 > maxWidth1) maxWidth1 = w1;

			double w2 = ListViewHelper.MeasureTextWidth(item.TimeCreated.ToString());
			if (w2 > maxWidth2) maxWidth2 = w2;

			double w3 = ListViewHelper.MeasureTextWidth(item.SignatureStatus.ToString());
			if (w3 > maxWidth3) maxWidth3 = w3;

			double w4 = ListViewHelper.MeasureTextWidth(item.Action.ToString());
			if (w4 > maxWidth4) maxWidth4 = w4;

			double w5 = ListViewHelper.MeasureTextWidth(item.OriginalFileName);
			if (w5 > maxWidth5) maxWidth5 = w5;

			double w6 = ListViewHelper.MeasureTextWidth(item.InternalName);
			if (w6 > maxWidth6) maxWidth6 = w6;

			double w7 = ListViewHelper.MeasureTextWidth(item.FileDescription);
			if (w7 > maxWidth7) maxWidth7 = w7;

			double w8 = ListViewHelper.MeasureTextWidth(item.ProductName);
			if (w8 > maxWidth8) maxWidth8 = w8;

			double w9 = ListViewHelper.MeasureTextWidth(item.FileVersion?.ToString());
			if (w9 > maxWidth9) maxWidth9 = w9;

			double w10 = ListViewHelper.MeasureTextWidth(item.PackageFamilyName);
			if (w10 > maxWidth10) maxWidth10 = w10;

			double w11 = ListViewHelper.MeasureTextWidth(item.SHA256Hash);
			if (w11 > maxWidth11) maxWidth11 = w11;

			double w12 = ListViewHelper.MeasureTextWidth(item.SHA1Hash);
			if (w12 > maxWidth12) maxWidth12 = w12;

			double w13 = ListViewHelper.MeasureTextWidth(item.SISigningScenario.ToString());
			if (w13 > maxWidth13) maxWidth13 = w13;

			double w14 = ListViewHelper.MeasureTextWidth(item.FilePath);
			if (w14 > maxWidth14) maxWidth14 = w14;

			double w15 = ListViewHelper.MeasureTextWidth(item.SHA1FlatHash);
			if (w15 > maxWidth15) maxWidth15 = w15;

			double w16 = ListViewHelper.MeasureTextWidth(item.SHA256FlatHash);
			if (w16 > maxWidth16) maxWidth16 = w16;

			double w17 = ListViewHelper.MeasureTextWidth(item.FilePublishersToDisplay);
			if (w17 > maxWidth17) maxWidth17 = w17;

			double w18 = ListViewHelper.MeasureTextWidth(item.Opus);
			if (w18 > maxWidth18) maxWidth18 = w18;

			double w19 = ListViewHelper.MeasureTextWidth(item.PolicyGUID.ToString());
			if (w19 > maxWidth19) maxWidth19 = w19;

			double w20 = ListViewHelper.MeasureTextWidth(item.PolicyName);
			if (w20 > maxWidth20) maxWidth20 = w20;

			double w21 = ListViewHelper.MeasureTextWidth(item.ComputerName);
			if (w21 > maxWidth21) maxWidth21 = w21;
		}

		// Set the column width properties.
		ColumnWidthEventLogs1 = new GridLength(maxWidth1);
		ColumnWidthEventLogs2 = new GridLength(maxWidth2);
		ColumnWidthEventLogs3 = new GridLength(maxWidth3);
		ColumnWidthEventLogs4 = new GridLength(maxWidth4);
		ColumnWidthEventLogs5 = new GridLength(maxWidth5);
		ColumnWidthEventLogs6 = new GridLength(maxWidth6);
		ColumnWidthEventLogs7 = new GridLength(maxWidth7);
		ColumnWidthEventLogs8 = new GridLength(maxWidth8);
		ColumnWidthEventLogs9 = new GridLength(maxWidth9);
		ColumnWidthEventLogs10 = new GridLength(maxWidth10);
		ColumnWidthEventLogs11 = new GridLength(maxWidth11);
		ColumnWidthEventLogs12 = new GridLength(maxWidth12);
		ColumnWidthEventLogs13 = new GridLength(maxWidth13);
		ColumnWidthEventLogs14 = new GridLength(maxWidth14);
		ColumnWidthEventLogs15 = new GridLength(maxWidth15);
		ColumnWidthEventLogs16 = new GridLength(maxWidth16);
		ColumnWidthEventLogs17 = new GridLength(maxWidth17);
		ColumnWidthEventLogs18 = new GridLength(maxWidth18);
		ColumnWidthEventLogs19 = new GridLength(maxWidth19);
		ColumnWidthEventLogs20 = new GridLength(maxWidth20);
		ColumnWidthEventLogs21 = new GridLength(maxWidth21);
	}

	#endregion


	#region LISTVIEW IMPLEMENTATIONS FOR LOCAL FILES

	// Properties to hold each columns' width.
	internal GridLength ColumnWidthLocalFiles1
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles2
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles3
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles4
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles5
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles6
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles7
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles8
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles9
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles10
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles11
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles12
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles13
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles14
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles15
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles16
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles17
	{
		get; set => SetProperty(ref field, value);
	}

	internal GridLength ColumnWidthLocalFiles18
	{
		get; set => SetProperty(ref field, value);
	}

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidthLocalFiles()
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
		foreach (FileIdentity item in LocalFilesFileIdentities)
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
		ColumnWidthLocalFiles1 = new GridLength(maxWidth1);
		ColumnWidthLocalFiles2 = new GridLength(maxWidth2);
		ColumnWidthLocalFiles3 = new GridLength(maxWidth3);
		ColumnWidthLocalFiles4 = new GridLength(maxWidth4);
		ColumnWidthLocalFiles5 = new GridLength(maxWidth5);
		ColumnWidthLocalFiles6 = new GridLength(maxWidth6);
		ColumnWidthLocalFiles7 = new GridLength(maxWidth7);
		ColumnWidthLocalFiles8 = new GridLength(maxWidth8);
		ColumnWidthLocalFiles9 = new GridLength(maxWidth9);
		ColumnWidthLocalFiles10 = new GridLength(maxWidth10);
		ColumnWidthLocalFiles11 = new GridLength(maxWidth11);
		ColumnWidthLocalFiles12 = new GridLength(maxWidth12);
		ColumnWidthLocalFiles13 = new GridLength(maxWidth13);
		ColumnWidthLocalFiles14 = new GridLength(maxWidth14);
		ColumnWidthLocalFiles15 = new GridLength(maxWidth15);
		ColumnWidthLocalFiles16 = new GridLength(maxWidth16);
		ColumnWidthLocalFiles17 = new GridLength(maxWidth17);
		ColumnWidthLocalFiles18 = new GridLength(maxWidth18);
	}

	#endregion


	/// <summary>
	/// Event handler for the Clear Data button
	/// </summary>
	internal void ClearLocalFilesDataButton_Click()
	{
		LocalFilesFileIdentities.Clear();
		LocalFilesAllFileIdentities.Clear();

		UpdateTotalFiles(true);
	}


	/// <summary>
	/// Updates the total logs count displayed on the UI
	/// </summary>
	internal void UpdateTotalFiles(bool? Zero = null)
	{
		if (Zero == true)
		{
			// Update the InfoBadge for the top menu
			LocalFilesCountInfoBadgeOpacity = 1;
			LocalFilesCountInfoBadgeValue = 0;
		}
		else
		{
			// Update the InfoBadge for the top menu
			LocalFilesCountInfoBadgeOpacity = 1;
			LocalFilesCountInfoBadgeValue = LocalFilesFileIdentities.Count;
		}
	}


	/// <summary>
	/// Event handler for the Clear Data button
	/// </summary>
	internal void ClearEventLogsDataButton_Click()
	{
		EventLogsFileIdentities.Clear();
		EventLogsAllFileIdentities.Clear();

		UpdateTotalLogs(true);
	}

	/// <summary>
	/// Updates the total logs count displayed on the UI
	/// </summary>
	internal void UpdateTotalLogs(bool? Zero = null)
	{
		if (Zero == true)
		{
			// Update the InfoBadge for the top menu
			EventLogsCountInfoBadgeOpacity = 1;
			EventLogsCountInfoBadgeValue = 0;
		}
		else
		{
			// Update the InfoBadge for the top menu
			EventLogsCountInfoBadgeOpacity = 1;
			EventLogsCountInfoBadgeValue = EventLogsFileIdentities.Count;
		}
	}
}
