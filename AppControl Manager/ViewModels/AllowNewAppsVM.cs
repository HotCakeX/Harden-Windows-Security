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
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.
internal sealed partial class AllowNewAppsVM : ViewModelBase
{

	internal EventLogUtility EventLogsUtil { get; } = App.AppHost.Services.GetRequiredService<EventLogUtility>();

	#region

	// To store the FileIdentities displayed on the Local Files ListView
	internal ObservableCollection<FileIdentity> LocalFilesFileIdentities
	{
		get; set => SP(ref field, value);
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
		get; set => SP(ref field, value);
	} = Visibility.Collapsed;

	/// <summary>
	/// Holds the state of the Event Logs menu item, indicating whether it is enabled or disabled.
	/// </summary>
	internal bool EventLogsMenuItemState { get; set => SP(ref field, value); }

	/// <summary>
	/// Stores the state of the local files menu item as a boolean value. Indicates whether the local files menu item is
	/// enabled or disabled.
	/// </summary>
	internal bool LocalFilesMenuItemState { get; set => SP(ref field, value); }

	/// <summary>
	/// Stores the count of local files for display in an info badge. Used to track and indicate the number of local files.
	/// </summary>
	internal int LocalFilesCountInfoBadgeValue { get; set => SP(ref field, value); }

	/// <summary>
	/// Stores the opacity level for the local files count info badge. It is a double value representing transparency.
	/// </summary>
	internal double LocalFilesCountInfoBadgeOpacity { get; set => SP(ref field, value); }

	/// <summary>
	/// Stores the count of event logs for the info badge. Used to track the number of events for display purposes.
	/// </summary>
	internal int EventLogsCountInfoBadgeValue { get; set => SP(ref field, value); }

	/// <summary>
	/// Stores the opacity level for the event logs count info badge. It is a double value representing transparency.
	/// </summary>
	internal double EventLogsCountInfoBadgeOpacity { get; set => SP(ref field, value); }

	/// <summary>
	/// Toggle button to determine whether the new Supplemental policy should be deployed on the system after creation or not
	/// </summary>
	internal bool DeployPolicy { get; set => SP(ref field, value); }

	internal bool DeployPolicyState { get; set => SP(ref field, value); }

	#endregion


	#region LISTVIEW IMPLEMENTATIONS FOR EVENT LOGS

	// Properties to hold each columns' width.
	internal GridLength ColumnWidthEventLogs1 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs2 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs3 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs4 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs5 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs6 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs7 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs8 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs9 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs10 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs11 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs12 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs13 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs14 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs15 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs16 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs17 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs18 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs19 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs20 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthEventLogs21 { get; set => SP(ref field, value); }

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidthEventLogs()
	{
		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FileNameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("TimeCreatedHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SignatureStatusHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("ActionHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("OriginalFileNameHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("InternalNameHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FileDescriptionHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("ProductNameHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FileVersionHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("PackageFamilyNameHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA256HashHeader/Text"));
		double maxWidth12 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA1HashHeader/Text"));
		double maxWidth13 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SigningScenarioHeader/Text"));
		double maxWidth14 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FilePathHeader/Text"));
		double maxWidth15 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA1FlatHashHeader/Text"));
		double maxWidth16 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("SHA256FlatHashHeader/Text"));
		double maxWidth17 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("FilePublishersHeader/Text"));
		double maxWidth18 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("OpusDataHeader/Text"));
		double maxWidth19 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("PolicyGUIDHeader/Text"));
		double maxWidth20 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("PolicyNameHeader/Text"));
		double maxWidth21 = ListViewHelper.MeasureText(GlobalVars.Rizz.GetString("ComputerNameHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (FileIdentity item in EventLogsFileIdentities)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.FileName, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.TimeCreated.ToString(), maxWidth2);
			maxWidth3 = ListViewHelper.MeasureText(item.SignatureStatus.ToString(), maxWidth3);
			maxWidth4 = ListViewHelper.MeasureText(item.Action.ToString(), maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.OriginalFileName, maxWidth5);
			maxWidth6 = ListViewHelper.MeasureText(item.InternalName, maxWidth6);
			maxWidth7 = ListViewHelper.MeasureText(item.FileDescription, maxWidth7);
			maxWidth8 = ListViewHelper.MeasureText(item.ProductName, maxWidth8);
			maxWidth9 = ListViewHelper.MeasureText(item.FileVersion?.ToString(), maxWidth9);
			maxWidth10 = ListViewHelper.MeasureText(item.PackageFamilyName, maxWidth10);
			maxWidth11 = ListViewHelper.MeasureText(item.SHA256Hash, maxWidth11);
			maxWidth12 = ListViewHelper.MeasureText(item.SHA1Hash, maxWidth12);
			maxWidth13 = ListViewHelper.MeasureText(item.SISigningScenario.ToString(), maxWidth13);
			maxWidth14 = ListViewHelper.MeasureText(item.FilePath, maxWidth14);
			maxWidth15 = ListViewHelper.MeasureText(item.SHA1FlatHash, maxWidth15);
			maxWidth16 = ListViewHelper.MeasureText(item.SHA256FlatHash, maxWidth16);
			maxWidth17 = ListViewHelper.MeasureText(item.FilePublishersToDisplay, maxWidth17);
			maxWidth18 = ListViewHelper.MeasureText(item.Opus, maxWidth18);
			maxWidth19 = ListViewHelper.MeasureText(item.PolicyGUID.ToString(), maxWidth19);
			maxWidth20 = ListViewHelper.MeasureText(item.PolicyName, maxWidth20);
			maxWidth21 = ListViewHelper.MeasureText(item.ComputerName, maxWidth21);
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
	internal GridLength ColumnWidthLocalFiles1 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles2 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles3 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles4 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles5 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles6 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles7 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles8 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles9 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles10 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles11 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles12 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles13 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles14 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles15 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles16 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles17 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidthLocalFiles18 { get; set => SP(ref field, value); }

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// It should always run once ALL the data have been added to the ObservableCollection that is the ItemsSource of the ListView
	/// And only after this method, the ItemsSource must be assigned to the ListView.
	/// </summary>
	internal void CalculateColumnWidthLocalFiles()
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
		foreach (FileIdentity item in LocalFilesFileIdentities)
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
