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
using System.ComponentModel;
using System.Runtime.CompilerServices;
using AppControlManager.IntelGathering;
using AppControlManager.Others;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.
internal sealed partial class AllowNewAppsVM : INotifyPropertyChanged
{
	// This event is raised when a property changes.
	public event PropertyChangedEventHandler? PropertyChanged;


	#region

	// To store the FileIdentities displayed on the Local Files ListView
	internal readonly ObservableCollection<FileIdentity> LocalFilesFileIdentities = [];

	// Store all outputs for searching, used as a temporary storage for filtering
	// If ObservableCollection were used directly, any filtering or modification could remove items permanently
	// from the collection, making it difficult to reset or apply different filters without re-fetching data.
	internal readonly List<FileIdentity> LocalFilesAllFileIdentities = [];


	// To store the FileIdentities displayed on the Event Logs ListView
	internal readonly ObservableCollection<FileIdentity> EventLogsFileIdentities = [];

	// Store all outputs for searching, used as a temporary storage for filtering
	// If ObservableCollection were used directly, any filtering or modification could remove items permanently
	// from the collection, making it difficult to reset or apply different filters without re-fetching data.
	internal readonly List<FileIdentity> EventLogsAllFileIdentities = [];

	#endregion


	#region UI-Bound Properties

	/// <summary>
	/// Holds the state of the Event Logs menu item, indicating whether it is enabled or disabled.
	/// </summary>
	private bool _EventLogsMenuItemState;
	internal bool EventLogsMenuItemState
	{
		get => _EventLogsMenuItemState;
		set => SetProperty(_EventLogsMenuItemState, value, newValue => _EventLogsMenuItemState = newValue);
	}

	/// <summary>
	/// Stores the state of the local files menu item as a boolean value. Indicates whether the local files menu item is
	/// enabled or disabled.
	/// </summary>
	private bool _LocalFilesMenuItemState;
	internal bool LocalFilesMenuItemState
	{
		get => _LocalFilesMenuItemState;
		set => SetProperty(_LocalFilesMenuItemState, value, newValue => _LocalFilesMenuItemState = newValue);
	}

	/// <summary>
	/// Stores the count of local files for display in an info badge. Used to track and indicate the number of local files.
	/// </summary>
	private int _LocalFilesCountInfoBadgeValue;
	internal int LocalFilesCountInfoBadgeValue
	{
		get => _LocalFilesCountInfoBadgeValue;
		set => SetProperty(_LocalFilesCountInfoBadgeValue, value, newValue => _LocalFilesCountInfoBadgeValue = newValue);
	}

	/// <summary>
	/// Stores the opacity level for the local files count info badge. It is a double value representing transparency.
	/// </summary>
	private double _LocalFilesCountInfoBadgeOpacity;
	internal double LocalFilesCountInfoBadgeOpacity
	{
		get => _LocalFilesCountInfoBadgeOpacity;
		set => SetProperty(_LocalFilesCountInfoBadgeOpacity, value, newValue => _LocalFilesCountInfoBadgeOpacity = newValue);
	}

	/// <summary>
	/// Stores the count of event logs for the info badge. Used to track the number of events for display purposes.
	/// </summary>
	private int _EventLogsCountInfoBadgeValue;
	internal int EventLogsCountInfoBadgeValue
	{
		get => _EventLogsCountInfoBadgeValue;
		set => SetProperty(_EventLogsCountInfoBadgeValue, value, newValue => _EventLogsCountInfoBadgeValue = newValue);
	}

	/// <summary>
	/// Stores the opacity level for the event logs count info badge. It is a double value representing transparency.
	/// </summary>
	private double _EventLogsCountInfoBadgeOpacity;
	internal double EventLogsCountInfoBadgeOpacity
	{
		get => _EventLogsCountInfoBadgeOpacity;
		set => SetProperty(_EventLogsCountInfoBadgeOpacity, value, newValue => _EventLogsCountInfoBadgeOpacity = newValue);
	}

	/// <summary>
	/// Toggle button to determine whether the new Supplemental policy should be deployed on the system after creation or not
	/// </summary>
	private bool _DeployPolicy = true;
	internal bool DeployPolicy
	{
		get => _DeployPolicy;
		set => SetProperty(_DeployPolicy, value, newValue => _DeployPolicy = newValue);
	}

	private bool _DeployPolicyState = true;
	internal bool DeployPolicyState
	{
		get => _DeployPolicyState;
		set => SetProperty(_DeployPolicyState, value, newValue => _DeployPolicyState = newValue);
	}

	#endregion


	#region LISTVIEW IMPLEMENTATIONS FOR EVENT LOGS

	// Properties to hold each columns' width.
	private GridLength _ColumnWidthEventLogs1;
	internal GridLength ColumnWidthEventLogs1
	{
		get => _ColumnWidthEventLogs1;
		set { _ColumnWidthEventLogs1 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs1)); }
	}

	private GridLength _ColumnWidthEventLogs2;
	internal GridLength ColumnWidthEventLogs2
	{
		get => _ColumnWidthEventLogs2;
		set { _ColumnWidthEventLogs2 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs2)); }
	}

	private GridLength _ColumnWidthEventLogs3;
	internal GridLength ColumnWidthEventLogs3
	{
		get => _ColumnWidthEventLogs3;
		set { _ColumnWidthEventLogs3 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs3)); }
	}

	private GridLength _ColumnWidthEventLogs4;
	internal GridLength ColumnWidthEventLogs4
	{
		get => _ColumnWidthEventLogs4;
		set { _ColumnWidthEventLogs4 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs4)); }
	}

	private GridLength _ColumnWidthEventLogs5;
	internal GridLength ColumnWidthEventLogs5
	{
		get => _ColumnWidthEventLogs5;
		set { _ColumnWidthEventLogs5 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs5)); }
	}

	private GridLength _ColumnWidthEventLogs6;
	internal GridLength ColumnWidthEventLogs6
	{
		get => _ColumnWidthEventLogs6;
		set { _ColumnWidthEventLogs6 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs6)); }
	}

	private GridLength _ColumnWidthEventLogs7;
	internal GridLength ColumnWidthEventLogs7
	{
		get => _ColumnWidthEventLogs7;
		set { _ColumnWidthEventLogs7 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs7)); }
	}

	private GridLength _ColumnWidthEventLogs8;
	internal GridLength ColumnWidthEventLogs8
	{
		get => _ColumnWidthEventLogs8;
		set { _ColumnWidthEventLogs8 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs8)); }
	}

	private GridLength _ColumnWidthEventLogs9;
	internal GridLength ColumnWidthEventLogs9
	{
		get => _ColumnWidthEventLogs9;
		set { _ColumnWidthEventLogs9 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs9)); }
	}

	private GridLength _ColumnWidthEventLogs10;
	internal GridLength ColumnWidthEventLogs10
	{
		get => _ColumnWidthEventLogs10;
		set { _ColumnWidthEventLogs10 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs10)); }
	}

	private GridLength _ColumnWidthEventLogs11;
	internal GridLength ColumnWidthEventLogs11
	{
		get => _ColumnWidthEventLogs11;
		set { _ColumnWidthEventLogs11 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs11)); }
	}

	private GridLength _ColumnWidthEventLogs12;
	internal GridLength ColumnWidthEventLogs12
	{
		get => _ColumnWidthEventLogs12;
		set { _ColumnWidthEventLogs12 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs12)); }
	}

	private GridLength _ColumnWidthEventLogs13;
	internal GridLength ColumnWidthEventLogs13
	{
		get => _ColumnWidthEventLogs13;
		set { _ColumnWidthEventLogs13 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs13)); }
	}

	private GridLength _ColumnWidthEventLogs14;
	internal GridLength ColumnWidthEventLogs14
	{
		get => _ColumnWidthEventLogs14;
		set { _ColumnWidthEventLogs14 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs14)); }
	}

	private GridLength _ColumnWidthEventLogs15;
	internal GridLength ColumnWidthEventLogs15
	{
		get => _ColumnWidthEventLogs15;
		set { _ColumnWidthEventLogs15 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs15)); }
	}

	private GridLength _ColumnWidthEventLogs16;
	internal GridLength ColumnWidthEventLogs16
	{
		get => _ColumnWidthEventLogs16;
		set { _ColumnWidthEventLogs16 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs16)); }
	}

	private GridLength _ColumnWidthEventLogs17;
	internal GridLength ColumnWidthEventLogs17
	{
		get => _ColumnWidthEventLogs17;
		set { _ColumnWidthEventLogs17 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs17)); }
	}

	private GridLength _ColumnWidthEventLogs18;
	internal GridLength ColumnWidthEventLogs18
	{
		get => _ColumnWidthEventLogs18;
		set { _ColumnWidthEventLogs18 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs18)); }
	}

	private GridLength _ColumnWidthEventLogs19;
	internal GridLength ColumnWidthEventLogs19
	{
		get => _ColumnWidthEventLogs19;
		set { _ColumnWidthEventLogs19 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs19)); }
	}

	private GridLength _ColumnWidthEventLogs20;
	internal GridLength ColumnWidthEventLogs20
	{
		get => _ColumnWidthEventLogs20;
		set { _ColumnWidthEventLogs20 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs20)); }
	}

	private GridLength _ColumnWidthEventLogs21;
	internal GridLength ColumnWidthEventLogs21
	{
		get => _ColumnWidthEventLogs21;
		set { _ColumnWidthEventLogs21 = value; OnPropertyChanged(nameof(ColumnWidthEventLogs21)); }
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
	private GridLength _ColumnWidthLocalFiles1;
	internal GridLength ColumnWidthLocalFiles1
	{
		get => _ColumnWidthLocalFiles1;
		set { _ColumnWidthLocalFiles1 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles1)); }
	}

	private GridLength _ColumnWidthLocalFiles2;
	internal GridLength ColumnWidthLocalFiles2
	{
		get => _ColumnWidthLocalFiles2;
		set { _ColumnWidthLocalFiles2 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles2)); }
	}

	private GridLength _ColumnWidthLocalFiles3;
	internal GridLength ColumnWidthLocalFiles3
	{
		get => _ColumnWidthLocalFiles3;
		set { _ColumnWidthLocalFiles3 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles3)); }
	}

	private GridLength _ColumnWidthLocalFiles4;
	internal GridLength ColumnWidthLocalFiles4
	{
		get => _ColumnWidthLocalFiles4;
		set { _ColumnWidthLocalFiles4 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles4)); }
	}

	private GridLength _ColumnWidthLocalFiles5;
	internal GridLength ColumnWidthLocalFiles5
	{
		get => _ColumnWidthLocalFiles5;
		set { _ColumnWidthLocalFiles5 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles5)); }
	}

	private GridLength _ColumnWidthLocalFiles6;
	internal GridLength ColumnWidthLocalFiles6
	{
		get => _ColumnWidthLocalFiles6;
		set { _ColumnWidthLocalFiles6 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles6)); }
	}

	private GridLength _ColumnWidthLocalFiles7;
	internal GridLength ColumnWidthLocalFiles7
	{
		get => _ColumnWidthLocalFiles7;
		set { _ColumnWidthLocalFiles7 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles7)); }
	}

	private GridLength _ColumnWidthLocalFiles8;
	internal GridLength ColumnWidthLocalFiles8
	{
		get => _ColumnWidthLocalFiles8;
		set { _ColumnWidthLocalFiles8 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles8)); }
	}

	private GridLength _ColumnWidthLocalFiles9;
	internal GridLength ColumnWidthLocalFiles9
	{
		get => _ColumnWidthLocalFiles9;
		set { _ColumnWidthLocalFiles9 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles9)); }
	}

	private GridLength _ColumnWidthLocalFiles10;
	internal GridLength ColumnWidthLocalFiles10
	{
		get => _ColumnWidthLocalFiles10;
		set { _ColumnWidthLocalFiles10 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles10)); }
	}

	private GridLength _ColumnWidthLocalFiles11;
	internal GridLength ColumnWidthLocalFiles11
	{
		get => _ColumnWidthLocalFiles11;
		set { _ColumnWidthLocalFiles11 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles11)); }
	}

	private GridLength _ColumnWidthLocalFiles12;
	internal GridLength ColumnWidthLocalFiles12
	{
		get => _ColumnWidthLocalFiles12;
		set { _ColumnWidthLocalFiles12 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles12)); }
	}

	private GridLength _ColumnWidthLocalFiles13;
	internal GridLength ColumnWidthLocalFiles13
	{
		get => _ColumnWidthLocalFiles13;
		set { _ColumnWidthLocalFiles13 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles13)); }
	}

	private GridLength _ColumnWidthLocalFiles14;
	internal GridLength ColumnWidthLocalFiles14
	{
		get => _ColumnWidthLocalFiles14;
		set { _ColumnWidthLocalFiles14 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles14)); }
	}

	private GridLength _ColumnWidthLocalFiles15;
	internal GridLength ColumnWidthLocalFiles15
	{
		get => _ColumnWidthLocalFiles15;
		set { _ColumnWidthLocalFiles15 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles15)); }
	}

	private GridLength _ColumnWidthLocalFiles16;
	internal GridLength ColumnWidthLocalFiles16
	{
		get => _ColumnWidthLocalFiles16;
		set { _ColumnWidthLocalFiles16 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles16)); }
	}

	private GridLength _ColumnWidthLocalFiles17;
	internal GridLength ColumnWidthLocalFiles17
	{
		get => _ColumnWidthLocalFiles17;
		set { _ColumnWidthLocalFiles17 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles17)); }
	}

	private GridLength _ColumnWidthLocalFiles18;
	internal GridLength ColumnWidthLocalFiles18
	{
		get => _ColumnWidthLocalFiles18;
		set { _ColumnWidthLocalFiles18 = value; OnPropertyChanged(nameof(ColumnWidthLocalFiles18)); }
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

	/// <summary>
	/// Sets the property and raises the PropertyChanged event if the value has changed.
	/// This also prevents infinite loops where a property raises OnPropertyChanged which could trigger an update in the UI, and the UI might call set again, leading to an infinite loop.
	/// </summary>
	/// <typeparam name="T"></typeparam>
	/// <param name="currentValue"></param>
	/// <param name="newValue"></param>
	/// <param name="setter"></param>
	/// <param name="propertyName"></param>
	/// <returns></returns>
	private bool SetProperty<T>(T currentValue, T newValue, Action<T> setter, [CallerMemberName] string? propertyName = null)
	{
		if (EqualityComparer<T>.Default.Equals(currentValue, newValue))
			return false;
		setter(newValue);
		OnPropertyChanged(propertyName);
		return true;
	}


	private void OnPropertyChanged(string? propertyName)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}
}
