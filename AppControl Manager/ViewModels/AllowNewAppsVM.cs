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
using System.IO;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.Pages;
using AppControlManager.SiPolicy;
using AppControlManager.SiPolicyIntel;
using AppControlManager.XMLOps;
using CommunityToolkit.WinUI;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;

namespace AppControlManager.ViewModels;

internal sealed partial class AllowNewAppsVM : ViewModelBase
{

	internal readonly EventLogUtility EventLogsUtil;
	private readonly PolicyEditorVM PolicyEditorViewModel;

	internal AllowNewAppsVM(EventLogUtility _EventLogUtility, PolicyEditorVM _PolicyEditorVM)
	{
		Step1Border_Brush = linearGradientBrush;

		Step2ProgressRingProgress = new Progress<double>(p => Step2ProgressRingValue = p);

		EventLogsUtil = _EventLogUtility;
		PolicyEditorViewModel = _PolicyEditorVM;

		Step1InfoBar = new InfoBarSettings(
			() => Step1InfoBar_IsOpen, value => Step1InfoBar_IsOpen = value,
			() => Step1InfoBar_Message, value => Step1InfoBar_Message = value,
			() => Step1InfoBar_Severity, value => Step1InfoBar_Severity = value,
			() => Step1InfoBar_IsClosable, value => Step1InfoBar_IsClosable = value,
			Dispatcher,
			() => Step1InfoBar_Title, value => Step1InfoBar_Title = value);

		Step2InfoBar = new InfoBarSettings(
			() => Step2InfoBar_IsOpen, value => Step2InfoBar_IsOpen = value,
			() => Step2InfoBar_Message, value => Step2InfoBar_Message = value,
			() => Step2InfoBar_Severity, value => Step2InfoBar_Severity = value,
			() => Step2InfoBar_IsClosable, value => Step2InfoBar_IsClosable = value,
			Dispatcher,
			() => Step2InfoBar_Title, value => Step2InfoBar_Title = value);

		Step3InfoBar = new InfoBarSettings(
			() => Step3InfoBar_IsOpen, value => Step3InfoBar_IsOpen = value,
			() => Step3InfoBar_Message, value => Step3InfoBar_Message = value,
			() => Step3InfoBar_Severity, value => Step3InfoBar_Severity = value,
			() => Step3InfoBar_IsClosable, value => Step3InfoBar_IsClosable = value,
			Dispatcher,
			() => Step3InfoBar_Title, value => Step3InfoBar_Title = value);

		// To adjust the initial width of the columns, giving them nice paddings.
		CalculateColumnWidthLocalFiles();
		CalculateColumnWidthEventLogs();
	}

	#region

	// To store the FileIdentities displayed on the Local Files ListView
	internal ObservableCollection<FileIdentity> LocalFilesFileIdentities { get; set => SP(ref field, value); } = [];

	// Store all outputs for searching, used as a temporary storage for filtering
	// If ObservableCollection were used directly, any filtering or modification could remove items permanently
	// from the collection, making it difficult to reset or apply different filters without re-fetching data.
	internal readonly List<FileIdentity> LocalFilesAllFileIdentities = [];

	private ListViewHelper.SortState SortStateLocalFiles { get; set; } = new();

	// To store the FileIdentities displayed on the Event Logs ListView
	internal readonly ObservableCollection<FileIdentity> EventLogsFileIdentities = [];

	// Store all outputs for searching, used as a temporary storage for filtering
	// If ObservableCollection were used directly, any filtering or modification could remove items permanently
	// from the collection, making it difficult to reset or apply different filters without re-fetching data.
	internal readonly List<FileIdentity> EventLogsAllFileIdentities = [];

	private ListViewHelper.SortState SortStateEventLogs { get; set; } = new();

	#endregion


	#region UI-Bound Properties

	/// <summary>
	/// The user selected XML base policy path.
	/// </summary>
	internal string? selectedXMLFilePath { get; set => SP(ref field, value); }

	/// <summary>
	/// The user selected Supplemental policy name.
	/// </summary>
	internal string? selectedSupplementalPolicyName { get; set => SPT(ref field, value); }

	/// <summary>
	/// The user selected directories to scan
	/// </summary>
	internal readonly UniqueStringObservableCollection selectedDirectoriesToScan = [];

	/// <summary>
	/// Custom HashSet to store the output of both local files and event logs scans
	/// If the same file is detected in event logs And local file scans, the one with IsECCSigned property set to true will be kept
	/// So that the respective methods will make Hash based rule for that file since AppControl doesn't support ECC Signed files yet
	/// </summary>
	internal readonly FileIdentityECCBasedHashSet fileIdentities = new();

	/// <summary>
	/// Will determine whether the user selected XML policy file is signed or unsigned
	/// </summary>
	private bool _IsSignedPolicy;

	/// <summary>
	/// Gets or sets a value indicating whether the supplemental policy name text box is enabled.
	/// </summary>
	internal bool SupplementalPolicyNameTextBoxIsEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Only the logs generated after this time will be shown
	/// It will be set when user moves from Step1 to Step2
	/// </summary>
	internal DateTime? LogsScanStartTime;

	/// <summary>
	/// The base policy XML objectified
	/// </summary>
	internal SiPolicy.SiPolicy? _BasePolicyObject;

	// To hold the necessary details for policy signing if the selected base policy is signed
	// They will be retrieved from the content dialog
	private string? _CertCN;
	private string? _CertPath;

	// Paths for the entire operation of this page
	private DirectoryInfo? stagingArea;
	private string? tempBasePolicyPath;
	private string? AuditModeCIP;
	private string? EnforcedModeCIP;

	internal bool BrowseForXMLPolicyButtonIsEnabled { get; set => SP(ref field, value); } = true;
	internal bool GoToStep2ButtonIsEnabled { get; set => SP(ref field, value); } = true;

	internal double Step1GridOpacity { get; set => SP(ref field, value); } = 1;

	internal bool LogSizeNumberBoxIsEnabled { get; set => SP(ref field, value); } = true;

	internal bool ResetStepsButtonIsEnabled { get; set => SP(ref field, value); } = true;

	internal bool ResetProgressRingIsActive { get; set => SP(ref field, value); }

	internal bool Step1ProgressRingIsActive { get; set => SP(ref field, value); }

	internal bool Step2ProgressRingIsActive { get; set => SP(ref field, value); }

	internal bool Step2ProgressRingIsIndeterminate { get; set => SP(ref field, value); }

	internal bool GoToStep3ButtonIsEnabled { get; set => SP(ref field, value); }

	internal double Step2GridOpacity { get; set => SP(ref field, value); } = 0.5;

	internal double Step3GridOpacity { get; set => SP(ref field, value); } = 0.5;

	internal bool CreatePolicyButtonIsEnabled { get; set => SP(ref field, value); }

	internal bool ScanLevelComboBoxIsEnabled { get; set => SP(ref field, value); }

	internal bool BrowseForFoldersButtonIsEnabled { get; set => SP(ref field, value); }

	/// <summary>
	/// Path of the Supplemental policy that is created
	/// </summary>
	internal string? finalSupplementalPolicyPath { get; set => SP(ref field, value); }

	internal Visibility BrowseForXMLPolicyButtonLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal Visibility OpenInPolicyEditorInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

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
	/// Toggle button to determine whether the new Supplemental policy should be deployed on the system after creation or not.
	/// </summary>
	internal bool DeployPolicy { get; set => SP(ref field, value); }

	/// <summary>
	/// The Enabled/Disabled state of the DeployPolicy button.
	/// </summary>
	internal bool DeployPolicyState { get; set => SP(ref field, value); }

	internal InfoBarSeverity Step1InfoBar_Severity { get; set => SP(ref field, value); }
	internal bool Step1InfoBar_IsOpen { get; set => SP(ref field, value); }
	internal bool Step1InfoBar_IsClosable { get; set => SP(ref field, value); }
	internal string? Step1InfoBar_Message { get; set => SP(ref field, value); }
	internal string? Step1InfoBar_Title { get; set => SP(ref field, value); }

	private readonly InfoBarSettings Step1InfoBar;

	internal InfoBarSeverity Step2InfoBar_Severity { get; set => SP(ref field, value); }
	internal bool Step2InfoBar_IsOpen { get; set => SP(ref field, value); }
	internal bool Step2InfoBar_IsClosable { get; set => SP(ref field, value); }
	internal string? Step2InfoBar_Message { get; set => SP(ref field, value); }
	internal string? Step2InfoBar_Title { get; set => SP(ref field, value); }

	private readonly InfoBarSettings Step2InfoBar;

	internal InfoBarSeverity Step3InfoBar_Severity { get; set => SP(ref field, value); }
	internal bool Step3InfoBar_IsOpen { get; set => SP(ref field, value); }
	internal bool Step3InfoBar_IsClosable { get; set => SP(ref field, value); }
	internal string? Step3InfoBar_Message { get; set => SP(ref field, value); }
	internal string? Step3InfoBar_Title { get; set => SP(ref field, value); }

	private readonly InfoBarSettings Step3InfoBar;

	/// <summary>
	/// Gradient color used for the active border.
	/// </summary>
	internal LinearGradientBrush linearGradientBrush = new()
	{
		StartPoint = new Windows.Foundation.Point(0, 0),
		EndPoint = new Windows.Foundation.Point(1, 1),
		GradientStops =
		[
			new GradientStop { Color = Colors.HotPink, Offset = 0.0 },
			new GradientStop { Color = Colors.Wheat,  Offset = 1.0 }
		]
	};

	/// <summary>
	/// Create a ThemeShadow used to highlight the active section/border.
	/// </summary>
	internal static Shadow? ThemeShadow = new ThemeShadow();

	// The default styles when the page is first constructed.
	internal Brush? Step1Border_Brush { get; set => SP(ref field, value); }
	internal Thickness Step1Border_Thickness { get; set => SP(ref field, value); } = new Thickness(1);
	internal Vector3 Step1Border_Translation { get; set => SP(ref field, value); } = new Vector3(0, 0, 40);
	internal Shadow? Step1Border_Shadow { get; set => SP(ref field, value); } = ThemeShadow;

	internal Brush? Step2Border_Brush { get; set => SP(ref field, value); }
	internal Thickness Step2Border_Thickness { get; set => SP(ref field, value); } = new Thickness(0);
	internal Vector3 Step2Border_Translation { get; set => SP(ref field, value); } = new Vector3(0, 0, 0);
	internal Shadow? Step2Border_Shadow { get; set => SP(ref field, value); }

	internal Brush? Step3Border_Brush { get; set => SP(ref field, value); }
	internal Thickness Step3Border_Thickness { get; set => SP(ref field, value); } = new Thickness(0);
	internal Vector3 Step3Border_Translation { get; set => SP(ref field, value); } = new Vector3(0, 0, 0);
	internal Shadow? Step3Border_Shadow { get; set => SP(ref field, value); }

	internal void Step1Border_SetStyles()
	{
		Step1Border_Brush = linearGradientBrush;
		Step1Border_Thickness = new Thickness(1);
		Step1Border_Translation += new Vector3(0, 0, 40);
		Step1Border_Shadow = ThemeShadow;
	}

	internal void Step2Border_SetStyles()
	{
		Step2Border_Brush = linearGradientBrush;
		Step2Border_Thickness = new Thickness(1);
		Step2Border_Translation += new Vector3(0, 0, 40);
		Step2Border_Shadow = ThemeShadow;
	}

	internal void Step3Border_SetStyles()
	{
		Step3Border_Brush = linearGradientBrush;
		Step3Border_Thickness = new Thickness(1);
		Step3Border_Translation += new Vector3(0, 0, 40);
		Step3Border_Shadow = ThemeShadow;
	}

	internal void Step1Border_ResetStyles()
	{
		// Reset the BorderBrush and BorderThickness to their default values
		Step1Border_Brush = null;
		Step1Border_Thickness = new Thickness(0);
		Step1Border_Translation = new Vector3(0, 0, 0); // Reset the border depth
		Step1Border_Shadow = null;
	}

	internal void Step2Border_ResetStyles()
	{
		Step2Border_Brush = null;
		Step2Border_Thickness = new Thickness(0);
		Step2Border_Translation = new Vector3(0, 0, 0); // Reset the border depth
		Step2Border_Shadow = null;
	}

	internal void Step3Border_ResetStyles()
	{
		Step3Border_Brush = null;
		Step3Border_Thickness = new Thickness(0);
		Step3Border_Translation = new Vector3(0, 0, 0); // Reset the border depth
		Step3Border_Shadow = null;
	}

	#endregion


	#region Steps management

	internal void DisableStep1(bool ResetInfoBar = true)
	{
		BrowseForXMLPolicyButtonIsEnabled = false;
		GoToStep2ButtonIsEnabled = false;
		SupplementalPolicyNameTextBoxIsEnabled = false;
		Step1GridOpacity = 0.5;
		Step1Border_ResetStyles();

		if (ResetInfoBar)
		{
			Step1InfoBar_IsOpen = false;
			Step1InfoBar_Message = null;
		}

		LogSizeNumberBoxIsEnabled = false;
	}

	internal void EnableStep1()
	{
		BrowseForXMLPolicyButtonIsEnabled = true;
		GoToStep2ButtonIsEnabled = true;
		SupplementalPolicyNameTextBoxIsEnabled = true;
		Step1GridOpacity = 1;
		Step1Border_SetStyles();
		LogSizeNumberBoxIsEnabled = true;
	}

	internal void DisableStep2()
	{
		BrowseForFoldersButtonIsEnabled = false;
		GoToStep3ButtonIsEnabled = false;
		Step2GridOpacity = 0.5;
		Step2Border_ResetStyles();
		Step2InfoBar_IsOpen = false;
		Step2InfoBar_Message = null;
	}

	internal void EnableStep2()
	{
		BrowseForFoldersButtonIsEnabled = true;
		Step2GridOpacity = 1;
		GoToStep3ButtonIsEnabled = true;
		Step2Border_SetStyles();
	}

	internal void DisableStep3()
	{
		DeployPolicyState = false;
		ScanLevelComboBoxIsEnabled = false;
		CreatePolicyButtonIsEnabled = false;
		Step3GridOpacity = 0.5;
		Step3Border_ResetStyles();
		Step3InfoBar_IsOpen = false;
		Step3InfoBar_Message = null;
	}

	internal void EnableStep3()
	{
		DeployPolicyState = true;
		ScanLevelComboBoxIsEnabled = true;
		CreatePolicyButtonIsEnabled = true;
		Step3GridOpacity = 1;
		Step3Border_SetStyles();
	}

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
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.GetStr("FileNameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.GetStr("TimeCreatedHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.GetStr("SignatureStatusHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.GetStr("ActionHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.GetStr("OriginalFileNameHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(GlobalVars.GetStr("InternalNameHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureText(GlobalVars.GetStr("FileDescriptionHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureText(GlobalVars.GetStr("ProductNameHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureText(GlobalVars.GetStr("FileVersionHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureText(GlobalVars.GetStr("PackageFamilyNameHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureText(GlobalVars.GetStr("SHA256HashHeader/Text"));
		double maxWidth12 = ListViewHelper.MeasureText(GlobalVars.GetStr("SHA1HashHeader/Text"));
		double maxWidth13 = ListViewHelper.MeasureText(GlobalVars.GetStr("SigningScenarioHeader/Text"));
		double maxWidth14 = ListViewHelper.MeasureText(GlobalVars.GetStr("FilePathHeader/Text"));
		double maxWidth15 = ListViewHelper.MeasureText(GlobalVars.GetStr("SHA1FlatHashHeader/Text"));
		double maxWidth16 = ListViewHelper.MeasureText(GlobalVars.GetStr("SHA256FlatHashHeader/Text"));
		double maxWidth17 = ListViewHelper.MeasureText(GlobalVars.GetStr("FilePublishersHeader/Text"));
		double maxWidth18 = ListViewHelper.MeasureText(GlobalVars.GetStr("OpusDataHeader/Text"));
		double maxWidth19 = ListViewHelper.MeasureText(GlobalVars.GetStr("PolicyGUIDHeader/Text"));
		double maxWidth20 = ListViewHelper.MeasureText(GlobalVars.GetStr("PolicyNameHeader/Text"));
		double maxWidth21 = ListViewHelper.MeasureText(GlobalVars.GetStr("ComputerNameHeader/Text"));

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
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.GetStr("FileNameHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.GetStr("SignatureStatusHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.GetStr("OriginalFileNameHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.GetStr("InternalNameHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.GetStr("FileDescriptionHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(GlobalVars.GetStr("ProductNameHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureText(GlobalVars.GetStr("FileVersionHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureText(GlobalVars.GetStr("PackageFamilyNameHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureText(GlobalVars.GetStr("SHA256HashHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureText(GlobalVars.GetStr("SHA1HashHeader/Text"));
		double maxWidth11 = ListViewHelper.MeasureText(GlobalVars.GetStr("SigningScenarioHeader/Text"));
		double maxWidth12 = ListViewHelper.MeasureText(GlobalVars.GetStr("FilePathHeader/Text"));
		double maxWidth13 = ListViewHelper.MeasureText(GlobalVars.GetStr("SHA1PageHashHeader/Text"));
		double maxWidth14 = ListViewHelper.MeasureText(GlobalVars.GetStr("SHA256PageHashHeader/Text"));
		double maxWidth15 = ListViewHelper.MeasureText(GlobalVars.GetStr("HasWHQLSignerHeader/Text"));
		double maxWidth16 = ListViewHelper.MeasureText(GlobalVars.GetStr("FilePublishersHeader/Text"));
		double maxWidth17 = ListViewHelper.MeasureText(GlobalVars.GetStr("IsECCSignedHeader/Text"));
		double maxWidth18 = ListViewHelper.MeasureText(GlobalVars.GetStr("OpusDataHeader/Text"));

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

		CalculateColumnWidthLocalFiles();
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

		CalculateColumnWidthEventLogs();
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
	/// Event handler to open the supplemental policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor() => await PolicyEditorViewModel.OpenInPolicyEditor(finalSupplementalPolicyPath);

	internal async void OpenInDefaultFileHandler_Internal() => await OpenInDefaultFileHandler(finalSupplementalPolicyPath);

	/// <summary>
	/// Event handler for the clear button in the base policy path selection button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void BrowseForXMLPolicyButton_Flyout_Clear_Click(object sender, RoutedEventArgs e)
	{
		selectedXMLFilePath = null;
		tempBasePolicyPath = null;
	}

	/// <summary>
	/// Event handler for the Create Policy button - Step 3
	/// </summary>
	internal async void CreatePolicyButton_Click()
	{
		try
		{
			// Disable the CreatePolicy button for the duration of the operation
			CreatePolicyButtonIsEnabled = false;

			ResetStepsButtonIsEnabled = false;

			OpenInPolicyEditorInfoBarActionButtonVisibility = Visibility.Collapsed;

			Step3InfoBar_IsClosable = false;

			Step3InfoBar.WriteInfo(GlobalVars.GetStr("CreatingPolicyFromLogsOrScans"));

			// Check if there are items for the local file scans ListView
			if (LocalFilesAllFileIdentities.Count > 0)
			{
				// convert every selected item to FileIdentity and store it in the list
				foreach (FileIdentity item in LocalFilesAllFileIdentities)
				{
					_ = fileIdentities.Add(item);
				}
			}

			// Check if there are selected items for the Event Logs scan ListView
			if (EventLogsAllFileIdentities.Count > 0)
			{
				// convert every selected item to FileIdentity and store it in the list
				foreach (FileIdentity item in EventLogsAllFileIdentities)
				{
					_ = fileIdentities.Add(item);
				}
			}

			// If there are no logs to create a Supplemental policy with
			if (fileIdentities.Count is 0)
			{
				Step3InfoBar.WriteWarning(GlobalVars.GetStr("NoLogsOrFilesForSupplementalPolicy"));
				return;
			}

			await Task.Run(() =>
			{

				if (stagingArea is null)
				{
					throw new InvalidOperationException(GlobalVars.GetStr("StagingAreaNotFound"));
				}

				// Get the path to an empty policy file
				string EmptyPolicyPath = PrepareEmptyPolicy.Prepare(stagingArea.FullName);

				// Separate the signed and unsigned data
				FileBasedInfoPackage DataPackage = SignerAndHashBuilder.BuildSignerAndHashObjects(data: [.. fileIdentities.FileIdentitiesInternal], level: ScanLevelComboBoxSelectedItem.Level, folderPaths: selectedDirectoriesToScan);

				// Insert the data into the empty policy file
				Master.Initiate(DataPackage, EmptyPolicyPath, Authorization.Allow);

				string OutputPath = Path.Combine(GlobalVars.UserConfigDir, $"{selectedSupplementalPolicyName}.xml");

				// Set the BasePolicyID of our new policy to the one from user selected policy
				_ = SetCiPolicyInfo.Set(EmptyPolicyPath, true, selectedSupplementalPolicyName, _BasePolicyObject!.BasePolicyID, null);

				// Configure policy rule options
				CiRuleOptions.Set(filePath: EmptyPolicyPath, template: CiRuleOptions.PolicyTemplate.Supplemental);

				// Set policy version
				SetCiPolicyInfo.Set(EmptyPolicyPath, new Version("1.0.0.0"));

				if (_IsSignedPolicy)
				{
					// Add certificate's details to the supplemental policy
					_ = AddSigningDetails.Add(EmptyPolicyPath, _CertPath!);
				}

				// Copying the policy file to the User Config directory - outside of the temporary staging area
				File.Copy(EmptyPolicyPath, OutputPath, true);

				string CIPPath = Path.Combine(stagingArea.FullName, $"{selectedSupplementalPolicyName}.cip");

				// Convert the XML file to CIP
				Management.ConvertXMLToBinary(OutputPath, null, CIPPath);

				// Add the supplemental policy path to the class variable
				finalSupplementalPolicyPath = OutputPath;

				if (_IsSignedPolicy)
				{
					// Sign the CIP
					Signing.Main.SignCIP(CIPPath, _CertCN);
				}
				else
				{
					Management.ConvertXMLToBinary(OutputPath, null, CIPPath);
				}

				// If user selected to deploy the policy
				if (DeployPolicy)
				{
#if !DEBUG
					CiToolHelper.UpdatePolicy(CIPPath);
#endif
				}

				// If not deploying it, copy the CIP file to the user config directory, just like the XML policy file
				else
				{
					string finalCIPPath = Path.Combine(GlobalVars.UserConfigDir, Path.GetFileName(CIPPath));
					File.Copy(CIPPath, finalCIPPath, true);
				}
			});

			Step3InfoBar.WriteSuccess(DeployPolicy ? GlobalVars.GetStr("SuccessfullyCreatedAndDeployedPolicy") : GlobalVars.GetStr("SuccessfullyCreatedPolicy"));

			OpenInPolicyEditorInfoBarActionButtonVisibility = Visibility.Visible;
		}
		catch (Exception ex)
		{
			Step3InfoBar.WriteError(ex);
		}
		finally
		{
			CreatePolicyButtonIsEnabled = true;
			ResetStepsButtonIsEnabled = true;
			Step3InfoBar_IsClosable = true;

			// Clear the private variable after the policy is created. This allows the user to remove some items from the logs and recreate the policy with less data if needed.
			fileIdentities.FileIdentitiesInternal.Clear();
		}
	}

	/// <summary>
	/// Handles the click event for a button to browse and select an XML policy file.
	/// </summary>
	/// <exception cref="InvalidOperationException">Thrown when the selected file path is not a valid XML file.</exception>
	internal void BrowseForXMLPolicyButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrWhiteSpace(selectedFile))
		{
			// The extra validations are required since user can provide path in the text box directly
			if (File.Exists(selectedFile) && Path.GetExtension(selectedFile).Equals(".xml", StringComparison.OrdinalIgnoreCase))
			{
				// Store the selected XML file path
				selectedXMLFilePath = selectedFile;
			}
			else
			{
				throw new InvalidOperationException(string.Format(GlobalVars.GetStr("SelectedItemNotValidXmlFilePath"), selectedFile));
			}
		}
	}

	/// <summary>
	/// Handles the click event for a button to browse and select multiple folders. Selected folders are added to a
	/// collection and displayed in the UI.
	/// </summary>
	internal void BrowseForFoldersButton_Click()
	{
		List<string> selectedFolders = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

		if (selectedFolders.Count > 0)
		{
			// Add each folder to the HashSet of the selected directories
			foreach (string folder in selectedFolders)
			{
				selectedDirectoriesToScan.Add(folder);
			}
		}
	}

	#region Local Files Section

	internal string? LocalFilesAllFileIdentitiesSearchText
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ApplyFiltersLocalFiles();
			}
		}
	}

	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	internal void ListViewFlyoutMenuCopy_Click_LocalFiles()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Allow_New_Apps_LocalFiles_ScanResults);
		if (lv is null) return;

		// Check if there are selected items in the ListView
		if (lv.SelectedItems.Count > 0)
		{
			ListViewHelper.ConvertRowToText(lv.SelectedItems, ListViewHelper.FileIdentityPropertyMappings);
		}
	}

	/// <summary>
	/// Applies the date and search filters to the data grid
	/// </summary>
	private void ApplyFiltersLocalFiles()
	{
		ListViewHelper.ApplyFilters(
			allFileIdentities: LocalFilesAllFileIdentities.AsEnumerable(),
			filteredCollection: LocalFilesFileIdentities,
			searchText: LocalFilesAllFileIdentitiesSearchText,
			selectedDate: null,
			regKey: ListViewHelper.ListViewsRegistry.Allow_New_Apps_LocalFiles_ScanResults
		);

		UpdateTotalFiles();
	}

	/// <summary>
	/// Selects all of the displayed rows on the ListView
	/// </summary>
	internal void SelectAll_Click_LocalFiles()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Allow_New_Apps_LocalFiles_ScanResults);
		if (lv is null) return;

		lv.SelectedItems.Clear();

		foreach (FileIdentity item in LocalFilesFileIdentities)
		{
			// Select each item
			lv.SelectedItems.Add(item);
		}
	}

	/// <summary>
	/// De-selects all of the displayed rows on the ListView
	/// </summary>
	internal void DeSelectAll_Click_LocalFiles()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Allow_New_Apps_LocalFiles_ScanResults);
		if (lv is null) return;

		lv.SelectedItems.Clear(); // Deselect all rows by clearing SelectedItems
	}

	/// <summary>
	/// Deletes the selected row from the results
	/// </summary>
	internal void ListViewFlyoutMenuDelete_Click_LocalFiles()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Allow_New_Apps_LocalFiles_ScanResults);
		if (lv is null) return;

		// Collect the selected items to delete
		List<FileIdentity> itemsToDelete = [.. lv.SelectedItems.Cast<FileIdentity>()];

		// Remove each selected item from the FileIdentities collection
		foreach (FileIdentity item in itemsToDelete)
		{
			_ = LocalFilesFileIdentities.Remove(item);
			_ = LocalFilesAllFileIdentities.Remove(item);
		}

		UpdateTotalFiles();
	}

	#endregion

	#region Event Logs Section

	internal string? EventLogsAllFileIdentitiesSearchText
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ApplyFiltersEventLogs();
			}
		}
	}

	/// <summary>
	/// Applies the date and search filters to the data grid
	/// </summary>
	private void ApplyFiltersEventLogs()
	{
		ListViewHelper.ApplyFilters(
			allFileIdentities: EventLogsAllFileIdentities.AsEnumerable(),
			filteredCollection: EventLogsFileIdentities,
			searchText: EventLogsAllFileIdentitiesSearchText,
			selectedDate: null,
			regKey: ListViewHelper.ListViewsRegistry.Allow_New_Apps_EventLogs_ScanResults
		);

		UpdateTotalLogs();
	}

	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	internal void ListViewFlyoutMenuCopy_Click_EventLogs()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Allow_New_Apps_EventLogs_ScanResults);
		if (lv is null) return;

		// Check if there are selected items in the ListView
		if (lv.SelectedItems.Count > 0)
		{
			ListViewHelper.ConvertRowToText(lv.SelectedItems, ListViewHelper.FileIdentityPropertyMappings);
		}
	}

	/// <summary>
	/// Selects all of the displayed rows on the ListView
	/// </summary>
	internal void SelectAll_Click_EventLogs()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Allow_New_Apps_EventLogs_ScanResults);
		if (lv is null) return;

		lv.SelectedItems.Clear();

		foreach (FileIdentity item in EventLogsFileIdentities)
		{
			// Select each item
			lv.SelectedItems.Add(item);
		}
	}

	/// <summary>
	/// De-selects all of the displayed rows on the ListView
	/// </summary>
	internal void DeSelectAll_Click_EventLogs()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Allow_New_Apps_EventLogs_ScanResults);
		if (lv is null) return;

		lv.SelectedItems.Clear(); // Deselect all rows by clearing SelectedItems
	}

	/// <summary>
	/// Deletes the selected row from the results
	/// </summary>
	internal void ListViewFlyoutMenuDelete_Click_EventLogs()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Allow_New_Apps_EventLogs_ScanResults);
		if (lv is null) return;

		// Collect the selected items to delete
		List<FileIdentity> itemsToDelete = [.. lv.SelectedItems.Cast<FileIdentity>()];

		// Remove each selected item from the FileIdentities collection
		foreach (FileIdentity item in itemsToDelete)
		{
			_ = EventLogsFileIdentities.Remove(item);
			_ = EventLogsAllFileIdentities.Remove(item);
		}

		UpdateTotalLogs();
	}

	#endregion

	/// <summary>
	/// Local event handler that are assigned to the sidebar button.
	/// </summary>
	internal void LightUp1()
	{
		if (AllowNewAppsStart.BrowseForXMLPolicyButtonPub is not null && AllowNewAppsStart.BrowseForXMLPolicyButton_FlyOutPub is not null)
			AllowNewAppsStart.BrowseForXMLPolicyButton_FlyOutPub.ShowAt(AllowNewAppsStart.BrowseForXMLPolicyButtonPub);
		selectedXMLFilePath = MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic;
	}


	internal double Step2ProgressRingValue { get; set => SP(ref field, value); }

	// A Progress<double> so Report() callbacks run on the UI thread
	internal IProgress<double> Step2ProgressRingProgress;

	internal ScanLevelsComboBoxType ScanLevelComboBoxSelectedItem { get; set => SP(ref field, value); } = DefaultScanLevel;


	/// <summary>
	/// Step 1 validation
	/// </summary>
	/// <exception cref="InvalidOperationException"></exception>
	internal async void GoToStep2Button_Click()
	{
		bool errorOccurred = false;

		try
		{
			Step1ProgressRingIsActive = true;
			GoToStep2ButtonIsEnabled = false;
			ResetStepsButtonIsEnabled = false;

			Step1InfoBar_IsClosable = false;

			Step1InfoBar.WriteInfo(GlobalVars.GetStr("Starting"));

			// Ensure the text box for policy file name is filled
			if (string.IsNullOrWhiteSpace(selectedSupplementalPolicyName))
			{
				throw new InvalidOperationException(GlobalVars.GetStr("ErrorSelectSupplementalPolicyName"));
			}

			// Ensure user selected a XML policy file path
			if (string.IsNullOrWhiteSpace(selectedXMLFilePath))
			{
				throw new InvalidOperationException(GlobalVars.GetStr("ErrorSelectXMLPolicyFile"));
			}

			// Ensure the selected XML file path exists on the disk
			if (!File.Exists(selectedXMLFilePath))
			{
				throw new InvalidOperationException(GlobalVars.GetStr("ErrorXMLFileDoesNotExist") + ": " + selectedXMLFilePath);
			}

			await Task.Run(() =>
			{
				// Instantiate the selected policy file
				_BasePolicyObject = Management.Initialize(selectedXMLFilePath, null);

				if (_BasePolicyObject.PolicyType is not PolicyType.BasePolicy)
				{
					throw new InvalidOperationException(GlobalVars.GetStr("ErrorPolicyMustBeBase") + _BasePolicyObject.PolicyType);
				}

				// Get all deployed base policies
				List<CiPolicyInfo> allDeployedBasePolicies = CiToolHelper.GetPolicies(false, true, false);

				// Get all the deployed base policyIDs
				List<string?> CurrentlyDeployedBasePolicyIDs = [.. allDeployedBasePolicies.Select(p => p.BasePolicyID)];

				// Trim the curly braces from the policyID
				string trimmedPolicyID = _BasePolicyObject.PolicyID.TrimStart('{').TrimEnd('}');

				// Make sure the selected policy is deployed on the system
				if (!CurrentlyDeployedBasePolicyIDs.Any(id => string.Equals(id, trimmedPolicyID, StringComparison.OrdinalIgnoreCase)))
				{
					throw new InvalidOperationException(GlobalVars.GetStr("ErrorPolicyNotDeployed"));
				}

				// If the policy doesn't have any rule options or it doesn't have the EnabledUnsignedSystemIntegrityPolicy rule option then it is signed
				_IsSignedPolicy = !_BasePolicyObject.Rules.Any(rule => rule.Item is OptionType.EnabledUnsignedSystemIntegrityPolicy);
			});

			if (_IsSignedPolicy)
			{

				Logger.Write(GlobalVars.GetStr("SignedPolicyDetected"));

				#region Signing Details acquisition

				// Instantiate the Content Dialog
				using SigningDetailsDialog customDialog = new(_BasePolicyObject);

				// Show the dialog and await its result
				ContentDialogResult result = await customDialog.ShowAsync();

				// Ensure primary button was selected
				if (result is ContentDialogResult.Primary)
				{
					_CertPath = customDialog.CertificatePath!;
					_CertCN = customDialog.CertificateCommonName!;
				}
				else
				{
					GoToStep2ButtonIsEnabled = true;

					return;
				}

				#endregion
			}

			// Execute the main tasks of step 1
			await Task.Run(() =>
			{

				// Create the required directory and file paths in step 1
				stagingArea = StagingArea.NewStagingArea("AllowNewApps");
				tempBasePolicyPath = Path.Combine(stagingArea.FullName, "BasePolicy.XML");
				AuditModeCIP = Path.Combine(stagingArea.FullName, "BaseAudit.cip");

				// Make sure it stays unique because it's being put outside of the StagingArea and we don't want any other command to remove or overwrite it
				EnforcedModeCIP = Path.Combine(GlobalVars.UserConfigDir, $"BaseEnforced-{Guid.CreateVersion7().ToString("N")}.cip");

				Step1InfoBar.WriteInfo(GlobalVars.GetStr("DeployingInAuditWait"));

				// Creating a copy of the original policy in the Staging Area so that the original one will be unaffected
				File.Copy(selectedXMLFilePath, tempBasePolicyPath, true);

				// If the policy is Unsigned
				if (!_IsSignedPolicy)
				{
					// Create audit mode CIP
					CiRuleOptions.Set(filePath: tempBasePolicyPath, rulesToAdd: [OptionType.EnabledAuditMode]);
					Management.ConvertXMLToBinary(tempBasePolicyPath, null, AuditModeCIP);

					// Create Enforced mode CIP
					CiRuleOptions.Set(filePath: tempBasePolicyPath, rulesToRemove: [OptionType.EnabledAuditMode]);
					Management.ConvertXMLToBinary(tempBasePolicyPath, null, EnforcedModeCIP);
				}
				// If the policy is Signed
				else
				{
					// Create audit mode CIP
					CiRuleOptions.Set(filePath: tempBasePolicyPath, rulesToAdd: [OptionType.EnabledAuditMode], rulesToRemove: [OptionType.EnabledUnsignedSystemIntegrityPolicy]);

					// Convert the XML file to CIP
					Management.ConvertXMLToBinary(tempBasePolicyPath, null, AuditModeCIP);

					// Sign the CIP
					Signing.Main.SignCIP(AuditModeCIP, _CertCN);

					// Create Enforced mode CIP
					CiRuleOptions.Set(filePath: tempBasePolicyPath, rulesToRemove: [OptionType.EnabledAuditMode, OptionType.EnabledUnsignedSystemIntegrityPolicy]);

					// Convert the XML file to CIP
					Management.ConvertXMLToBinary(tempBasePolicyPath, null, EnforcedModeCIP);

					// Sign the CIP
					Signing.Main.SignCIP(EnforcedModeCIP, _CertCN);
				}

				Logger.Write(GlobalVars.GetStr("CreatingSnapBackGuarantee"));
				SnapBackGuarantee.Create(EnforcedModeCIP);

#if !DEBUG
				Logger.Write(GlobalVars.GetStr("DeployingAuditModePolicy"));
				CiToolHelper.UpdatePolicy(AuditModeCIP);
#endif

				Logger.Write(GlobalVars.GetStr("BasePolicyRedeployedInAuditMode"));

				EventLogUtility.SetLogSize(EventLogsUtil.MaxSizeMB);
			});

			DisableStep1();
			EnableStep2();
			DisableStep3();

			// Capture the current time so that the audit logs that will be displayed will be newer than that
			LogsScanStartTime = DateTime.Now;
		}
		catch (Exception ex)
		{
			errorOccurred = true;
			Step1InfoBar.WriteError(ex);
		}
		finally
		{
			Step1ProgressRingIsActive = false;
			ResetStepsButtonIsEnabled = true;
			Step1InfoBar_IsClosable = true;

			// Only re-enable the button if errors occurred, otherwise we don't want to override the work that DisableStep1() method does
			if (errorOccurred)
			{
				GoToStep2ButtonIsEnabled = true;

				// Clear the variables if errors occurred in step 1
				_BasePolicyObject = null;
				_CertCN = null;
				_CertPath = null;
			}
		}
	}

	/// <summary>
	/// Step 2 validation
	/// </summary>
	internal async void GoToStep3Button_Click()
	{

		bool errorsOccurred = false;

		try
		{
			Step2ProgressRingIsActive = true;
			GoToStep3ButtonIsEnabled = false;
			ResetStepsButtonIsEnabled = false;

			Step2InfoBar_IsClosable = false;

			// While the base policy is being deployed is audit mode, set the progress ring as indeterminate
			Step2ProgressRingIsIndeterminate = true;

			// Enable the ListView pages so user can select the logs
			EventLogsMenuItemState = true;
			LocalFilesMenuItemState = true;

			await Task.Run(async () =>
			{

				// Deploy the base policy in enforced mode before proceeding with scans
				if (EnforcedModeCIP is null)
				{
					throw new InvalidOperationException(GlobalVars.GetStr("ErrorEnforcedModeCIPNotFound"));
				}

				Step2InfoBar.WriteInfo(GlobalVars.GetStr("DeployingEnforceMode"));

#if !DEBUG
				Logger.Write(GlobalVars.GetStr("DeployingEnforceMode"));
				CiToolHelper.UpdatePolicy(EnforcedModeCIP);
#endif

				// Delete the enforced mode CIP file after deployment
				File.Delete(EnforcedModeCIP);

				// Remove the snap back guarantee task and related .bat file after successfully re-deploying the Enforced mode policy
				SnapBackGuarantee.Remove();

				// Check if user selected directories to be scanned
				if (selectedDirectoriesToScan.Count > 0)
				{
					Step2InfoBar.WriteInfo(GlobalVars.GetStr("ScanningSelectedDirectories"));

					// Set the progress ring to no longer be indeterminate since file scan will take control of its value
					Step2ProgressRingIsIndeterminate = false;

					// Get all of the AppControl compatible files from user selected directories
					(IEnumerable<string>, int) DetectedFilesInSelectedDirectories = FileUtility.GetFilesFast(selectedDirectoriesToScan, null, null);

					// If any App Control compatible files were found in the user selected directories
					if (DetectedFilesInSelectedDirectories.Item2 > 0)
					{
						Step2InfoBar.WriteInfo(string.Format(GlobalVars.GetStr("ScanningNFilesFoundInSelectedDirectories"), DetectedFilesInSelectedDirectories.Item2));

						// Set the progress ring to no longer be indeterminate since file scan will take control of its value
						Step2ProgressRingIsIndeterminate = false;

						// Scan all of the detected files from the user selected directories
						IEnumerable<FileIdentity> LocalFilesResults = LocalFilesScan.Scan(
							DetectedFilesInSelectedDirectories,
							2,
							Step2ProgressRingProgress);

						// Add the results to the backing list
						LocalFilesAllFileIdentities.Clear();
						LocalFilesAllFileIdentities.AddRange(LocalFilesResults);

						await Dispatcher.EnqueueAsync(() =>
						{
							// Add the results of the Files/Directories scans to the ObservableCollection
							LocalFilesFileIdentities = new(LocalFilesResults);

							CalculateColumnWidthLocalFiles();
						});

					}
				}
			});

			// Update the InfoBadge for the top menu
			LocalFilesCountInfoBadgeValue = LocalFilesFileIdentities.Count;
			LocalFilesCountInfoBadgeOpacity = 1;

			Step2InfoBar.WriteInfo(GlobalVars.GetStr("ScanningEventLogs"));

			// Log scanning doesn't produce determinate real time progress so setting it as indeterminate
			Step2ProgressRingIsIndeterminate = true;

			// Check for available logs

			// Grab the App Control Logs
			HashSet<FileIdentity> Output = await GetEventLogsData.GetAppControlEvents();

#if !DEBUG

			// Filter the logs and keep only ones generated after audit mode policy was deployed
			await Task.Run(() =>
			{
				Output = [.. Output.Where(fileIdentity => fileIdentity.TimeCreated >= LogsScanStartTime)];
			});

#endif

			Step2InfoBar.WriteInfo(string.Format(GlobalVars.GetStr("NLogsGeneratedDuringAuditPhase"), Output.Count));

			// If any logs were generated since audit mode policy was deployed
			if (Output.Count > 0)
			{
				// Add the results to the backing list
				EventLogsAllFileIdentities.Clear();
				EventLogsAllFileIdentities.AddRange(Output);

				await Dispatcher.EnqueueAsync(() =>
				{
					EventLogsFileIdentities.Clear();

					// Add the event logs to the ObservableCollection
					foreach (FileIdentity item in Output)
					{
						EventLogsFileIdentities.Add(item);
					}

					CalculateColumnWidthEventLogs();
				});
			}

			// Update the InfoBadge for the top menu
			EventLogsCountInfoBadgeValue = EventLogsFileIdentities.Count;
			EventLogsCountInfoBadgeOpacity = 1;

			DisableStep1();
			DisableStep2();
			EnableStep3();
		}
		catch (Exception ex)
		{
			errorsOccurred = true;
			Step2InfoBar.WriteError(ex);
		}
		finally
		{
			Step2ProgressRingIsActive = false;
			ResetStepsButtonIsEnabled = true;
			Step2InfoBar_IsClosable = true;

			if (errorsOccurred)
			{
				// Re-enable the button allowing the user to fix any potential issues.
				GoToStep3ButtonIsEnabled = true;
			}
		}
	}


	/// <summary>
	/// Steps Reset
	/// </summary>
	internal async void ResetStepsButton_Click()
	{
		try
		{
			ResetStepsButtonIsEnabled = false;
			ResetProgressRingIsActive = true;

			// Disable all steps
			// Since there is opening/closing animations, we can't quickly set its IsOpen property to false and true
			DisableStep1(false);
			DisableStep2();
			DisableStep3();

			Step1InfoBar_IsClosable = false;

			Step1InfoBar.WriteInfo(GlobalVars.GetStr("Resetting"));

			// Hide the action button for InfoBar in Step 3 that offers to open the supplemental policy in the Policy Editor
			OpenInPolicyEditorInfoBarActionButtonVisibility = Visibility.Collapsed;

			// Clear the path to the supplemental policy
			finalSupplementalPolicyPath = null;

			// Clear the ListViews and their respective search/filter-related lists
			LocalFilesFileIdentities.Clear();
			LocalFilesAllFileIdentities.Clear();
			EventLogsFileIdentities.Clear();
			EventLogsAllFileIdentities.Clear();

			// reset the class variables back to their default states
			fileIdentities.FileIdentitiesInternal.Clear();
			selectedDirectoriesToScan.Clear();
			DeployPolicy = true;
			selectedSupplementalPolicyName = null;
			LogsScanStartTime = null;
			tempBasePolicyPath = null;
			_BasePolicyObject = null;
			_CertCN = null;
			_CertPath = null;
			_IsSignedPolicy = false;

			// Disable the data grids access
			EventLogsMenuItemState = false;
			LocalFilesMenuItemState = false;


			// Update the InfoBadges for the top menu
			LocalFilesCountInfoBadgeValue = 0;
			LocalFilesCountInfoBadgeOpacity = 0;
			EventLogsCountInfoBadgeOpacity = 0;
			EventLogsCountInfoBadgeValue = 0;

			// Reset the UI inputs back to their default states
			DeployPolicy = true;

			// Run the main reset tasks on a different thread
			await Task.Run(() =>
			{

				// Deploy the base policy in enforced mode if user advanced to that step
				if (Path.Exists(EnforcedModeCIP))
				{

#if !DEBUG
					Logger.Write(GlobalVars.GetStr("DeployingEnforceModeCuzReset"));
					CiToolHelper.UpdatePolicy(EnforcedModeCIP);
#endif

					// Delete the enforced mode CIP file from the user config directory after deploying it
					File.Delete(EnforcedModeCIP);
				}

				// Remove the snap back guarantee task and .bat file if it exists
				SnapBackGuarantee.Remove();
			});

			Step1InfoBar.WriteSuccess(GlobalVars.GetStr("ResetSuccessful"));
		}
		catch (Exception ex)
		{
			Step1InfoBar.WriteError(ex);
		}
		finally
		{
			// Enable the step1 for new operation
			EnableStep1();
			ResetProgressRingIsActive = false;
			ResetStepsButtonIsEnabled = true;

			Step1InfoBar_IsClosable = true;
		}
	}

	/// <summary>
	/// Clears the text box and the list of selected directories when the button is clicked.
	/// </summary>
	internal void ClearSelectedDirectoriesButton_Click() => selectedDirectoriesToScan.Clear();

	/// <summary>
	/// CTRL + C shortcuts event handler
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	internal void CtrlC_Invoked_EventLogs(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		ListViewFlyoutMenuCopy_Click_EventLogs();
		args.Handled = true;
	}

	/// <summary>
	/// CTRL + C shortcuts event handler
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	internal void CtrlC_Invoked_LocalFiles(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		ListViewFlyoutMenuCopy_Click_LocalFiles();
		args.Handled = true;
	}

	internal void HeaderColumnSortingButton_Click_LocalFiles(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			// Look up the mapping in the reusable property mappings dictionary.
			if (ListViewHelper.FileIdentityPropertyMappings.TryGetValue(key, out (string Label, Func<FileIdentity, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					keySelector: mapping.Getter,
					searchBoxText: LocalFilesAllFileIdentitiesSearchText,
					originalList: LocalFilesAllFileIdentities,
					observableCollection: LocalFilesFileIdentities,
					sortState: SortStateLocalFiles,
					newKey: key,
					regKey: ListViewHelper.ListViewsRegistry.Allow_New_Apps_LocalFiles_ScanResults);
			}
		}
	}

	internal void HeaderColumnSortingButton_Click_EventLogs(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			// Look up the mapping using the key.
			if (ListViewHelper.FileIdentityPropertyMappings.TryGetValue(key, out (string Label, Func<FileIdentity, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
						keySelector: mapping.Getter,
						searchBoxText: EventLogsAllFileIdentitiesSearchText,
						originalList: EventLogsAllFileIdentities,
						observableCollection: EventLogsFileIdentities,
						sortState: SortStateEventLogs,
						newKey: key,
						regKey: ListViewHelper.ListViewsRegistry.Allow_New_Apps_EventLogs_ScanResults);
			}
		}
	}


	internal void _OpenInFileExplorer_LocalFiles() => OpenInFileExplorer(ListViewHelper.ListViewsRegistry.Allow_New_Apps_LocalFiles_ScanResults);
	internal void _OpenInFileExplorerShortCut_LocalFiles(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		_OpenInFileExplorer_LocalFiles();
		args.Handled = true;
	}

	internal void _OpenInFileExplorer_EventLogs() => OpenInFileExplorer(ListViewHelper.ListViewsRegistry.Allow_New_Apps_EventLogs_ScanResults);
	internal void _OpenInFileExplorerShortCut_EventLogs(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		_OpenInFileExplorer_EventLogs();
		args.Handled = true;
	}

	/// <summary>
	/// Exports Event Logs data to JSON.
	/// </summary>
	internal async void ExportEventLogsToJsonButton_Click()
	{
		try
		{
			await FileIdentity.ExportToJson(EventLogsFileIdentities, Step1InfoBar);
		}
		catch (Exception ex)
		{
			Step1InfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Exports Local Files data to JSON.
	/// </summary>
	internal async void ExportLocalFilesToJsonButton_Click()
	{
		try
		{
			await FileIdentity.ExportToJson(LocalFilesFileIdentities, Step1InfoBar);
		}
		catch (Exception ex)
		{
			Step1InfoBar.WriteError(ex);
		}
	}
}
