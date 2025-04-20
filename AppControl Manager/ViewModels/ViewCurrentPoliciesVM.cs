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
using System.Text;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.Main;
using AppControlManager.Others;
using CommunityToolkit.WinUI;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel.DataTransfer;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.

internal sealed partial class ViewCurrentPoliciesVM : ViewModelBase
{

	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();

	// To store the policies displayed on the ListView
	internal readonly ObservableCollection<CiPolicyInfo> AllPolicies = [];

	// Store all outputs for searching
	internal readonly List<CiPolicyInfo> AllPoliciesOutput = [];


	#region UI-Bound Properties

	private bool _UIElementsEnabledState = true;
	internal bool UIElementsEnabledState
	{
		get => _UIElementsEnabledState;
		set => SetProperty(_UIElementsEnabledState, value, newValue => _UIElementsEnabledState = newValue);
	}

	private bool _IncludeSystemPoliciesCheckboxState;
	internal bool IncludeSystemPoliciesCheckboxState
	{
		get => _IncludeSystemPoliciesCheckboxState;
		set => SetProperty(_IncludeSystemPoliciesCheckboxState, value, newValue => _IncludeSystemPoliciesCheckboxState = newValue);
	}

	private bool _IncludeBasePoliciesCheckboxState = true;
	internal bool IncludeBasePoliciesCheckboxState
	{
		get => _IncludeBasePoliciesCheckboxState;
		set => SetProperty(_IncludeBasePoliciesCheckboxState, value, newValue => _IncludeBasePoliciesCheckboxState = newValue);
	}

	private bool _IncludeSupplementalPoliciesCheckboxState = true;
	internal bool IncludeSupplementalPoliciesCheckboxState
	{
		get => _IncludeSupplementalPoliciesCheckboxState;
		set => SetProperty(_IncludeSupplementalPoliciesCheckboxState, value, newValue => _IncludeSupplementalPoliciesCheckboxState = newValue);
	}

	private bool _IncludeAppControlManagerSupplementalPoliciesCheckboxState;
	internal bool IncludeAppControlManagerSupplementalPoliciesCheckboxState
	{
		get => _IncludeAppControlManagerSupplementalPoliciesCheckboxState;
		set => SetProperty(_IncludeAppControlManagerSupplementalPoliciesCheckboxState, value, newValue => _IncludeAppControlManagerSupplementalPoliciesCheckboxState = newValue);
	}

	private string _PoliciesCountTextBox = "Number of Policies: 0";
	internal string PoliciesCountTextBox
	{
		get => _PoliciesCountTextBox;
		set => SetProperty(_PoliciesCountTextBox, value, newValue => _PoliciesCountTextBox = newValue);
	}

	private string? _SearchBoxTextBox;
	internal string? SearchBoxTextBox
	{
		get => _SearchBoxTextBox;
		set => SetProperty(_SearchBoxTextBox, value, newValue => _SearchBoxTextBox = newValue);
	}

	private bool _RemovePolicyButtonState;
	internal bool RemovePolicyButtonState
	{
		get => _RemovePolicyButtonState;
		set => SetProperty(_RemovePolicyButtonState, value, newValue => _RemovePolicyButtonState = newValue);
	}

	private CiPolicyInfo? _ListViewSelectedPolicy;
	internal CiPolicyInfo? ListViewSelectedPolicy
	{
		get => _ListViewSelectedPolicy;
		set => SetProperty(_ListViewSelectedPolicy, value, newValue => _ListViewSelectedPolicy = newValue);
	}

	private string? _SwapPolicyComboBoxSelectedItem;
	internal string? SwapPolicyComboBoxSelectedItem
	{
		get => _SwapPolicyComboBoxSelectedItem;
		set => SetProperty(_SwapPolicyComboBoxSelectedItem, value, newValue => _SwapPolicyComboBoxSelectedItem = newValue);
	}

	private int _SwapPolicyComboBoxSelectedIndex;
	internal int SwapPolicyComboBoxSelectedIndex
	{
		get => _SwapPolicyComboBoxSelectedIndex;
		set => SetProperty(_SwapPolicyComboBoxSelectedIndex, value, newValue => _SwapPolicyComboBoxSelectedIndex = newValue);
	}

	private bool _SwapPolicyComboBoxState;
	internal bool SwapPolicyComboBoxState
	{
		get => _SwapPolicyComboBoxState;
		set => SetProperty(_SwapPolicyComboBoxState, value, newValue => _SwapPolicyComboBoxState = newValue);
	}

	private int _ListViewSelectedIndex;
	internal int ListViewSelectedIndex
	{
		get => _ListViewSelectedIndex;
		set => SetProperty(_ListViewSelectedIndex, value, newValue => _ListViewSelectedIndex = newValue);
	}



	#region Properties to hold each columns' width.
	private GridLength _columnWidth1;
	internal GridLength ColumnWidth1
	{
		get => _columnWidth1;
		set { _columnWidth1 = value; OnPropertyChanged(nameof(ColumnWidth1)); }
	}

	private GridLength _columnWidth2;
	internal GridLength ColumnWidth2
	{
		get => _columnWidth2;
		set { _columnWidth2 = value; OnPropertyChanged(nameof(ColumnWidth2)); }
	}

	private GridLength _columnWidth3;
	internal GridLength ColumnWidth3
	{
		get => _columnWidth3;
		set { _columnWidth3 = value; OnPropertyChanged(nameof(ColumnWidth3)); }
	}

	private GridLength _columnWidth4;
	internal GridLength ColumnWidth4
	{
		get => _columnWidth4;
		set { _columnWidth4 = value; OnPropertyChanged(nameof(ColumnWidth4)); }
	}

	private GridLength _columnWidth5;
	internal GridLength ColumnWidth5
	{
		get => _columnWidth5;
		set { _columnWidth5 = value; OnPropertyChanged(nameof(ColumnWidth5)); }
	}

	private GridLength _columnWidth6;
	internal GridLength ColumnWidth6
	{
		get => _columnWidth6;
		set { _columnWidth6 = value; OnPropertyChanged(nameof(ColumnWidth6)); }
	}

	private GridLength _columnWidth7;
	internal GridLength ColumnWidth7
	{
		get => _columnWidth7;
		set { _columnWidth7 = value; OnPropertyChanged(nameof(ColumnWidth7)); }
	}

	private GridLength _columnWidth8;
	internal GridLength ColumnWidth8
	{
		get => _columnWidth8;
		set { _columnWidth8 = value; OnPropertyChanged(nameof(ColumnWidth8)); }
	}

	private GridLength _columnWidth9;
	internal GridLength ColumnWidth9
	{
		get => _columnWidth9;
		set { _columnWidth9 = value; OnPropertyChanged(nameof(ColumnWidth9)); }
	}

	private GridLength _columnWidth10;
	internal GridLength ColumnWidth10
	{
		get => _columnWidth10;
		set { _columnWidth10 = value; OnPropertyChanged(nameof(ColumnWidth10)); }
	}

	#endregion

	#endregion

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// </summary>
	private void CalculateColumnWidths()
	{
		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("PolicyIDHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("BasePolicyIDHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("FriendlyNameHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("VersionHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("IsAuthorizedHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("IsEnforcedHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("IsOnDiskHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("IsSignedPolicyHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("IsSystemPolicyHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureTextWidth(GlobalVars.Rizz.GetString("PolicyOptionsHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (CiPolicyInfo item in AllPolicies)
		{
			double w1 = ListViewHelper.MeasureTextWidth(item.PolicyID);
			if (w1 > maxWidth1) maxWidth1 = w1;

			double w2 = ListViewHelper.MeasureTextWidth(item.BasePolicyID);
			if (w2 > maxWidth2) maxWidth2 = w2;

			double w3 = ListViewHelper.MeasureTextWidth(item.FriendlyName);
			if (w3 > maxWidth3) maxWidth3 = w3;

			double w4 = ListViewHelper.MeasureTextWidth(item.Version?.ToString());
			if (w4 > maxWidth4) maxWidth4 = w4;

			double w5 = ListViewHelper.MeasureTextWidth(item.IsAuthorized.ToString());
			if (w5 > maxWidth5) maxWidth5 = w5;

			double w6 = ListViewHelper.MeasureTextWidth(item.IsEnforced.ToString());
			if (w6 > maxWidth6) maxWidth6 = w6;

			double w7 = ListViewHelper.MeasureTextWidth(item.IsOnDisk.ToString());
			if (w7 > maxWidth7) maxWidth7 = w7;

			double w8 = ListViewHelper.MeasureTextWidth(item.IsSignedPolicy.ToString());
			if (w8 > maxWidth8) maxWidth8 = w8;

			double w9 = ListViewHelper.MeasureTextWidth(item.IsSystemPolicy.ToString());
			if (w9 > maxWidth9) maxWidth9 = w9;

			double w10 = ListViewHelper.MeasureTextWidth(item.PolicyOptionsDisplay);
			if (w10 > maxWidth10) maxWidth10 = w10;
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
	}



	/// <summary>
	/// Retrieve the policies from the system
	/// </summary>
	internal async void RetrievePolicies()
	{
		try
		{
			UIElementsEnabledState = false;

			// Clear the policies before getting and showing the new ones
			// They also set the "SelectedItem" property of the ListView to null
			AllPolicies.Clear();
			AllPoliciesOutput.Clear();

			// The checkboxes belong to the UI thread so can't use their bool value directly on the Task.Run's thread
			bool ShouldIncludeSystem = IncludeSystemPoliciesCheckboxState;
			bool ShouldIncludeBase = IncludeBasePoliciesCheckboxState;
			bool ShouldIncludeSupplemental = IncludeSupplementalPoliciesCheckboxState;
			bool ShouldIncludeAppControlManagerSupplementalPolicy = IncludeAppControlManagerSupplementalPoliciesCheckboxState;

			List<CiPolicyInfo> policies = [];

			// Check if the AppControlManagerSupplementalPolicy checkbox is checked, if it is, show the automatic policy
			if (ShouldIncludeAppControlManagerSupplementalPolicy)
			{
				// Run the GetPolicies method asynchronously
				policies = await Task.Run(() => CiToolHelper.GetPolicies(ShouldIncludeSystem, ShouldIncludeBase, ShouldIncludeSupplemental));
			}
			// Filter out the AppControlManagerSupplementalPolicy automatic policies from the list
			else
			{
				// Run the GetPolicies method asynchronously
				policies = await Task.Run(() => CiToolHelper.GetPolicies(ShouldIncludeSystem, ShouldIncludeBase, ShouldIncludeSupplemental).Where(x => !string.Equals(x.FriendlyName, GlobalVars.AppControlManagerSpecialPolicyName, StringComparison.OrdinalIgnoreCase)).ToList());
			}

			// Store all of the policies in the ObservableCollection
			foreach (CiPolicyInfo policy in policies)
			{
				// Attach the current instance of the ViewModel class to the object so we can use it in the XAML via compiled binding to find this ViewModel in the ItemTemplate of the ListView
				policy.ParentViewModel = this;

				// Add the retrieved policies to the list in class instance
				AllPoliciesOutput.Add(policy);

				// Add the retrieved policies to the ObservableCollection
				AllPolicies.Add(policy);
			}

			// Update the UI once the task completes
			PoliciesCountTextBox = GlobalVars.Rizz.GetString("NumberOfPolicies") + policies.Count;

			CalculateColumnWidths();
		}
		finally
		{
			UIElementsEnabledState = true;
		}
	}


	/// <summary>
	/// Event handler for when the Swap Policy ComboBox's selection changes
	/// </summary>
	internal async void SwapPolicyComboBox_SelectionChanged()
	{
		if (ListViewSelectedPolicy is null)
		{
			return;
		}

		bool reEnableButtonAtTheEnd = true;

		try
		{
			SwapPolicyComboBoxState = false;
			RemovePolicyButtonState = false;
			UIElementsEnabledState = false;

			string policyID = ListViewSelectedPolicy.PolicyID!.ToString();

			TextBlock formattedTextBlock = new()
			{
				TextWrapping = TextWrapping.WrapWholeWords,
				IsTextSelectionEnabled = true
			};

			SolidColorBrush violetBrush = new(Colors.Violet);
			SolidColorBrush hotPinkBrush = new(Colors.HotPink);

			// Create normal text runs
			Run normalText1 = new() { Text = GlobalVars.Rizz.GetString("SelectedPolicyName") };
			Run normalText2 = new() { Text = GlobalVars.Rizz.GetString("AndID") };
			Run normalText3 = new() { Text = GlobalVars.Rizz.GetString("WillBeChangedTo") };
			Run normalText4 = new() { Text = GlobalVars.Rizz.GetString("PolicyRedeployInfo") };

			// Create colored runs
			Run accentPolicyName = new() { Text = ListViewSelectedPolicy.FriendlyName, Foreground = violetBrush };
			Run accentPolicyID = new() { Text = policyID, Foreground = violetBrush };
			Run accentPolicyType = new() { Text = SwapPolicyComboBoxSelectedItem, Foreground = hotPinkBrush };

			// Create bold text run
			Bold boldText = new();
			boldText.Inlines.Add(new Run() { Text = GlobalVars.Rizz.GetString("SupplementalPolicyContinues") });

			// Add runs to the TextBlock
			formattedTextBlock.Inlines.Add(normalText1);
			formattedTextBlock.Inlines.Add(accentPolicyName);
			formattedTextBlock.Inlines.Add(normalText2);
			formattedTextBlock.Inlines.Add(accentPolicyID);
			formattedTextBlock.Inlines.Add(normalText3);
			formattedTextBlock.Inlines.Add(accentPolicyType);
			formattedTextBlock.Inlines.Add(new LineBreak());
			formattedTextBlock.Inlines.Add(new LineBreak());
			formattedTextBlock.Inlines.Add(normalText4);
			formattedTextBlock.Inlines.Add(new LineBreak());
			formattedTextBlock.Inlines.Add(new LineBreak());
			formattedTextBlock.Inlines.Add(boldText);

			// Create and display a ContentDialog with styled TextBlock
			ContentDialog dialog = new()
			{
				Title = GlobalVars.Rizz.GetString("SwappingPolicyTitle"),
				Content = formattedTextBlock,
				PrimaryButtonText = GlobalVars.Rizz.GetString("OK"),
				BorderBrush = Application.Current.Resources["AccentFillColorDefaultBrush"] as Brush ?? new SolidColorBrush(Colors.Transparent),
				BorderThickness = new Thickness(1),
				CloseButtonText = GlobalVars.Rizz.GetString("Cancel"),
				XamlRoot = Pages.ViewCurrentPolicies.Instance.XamlRoot, // Set XamlRoot to the current page's XamlRoot
				RequestedTheme = string.Equals(AppSettings.AppTheme, "Light", StringComparison.OrdinalIgnoreCase) ? ElementTheme.Light : (string.Equals(AppSettings.AppTheme, "Dark", StringComparison.OrdinalIgnoreCase) ? ElementTheme.Dark : ElementTheme.Default)
			};

			App.CurrentlyOpenContentDialog = dialog;

			// Show the dialog and wait for user response
			ContentDialogResult result = await dialog.ShowAsync();

			// If the user did not select "OK", return from the method
			if (result is not ContentDialogResult.Primary)
			{
				reEnableButtonAtTheEnd = false;
				return;
			}

			await Task.Run(() =>
			{

				string stagingArea = StagingArea.NewStagingArea("PolicySwapping").FullName;

				switch (SwapPolicyComboBoxSelectedIndex)
				{
					case 0: // Default Windows
						{
							_ = BasePolicyCreator.BuildDefaultWindows(
							StagingArea: stagingArea,
							IsAudit: false,
							LogSize: null,
							deploy: true,
							RequireEVSigners: false,
							EnableScriptEnforcement: false,
							TestMode: false,
							deployAppControlSupplementalPolicy: false,
							PolicyIDToUse: policyID,
							DeployMicrosoftRecommendedBlockRules: false
							);

							break;
						}
					case 1: // Allow Microsoft
						{
							_ = BasePolicyCreator.BuildAllowMSFT(
							StagingArea: stagingArea,
							IsAudit: false,
							LogSize: null,
							deploy: true,
							RequireEVSigners: false,
							EnableScriptEnforcement: false,
							TestMode: false,
							deployAppControlSupplementalPolicy: false,
							PolicyIDToUse: policyID,
							DeployMicrosoftRecommendedBlockRules: false
							);

							break;
						}
					case 2: // Signed and Reputable
						{
							_ = BasePolicyCreator.BuildSignedAndReputable(
							StagingArea: stagingArea,
							IsAudit: false,
							LogSize: null,
							deploy: true,
							RequireEVSigners: false,
							EnableScriptEnforcement: false,
							TestMode: false,
							deployAppControlSupplementalPolicy: false,
							PolicyIDToUse: policyID,
							DeployMicrosoftRecommendedBlockRules: false
							);

							break;
						}
					case 3: // Strict Kernel-Mode
						{
							_ = BasePolicyCreator.BuildStrictKernelMode(
								StagingArea: stagingArea,
								IsAudit: false,
								NoFlightRoots: false,
								deploy: true,
								PolicyIDToUse: policyID);

							break;
						}
					case 4: // Strict Kernel-Mode(No Flight Roots)
						{
							_ = BasePolicyCreator.BuildStrictKernelMode(
								StagingArea: stagingArea,
								IsAudit: false,
								NoFlightRoots: true,
								deploy: true,
								PolicyIDToUse: policyID);

							break;
						}
					default:
						{
							break;
						}
				}
			});
		}
		finally
		{
			// Refresh the ListView's policies and their count
			RetrievePolicies();

			if (reEnableButtonAtTheEnd)
			{
				SwapPolicyComboBoxState = true;
			}

			RemovePolicyButtonState = true;

			UIElementsEnabledState = true;
		}
	}


	/// <summary>
	/// Event handler for the RemovePolicyButton click
	/// </summary>
	internal async void RemovePolicy_Click()
	{

		List<CiPolicyInfo> policiesToRemove = [];

		try
		{
			// Disable the remove button while the selected policy is being processed
			// It will stay disabled until user selects another removable policy
			RemovePolicyButtonState = false;

			UIElementsEnabledState = false;

			// Make sure we have a valid selected non-system policy that is on disk
			if (ListViewSelectedPolicy is not null && !ListViewSelectedPolicy.IsSystemPolicy && ListViewSelectedPolicy.IsOnDisk)
			{
				// List of all the deployed non-system policies
				List<CiPolicyInfo> currentlyDeployedPolicies = [];

				// List of all the deployed base policy IDs
				List<string?> currentlyDeployedBasePolicyIDs = [];

				// List of all the deployed AppControlManagerSupplementalPolicy
				List<CiPolicyInfo> currentlyDeployedAppControlManagerSupplementalPolicies = [];

				// Populate the lists defined above
				await Task.Run(() =>
				{
					currentlyDeployedPolicies = CiToolHelper.GetPolicies(false, true, true);

					currentlyDeployedBasePolicyIDs = [.. currentlyDeployedPolicies.Where(x => string.Equals(x.PolicyID, x.BasePolicyID, StringComparison.OrdinalIgnoreCase)).Select(p => p.BasePolicyID)];

					currentlyDeployedAppControlManagerSupplementalPolicies = [.. currentlyDeployedPolicies.Where(p => string.Equals(p.FriendlyName, GlobalVars.AppControlManagerSpecialPolicyName, StringComparison.OrdinalIgnoreCase))];
				});


				// Check if the selected policy has the FriendlyName "AppControlManagerSupplementalPolicy"
				if (string.Equals(ListViewSelectedPolicy.FriendlyName, GlobalVars.AppControlManagerSpecialPolicyName, StringComparison.OrdinalIgnoreCase))
				{

					// Check if the base policy of the AppControlManagerSupplementalPolicy Supplemental policy is currently deployed on the system
					// And only then show the prompt, otherwise allow for its removal just like any other policy since it's a stray Supplemental policy
					if (currentlyDeployedBasePolicyIDs.Contains(ListViewSelectedPolicy.BasePolicyID))
					{
						// Create and display a ContentDialog with Yes and No options
						ContentDialog dialog = new()
						{
							Title = GlobalVars.Rizz.GetString("WarningTitle"),
							Content = GlobalVars.Rizz.GetString("ManualRemovalWarning") + GlobalVars.AppControlManagerSpecialPolicyName + "' " + GlobalVars.Rizz.GetString("ManualRemovalWarningEnd"),
							PrimaryButtonText = GlobalVars.Rizz.GetString("Yes"),
							BorderBrush = Application.Current.Resources["AccentFillColorDefaultBrush"] as Brush ?? new SolidColorBrush(Colors.Transparent),
							BorderThickness = new Thickness(1),
							CloseButtonText = GlobalVars.Rizz.GetString("No"),
							XamlRoot = Pages.ViewCurrentPolicies.Instance.XamlRoot, // Set XamlRoot to the current page's XamlRoot
							RequestedTheme = string.Equals(AppSettings.AppTheme, "Light", StringComparison.OrdinalIgnoreCase) ? ElementTheme.Light : (string.Equals(AppSettings.AppTheme, "Dark", StringComparison.OrdinalIgnoreCase) ? ElementTheme.Dark : ElementTheme.Default)
						};

						App.CurrentlyOpenContentDialog = dialog;

						// Show the dialog and wait for user response
						ContentDialogResult result = await dialog.ShowAsync();

						// If the user did not select "Yes", return from the method
						if (result is not ContentDialogResult.Primary)
						{
							return;
						}

					}
				}

				// Add the policy to the removal list
				policiesToRemove.Add(ListViewSelectedPolicy);

				#region


				// If the policy that's going to be removed is a base policy
				if (string.Equals(ListViewSelectedPolicy.PolicyID, ListViewSelectedPolicy.BasePolicyID, StringComparison.OrdinalIgnoreCase))
				{
					// Check if it's unsigned, Or it is signed but doesn't have the "Enabled:Unsigned System Integrity Policy" rule option
					// Meaning it was re-signed in unsigned mode and can be now safely removed
					if (!ListViewSelectedPolicy.IsSignedPolicy || (ListViewSelectedPolicy.IsSignedPolicy && ListViewSelectedPolicy.PolicyOptions is not null && ListViewSelectedPolicy.PolicyOptionsDisplay.Contains("Enabled:Unsigned System Integrity Policy", StringComparison.OrdinalIgnoreCase)))
					{
						// Find any automatic AppControlManagerSupplementalPolicy that is associated with it and still on the system
						List<CiPolicyInfo> extraPoliciesToRemove = [.. currentlyDeployedAppControlManagerSupplementalPolicies.Where(p => string.Equals(p.BasePolicyID, ListViewSelectedPolicy.PolicyID, StringComparison.OrdinalIgnoreCase) && p.IsOnDisk)];

						if (extraPoliciesToRemove.Count > 0)
						{
							foreach (CiPolicyInfo item in extraPoliciesToRemove)
							{
								policiesToRemove.Add(item);
							}
						}
					}
				}

				#endregion

				// If there are policies to be removed
				if (policiesToRemove.Count > 0)
				{

					DirectoryInfo stagingArea = StagingArea.NewStagingArea("PolicyRemoval");


					foreach (CiPolicyInfo policy in policiesToRemove)
					{
						// Remove the policy directly from the system if it's unsigned or supplemental
						if (!policy.IsSignedPolicy || !string.Equals(policy.PolicyID, policy.BasePolicyID, StringComparison.OrdinalIgnoreCase))
						{
							await Task.Run(() =>
							{
								CiToolHelper.RemovePolicy(policy.PolicyID!);
							});
						}

						// At this point the policy is definitely a Signed Base policy
						else
						{
							// If the EnabledUnsignedSystemIntegrityPolicy policy rule option exists
							// Which means 1st stage already happened
							if (policy.PolicyOptions is not null && policy.PolicyOptionsDisplay.Contains("Enabled:Unsigned System Integrity Policy", StringComparison.OrdinalIgnoreCase))
							{
								// And if system was rebooted once after performing the 1st removal stage
								if (VerifyRemovalEligibility(policy.PolicyID!))
								{
									CiToolHelper.RemovePolicy(policy.PolicyID!);

									// Remove the PolicyID from the SignedPolicyStage1RemovalTimes dictionary
									UserConfiguration.RemoveSignedPolicyStage1RemovalTime(policy.PolicyID!);
								}
								else
								{
									// Create and display a ContentDialog
									ContentDialog dialog = new()
									{
										Title = GlobalVars.Rizz.GetString("WarningTitle"),
										Content = GlobalVars.Rizz.GetString("RestartRequired") + policy.FriendlyName + "' " + GlobalVars.Rizz.GetString("RestartRequiredEnd") + policy.PolicyID + "' you must restart your system.",
										PrimaryButtonText = GlobalVars.Rizz.GetString("Understand"),
										BorderBrush = Application.Current.Resources["AccentFillColorDefaultBrush"] as Brush ?? new SolidColorBrush(Colors.Transparent),
										BorderThickness = new Thickness(1),
										XamlRoot = Pages.ViewCurrentPolicies.Instance.XamlRoot, // Set XamlRoot to the current page's XamlRoot
										RequestedTheme = string.Equals(AppSettings.AppTheme, "Light", StringComparison.OrdinalIgnoreCase) ? ElementTheme.Light : (string.Equals(AppSettings.AppTheme, "Dark", StringComparison.OrdinalIgnoreCase) ? ElementTheme.Dark : ElementTheme.Default)
									};

									App.CurrentlyOpenContentDialog = dialog;

									// Show the dialog and wait for user response
									_ = await dialog.ShowAsync();

									// Exit the method, nothing more can be done about the selected policy
									return;
								}
							}

							// Treat it as a new signed policy removal
							else
							{

								#region Signing Details acquisition

								string CertCN;
								string CertPath;
								string SignToolPath;
								string XMLPolicyPath;

								// Instantiate the Content Dialog
								SigningDetailsDialogForRemoval customDialog = new(currentlyDeployedBasePolicyIDs, policy.PolicyID!);

								App.CurrentlyOpenContentDialog = customDialog;

								// Show the dialog and await its result
								ContentDialogResult result = await customDialog.ShowAsync();

								// Ensure primary button was selected
								if (result is ContentDialogResult.Primary)
								{
									SignToolPath = customDialog.SignToolPath!;
									CertPath = customDialog.CertificatePath!;
									CertCN = customDialog.CertificateCommonName!;
									XMLPolicyPath = customDialog.XMLPolicyPath!;

									// Sometimes the content dialog lingers on or re-appears so making sure it hides
									customDialog.Hide();

								}
								else
								{
									return;
								}

								#endregion

								// Add the unsigned policy rule option to the policy
								CiRuleOptions.Set(filePath: XMLPolicyPath, rulesToAdd: [SiPolicy.OptionType.EnabledUnsignedSystemIntegrityPolicy]);

								// Making sure SupplementalPolicySigners do not exist in the XML policy
								CiPolicyHandler.RemoveSupplementalSigners(XMLPolicyPath);

								// Define the path for the CIP file
								string randomString = Guid.CreateVersion7().ToString("N");
								string xmlFileName = Path.GetFileName(XMLPolicyPath);
								string CIPFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip");

								string CIPp7SignedFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip.p7");

								// Convert the XML file to CIP, overwriting the unsigned one
								PolicyToCIPConverter.Convert(XMLPolicyPath, CIPFilePath);

								// Sign the CIP
								SignToolHelper.Sign(new FileInfo(CIPFilePath), new FileInfo(SignToolPath), CertCN);

								// Rename the .p7 signed file to .cip
								File.Move(CIPp7SignedFilePath, CIPFilePath, true);

								// Deploy the signed CIP file
								CiToolHelper.UpdatePolicy(CIPFilePath);

								SiPolicy.SiPolicy policyObj = SiPolicy.Management.Initialize(XMLPolicyPath, null);

								// The time of first stage of the signed policy removal
								// Since policy object has the full ID, in upper case with curly brackets,
								// We need to normalize them to match what the CiPolicyInfo class uses
								UserConfiguration.AddSignedPolicyStage1RemovalTime(policyObj.PolicyID.Trim('{', '}').ToLowerInvariant(), DateTime.UtcNow);
							}
						}
					}
				}
			}
		}
		finally
		{
			// Refresh the ListView's policies and their count
			RetrievePolicies();

			UIElementsEnabledState = true;
		}
	}


	/// <summary>
	/// If returns true, the signed policy can be removed
	/// </summary>
	/// <param name="policyID"></param>
	/// <returns></returns>
	private static bool VerifyRemovalEligibility(string policyID)
	{
		// When system was last reboot
		DateTime lastRebootTimeUtc = DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);

		Logger.Write(GlobalVars.Rizz.GetString("LastRebootTime") + lastRebootTimeUtc + " (UTC)");

		// When the policy's 1st stage was completed
		DateTime? stage1RemovalTime = UserConfiguration.QuerySignedPolicyStage1RemovalTime(policyID);

		if (stage1RemovalTime is not null)
		{
			Logger.Write(GlobalVars.Rizz.GetString("PolicyStage1Completed") + policyID + "' " + GlobalVars.Rizz.GetString("CompletedAt") + stage1RemovalTime + " (UTC)");

			if (stage1RemovalTime < lastRebootTimeUtc)
			{
				Logger.Write(GlobalVars.Rizz.GetString("PolicySafeToRemove"));

				return true;
			}
		}

		return false;
	}


	#region Sorting

	/// <summary>
	/// Defines the available columns for sorting.
	/// </summary>
	private enum SortColumnEnum
	{
		PolicyID,
		BasePolicyID,
		FriendlyName,
		Version,
		IsAuthorized,
		IsEnforced,
		IsOnDisk,
		IsSignedPolicy,
		IsSystemPolicy,
		PolicyOptions
	}


	// Sorting state – current sort column and direction
	private SortColumnEnum? _currentSortColumn;
	private bool _isDescending = true; // When a column is first clicked, sort descending by default.

	/// <summary>
	/// This method is invoked by each header button when clicked.
	/// </summary>
	/// <param name="newSortColumn">The column that needs to be sorted.</param>
	private async void Sort(SortColumnEnum newSortColumn)
	{

		// Get the ScrollViewer from the ListView
		ListView listView = Pages.ViewCurrentPolicies.Instance.DeployedPoliciesListView;
		ScrollViewer? scrollViewer = listView.FindScrollViewer();

		double? savedHorizontal = null;
		if (scrollViewer != null)
		{
			savedHorizontal = scrollViewer.HorizontalOffset;
		}


		// If the same column is clicked again, toggle the sorting direction.
		// Otherwise, if a new column is clicked, start with descending order.
		if (_currentSortColumn.HasValue && _currentSortColumn.Value == newSortColumn)
		{
			_isDescending = !_isDescending;
		}
		else
		{
			_currentSortColumn = newSortColumn;
			_isDescending = true;
		}

		// Determine if there is an active search; if not, use the complete list.
		bool isSearchEmpty = string.IsNullOrWhiteSpace(SearchBoxTextBox);

		List<CiPolicyInfo> sourceData = isSearchEmpty ? AllPoliciesOutput : AllPolicies.ToList();

		List<CiPolicyInfo> sortedData = [];

		switch (newSortColumn)
		{
			case SortColumnEnum.PolicyID:
				sortedData = _isDescending
					? sourceData.OrderByDescending(p => p.PolicyID).ToList()
					: sourceData.OrderBy(p => p.PolicyID).ToList();
				break;
			case SortColumnEnum.BasePolicyID:
				sortedData = _isDescending
					? sourceData.OrderByDescending(p => p.BasePolicyID).ToList()
					: sourceData.OrderBy(p => p.BasePolicyID).ToList();
				break;
			case SortColumnEnum.FriendlyName:
				sortedData = _isDescending
					? sourceData.OrderByDescending(p => p.FriendlyName).ToList()
					: sourceData.OrderBy(p => p.FriendlyName).ToList();
				break;
			case SortColumnEnum.Version:
				sortedData = _isDescending
					? sourceData.OrderByDescending(p => p.Version).ToList()
					: sourceData.OrderBy(p => p.Version).ToList();
				break;
			case SortColumnEnum.IsAuthorized:
				sortedData = _isDescending
					? sourceData.OrderByDescending(p => p.IsAuthorized).ToList()
					: sourceData.OrderBy(p => p.IsAuthorized).ToList();
				break;
			case SortColumnEnum.IsEnforced:
				sortedData = _isDescending
					? sourceData.OrderByDescending(p => p.IsEnforced).ToList()
					: sourceData.OrderBy(p => p.IsEnforced).ToList();
				break;
			case SortColumnEnum.IsOnDisk:
				sortedData = _isDescending
					? sourceData.OrderByDescending(p => p.IsOnDisk).ToList()
					: sourceData.OrderBy(p => p.IsOnDisk).ToList();
				break;
			case SortColumnEnum.IsSignedPolicy:
				sortedData = _isDescending
					? sourceData.OrderByDescending(p => p.IsSignedPolicy).ToList()
					: sourceData.OrderBy(p => p.IsSignedPolicy).ToList();
				break;
			case SortColumnEnum.IsSystemPolicy:
				sortedData = _isDescending
					? sourceData.OrderByDescending(p => p.IsSystemPolicy).ToList()
					: sourceData.OrderBy(p => p.IsSystemPolicy).ToList();
				break;
			case SortColumnEnum.PolicyOptions:
				sortedData = _isDescending
					? sourceData.OrderByDescending(p => p.PolicyOptionsDisplay).ToList()
					: sourceData.OrderBy(p => p.PolicyOptionsDisplay).ToList();
				break;
			default:
				break;
		}

		// Update the ObservableCollection on the UI thread.
		await Dispatcher.EnqueueAsync(() =>
		{
			AllPolicies.Clear();
			foreach (CiPolicyInfo item in sortedData)
			{
				AllPolicies.Add(item);
			}

			if (scrollViewer != null && savedHorizontal.HasValue)
			{
				// restore horizontal scroll position
				_ = scrollViewer.ChangeView(savedHorizontal, null, null, disableAnimation: false);
			}
		});
	}


	// These methods are bound to each column header button's Click event.
	internal void SortByPolicyID()
	{
		Sort(SortColumnEnum.PolicyID);
	}
	internal void SortByBasePolicyID()
	{
		Sort(SortColumnEnum.BasePolicyID);
	}
	internal void SortByFriendlyName()
	{
		Sort(SortColumnEnum.FriendlyName);
	}
	internal void SortByVersion()
	{
		Sort(SortColumnEnum.Version);
	}
	internal void SortByIsAuthorized()
	{
		Sort(SortColumnEnum.IsAuthorized);
	}
	internal void SortByIsEnforced()
	{
		Sort(SortColumnEnum.IsEnforced);
	}
	internal void SortByIsOnDisk()
	{
		Sort(SortColumnEnum.IsOnDisk);
	}
	internal void SortByIsSignedPolicy()
	{
		Sort(SortColumnEnum.IsSignedPolicy);
	}
	internal void SortByIsSystemPolicy()
	{
		Sort(SortColumnEnum.IsSystemPolicy);
	}
	internal void SortByPolicyOptions()
	{
		Sort(SortColumnEnum.PolicyOptions);
	}


	#endregion


	/// <summary>
	/// Event handler for the search box text change
	/// </summary>
	internal async void SearchBox_TextChanged()
	{
		string? searchTerm = SearchBoxTextBox?.Trim();

		if (searchTerm is null)
			return;

		// Get the ScrollViewer from the ListView
		ListView listView = Pages.ViewCurrentPolicies.Instance.DeployedPoliciesListView;
		ScrollViewer? scrollViewer = listView.FindScrollViewer();

		double? savedHorizontal = null;
		if (scrollViewer != null)
		{
			savedHorizontal = scrollViewer.HorizontalOffset;
		}

		IEnumerable<CiPolicyInfo> filteredResults = [];

		await Task.Run(() =>
		{
			// Perform a case-insensitive search in all relevant fields
			filteredResults = AllPoliciesOutput.Where(p =>
			(p.PolicyID?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.FriendlyName?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.VersionString?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
			(p.IsSystemPolicy.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(p.IsSignedPolicy.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(p.IsOnDisk.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(p.IsEnforced.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase)) ||
			(p.PolicyOptionsDisplay?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false)
			);
		});

		AllPolicies.Clear();

		// Update the ObservableCollection with the filtered results
		foreach (CiPolicyInfo item in filteredResults)
		{
			AllPolicies.Add(item);
		}

		// Update the policies count text
		PoliciesCountTextBox = GlobalVars.Rizz.GetString("NumberOfPolicies") + AllPolicies.Count;

		if (scrollViewer != null && savedHorizontal.HasValue)
		{
			// restore horizontal scroll position
			_ = scrollViewer.ChangeView(savedHorizontal, null, null, disableAnimation: false);
		}
	}


	// A counter to prevent SelectionChanged event from firing twice when right-clicking on an unselected row
	internal int _skipSelectionChangedCount;

	/// <summary>
	/// Event handler for when a policy is selected from the ListView. It will contain the selected policy.
	/// When the Refresh button is pressed, this event is fired again, but due to clearing the existing data in the refresh event handler, ListView's SelectedItem property will be null,
	/// so we detect it here and return from the method without assigning null to the selectedPolicy class instance.
	/// </summary>
	internal async void DeployedPolicies_SelectionChanged()
	{

		// Check if we need to skip this event.
		if (_skipSelectionChangedCount > 0)
		{
			_skipSelectionChangedCount--;
			return;
		}

		await ListViewHelper.SmoothScrollIntoViewWithIndexCenterVerticallyOnlyAsync(listViewBase: Pages.ViewCurrentPolicies.Instance.DeployedPoliciesListView, listView: Pages.ViewCurrentPolicies.Instance.DeployedPoliciesListView, index: ListViewSelectedIndex, disableAnimation: false, scrollIfVisible: true, additionalHorizontalOffset: 0, additionalVerticalOffset: 0);


		if (ListViewSelectedPolicy is null)
		{
			return;
		}

		// Check if:
		if (
			// It's a non-system policy
			!ListViewSelectedPolicy.IsSystemPolicy &&
			// It's available on disk
			ListViewSelectedPolicy.IsOnDisk)
		{
			// Enable the RemovePolicyButton
			RemovePolicyButtonState = true;
		}
		else
		{
			// Disable the button if no proper policy is selected
			RemovePolicyButtonState = false;
		}

		// Enable the Swap Policy ComboBox only when the selected policy is a base type, unsigned and non-system
		SwapPolicyComboBoxState = string.Equals(ListViewSelectedPolicy.BasePolicyID, ListViewSelectedPolicy.PolicyID, StringComparison.OrdinalIgnoreCase) && !ListViewSelectedPolicy.IsSignedPolicy && !ListViewSelectedPolicy.IsSystemPolicy;
	}




	/// <summary>
	/// Converts the properties of a CiPolicyInfo row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	/// <param name="row">The selected CiPolicyInfo row from the ListView.</param>
	/// <returns>A formatted string of the row's properties with labels.</returns>
	private static string ConvertRowToText(CiPolicyInfo row)
	{
		// Use StringBuilder to format each property with its label for easy reading
		return new StringBuilder()
			.AppendLine(GlobalVars.Rizz.GetString("PolicyIDLabel") + row.PolicyID)
			.AppendLine(GlobalVars.Rizz.GetString("BasePolicyIDLabel") + row.BasePolicyID)
			.AppendLine(GlobalVars.Rizz.GetString("FriendlyNameLabel") + row.FriendlyName)
			.AppendLine(GlobalVars.Rizz.GetString("VersionLabel") + row.Version)
			.AppendLine(GlobalVars.Rizz.GetString("IsAuthorizedLabel") + row.IsAuthorized)
			.AppendLine(GlobalVars.Rizz.GetString("IsEnforcedLabel") + row.IsEnforced)
			.AppendLine(GlobalVars.Rizz.GetString("IsOnDiskLabel") + row.IsOnDisk)
			.AppendLine(GlobalVars.Rizz.GetString("IsSignedPolicyLabel") + row.IsSignedPolicy)
			.AppendLine(GlobalVars.Rizz.GetString("IsSystemPolicyLabel") + row.IsSystemPolicy)
			.AppendLine(GlobalVars.Rizz.GetString("PolicyOptionsLabel") + row.PolicyOptionsDisplay)
			.ToString();
	}

	/// <summary>
	/// Copies the selected rows to the clipboard in a formatted manner, with each property labeled for clarity.
	/// </summary>
	internal void ListViewFlyoutMenuCopy_Click()
	{
		// Check if there are selected items in the ListView
		if (ListViewSelectedPolicy is not null)
		{
			// Initialize StringBuilder to store all selected rows' data with labels
			StringBuilder dataBuilder = new();

			// Append each row's formatted data to the StringBuilder
			_ = dataBuilder.AppendLine(ConvertRowToText(ListViewSelectedPolicy));

			// Add a separator between rows for readability in multi-row copies
			_ = dataBuilder.AppendLine(ListViewHelper.DefaultDelimiter);

			// Create a DataPackage to hold the text data
			DataPackage dataPackage = new();

			// Set the formatted text as the content of the DataPackage
			dataPackage.SetText(dataBuilder.ToString());

			// Copy the DataPackage content to the clipboard
			Clipboard.SetContent(dataPackage);
		}
	}

	// Click event handlers for each property
	internal void CopyPolicyID_Click() => CopyToClipboard((item) => item.PolicyID?.ToString());
	internal void CopyBasePolicyID_Click() => CopyToClipboard((item) => item.BasePolicyID?.ToString());
	internal void CopyFriendlyName_Click() => CopyToClipboard((item) => item.FriendlyName);
	internal void CopyVersion_Click() => CopyToClipboard((item) => item.Version?.ToString());
	internal void CopyIsAuthorized_Click() => CopyToClipboard((item) => item.IsAuthorized.ToString());
	internal void CopyIsEnforced_Click() => CopyToClipboard((item) => item.IsEnforced.ToString());
	internal void CopyIsOnDisk_Click() => CopyToClipboard((item) => item.IsOnDisk.ToString());
	internal void CopyIsSignedPolicy_Click() => CopyToClipboard((item) => item.IsSignedPolicy.ToString());
	internal void CopyIsSystemPolicy_Click() => CopyToClipboard((item) => item.IsSystemPolicy.ToString());
	internal void CopyPolicyOptionsDisplay_Click() => CopyToClipboard((item) => item.PolicyOptionsDisplay);

#pragma warning disable CA1822

	/// <summary>
	/// Helper method to copy a specified property to clipboard without reflection
	/// </summary>
	/// <param name="getProperty">Function that retrieves the desired property value as a string</param>
	private void CopyToClipboard(Func<CiPolicyInfo, string?> getProperty)
	{
		if (ListViewSelectedPolicy is null)
			return;

		string? propertyValue = getProperty(ListViewSelectedPolicy);
		if (propertyValue is not null)
		{
			DataPackage dataPackage = new();
			dataPackage.SetText(propertyValue);
			Clipboard.SetContent(dataPackage);
		}
	}

#pragma warning restore CA1822

}
