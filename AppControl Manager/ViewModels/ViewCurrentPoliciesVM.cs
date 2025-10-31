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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.CustomUIElements;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.SiPolicy;
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;

namespace AppControlManager.ViewModels;

internal sealed partial class ViewCurrentPoliciesVM : ViewModelBase
{
	internal ViewCurrentPoliciesVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		// To adjust the initial width of the columns, giving them nice paddings.
		CalculateColumnWidths();
	}

	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	// To store the policies displayed on the ListView
	internal readonly ObservableCollection<CiPolicyInfo> AllPolicies = [];

	// Store all outputs for searching
	internal readonly List<CiPolicyInfo> AllPoliciesOutput = [];


	#region UI-Bound Properties

	internal bool UIElementsEnabledState
	{
		get; set => SP(ref field, value);
	} = true;

	internal bool IncludeSystemPoliciesCheckboxState { get; set => SP(ref field, value); }

	internal bool IncludeBasePoliciesCheckboxState
	{
		get; set => SP(ref field, value);
	} = true;

	internal bool IncludeSupplementalPoliciesCheckboxState
	{
		get; set => SP(ref field, value);
	} = true;

	internal bool IncludeAppControlManagerSupplementalPoliciesCheckboxState { get; set => SP(ref field, value); }

	internal string? SearchBoxTextBox { get; set => SPT(ref field, value); }

	internal bool RemovePolicyButtonState { get; set => SP(ref field, value); }

	internal CiPolicyInfo? ListViewSelectedPolicy { get; set => SP(ref field, value); }

	private static readonly string[] PolicyLevels = [
	 "Default Windows",
	 "Allow Microsoft",
	 "Signed and Reputable",
	 "Strict Kernel-Mode",
	 "Strict Kernel-Mode (No Flight Roots)"
	];

	internal int SwapPolicyComboBoxSelectedIndex
	{
		get;
		set
		{   // Instead of attaching the method to the SelectionChanged event of the ComboBox, we check changes in the SelectedItemIndex in here.
			// Value is set to -1 by the method that retrieves the policies.
			if (SP(ref field, value) && value != -1)
			{
				SwapPolicyComboBox_SelectionChanged();
			}
		}
	}

	internal bool SwapPolicyComboBoxState { get; set => SP(ref field, value); }

	internal int ListViewSelectedIndex { get; set => SP(ref field, value); }

	/// <summary>
	/// Path to the selected policy file on disk, if any.
	/// </summary>
	internal string? SelectedPolicyLocalFilePath { get; set => SPT(ref field, value); }

	#region Properties to hold each columns' width.

	internal GridLength ColumnWidth1 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth2 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth3 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth4 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth5 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth6 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth7 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth8 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth9 { get; set => SP(ref field, value); }
	internal GridLength ColumnWidth10 { get; set => SP(ref field, value); }

	#endregion

	#endregion

	/// <summary>
	/// Calculates the maximum required width for each column (including header text)
	/// and assigns the value (with a little extra padding) to the corresponding property.
	/// </summary>
	private void CalculateColumnWidths()
	{
		// Measure header text widths first.
		double maxWidth1 = ListViewHelper.MeasureText(GlobalVars.GetStr("PolicyIDHeader/Text"));
		double maxWidth2 = ListViewHelper.MeasureText(GlobalVars.GetStr("BasePolicyIDHeader/Text"));
		double maxWidth3 = ListViewHelper.MeasureText(GlobalVars.GetStr("FriendlyNameHeader/Text"));
		double maxWidth4 = ListViewHelper.MeasureText(GlobalVars.GetStr("VersionHeader/Text"));
		double maxWidth5 = ListViewHelper.MeasureText(GlobalVars.GetStr("IsAuthorizedHeader/Text"));
		double maxWidth6 = ListViewHelper.MeasureText(GlobalVars.GetStr("IsEnforcedHeader/Text"));
		double maxWidth7 = ListViewHelper.MeasureText(GlobalVars.GetStr("IsOnDiskHeader/Text"));
		double maxWidth8 = ListViewHelper.MeasureText(GlobalVars.GetStr("IsSignedPolicyHeader/Text"));
		double maxWidth9 = ListViewHelper.MeasureText(GlobalVars.GetStr("IsSystemPolicyHeader/Text"));
		double maxWidth10 = ListViewHelper.MeasureText(GlobalVars.GetStr("PolicyOptionsHeader/Text"));

		// Iterate over all items to determine the widest string for each column.
		foreach (CiPolicyInfo item in AllPolicies)
		{
			maxWidth1 = ListViewHelper.MeasureText(item.PolicyID, maxWidth1);
			maxWidth2 = ListViewHelper.MeasureText(item.BasePolicyID, maxWidth2);
			maxWidth3 = ListViewHelper.MeasureText(item.FriendlyName, maxWidth3);
			maxWidth4 = ListViewHelper.MeasureText(item.Version?.ToString(), maxWidth4);
			maxWidth5 = ListViewHelper.MeasureText(item.IsAuthorized.ToString(), maxWidth5);
			maxWidth6 = ListViewHelper.MeasureText(item.IsEnforced.ToString(), maxWidth6);
			maxWidth7 = ListViewHelper.MeasureText(item.IsOnDisk.ToString(), maxWidth7);
			maxWidth8 = ListViewHelper.MeasureText(item.IsSignedPolicy.ToString(), maxWidth8);
			maxWidth9 = ListViewHelper.MeasureText(item.IsSystemPolicy.ToString(), maxWidth9);
			maxWidth10 = ListViewHelper.MeasureText(item.PolicyOptionsDisplay, maxWidth10);
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

			SelectedPolicyLocalFilePath = null;

			SwapPolicyComboBoxSelectedIndex = -1;

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

			// Add all the retrieved policies to the list in class instance
			AllPoliciesOutput.AddRange(policies);

			// Store all of the policies in the ObservableCollection
			foreach (CiPolicyInfo policy in policies)
			{
				// Add the retrieved policies to the ObservableCollection
				AllPolicies.Add(policy);
			}

			CalculateColumnWidths();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			UIElementsEnabledState = true;
		}
	}


	/// <summary>
	/// Event handler for when the Swap Policy ComboBox's selection changes
	/// </summary>
	private async void SwapPolicyComboBox_SelectionChanged()
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
			Run normalText1 = new() { Text = GlobalVars.GetStr("SelectedPolicyName") };
			Run normalText2 = new() { Text = GlobalVars.GetStr("AndID") };
			Run normalText3 = new() { Text = GlobalVars.GetStr("WillBeChangedTo") };
			Run normalText4 = new() { Text = GlobalVars.GetStr("PolicyRedeployInfo") };

			// Create colored runs
			Run accentPolicyName = new() { Text = ListViewSelectedPolicy.FriendlyName, Foreground = violetBrush };
			Run accentPolicyID = new() { Text = policyID, Foreground = violetBrush };
			Run accentPolicyType = new() { Text = PolicyLevels[SwapPolicyComboBoxSelectedIndex], Foreground = hotPinkBrush };

			// Create bold text run
			Bold boldText = new();
			boldText.Inlines.Add(new Run() { Text = GlobalVars.GetStr("SupplementalPolicyContinues") });

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
			using ContentDialogV2 dialog = new()
			{
				Title = GlobalVars.GetStr("SwappingPolicyTitle"),
				Content = formattedTextBlock,
				PrimaryButtonText = GlobalVars.GetStr("OK"),
				CloseButtonText = GlobalVars.GetStr("Cancel"),
			};

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
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
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
						using ContentDialogV2 dialog = new()
						{
							Title = GlobalVars.GetStr("WarningTitle"),
							Content = GlobalVars.GetStr("ManualRemovalWarning") + GlobalVars.AppControlManagerSpecialPolicyName + "' " + GlobalVars.GetStr("ManualRemovalWarningEnd"),
							PrimaryButtonText = GlobalVars.GetStr("Yes"),
							CloseButtonText = GlobalVars.GetStr("No"),
						};

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
									using ContentDialogV2 dialog = new()
									{
										Title = GlobalVars.GetStr("WarningTitle"),
										Content = GlobalVars.GetStr("RestartRequired") + policy.FriendlyName + "' " + GlobalVars.GetStr("RestartRequiredEnd") + policy.PolicyID + "' you must restart your system.",
										PrimaryButtonText = GlobalVars.GetStr("Understand"),
									};

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
								string XMLPolicyPath;

								// Instantiate the Content Dialog
								using (SigningDetailsDialogForRemoval customDialog = new(currentlyDeployedBasePolicyIDs, policy.PolicyID!))
								{

									// Show the dialog and await its result
									ContentDialogResult result = await customDialog.ShowAsync();

									// Ensure primary button was selected
									if (result is ContentDialogResult.Primary)
									{
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
								}
								#endregion

								// Add the unsigned policy rule option to the policy
								CiRuleOptions.Set(filePath: XMLPolicyPath, rulesToAdd: [OptionType.EnabledUnsignedSystemIntegrityPolicy]);

								// Making sure SupplementalPolicySigners do not exist in the XML policy
								CiPolicyHandler.RemoveSupplementalSigners(XMLPolicyPath);

								// Define the path for the CIP file
								string randomString = Guid.CreateVersion7().ToString("N");
								string xmlFileName = Path.GetFileName(XMLPolicyPath);
								string CIPFilePath = Path.Combine(stagingArea.FullName, $"{xmlFileName}-{randomString}.cip");

								// Convert the XML file to CIP, overwriting the unsigned one
								Management.ConvertXMLToBinary(XMLPolicyPath, null, CIPFilePath);

								// Sign the CIP
								Signing.Main.SignCIP(CIPFilePath, CertCN);

								// Deploy the signed CIP file
								CiToolHelper.UpdatePolicy(CIPFilePath);

								SiPolicy.SiPolicy policyObj = Management.Initialize(XMLPolicyPath, null);

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
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
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

		Logger.Write(GlobalVars.GetStr("LastRebootTime") + lastRebootTimeUtc + " (UTC)");

		// When the policy's 1st stage was completed
		DateTime? stage1RemovalTime = UserConfiguration.QuerySignedPolicyStage1RemovalTime(policyID);

		if (stage1RemovalTime is not null)
		{
			Logger.Write(GlobalVars.GetStr("PolicyStage1Completed") + policyID + "' " + GlobalVars.GetStr("CompletedAt") + stage1RemovalTime + " (UTC)");

			if (stage1RemovalTime < lastRebootTimeUtc)
			{
				Logger.Write(GlobalVars.GetStr("PolicySafeToRemove"));

				return true;
			}
		}

		return false;
	}


	#region Sorting

	private ListViewHelper.SortState SortState { get; set; } = new();

	// Pre‑computed property getters for high performance.
	// Used for column sorting and column copying (single cell and entire row), for all ListViews that display CiPolicyInfo data type
	internal static readonly FrozenDictionary<string, (string Label, Func<CiPolicyInfo, object?> Getter)> CiPolicyInfoPropertyMappings
		= new Dictionary<string, (string Label, Func<CiPolicyInfo, object?> Getter)>
		{
			{ "PolicyID",        (GlobalVars.GetStr("PolicyIDLabel"),        ci => ci.PolicyID) },
			{ "BasePolicyID",    (GlobalVars.GetStr("BasePolicyIDLabel"),    ci => ci.BasePolicyID) },
			{ "FriendlyName",    (GlobalVars.GetStr("FriendlyNameLabel"),    ci => ci.FriendlyName) },
			{ "Version",         (GlobalVars.GetStr("VersionLabel/Text"),    ci => ci.Version) },
			{ "VersionString",   (GlobalVars.GetStr("VersionLabel/Text"),    ci => ci.VersionString) },
			{ "IsSystemPolicy",  (GlobalVars.GetStr("IsSystemPolicyLabel"),  ci => ci.IsSystemPolicy) },
			{ "IsSignedPolicy",  (GlobalVars.GetStr("IsSignedPolicyLabel"),  ci => ci.IsSignedPolicy) },
			{ "IsOnDisk",        (GlobalVars.GetStr("IsOnDiskLabel"),        ci => ci.IsOnDisk) },
			{ "IsEnforced",      (GlobalVars.GetStr("IsEnforcedLabel"),      ci => ci.IsEnforced) },
			{ "IsAuthorized",    (GlobalVars.GetStr("IsAuthorizedLabel"),    ci => ci.IsAuthorized) },
			{ "PolicyOptions",   (GlobalVars.GetStr("PolicyOptionsLabel"),   ci => ci.PolicyOptionsDisplay) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	internal void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			// Look up the mapping in the reusable property mappings dictionary.
			if (CiPolicyInfoPropertyMappings.TryGetValue(key, out (string Label, Func<CiPolicyInfo, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					keySelector: mapping.Getter,
					searchBoxText: SearchBoxTextBox,
					originalList: AllPoliciesOutput,
					observableCollection: AllPolicies,
					sortState: SortState,
					newKey: key,
					regKey: ListViewHelper.ListViewsRegistry.Locally_Deployed_Policies);
			}
		}
	}

	#endregion


	/// <summary>
	/// Event handler for the search box text change
	/// </summary>
	internal async void SearchBox_TextChanged()
	{
		try
		{

			string? searchTerm = SearchBoxTextBox?.Trim();

			if (searchTerm is null)
				return;

			// Get the ListView ScrollViewer info
			ScrollViewer? Sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.Locally_Deployed_Policies);

			double? savedHorizontal = null;
			if (Sv != null)
			{
				savedHorizontal = Sv.HorizontalOffset;
			}

			IEnumerable<CiPolicyInfo> filteredResults = [];

			await Task.Run(() =>
			{
				// Perform a case-insensitive search in all relevant fields
				filteredResults = AllPoliciesOutput.Where(p =>
				(p.PolicyID?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.FriendlyName?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				(p.VersionString?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false) ||
				p.IsSystemPolicy.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				p.IsSignedPolicy.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				p.IsOnDisk.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				p.IsEnforced.ToString().Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
				(p.PolicyOptionsDisplay?.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ?? false)
				);
			});

			AllPolicies.Clear();

			// Update the ObservableCollection with the filtered results
			foreach (CiPolicyInfo item in filteredResults)
			{
				AllPolicies.Add(item);
			}

			if (Sv != null && savedHorizontal.HasValue)
			{
				// restore horizontal scroll position
				_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}


	/// <summary>
	/// Event handler for when a policy is selected from the ListView. It will contain the selected policy.
	/// When the Refresh button is pressed, this event is fired again, but due to clearing the existing data in the refresh event handler, ListView's SelectedItem property will be null,
	/// so we detect it here and return from the method without assigning null to the selectedPolicy class instance.
	/// </summary>
	internal void DeployedPolicies_SelectionChanged()
	{
		if (ListViewSelectedPolicy is null)
		{
			SelectedPolicyLocalFilePath = null;
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

		// Get the local CIP file path of the selected policy, if it exists on the system.
		SelectedPolicyLocalFilePath = GetLocalCIPFile(ListViewSelectedPolicy);
	}

	/// <summary>
	/// Converts the properties of a CiPolicyInfo row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	internal void CopySelectedPolicies_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Locally_Deployed_Policies);

		if (lv is null) return;

		if (lv.SelectedItems.Count > 0)
		{
			// SelectedItems is an IList, and contains CiPolicyInfo
			ListViewHelper.ConvertRowToText(lv.SelectedItems, CiPolicyInfoPropertyMappings);
		}
	}

	/// <summary>
	/// Copy a single property of the current selection
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void CopyPolicyProperty_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;
		string key = (string)menuItem.Tag;

		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.Locally_Deployed_Policies);

		if (lv is null) return;

		if (CiPolicyInfoPropertyMappings.TryGetValue(key, out var map))
		{
			// TElement = CiPolicyInfo, copy just that one property
			ListViewHelper.CopyToClipboard<CiPolicyInfo>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}

	/// <summary>
	/// Event handler to prevent the MenuFlyout to automatically close immediately after selecting a checkbox or any button in it
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	internal void MenuFlyout_Closing(FlyoutBase sender, FlyoutBaseClosingEventArgs args)
	{
		if (sender is MenuFlyoutV2 { IsPointerOver: true })
		{
			args.Cancel = true;
		}
	}

	/// <summary>
	/// Path to the directory where unsigned Code Integrity policies are located.
	/// </summary>
	private static readonly string UnsignedPoliciesPath = Path.Combine(GlobalVars.SystemDrive, "Windows", "System32", "CodeIntegrity", "CIPolicies", "Active");

	/// <summary>
	/// To avoid querying the EFI partition path multiple times, we store it here after the first successful retrieval.
	/// </summary>
	private static string? EFIRootPath;

	/// <summary>
	/// Finds the local CIP file path of a given policy, if it exists on the system.
	/// </summary>
	/// <param name="policyInfoObj"></param>
	/// <returns></returns>
	internal static string? GetLocalCIPFile(CiPolicyInfo? policyInfoObj)
	{
		string? output = null;

		if (policyInfoObj is null || policyInfoObj.PolicyID is null)
			return output;

		// Normalized file name because that's how Code Integrity policies are saved on the disk.
		string policyIDAsGUID = $"{{{policyInfoObj.PolicyID}}}.cip";

		// Try to find it first among unsigned policeis.
		string[] files = Directory.GetFiles(UnsignedPoliciesPath, policyIDAsGUID, SearchOption.AllDirectories);

		// Check if any files were found
		if (files.Length > 0)
		{
			output = files[0];
		}
		// Now search among the signed policies
		else
		{
			// Get the EFI partition path if we haven't already gotten it
			if (EFIRootPath is null)
				EFIRootPath = IntelGathering.DriveLetterMapper.GetEfiPartitionRootPath();

			// If we couldn't get the EFI partition path
			if (EFIRootPath is not null)
			{
				// Search recursively on the EFI partition
				string[] files2 = Directory.GetFiles(EFIRootPath, policyIDAsGUID, SearchOption.AllDirectories);

				if (files2.Length > 0)
				{
					output = files2[0];
				}
			}
		}

		return output;
	}

	/// <summary>
	/// Event handler for the button that opens the selected policy in the Policy Editor
	/// </summary>
	internal async void OpenSelectedPolicyInPolicyEditor()
	{
		if (SelectedPolicyLocalFilePath is null)
			return;

		try
		{
			UIElementsEnabledState = false;

			await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(SelectedPolicyLocalFilePath);
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			UIElementsEnabledState = true;
		}
	}

}
