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
using System.Threading.Tasks;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using HardenWindowsSecurity.ExploitMitigation;
using HardenWindowsSecurity.GroupPolicy;
using HardenWindowsSecurity.Helpers;
using HardenWindowsSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenWindowsSecurity.ViewModels;

internal enum MUnitOperation
{
	Apply,
	Remove,
	Verify
}

internal sealed partial class MicrosoftDefenderVM : ViewModelBase, IMUnitListViewModel
{
	internal MicrosoftDefenderVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			null, null);

		_ = Task.Run(CreateUIValuesCategories);
	}

	/// <summary>
	/// The main InfoBar for the Settings VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	public Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	private List<RegistryPolicyEntry> DefenderPolicyFrmJSON { get; set; } = [];

	public bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressBarVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	internal static readonly string JSONConfigPath = Path.Combine(AppContext.BaseDirectory, "Resources", "MSDefender.json");

	/// <summary>
	/// Items Source of the ListView.
	/// </summary>
	public ObservableCollection<GroupInfoListForMUnit> ListViewItemsSource { get; set => SP(ref field, value); } = [];

	/// <summary>
	/// Selected Items list in the ListView.
	/// </summary>
	internal List<MUnit> ItemsSourceSelectedItems = [];

	// To create a collection of grouped items, create a query that groups
	// an existing list, or returns a grouped collection from a database.
	// The following method is used to create the ItemsSource for our CollectionViewSource that is defined in XAML
	internal void CreateUIValuesCategories()
	{
		List<MUnit> allResults = [];
		IEnumerable<GroupInfoListForMUnit> query = [];

		try
		{
			_ = Dispatcher.TryEnqueue(() =>
			{
				ElementsAreEnabled = false;
			});

			allResults = CreateGroupPolicyUnits();
			allResults.AddRange(CreateUnits());

			// Grab Protection Categories objects
			query = from item in allResults

						// Group the items returned from the query, sort and select the ones you want to keep
					group item by item.Name![..1].ToUpper() into g
					orderby g.Key

					// GroupInfoListForMUnit is a simple custom class that has an IEnumerable type attribute, and
					// a key attribute. The IGrouping-typed variable g now holds the App objects,
					// and these objects will be used to create a new GroupInfoListForMUnit object.
					select new GroupInfoListForMUnit(
						items: g,
						key: g.Key);

			_ = Dispatcher.TryEnqueue(() =>
			{
				ListViewItemsSource = new(query);
			});
		}

		catch (Exception ex)
		{
			_ = Dispatcher.TryEnqueue(() =>
			{
				MainInfoBar.WriteError(ex);
			});
		}
		finally
		{
			_ = Dispatcher.TryEnqueue(() =>
			{
				ElementsAreEnabled = true;
			});
		}
	}

	/// <summary>
	/// ListView reference of the UI.
	/// </summary>
	public ListViewBase? UIListView { get; set; }

	/// <summary>
	/// For selecting all items on the UI.Will automatically trigger <see cref="ListView_SelectionChanged"/> method as well,
	/// Adding the items to <see cref="ItemsSourceSelectedItems"/>.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	public void ListView_SelectAll(object sender, RoutedEventArgs e)
	{
		foreach (GroupInfoListForMUnit group in ListViewItemsSource)
		{
			foreach (MUnit item in group)
			{
				UIListView?.SelectedItems.Add(item);
			}
		}
	}

	/// <summary>
	/// For De-selecting all items on the UI.Will automatically trigger <see cref="ListView_SelectionChanged"/> method as well,
	/// Removing the items from <see cref="ItemsSourceSelectedItems"/>.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	public void ListView_RemoveSelections(object sender, RoutedEventArgs e)
	{
		UIListView?.SelectedItems.Clear();
	}

	/// <summary>
	/// Event handler for the SelectionChanged event of the ListView.
	/// Triggered by <see cref="ListView_SelectAll(object, RoutedEventArgs)"/> and <see cref="ListView_RemoveSelections(object, RoutedEventArgs)"/> to keep things consistent.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	public void ListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		foreach (MUnit item in e.AddedItems.Cast<MUnit>())
		{
			ItemsSourceSelectedItems.Add(item);
		}

		foreach (MUnit item in e.RemovedItems.Cast<MUnit>())
		{
			_ = ItemsSourceSelectedItems.Remove(item);
		}
	}

	/// <summary>
	/// Processes MUnits with bulk Group Policy operations.
	/// </summary>
	/// <param name="mUnits">The MUnits to process</param>
	/// <param name="operation">The operation to perform</param>
	private void ProcessMUnitsWithBulkOperations(List<MUnit> mUnits, MUnitOperation operation)
	{
		_ = Task.Run(() =>
		{
			try
			{
				_ = Dispatcher.TryEnqueue(() =>
				{
					ElementsAreEnabled = false;
					string operationText = operation switch
					{
						MUnitOperation.Apply => "Applying",
						MUnitOperation.Remove => "Removing",
						MUnitOperation.Verify => "Verifying",
						_ => "Processing"
					};
					MainInfoBar.WriteInfo($"{operationText} {mUnits.Count} security measures...");
				});

				// Separate Group Policy and non-Group Policy MUnits
				List<MUnit> groupPolicyMUnits = [];
				List<MUnit> regularMUnits = [];

				foreach (MUnit mUnit in mUnits)
				{
					if (IsGroupPolicyMUnit(mUnit))
					{
						groupPolicyMUnits.Add(mUnit);
					}
					else
					{
						regularMUnits.Add(mUnit);
					}
				}

				// Process Group Policy MUnits in bulk
				if (groupPolicyMUnits.Count > 0)
				{
					ProcessGroupPolicyMUnitsBulk(groupPolicyMUnits, operation);
				}

				// Process regular MUnits individually
				foreach (MUnit mUnit in regularMUnits)
				{
					ProcessRegularMUnit(mUnit, operation);
				}

				_ = Dispatcher.TryEnqueue(() =>
				{
					string operationText = operation switch
					{
						MUnitOperation.Apply => "applied",
						MUnitOperation.Remove => "removed",
						MUnitOperation.Verify => "verified",
						_ => "processed"
					};
					MainInfoBar.WriteSuccess($"Successfully {operationText} {mUnits.Count} security measures");
				});
			}
			catch (Exception ex)
			{
				_ = Dispatcher.TryEnqueue(() =>
				{
					string operationText = operation switch
					{
						MUnitOperation.Apply => "apply",
						MUnitOperation.Remove => "remove",
						MUnitOperation.Verify => "verify",
						_ => "process"
					};
					MainInfoBar.WriteError(ex, $"Failed to {operationText} security measures: ");
				});
			}
			finally
			{
				_ = Dispatcher.TryEnqueue(() =>
				{
					ElementsAreEnabled = true;
				});
			}
		});
	}

	/// <summary>
	/// Determines if an MUnit uses Group Policy strategies
	/// </summary>
	/// <param name="mUnit">The MUnit to check</param>
	/// <returns>True if it's a Group Policy MUnit</returns>
	private static bool IsGroupPolicyMUnit(MUnit mUnit)
	{
		return mUnit.ApplyStrategy is IApplyGroupPolicy ||
			   mUnit.VerifyStrategy is IVerifyGroupPolicy ||
			   mUnit.RemoveStrategy is IRemoveGroupPolicy;
	}

	/// <summary>
	/// Processes Group Policy MUnits in bulk.
	/// </summary>
	/// <param name="groupPolicyMUnits">The Group Policy MUnits to process</param>
	/// <param name="operation">The operation to perform</param>
	private static void ProcessGroupPolicyMUnitsBulk(List<MUnit> groupPolicyMUnits, MUnitOperation operation)
	{
		try
		{
			List<RegistryPolicyEntry> allPolicies = [];

			// Collect all policies from the MUnits
			foreach (MUnit mUnit in groupPolicyMUnits)
			{
				List<RegistryPolicyEntry>? policies = operation switch
				{
					MUnitOperation.Apply when mUnit.ApplyStrategy is IApplyGroupPolicy applyStrategy => applyStrategy.Policies,
					MUnitOperation.Remove when mUnit.RemoveStrategy is IRemoveGroupPolicy removeStrategy => removeStrategy.Policies,
					MUnitOperation.Verify when mUnit.VerifyStrategy is IVerifyGroupPolicy verifyStrategy => verifyStrategy.Policies,
					_ => null
				};

				if (policies != null)
				{
					allPolicies.AddRange(policies);
				}
			}

			if (allPolicies.Count > 0)
			{
				// Perform bulk operation
				switch (operation)
				{
					case MUnitOperation.Apply:
						RegistryPolicyParser.AddPoliciesToSystem(allPolicies);
						// Mark all as applied
						foreach (MUnit mUnit in groupPolicyMUnits)
						{
							mUnit.IsApplied = true;
						}
						break;

					case MUnitOperation.Remove:
						RegistryPolicyParser.RemovePoliciesFromSystem(allPolicies);
						// Mark all as not applied
						foreach (MUnit mUnit in groupPolicyMUnits)
						{
							mUnit.IsApplied = false;
						}
						break;

					case MUnitOperation.Verify:
						Dictionary<RegistryPolicyEntry, bool> verificationResults = RegistryPolicyParser.VerifyPoliciesInSystem(allPolicies);

						// Update status based on verification results
						foreach (MUnit mUnit in groupPolicyMUnits)
						{
							if (mUnit.VerifyStrategy is IVerifyGroupPolicy verifyStrategy)
							{
								bool allPoliciesApplied = true;
								foreach (RegistryPolicyEntry policy in verifyStrategy.Policies)
								{
									if (!verificationResults.TryGetValue(policy, out bool isApplied) || !isApplied)
									{
										allPoliciesApplied = false;
										break;
									}
								}
								mUnit.IsApplied = allPoliciesApplied;
							}
						}
						break;
					default:
						break;
				}
			}
		}
		catch (Exception ex)
		{
			Logger.Write("Error processing Group Policy MUnits in bulk.");
			Logger.Write(ErrorWriter.FormatException(ex));
		}
	}

	/// <summary>
	/// Processes a regular (non-Group Policy) MUnit individually
	/// </summary>
	/// <param name="mUnit">The MUnit to process</param>
	/// <param name="operation">The operation to perform</param>
	private static void ProcessRegularMUnit(MUnit mUnit, MUnitOperation operation)
	{
		try
		{
			switch (operation)
			{
				case MUnitOperation.Apply:
					mUnit.ApplyStrategy.Apply();
					mUnit.IsApplied = true;
					break;

				case MUnitOperation.Remove:
					mUnit.RemoveStrategy?.Remove();
					mUnit.IsApplied = false;
					break;

				case MUnitOperation.Verify:
					if (mUnit.VerifyStrategy != null)
					{
						bool isApplied = mUnit.VerifyStrategy.Verify();
						mUnit.IsApplied = isApplied;
					}
					break;
				default:
					break;
			}
		}
		catch (Exception ex)
		{
			Logger.Write($"Error processing regular MUnit {mUnit.Name}");
			Logger.Write(ErrorWriter.FormatException(ex));
		}
	}

	/// <summary>
	/// Apply a single MUnit
	/// </summary>
	/// <param name="mUnit">The MUnit to apply</param>
	internal void ApplyMUnit(MUnit mUnit)
	{
		ProcessMUnitsWithBulkOperations([mUnit], MUnitOperation.Apply);
	}

	/// <summary>
	/// Remove a single MUnit
	/// </summary>
	/// <param name="mUnit">The MUnit to remove</param>
	internal void RemoveMUnit(MUnit mUnit)
	{
		if (mUnit.RemoveStrategy == null)
		{
			MainInfoBar.WriteWarning($"Remove strategy not available for: {mUnit.Name}");
			return;
		}

		ProcessMUnitsWithBulkOperations([mUnit], MUnitOperation.Remove);
	}

	/// <summary>
	/// Verify a single MUnit
	/// </summary>
	/// <param name="mUnit">The MUnit to verify</param>
	internal void VerifyMUnit(MUnit mUnit)
	{
		if (mUnit.VerifyStrategy == null)
		{
			MainInfoBar.WriteWarning($"Verify strategy not available for: {mUnit.Name}");
			return;
		}

		ProcessMUnitsWithBulkOperations([mUnit], MUnitOperation.Verify);
	}

	/// <summary>
	/// Apply all MUnits.
	/// </summary>
	public void ApplyAllMUnits()
	{
		List<MUnit> allMUnits = [];
		foreach (GroupInfoListForMUnit group in ListViewItemsSource)
		{
			allMUnits.AddRange(group);
		}

		if (allMUnits.Count > 0)
		{
			ProcessMUnitsWithBulkOperations(allMUnits, MUnitOperation.Apply);
		}
	}

	/// <summary>
	/// Apply only the selected MUnits.
	/// </summary>
	public void ApplySelectedMUnits()
	{
		if (ItemsSourceSelectedItems.Count > 0)
		{
			ProcessMUnitsWithBulkOperations(ItemsSourceSelectedItems, MUnitOperation.Apply);
		}
	}

	/// <summary>
	/// Remove all MUnits.
	/// </summary>
	public void RemoveAllMUnits()
	{
		List<MUnit> allMUnits = [];
		foreach (GroupInfoListForMUnit group in ListViewItemsSource)
		{
			foreach (MUnit mUnit in group)
			{
				if (mUnit.RemoveStrategy is not null)
				{
					allMUnits.Add(mUnit);
				}
			}
		}

		if (allMUnits.Count > 0)
		{
			ProcessMUnitsWithBulkOperations(allMUnits, MUnitOperation.Remove);
		}
	}

	/// <summary>
	/// Remove only the selected MUnits.
	/// </summary>
	public void RemoveSelectedMUnits()
	{
		List<MUnit> allMUnits = [];
		foreach (MUnit mUnit in ItemsSourceSelectedItems)
		{
			if (mUnit.RemoveStrategy is not null)
			{
				allMUnits.Add(mUnit);
			}
		}

		if (allMUnits.Count > 0)
		{
			ProcessMUnitsWithBulkOperations(allMUnits, MUnitOperation.Remove);
		}
	}

	/// <summary>
	/// Verify all MUnits
	/// </summary>
	public void VerifyAllMUnits()
	{
		List<MUnit> allMUnits = [];
		foreach (GroupInfoListForMUnit group in ListViewItemsSource)
		{
			foreach (MUnit mUnit in group)
			{
				if (mUnit.VerifyStrategy is not null)
				{
					allMUnits.Add(mUnit);
				}
			}
		}

		if (allMUnits.Count > 0)
		{
			ProcessMUnitsWithBulkOperations(allMUnits, MUnitOperation.Verify);
		}
	}

	/// <summary>
	/// Verify only the selected MUnits.
	/// </summary>
	public void VerifySelectedMUnits()
	{
		List<MUnit> allMUnits = [];

		foreach (MUnit mUnit in ItemsSourceSelectedItems)
		{
			if (mUnit.VerifyStrategy is not null)
			{
				allMUnits.Add(mUnit);
			}
		}

		if (allMUnits.Count > 0)
		{
			ProcessMUnitsWithBulkOperations(allMUnits, MUnitOperation.Verify);
		}
	}

	/// <summary>
	/// Create <see cref="MUnit"/> that is for Group Policies only.
	/// </summary>
	internal List<MUnit> CreateGroupPolicyUnits()
	{

		DefenderPolicyFrmJSON = RegistryPolicyEntry.LoadWithFriendlyNameKeyResolve(JSONConfigPath) ?? throw new InvalidOperationException("Defender policies could not be found!");

		List<MUnit> temp = [];

		foreach (RegistryPolicyEntry entry in DefenderPolicyFrmJSON)
		{
			// Only add Main Category policies at this point
			if (entry.SubCategory is not null) continue;

			// Do this for all
			MUnit _mUnit = new(
			   category: Categories.MicrosoftDefender,
			   name: entry.FriendlyName,
			   applyStrategy: new GroupPolicyApply([entry]),
			   verifyStrategy: new GroupPolicyVerify([entry]),
			   removeStrategy: new GroupPolicyRemove([entry]),
			   defenderVM: this,
			   url: entry.URL);

			/*
			// Conditionally replace their verifications
			if (RegistryPolicyEntry.HasAlternateVerification(entry, "", ""))
			{
				_mUnit.VerifyStrategy = new GroupPolicyVerify([entry]);
			}
			*/

			temp.Add(_mUnit);
		}

		return temp;
	}

	/// <summary>
	/// Create <see cref="MUnit"/> that is not for Group Policies.
	/// </summary>
	/// <exception cref="InvalidOperationException"></exception>
	internal List<MUnit> CreateUnits()
	{
		List<MUnit> temp = [];

		// Enabling Restore point scan
		temp.Add(new(
			category: Categories.MicrosoftDefender,
			name: GlobalVars.GetStr("EnablingRestorePointScan-MSDefender"),

			applyStrategy: new DefaultApply(() =>
			{
				_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "bool Set DisableRestorePoint false");
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				string result = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "get DisableRestorePoint");

				if (bool.TryParse(result, out bool actualResult))
				{
					return actualResult;
				}

				return false;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "bool Set DisableRestorePoint true");
			}),

			defenderVM: this
			));

		// AllowSwitchToAsyncInspection
		temp.Add(new(
			category: Categories.MicrosoftDefender,
			name: GlobalVars.GetStr("AllowSwitchToAsyncInspection-MSDefender"),

			applyStrategy: new DefaultApply(() =>
			{
				_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "bool Set AllowSwitchToAsyncInspection true");
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				string result = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "get AllowSwitchToAsyncInspection");

				if (bool.TryParse(result, out bool actualResult))
				{
					return actualResult;
				}

				return false;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "bool Set AllowSwitchToAsyncInspection false");
			}),

			defenderVM: this
			));

		// EnableConvertWarnToBlock
		temp.Add(new(
			category: Categories.MicrosoftDefender,
			name: GlobalVars.GetStr("EnableConvertWarnToBlock-MSDefender"),

			applyStrategy: new DefaultApply(() =>
			{
				_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "bool Set EnableConvertWarnToBlock true");
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				string result = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "get EnableConvertWarnToBlock");

				if (bool.TryParse(result, out bool actualResult))
				{
					return actualResult;
				}

				return false;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "bool Set EnableConvertWarnToBlock false");
			}),

			defenderVM: this
			));

		// BruteForceProtectionLocalNetworkBlocking
		temp.Add(new(
			category: Categories.MicrosoftDefender,
			name: GlobalVars.GetStr("BruteForceProtectionLocalNetworkBlocking-MSDefender"),

			applyStrategy: new DefaultApply(() =>
			{
				_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "bool Set BruteForceProtectionLocalNetworkBlocking true");
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				string result = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "get BruteForceProtectionLocalNetworkBlocking");

				if (bool.TryParse(result, out bool actualResult))
				{
					return actualResult;
				}

				return false;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "bool Set BruteForceProtectionLocalNetworkBlocking false");
			}),

			defenderVM: this
			));

		// Adding OneDrive directories to Controlled Folder Access
		temp.Add(new(
			category: Categories.MicrosoftDefender,
			name: GlobalVars.GetStr("AddOneDriveDirsToCFA-MSDefender"),

			applyStrategy: new DefaultApply(() =>
			{
				string[] oneDriveDirs = OneDriveDirectories.Get();

				if (oneDriveDirs.Length > 0)
				{
					// Wrap them with double quotes and separate them with a space
					string oneDriveDirsFinal = string.Join(" ", oneDriveDirs.Select(item => $"\"{item}\""));

					_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, $"stringarray Add ControlledFolderAccessProtectedFolders {oneDriveDirsFinal}");
				}
			}),

			defenderVM: this
			));


		// Enable Mandatory ASLR for System
		temp.Add(new(
			category: Categories.MicrosoftDefender,
			name: GlobalVars.GetStr("EnableMandatoryASLR-MSDefender"),

			applyStrategy: new DefaultApply(() =>
			{
				Result systemResult = AddMitigationsToSystem(
					null,
					[MitigationOptions.ForceRelocateImages],
					null,
					null,
					false,
					false);

				if (!systemResult.IsSuccess)
				{
					throw new InvalidOperationException(systemResult.Error);
				}
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				Result<AppMitigations> systemPolicyResult = GetSystemPolicy();
				if (!systemPolicyResult.IsSuccess)
				{
					throw new InvalidOperationException(systemPolicyResult.Error);
				}

				AppMitigations system = systemPolicyResult.Value;
				return system.Aslr.ForceRelocateImages == OPTIONVALUE.ON;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				Result systemResult = AddMitigationsToSystem(
					[MitigationOptions.ForceRelocateImages],
					null,
					null,
					null,
					false,
					false);

				if (!systemResult.IsSuccess)
				{
					throw new InvalidOperationException(systemResult.Error);
				}
			}),

			defenderVM: this
			));


		// Create MUnits for Process Mitigations
		Manage.CreateMUnitEntries(this, temp);


		// BCD NX Bit Policy
		// bcdedit.exe /set '{current}' nx AlwaysOn
		temp.Add(new(
			category: Categories.MicrosoftDefender,
			name: GlobalVars.GetStr("SetNXBit-MSDefender"),

			applyStrategy: new DefaultApply(() =>
			{
				BCDManager.SetNxElement(3);

				// Verify new value after set
				long? newVal = BCDManager.GetNxElement();

				if (newVal != 3)
				{
					throw new InvalidOperationException(GlobalVars.GetStr("SetNXBitError-MSDefender"));
				}
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				return BCDManager.GetNxElement() == 3;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				// Set it back to the default value.
				BCDManager.SetNxElement(0);

				// Verify new value after set
				long? newVal = BCDManager.GetNxElement();

				if (newVal != 0)
				{
					throw new InvalidOperationException(GlobalVars.GetStr("SetNXBitError-MSDefender"));
				}
			}),

			defenderVM: this
			));


		// Apply exclusions for Mandatory ASLR
		temp.Add(new(
			category: Categories.MicrosoftDefender,
			name: GlobalVars.GetStr("ApplyMandatoryASLRExcl-MSDefender"),

			applyStrategy: new DefaultApply(() =>
			{
				// Collect all of the ASLR-Incompatible files.
				HashSet<string> results = BinarySecurityAnalyzer.GetASLRIncompatibleGitHubExes();

				if (results.Count > 0)
				{
					foreach (string item in results)
					{
						// Disable the Mandatory ASLR for the PE
						Result addResult = AddMitigationsForProcess(
						   item,
						   [MitigationOptions.ForceRelocateImages],
						   null,
						   null,
						   null,
						   false,
						   false);

						if (!addResult.IsSuccess)
						{
							throw new InvalidOperationException(addResult.Error);
						}
					}
				}

			}),

			defenderVM: this
			));


		// Smart App Control
		temp.Add(new(
			category: Categories.MicrosoftDefender,
			name: GlobalVars.GetStr("SAC-MSDefender"),

			applyStrategy: new DefaultApply(() =>
			{
				// Turn on SAC via Registry
				RegistryManager.Manager.EditRegistry(new(
					source: Source.Registry,
					keyName: @"SYSTEM\CurrentControlSet\Control\CI\Policy",
					valueName: "VerifiedAndReputablePolicyState",
					type: RegistryValueType.REG_DWORD,
					0,
					[])
				{
					RegValue = "1",
					policyAction = PolicyAction.Apply
				});


				// Apply policies for optional diagnostic data when SAC is turned on.
				RegistryPolicyParser.AddPoliciesToSystem(DefenderPolicyFrmJSON.Where(x => x.SubCategory is SubCategories.MSDefender_OptionalDiagnosticData).ToList());

			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				string? result = RegistryManager.Manager.ReadRegistry(
					new(
					source: Source.Registry,
					keyName: @"SYSTEM\CurrentControlSet\Control\CI\Policy",
					valueName: "VerifiedAndReputablePolicyState",
					type: RegistryValueType.REG_DWORD,
					0,
					[])
					{
						RegValue = "1"
					});


				if (result is null)
					return false;

				return string.Equals(result, "1", StringComparison.OrdinalIgnoreCase);
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				// Turn off SAC via Registry
				RegistryManager.Manager.EditRegistry(new(
					source: Source.Registry,
					keyName: @"SYSTEM\CurrentControlSet\Control\CI\Policy",
					valueName: "VerifiedAndReputablePolicyState",
					type: RegistryValueType.REG_DWORD,
					0,
					[])
				{
					RegValue = "0",
					policyAction = PolicyAction.Apply
				});

				List<RegistryPolicyEntry> policies = DefenderPolicyFrmJSON.Where(x => x.SubCategory is SubCategories.MSDefender_OptionalDiagnosticData).ToList();

				// Change them to 0 from 1 to disable the MSDefender_OptionalDiagnosticData Sub-Category policies.
				foreach (RegistryPolicyEntry item in policies)
				{
					item.Data = BitConverter.GetBytes(0);
				}

			}),

			defenderVM: this,

			subCategory: SubCategories.MSDefender_SmartAppControl
			));


		// Beta update channels for the Microsoft Defender
		temp.Add(new(
			category: Categories.MicrosoftDefender,
			name: GlobalVars.GetStr("BetaUpdateChannels-MSDefender"),

			applyStrategy: new DefaultApply(() =>
			{
				_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "string Set EngineUpdatesChannel 2");
				_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "string Set PlatformUpdatesChannel 2");
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				string? result1 = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "get EngineUpdatesChannel");
				string? result2 = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "get PlatformUpdatesChannel");

				if (string.Equals(result1, "2", StringComparison.OrdinalIgnoreCase) &&
					string.Equals(result2, "2", StringComparison.OrdinalIgnoreCase))
					return true;

				return false;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "string Set EngineUpdatesChannel 0");
				_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "string Set PlatformUpdatesChannel 0");
			}),

			defenderVM: this,

			subCategory: SubCategories.MSDefender_BetaUpdateChannelsForDefender
			));


		return temp;
	}

	/// <summary>
	/// Gets the current system process mitigation defaults stored in the registry.
	/// </summary>
	internal static Result<AppMitigations> GetSystemPolicy()
	{
		try
		{
			return SecurityPolicyRepository.RetrieveSystemSecurityConfiguration();
		}
		catch (Exception ex)
		{
			return Result<AppMitigations>.Failure($"Failed to get system policy: {ex.Message}");
		}
	}

	/// <summary>
	/// Add mitigations for the Process
	/// </summary>
	internal static Result AddMitigationsForProcess(string processName, MitigationOptions[]? disableList, MitigationOptions[]? enableList, string[]? EAFModulesList, string? isForce, bool isRemove, bool isReset)
	{
		try
		{
			if (enableList is null && disableList is null)
				return Result.Failure("The input parameters are invalid. Please specify a list of mitigations to enable or disable for this process.");

			if (processName.Equals(Path.GetFileNameWithoutExtension(processName)))
				processName = (processName + ".exe").ToLowerInvariant();

			Result<List<AppMitigations>> fromRegistryByNameResult = SecurityPolicyRepository.RetrieveSecurityConfigurationFromRegistryByName(processName);
			if (fromRegistryByNameResult.IsFailure)
				return Result.Failure(fromRegistryByNameResult.Error);

			List<AppMitigations> fromRegistryByName = fromRegistryByNameResult.Value;
			AppMitigations? appMitigations = null;
			if (fromRegistryByName.Count is 0)
				appMitigations = new AppMitigations(processName);
			else if (fromRegistryByName.Count > 1)
				return Result.Failure("Multiple mitigation policies found that may match the given process name. Please specify the full path to be matched instead.");
			else
				appMitigations = fromRegistryByName[0];

			return SetProcessMitigationsCommand.setEnableAndDisable(appMitigations, disableList, enableList, EAFModulesList, isForce, isRemove, isReset, isSystemMode: false);
		}
		catch (Exception ex)
		{
			return Result.Failure($"Failed to add mitigations for process: {ex.Message}");
		}
	}

	/// <summary>
	/// Add mitigations to the System
	/// </summary>
	internal static Result AddMitigationsToSystem(MitigationOptions[]? disableList, MitigationOptions[]? enableList, string[]? EAFModulesList, string? isForce, bool isRemove, bool isReset)
	{
		try
		{
			Result<AppMitigations> systemPolicyResult = SecurityPolicyRepository.RetrieveSystemSecurityConfiguration();
			AppMitigations appMitigations;
			if (systemPolicyResult.IsSuccess)
			{
				appMitigations = systemPolicyResult.Value;
			}
			else
			{
				appMitigations = new AppMitigations("System")
				{
					Source = "System Defaults"
				};
			}

			return SetProcessMitigationsCommand.setEnableAndDisable(appMitigations, disableList, enableList, EAFModulesList, isForce, isRemove, isReset, isSystemMode: true);
		}
		catch (Exception ex)
		{
			return Result.Failure($"Failed to add mitigations to system: {ex.Message}");
		}
	}

}
