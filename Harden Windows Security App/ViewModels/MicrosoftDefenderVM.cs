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
using AppControlManager.Others;
using AppControlManager.ViewModels;
using HardenWindowsSecurity.ExploitMitigation;
using HardenWindowsSecurity.Helpers;
using HardenWindowsSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenWindowsSecurity.ViewModels;

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

		// Initializing the cancellable buttons
		ApplyAllCancellableButton = new(GlobalVars.GetStr("ApplyAllButtonText/Text"));
		RemoveAllCancellableButton = new(GlobalVars.GetStr("RemoveAllButtonText/Text"));
		VerifyAllCancellableButton = new(GlobalVars.GetStr("VerifyAllButtonText"));

		IMUnitListViewModel.CreateUIValuesCategories(this);
	}

	/// <summary>
	/// The main InfoBar for this VM.
	/// </summary>
	public InfoBarSettings MainInfoBar { get; }

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	public Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

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

	/// <summary>
	/// Items Source of the ListView.
	/// </summary>
	public ObservableCollection<GroupInfoListForMUnit> ListViewItemsSource { get; set => SP(ref field, value); } = [];

	public List<GroupInfoListForMUnit> ListViewItemsSourceBackingField { get; set; } = [];

	/// <summary>
	/// Selected Items list in the ListView.
	/// </summary>
	public List<MUnit> ItemsSourceSelectedItems { get; set; } = [];

	/// <summary>
	/// Search keyword for ListView.
	/// </summary>
	public string? SearchKeyword { get; set; }

	/// <summary>
	/// Initialization details for the Apply All button
	/// </summary>
	public AnimatedCancellableButtonInitializer ApplyAllCancellableButton { get; }

	/// <summary>
	/// Initialization details for the Remove All button
	/// </summary>
	public AnimatedCancellableButtonInitializer RemoveAllCancellableButton { get; }

	/// <summary>
	/// Initialization details for the Verify All button
	/// </summary>
	public AnimatedCancellableButtonInitializer VerifyAllCancellableButton { get; }

	/// <summary>
	/// Total number of items loaded (all MUnits)
	/// </summary>
	public int TotalItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items currently displayed after filtering
	/// </summary>
	public int FilteredItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of currently selected items
	/// </summary>
	public int SelectedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items with Undetermined status (N/A state)
	/// </summary>
	public int UndeterminedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items with Applied status
	/// </summary>
	public int AppliedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Number of items with NotApplied status
	/// </summary>
	public int NotAppliedItemsCount { get; set => SP(ref field, value); }

	/// <summary>
	/// Creates all MUnits for this ViewModel.
	/// </summary>
	/// <returns>List of all MUnits for this ViewModel</returns>
	public List<MUnit> CreateAllMUnits()
	{
		// Register specialized strategies and dependencies.
		RegisterSpecializedStrategies();
		RegisterMUnitDependencies();

		List<MUnit> allResults = CreateMUnitsFromPolicies();
		allResults.AddRange(CreateUnits());
		return allResults;
	}

	/// <summary>
	/// Create MUnits from JSON policies using the centralized method.
	/// </summary>
	internal List<MUnit> CreateMUnitsFromPolicies()
	{
		return MUnit.CreateMUnitsFromPolicies(Categories.MicrosoftDefender);
	}

	/// <summary>
	/// Registers specialized strategies for specific policies.
	/// </summary>
	private void RegisterSpecializedStrategies()
	{
		// Register specialized verification strategy for Smart App Control so its status can be detected via COM too.
		SpecializedStrategiesRegistry.RegisterSpecializedVerification(
			"SYSTEM\\CurrentControlSet\\Control\\CI\\Policy|VerifiedAndReputablePolicyState",
			new SACSpecVerify()
		);

		// Register specialized verification strategy for Intel TDT so its status can be detected via COM too.
		SpecializedStrategiesRegistry.RegisterSpecializedVerification(
			"Software\\Policies\\Microsoft\\Windows Defender\\Features|TDTFeatureEnabled",
			new IntelTDTSpecVerify()
		);

		// SEE THE END OF THE FILE FOR MOAR EXAMPLES
		/*
		// E.g., registering specialized apply strategy that runs before the main operation
		SpecializedStrategiesRegistry.RegisterSpecializedApply(
			"Software\\Policies\\Microsoft\\Windows Defender\\Features|TDTFeatureEnabled",
			new TDTPreApplyCheck()
		);

		// E.g., registering specialized remove strategy that runs after the main operation
		SpecializedStrategiesRegistry.RegisterSpecializedRemove(
			"Software\\Policies\\Microsoft\\Windows Defender\\Features|TDTFeatureEnabled",
			new TDTPostRemoveCleanup()
		);
		*/
	}

	/// <summary>
	/// Registers MUnit dependencies to define relationships between security measures.
	/// This allows automatic application or removal of related policies.
	/// </summary>
	private void RegisterMUnitDependencies()
	{
		// Apply/Remove Diagnostic data when Smart App Control gets enabled/disabled.
		MUnitDependencyRegistry.RegisterDependency(
			primaryMUnitId: "SYSTEM\\CurrentControlSet\\Control\\CI\\Policy|VerifiedAndReputablePolicyState", // Primary MUnit (KeyName|ValueName)
			dependentMUnitId: "Software\\Policies\\Microsoft\\Windows\\DataCollection|AllowTelemetry",  // Dependent MUnit (KeyName|ValueName)
			type: DependencyType.Both,
			timing: ExecutionTiming.After
		);

		MUnitDependencyRegistry.RegisterDependency(
			primaryMUnitId: "SYSTEM\\CurrentControlSet\\Control\\CI\\Policy|VerifiedAndReputablePolicyState", // Primary MUnit (KeyName|ValueName)
			dependentMUnitId: "Software\\Policies\\Microsoft\\Windows\\DataCollection|DisableTelemetryOptInSettingsUx",  // Dependent MUnit (KeyName|ValueName)
			type: DependencyType.Both,
			timing: ExecutionTiming.After
		);

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
				string result = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "get 0 DisableRestorePoint");

				if (bool.TryParse(result, out bool actualResult))
				{
					return !actualResult; // Being false == true in this case.
				}

				return false;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "bool Set DisableRestorePoint true");
			})
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
				string result = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "get 0 AllowSwitchToAsyncInspection");

				if (bool.TryParse(result, out bool actualResult))
				{
					return actualResult;
				}

				return false;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "bool Set AllowSwitchToAsyncInspection false");
			})
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
				string result = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "get 0 EnableConvertWarnToBlock");

				if (bool.TryParse(result, out bool actualResult))
				{
					return actualResult;
				}

				return false;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "bool Set EnableConvertWarnToBlock false");
			})
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
				string result = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "get 0 BruteForceProtectionLocalNetworkBlocking");

				if (bool.TryParse(result, out bool actualResult))
				{
					return actualResult;
				}

				return false;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				_ = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "bool Set BruteForceProtectionLocalNetworkBlocking false");
			})
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
			})
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
			url: "https://support.microsoft.com/office/how-onedrive-safeguards-your-data-in-the-cloud-23c6ea94-3608-48d7-8bf0-80e142edd1e1"

			));


		// Create MUnits for Process Mitigations
		Manage.CreateMUnitEntries(temp);


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
			})
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

			})
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
				string? result1 = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "get 0 EngineUpdatesChannel");
				string? result2 = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "get 0 PlatformUpdatesChannel");

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

			subCategory: SubCategories.MSDefender_BetaUpdateChannelsForDefender
			));


		return temp;
	}

	/// <summary>
	/// Gets the current system process mitigation defaults stored in the registry.
	/// </summary>
	private static Result<AppMitigations> GetSystemPolicy()
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
	private static Result AddMitigationsForProcess(string processName, MitigationOptions[]? disableList, MitigationOptions[]? enableList, string[]? EAFModulesList, string? isForce, bool isRemove, bool isReset)
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
	private static Result AddMitigationsToSystem(MitigationOptions[]? disableList, MitigationOptions[]? enableList, string[]? EAFModulesList, string? isForce, bool isRemove, bool isReset)
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


	/// <summary>
	/// Specialized verification for Smart App Control.
	/// </summary>
	private sealed class SACSpecVerify : ISpecializedVerificationStrategy
	{
		public bool Verify()
		{
			try
			{
				string result = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "get 1 SmartAppControlState");

				return string.Equals(result, "on", StringComparison.OrdinalIgnoreCase);
			}
			catch (Exception ex)
			{
				Logger.Write(ErrorWriter.FormatException(ex));
				return false;
			}
		}
	}

	/// <summary>
	/// Specialized verification for Intel TDT.
	/// </summary>
	private sealed class IntelTDTSpecVerify : ISpecializedVerificationStrategy
	{
		public bool Verify()
		{
			try
			{
				string result = ProcessStarter.RunCommand(GlobalVars.ManageDefenderProcessPath, "get 1 TDTStatus");

				return string.Equals(result, "enabled", StringComparison.OrdinalIgnoreCase);
			}
			catch (Exception ex)
			{
				Logger.Write(ErrorWriter.FormatException(ex));
				return false;
			}
		}
	}


	/*
	/// <summary>
	/// E.g., specialized apply strategy that runs before the main apply operation.
	/// Can check system prerequisites before applying Intel TDT feature. Not exactly a realistic scenario but trying to be wholesome here for future-proofing.
	/// </summary>
	private sealed class TDTPreApplyCheck : ISpecializedApplyStrategy
	{
		public ExecutionTiming Timing => ExecutionTiming.Before;

		public void Apply()
		{
			// CUSTOM CODE
		}
	}

	/// <summary>
	/// E.g., specialized remove strategy that runs after the main remove operation.
	/// Maybe a JSON based policy needs some additional personal touch to be completely removed. Again not exactly a realistic scenario but for future-proofing.
	/// </summary>
	private sealed class TDTPostRemoveCleanup : ISpecializedRemoveStrategy
	{
		public ExecutionTiming Timing => ExecutionTiming.After;

		public void Remove()
		{
			// CUSTOM CODE
		}
	}
	*/

}
