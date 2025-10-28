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
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using AppControlManager.Others;
using HardenSystemSecurity.ExploitMitigation;
using HardenSystemSecurity.Helpers;
using HardenSystemSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.ViewModels;

internal sealed partial class MicrosoftDefenderVM : MUnitListViewModelBase
{
	[SetsRequiredMembers]
	internal MicrosoftDefenderVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		// Initializing the cancellable buttons
		ApplyAllCancellableButton = new(GlobalVars.GetStr("ApplyAllButtonText/Text"));
		RemoveAllCancellableButton = new(GlobalVars.GetStr("RemoveAllButtonText/Text"));
		VerifyAllCancellableButton = new(GlobalVars.GetStr("VerifyAllButtonText"));

		IMUnitListViewModel.CreateUIValuesCategories(this);

		// To size the listview columns with some padding after initial page load.
		ComputeColumnWidths();
	}

	/// <summary>
	/// Creates all MUnits for this ViewModel.
	/// </summary>
	/// <returns>List of all MUnits for this ViewModel</returns>
	private static readonly Lazy<List<MUnit>> LazyCatalog =
		new(() =>
		{
			#region One-time global registrations for this category - Registers specialized strategies for specific policies.

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

			// SEE THE END OF THE FILE FOR MORE EXAMPLES
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

			#endregion

			#region Register Dependencies

			/// Registers MUnit dependencies to define relationships between security measures.
			/// This allows automatic application or removal of related policies.


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


			#endregion

			// Create MUnits from JSON policies using the centralized method.
			List<MUnit> allResults = MUnit.CreateMUnitsFromPolicies(Categories.MicrosoftDefender);

			// Create programatic MUnits that are not from Group Policies.
			allResults.AddRange(CreateUnits());

			return allResults;

		}, LazyThreadSafetyMode.ExecutionAndPublication);

	/// <summary>
	/// Gets the current catalog of all MUnits for this ViewModel.
	/// </summary>
	public override List<MUnit> AllMUnits => LazyCatalog.Value;

	/// <summary>
	/// Create <see cref="MUnit"/> that is not for Group Policies.
	/// </summary>
	/// <exception cref="InvalidOperationException"></exception>
	private static List<MUnit> CreateUnits()
	{
		List<MUnit> temp = [];

		// Enabling Restore point scan
		temp.Add(new(
			category: Categories.MicrosoftDefender,
			name: GlobalVars.GetStr("EnablingRestorePointScan-MSDefender"),

			applyStrategy: new DefaultApply(() =>
			{
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "DisableRestorePoint"))
				{
					return;
				}

				_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "wmi bool ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference Set DisableRestorePoint false");
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "DisableRestorePoint"))
				{
					return false;
				}

				string result = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "get ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference DisableRestorePoint");

				if (bool.TryParse(result, out bool actualResult))
				{
					return !actualResult; // Being false == true in this case.
				}

				return false;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "DisableRestorePoint"))
				{
					return;
				}

				_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "wmi bool ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference Set DisableRestorePoint true");
			}),

			deviceIntents: [
				DeviceIntents.Intent.Business,
				DeviceIntents.Intent.SpecializedAccessWorkstation,
				DeviceIntents.Intent.PrivilegedAccessWorkstation,
				DeviceIntents.Intent.School
			]
			));

		// AllowSwitchToAsyncInspection
		temp.Add(new(
			category: Categories.MicrosoftDefender,
			name: GlobalVars.GetStr("AllowSwitchToAsyncInspection-MSDefender"),

			applyStrategy: new DefaultApply(() =>
			{
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "AllowSwitchToAsyncInspection"))
				{
					return;
				}

				_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "wmi bool ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference Set AllowSwitchToAsyncInspection true");
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "AllowSwitchToAsyncInspection"))
				{
					return false;
				}

				string result = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "get ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference AllowSwitchToAsyncInspection");

				if (bool.TryParse(result, out bool actualResult))
				{
					return actualResult;
				}

				return false;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "AllowSwitchToAsyncInspection"))
				{
					return;
				}

				_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "wmi bool ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference Set AllowSwitchToAsyncInspection false");
			}),

			deviceIntents: [
				DeviceIntents.Intent.All
			]
			));

		// EnableConvertWarnToBlock
		temp.Add(new(
			category: Categories.MicrosoftDefender,
			name: GlobalVars.GetStr("EnableConvertWarnToBlock-MSDefender"),

			applyStrategy: new DefaultApply(() =>
			{
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "EnableConvertWarnToBlock"))
				{
					return;
				}

				_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "wmi bool ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference Set EnableConvertWarnToBlock true");
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "EnableConvertWarnToBlock"))
				{
					return false;
				}

				string result = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "get ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference EnableConvertWarnToBlock");

				if (bool.TryParse(result, out bool actualResult))
				{
					return actualResult;
				}

				return false;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "EnableConvertWarnToBlock"))
				{
					return;
				}

				_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "wmi bool ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference Set EnableConvertWarnToBlock false");
			}),

			deviceIntents: [
				DeviceIntents.Intent.Business,
				DeviceIntents.Intent.SpecializedAccessWorkstation,
				DeviceIntents.Intent.PrivilegedAccessWorkstation,
				DeviceIntents.Intent.School
			]
			));

		// BruteForceProtectionLocalNetworkBlocking
		temp.Add(new(
			category: Categories.MicrosoftDefender,
			name: GlobalVars.GetStr("BruteForceProtectionLocalNetworkBlocking-MSDefender"),

			applyStrategy: new DefaultApply(() =>
			{
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "BruteForceProtectionLocalNetworkBlocking"))
				{
					return;
				}

				_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "wmi bool ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference Set BruteForceProtectionLocalNetworkBlocking true");
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "BruteForceProtectionLocalNetworkBlocking"))
				{
					return false;
				}

				string result = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "get ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference BruteForceProtectionLocalNetworkBlocking");

				if (bool.TryParse(result, out bool actualResult))
				{
					return actualResult;
				}

				return false;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "BruteForceProtectionLocalNetworkBlocking"))
				{
					return;
				}

				_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "wmi bool ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference Set BruteForceProtectionLocalNetworkBlocking false");
			}),

			deviceIntents: [
				DeviceIntents.Intent.Business,
				DeviceIntents.Intent.SpecializedAccessWorkstation,
				DeviceIntents.Intent.PrivilegedAccessWorkstation,
				DeviceIntents.Intent.School
			]
			));

		// Adding OneDrive directories to Controlled Folder Access
		temp.Add(new(
			category: Categories.MicrosoftDefender,
			name: GlobalVars.GetStr("AddOneDriveDirsToCFA-MSDefender"),

			applyStrategy: new DefaultApply(() =>
			{
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "ControlledFolderAccessProtectedFolders"))
				{
					return;
				}

				string[] oneDriveDirs = OneDriveDirectories.Get();

				if (oneDriveDirs.Length > 0)
				{
					// Wrap them with double quotes and separate them with a space
					string oneDriveDirsFinal = string.Join(" ", oneDriveDirs.Select(item => $"\"{item}\""));

					_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"wmi stringarray ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference Add ControlledFolderAccessProtectedFolders {oneDriveDirsFinal}");
				}
			}),
			deviceIntents: [
				DeviceIntents.Intent.All
			]
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
			url: "https://support.microsoft.com/office/how-onedrive-safeguards-your-data-in-the-cloud-23c6ea94-3608-48d7-8bf0-80e142edd1e1",

			deviceIntents: [
				DeviceIntents.Intent.Business,
				DeviceIntents.Intent.SpecializedAccessWorkstation,
				DeviceIntents.Intent.PrivilegedAccessWorkstation,
				DeviceIntents.Intent.School
			]

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
			}),
			deviceIntents: [
				DeviceIntents.Intent.All
			]
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

			deviceIntents: [
				DeviceIntents.Intent.Development
			]
			));


		// Beta update channels for the Microsoft Defender
		temp.Add(new(
			category: Categories.MicrosoftDefender,
			name: GlobalVars.GetStr("BetaUpdateChannels-MSDefender"),

			applyStrategy: new DefaultApply(() =>
			{
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "EngineUpdatesChannel"))
				{
					return;
				}
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "PlatformUpdatesChannel"))
				{
					return;
				}

				_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "wmi string ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference Set EngineUpdatesChannel 2");
				_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "wmi string ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference Set PlatformUpdatesChannel 2");
			}),

			verifyStrategy: new DefaultVerify(() =>
			{
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "EngineUpdatesChannel"))
				{
					return false;
				}
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "PlatformUpdatesChannel"))
				{
					return false;
				}

				string? result1 = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "get ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference EngineUpdatesChannel");
				string? result2 = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "get ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference PlatformUpdatesChannel");

				if (string.Equals(result1, "2", StringComparison.OrdinalIgnoreCase) &&
					string.Equals(result2, "2", StringComparison.OrdinalIgnoreCase))
					return true;

				return false;
			}),

			removeStrategy: new DefaultRemove(() =>
			{
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "EngineUpdatesChannel"))
				{
					return;
				}
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpPreference", "PlatformUpdatesChannel"))
				{
					return;
				}

				_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "wmi string ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference Set EngineUpdatesChannel 0");
				_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "wmi string ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference Set PlatformUpdatesChannel 0");
			}),

			subCategory: SubCategories.MSDefender_BetaUpdateChannelsForDefender,

			deviceIntents: [
				DeviceIntents.Intent.SpecializedAccessWorkstation
			]
			));


		const string Name = "MP_FORCE_USE_SANDBOX";
		const string Value = "1";

		// Microsoft Defender Sandbox
		temp.Add(new(
				category: Categories.MicrosoftDefender,
				name: GlobalVars.GetStr("EnableMDAVSandboxMode-MSDefender"),

				applyStrategy: new DefaultApply(() =>
				{
					Environment.SetEnvironmentVariable(Name, Value, EnvironmentVariableTarget.Machine);
				}),

				verifyStrategy: new DefaultVerify(() =>
				{
					string? current = Environment.GetEnvironmentVariable(Name, EnvironmentVariableTarget.Machine);
					return string.Equals(current, Value, StringComparison.OrdinalIgnoreCase);
				}),

				removeStrategy: new DefaultRemove(() =>
				{
					Environment.SetEnvironmentVariable(Name, null, EnvironmentVariableTarget.Machine);
				}),

				url: "https://learn.microsoft.com/defender-endpoint/sandbox-mdav",

				deviceIntents: [
					DeviceIntents.Intent.Development,
					DeviceIntents.Intent.School,
					DeviceIntents.Intent.Business,
					DeviceIntents.Intent.SpecializedAccessWorkstation,
					DeviceIntents.Intent.PrivilegedAccessWorkstation
				]
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
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpComputerStatus", "SmartAppControlState"))
				{
					return false;
				}

				string result = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "get ROOT\\Microsoft\\Windows\\Defender MSFT_MpComputerStatus SmartAppControlState");

				return string.Equals(result, "on", StringComparison.OrdinalIgnoreCase);
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
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
				if (!IsWmiPropertyAvailable("ROOT\\Microsoft\\Windows\\Defender", "MSFT_MpComputerStatus", "TDTStatus"))
				{
					return false;
				}

				string result = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "get ROOT\\Microsoft\\Windows\\Defender MSFT_MpComputerStatus TDTStatus");

				return string.Equals(result, "enabled", StringComparison.OrdinalIgnoreCase);
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
				return false;
			}
		}
	}


	/*
	/// <summary>
	/// E.g., specialized apply strategy that runs before the main apply operation.
	/// Can check system prerequisites before applying Intel TDT feature.
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
	/// Maybe a JSON based policy needs some additional personal touch to be completely removed.
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

	/// <summary>
	/// Checks availability of a WMI property via ComManager's GetAvailability command.
	/// Logs a unified message when the property is not available and returns false in that case.
	/// Returns true if available; false otherwise.
	/// </summary>
	private static bool IsWmiPropertyAvailable(string wmiNamespace, string className, string propertyName)
	{
		try
		{
			string output = ProcessStarter.RunCommand(
				GlobalVars.ComManagerProcessPath,
				$"getavailability {wmiNamespace} {className} {propertyName}");

			string token = output is not null ? output.Trim() : string.Empty;

			if (bool.TryParse(token, out bool exists))
			{
				if (!exists)
				{
					Logger.Write($"Property {propertyName} not available on {className}.");
				}
				return exists;
			}

			// Unexpected output token from ComManager -> treat as unavailable and log detail.
			Logger.Write($"Unexpected response while checking availability of {className}.{propertyName}: \"{token}\".");
			return false;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			return false;
		}
	}

	#region Exclusion

	// Column widths
	internal GridLength EXColWidth1 { get; set => SP(ref field, value); }
	internal GridLength EXColWidth2 { get; set => SP(ref field, value); }

	/// <summary>
	/// Compute dynamic column widths.
	/// </summary>
	private void ComputeColumnWidths()
	{
		double w1 = ListViewHelper.MeasureText(GlobalVars.GetStr("TargetHeader/Text"));
		double w2 = ListViewHelper.MeasureText(GlobalVars.GetStr("SourceHeader/Text"));

		foreach (Exclusions v in Exclusions)
		{
			w1 = ListViewHelper.MeasureText(v.Target, w1);
			w2 = ListViewHelper.MeasureText(v.SourceFriendlyName, w2);
		}

		EXColWidth1 = new GridLength(w1);
		EXColWidth2 = new GridLength(w2);
	}

	internal readonly ObservableCollection<Exclusions> Exclusions = [];
	private readonly List<Exclusions> AllExclusions = [];

	internal Visibility ExclusionProgressVisibility { get; private set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool ExclusionsUIIsEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ExclusionProgressVisibility = value ? Visibility.Collapsed : Visibility.Visible;

			}
		}
	} = true;

	internal string? ExclusionsSearchText
	{
		get; set
		{
			if (SPT(ref field, value))
			{
				SearchBox_TextChanged();
			}
		}
	}

	/// <summary>
	/// Clear the exclusions list in the UI.
	/// </summary>
	internal void ClearExclusionsList()
	{
		Exclusions.Clear();
		AllExclusions.Clear();
		ExclusionsSearchText = null;
		ComputeColumnWidths();
	}

	/// <summary>
	/// Mapping of sortable / copyable fields.
	/// </summary>
	private static readonly FrozenDictionary<string, (string Label, Func<Exclusions, object?> Getter)> _exclusionsMappings =
		new Dictionary<string, (string Label, Func<Exclusions, object?> Getter)>(StringComparer.OrdinalIgnoreCase)
		{
			{ "Target",     (GlobalVars.GetStr("TargetHeader/Text"),  v => v.Target) },
			{ "Source",     (GlobalVars.GetStr("SourceHeader/Text"),  v => v.SourceFriendlyName) }
		}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	#region Sort

	/// <summary>
	/// Local sort state
	/// </summary>
	private ListViewHelper.SortState SortState { get; set; } = new();

	internal void HeaderColumnSortingButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button button && button.Tag is string key)
		{
			// Look up the mapping in the reusable property mappings dictionary.
			if (_exclusionsMappings.TryGetValue(key, out (string Label, Func<Exclusions, object?> Getter) mapping))
			{
				ListViewHelper.SortColumn(
					mapping.Getter,
					ExclusionsSearchText,
					AllExclusions,
					Exclusions,
					SortState,
					key,
					regKey: ListViewHelper.ListViewsRegistry.MD_Exclusions);
			}
		}
	}
	#endregion

	#region Copy

	/// <summary>
	/// Converts selected Exclusions rows to text.
	/// </summary>
	internal void CopySelectedExclusions_Click()
	{
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.MD_Exclusions);
		if (lv is null) return;
		if (lv.SelectedItems.Count > 0)
		{
			// SelectedItems is an IList
			ListViewHelper.ConvertRowToText(lv.SelectedItems, _exclusionsMappings);
		}
	}

	/// <summary>
	/// Copy a single property of the current selection
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void CopyExclusionProperty_Click(object sender, RoutedEventArgs e)
	{
		MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;
		string key = (string)menuItem.Tag;
		ListView? lv = ListViewHelper.GetListViewFromCache(ListViewHelper.ListViewsRegistry.MD_Exclusions);
		if (lv is null) return;

		if (_exclusionsMappings.TryGetValue(key, out var map))
		{
			// TElement = Exclusions, copy just that one property
			ListViewHelper.CopyToClipboard<Exclusions>(ci => map.Getter(ci)?.ToString(), lv);
		}
	}

	#endregion

	#region Search

	/// <summary>
	/// Event handler for the SearchBox text change
	/// </summary>
	internal void SearchBox_TextChanged()
	{
		string? searchTerm = ExclusionsSearchText?.Trim();
		if (searchTerm is null)
			return;

		// Get the ListView ScrollViewer info
		ScrollViewer? Sv = ListViewHelper.GetScrollViewerFromCache(ListViewHelper.ListViewsRegistry.MD_Exclusions);

		double? savedHorizontal = null;
		if (Sv != null)
		{
			savedHorizontal = Sv.HorizontalOffset;
		}

		// Perform a case-insensitive search in all relevant fields
		List<Exclusions> filteredResults = AllExclusions.Where(v =>
			v.Target.Contains(searchTerm, StringComparison.OrdinalIgnoreCase) ||
			v.SourceFriendlyName.Contains(searchTerm, StringComparison.OrdinalIgnoreCase)).ToList();

		Exclusions.Clear();
		foreach (Exclusions item in filteredResults)
		{
			Exclusions.Add(item);
		}

		if (Sv != null && savedHorizontal.HasValue)
		{
			// restore horizontal scroll position
			_ = Sv.ChangeView(savedHorizontal, null, null, disableAnimation: false);
		}
	}
	#endregion

	/// <summary>
	/// Event handler for the UI.
	/// </summary>
	internal async void RetrieveAllExclusions() => await RetrieveAllExclusionsInternal();

	/// <summary>
	/// Retrieves all exclusions from Microsoft Defender.
	/// </summary>
	private async Task RetrieveAllExclusionsInternal()
	{

		try
		{
			ExclusionsUIIsEnabled = false;

			ClearExclusionsList();

			List<Exclusions> allData = [];

			await Task.Run(() =>
			{

				string results = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, "get ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference");

				List<Dictionary<string, object?>> DeserializedResults = ComJsonDeserializer.DeserializeInstances(results);

				if (DeserializedResults.Count <= 0)
					return;

				// Microsoft Defender - File and Folder paths exclusions
				if (DeserializedResults[0].TryGetValue("ExclusionPath", out object? ExclusionPath))
				{
					List<string> finalResults = ComJsonDeserializer.CoerceToStringList(ExclusionPath);

					foreach (string item in finalResults)
					{
						allData.Add(new(target: item, source: ExclusionSource.Antivirus_Path));
					}
				}

				// Microsoft Defender - Process exclusions
				if (DeserializedResults[0].TryGetValue("ExclusionProcess", out object? ExclusionProcess))
				{
					List<string> finalResults = ComJsonDeserializer.CoerceToStringList(ExclusionProcess);

					foreach (string item in finalResults)
					{
						allData.Add(new(target: item, source: ExclusionSource.Antivirus_Process));
					}
				}

				// Microsoft Defender - Extension exclusions
				if (DeserializedResults[0].TryGetValue("ExclusionExtension", out object? ExclusionExtension))
				{
					List<string> finalResults = ComJsonDeserializer.CoerceToStringList(ExclusionExtension);

					foreach (string item in finalResults)
					{
						allData.Add(new(target: item, source: ExclusionSource.Antivirus_Extension));
					}
				}

				// Controlled Folder Access exclusions
				if (DeserializedResults[0].TryGetValue("ControlledFolderAccessAllowedApplications", out object? cfaAppsObj))
				{
					List<string> finalResults = ComJsonDeserializer.CoerceToStringList(cfaAppsObj);

					foreach (string item in finalResults)
					{
						allData.Add(new(target: item, source: ExclusionSource.ControlledFolderAccess));
					}
				}

				// Attack Surface Reduction rules exclusions
				if (DeserializedResults[0].TryGetValue("AttackSurfaceReductionOnlyExclusions", out object? asrObj))
				{
					List<string> finalResults = ComJsonDeserializer.CoerceToStringList(asrObj);

					foreach (string item in finalResults)
					{
						allData.Add(new(target: item, source: ExclusionSource.AttackSurfaceReduction));
					}
				}
			});

			foreach (Exclusions item in allData)
			{
				Exclusions.Add(item);
				AllExclusions.Add(item);
			}

			ComputeColumnWidths();

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("RetrievedExclusionsSuccessfullyMsg"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ExclusionsUIIsEnabled = true;
		}
	}

	/// <summary>
	/// Add exclusions for Microsoft Defender - File path.
	/// </summary>
	internal async void AddFilePathExclusion()
	{
		try
		{
			ExclusionsUIIsEnabled = false;

			List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.AnyFilePickerFilter);

			if (selectedFiles.Count == 0)
				return;

			await Task.Run(() =>
			{
				foreach (string item in selectedFiles)
				{
					_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"wmi stringarray ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference add ExclusionPath \"{item}\"");

					MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("AddedExclusionMsg"), item));
				}
			});

			await RetrieveAllExclusionsInternal();

		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			MainInfoBarIsClosable = true;
			ExclusionsUIIsEnabled = true;
		}
	}

	/// <summary>
	/// Add exclusions for Microsoft Defender - Folder path.
	/// </summary>
	internal async void AddFolderPathExclusion()
	{
		try
		{
			ExclusionsUIIsEnabled = false;

			List<string> selectedFiles = FileDialogHelper.ShowMultipleDirectoryPickerDialog();

			if (selectedFiles.Count == 0)
				return;

			await Task.Run(() =>
			{
				foreach (string item in selectedFiles)
				{
					_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"wmi stringarray ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference add ExclusionPath \"{item}\"");

					MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("AddedExclusionMsg"), item));
				}
			});

			await RetrieveAllExclusionsInternal();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			MainInfoBarIsClosable = true;
			ExclusionsUIIsEnabled = true;
		}
	}

	/// <summary>
	/// Add exclusions for Microsoft Defender - Extension.
	/// </summary>
	internal async void AddExtensionExclusion()
	{
		try
		{
			ExclusionsUIIsEnabled = false;

			TextBox inputBox = new()
			{
				Header = "Enter the file extension to exclude",
				PlaceholderText = ".ext",
				Text = string.Empty
			};

			using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = GlobalVars.GetStr("AddExtensionExclusionText"),
				Content = inputBox,
				PrimaryButtonText = GlobalVars.GetStr("AddToExclusionsText"),
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Primary
			};

			// Show dialog
			ContentDialogResult result = await dialog.ShowAsync();

			// If user didn't confirm, exit early
			if (result != ContentDialogResult.Primary)
			{
				return;
			}

			string text = inputBox.Text;

			// Add to Defender exclusions
			await Task.Run(() =>
			{
				// Normalize and validate the extension
				string normalizedExtension = NormalizeExtensionOrThrow(text);

				_ = ProcessStarter.RunCommand(
					GlobalVars.ComManagerProcessPath,
					$"wmi stringarray ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference add ExclusionExtension \"{normalizedExtension}\"");

				MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("AddedExclusionMsg"), normalizedExtension));
			});

			await RetrieveAllExclusionsInternal();

		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			MainInfoBarIsClosable = true;
			ExclusionsUIIsEnabled = true;
		}
	}

	/// <summary>
	/// Method to normalize and validate a file extension.
	/// </summary>
	private static string NormalizeExtensionOrThrow(string value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			throw new InvalidOperationException(GlobalVars.GetStr("EnterFileExtensionText"));
		}

		string extension = value.Trim();

		// Prepend '.' if missing
		if (!extension.StartsWith('.'))
		{
			extension = "." + extension;
		}

		// Must have something after the dot
		if (extension.Length <= 1)
		{
			throw new InvalidOperationException(GlobalVars.GetStr("FileExtensionInvalidMsg"));
		}

		// Validate characters (no invalid file name characters allowed)
		char[] invalidChars = Path.GetInvalidFileNameChars();
		if (extension.IndexOfAny(invalidChars) >= 0)
		{
			throw new InvalidOperationException(GlobalVars.GetStr("FileExtensionHasInvalidCharsMsg"));
		}

		// Do not allow directory separators or drive specifiers
		if (extension.Contains('\\', StringComparison.Ordinal) ||
			extension.Contains('/', StringComparison.Ordinal) ||
			extension.Contains(':', StringComparison.Ordinal))
		{
			throw new InvalidOperationException("The file extension must not contain path separators or a drive specifier.");
		}

		return extension;
	}

	/// <summary>
	/// Add exclusions for Microsoft Defender - Process.
	/// </summary>
	internal async void AddProcessExclusion()
	{
		try
		{
			ExclusionsUIIsEnabled = false;

			TextBox inputBox = new()
			{
				Header = "Enter the process name (e.g., notepad.exe) or a full path",
				PlaceholderText = "notepad.exe",
				Text = string.Empty
			};

			using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
			{
				Title = GlobalVars.GetStr("AddProcessExclusionText"),
				Content = inputBox,
				PrimaryButtonText = GlobalVars.GetStr("AddToExclusionsText"),
				CloseButtonText = GlobalVars.GetStr("Cancel"),
				DefaultButton = ContentDialogButton.Primary
			};

			// Show dialog
			ContentDialogResult result = await dialog.ShowAsync();

			// If user didn't confirm, exit early
			if (result != ContentDialogResult.Primary)
			{
				return;
			}

			string text = inputBox.Text;

			// Add to Defender exclusions
			await Task.Run(() =>
			{
				// Normalize and validate the process name
				string normalizedProcessName = NormalizeProcessNameOrThrow(text);

				_ = ProcessStarter.RunCommand(
					GlobalVars.ComManagerProcessPath,
					$"wmi stringarray ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference add ExclusionProcess \"{normalizedProcessName}\"");

				MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("AddedExclusionMsg"), normalizedProcessName));
			});

			await RetrieveAllExclusionsInternal();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			MainInfoBarIsClosable = true;
			ExclusionsUIIsEnabled = true;
		}
	}

	/// <summary>
	/// Local function to normalize and validate a process name or path.
	/// </summary>
	private static string NormalizeProcessNameOrThrow(string value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			throw new InvalidOperationException(GlobalVars.GetStr("EnterProcessNameText"));
		}

		string input = value.Trim();

		// If it's a path, extract the file name
		string name = input;
		if (input.Contains('\\', StringComparison.Ordinal) ||
			input.Contains('/', StringComparison.Ordinal) ||
			input.Contains(':', StringComparison.Ordinal))
		{
			name = Path.GetFileName(input);
		}

		if (string.IsNullOrWhiteSpace(name))
		{
			throw new InvalidOperationException(GlobalVars.GetStr("ProcessNameInvalidMsg"));
		}

		// Ensure it ends with .exe
		if (!name.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
		{
			name += ".exe";
		}

		// Validate characters (no invalid file name characters allowed)
		char[] invalidChars = Path.GetInvalidFileNameChars();
		if (name.IndexOfAny(invalidChars) >= 0)
		{
			throw new InvalidOperationException(GlobalVars.GetStr("ProcessNameHasInvalidCharsMsg"));
		}

		// Must not contain path separators after normalization
		if (name.Contains('\\', StringComparison.Ordinal) ||
			name.Contains('/', StringComparison.Ordinal) ||
			name.Contains(':', StringComparison.Ordinal))
		{
			throw new InvalidOperationException("The process name must not contain path separators or a drive specifier.");
		}

		return name;
	}

	/// <summary>
	/// Add exclusions for Microsoft Defender - Controlled Folder Access.
	/// </summary>
	internal async void AddControlledFolderAccessExclusion()
	{
		try
		{
			ExclusionsUIIsEnabled = false;

			List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.AnyFilePickerFilter);

			if (selectedFiles.Count == 0)
				return;

			await Task.Run(() =>
			{
				foreach (string item in selectedFiles)
				{
					_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"wmi stringarray ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference add ControlledFolderAccessAllowedApplications \"{item}\"");

					MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("AddedExclusionMsg"), item));
				}
			});

			await RetrieveAllExclusionsInternal();

		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			MainInfoBarIsClosable = true;
			ExclusionsUIIsEnabled = true;
		}
	}

	/// <summary>
	/// Add exclusions for Microsoft Defender - Attack Surface Reduction.
	/// </summary>
	internal async void AddASRExclusion()
	{
		try
		{
			ExclusionsUIIsEnabled = false;

			List<string> selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.AnyFilePickerFilter);

			if (selectedFiles.Count == 0)
				return;

			await Task.Run(() =>
			{
				foreach (string item in selectedFiles)
				{
					_ = ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"wmi stringarray ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference add AttackSurfaceReductionOnlyExclusions \"{item}\"");

					MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("AddedExclusionMsg"), item));
				}
			});

			await RetrieveAllExclusionsInternal();

		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			MainInfoBarIsClosable = true;
			ExclusionsUIIsEnabled = true;
		}
	}

	/// <summary>
	/// Removes a single exclusion based on its source type.
	/// Triggered by the per-row context menu "Remove" item.
	/// </summary>
	internal async void RemoveExclusion_Click(object sender, RoutedEventArgs e)
	{
		try
		{
			ExclusionsUIIsEnabled = false;

			// Retrieve the specific exclusion from the flyout item's Tag
			MenuFlyoutItem menuItem = (MenuFlyoutItem)sender;

			Exclusions exclusion = (Exclusions)menuItem.Tag;

			// Map the ExclusionSource to the corresponding MSFT_MpPreference property
			// Each exclusion type is removed from its own string[] property via "remove"
			string propertyName = exclusion.Source switch
			{
				ExclusionSource.Antivirus_Path => "ExclusionPath",
				ExclusionSource.Antivirus_Extension => "ExclusionExtension",
				ExclusionSource.Antivirus_Process => "ExclusionProcess",
				ExclusionSource.ControlledFolderAccess => "ControlledFolderAccessAllowedApplications",
				ExclusionSource.AttackSurfaceReduction => "AttackSurfaceReductionOnlyExclusions",
				_ => throw new InvalidOperationException("Unsupported exclusion type.")
			};

			string target = exclusion.Target;

			// Perform the removal in background to keep UI responsive
			await Task.Run(() =>
			{
				_ = ProcessStarter.RunCommand(
					GlobalVars.ComManagerProcessPath,
					$"wmi stringarray ROOT\\Microsoft\\Windows\\Defender MSFT_MpPreference remove {propertyName} \"{target}\"");
			});

			// Refresh the list
			await RetrieveAllExclusionsInternal();

			MainInfoBar.WriteSuccess($"Removed exclusion: '{target}' from {exclusion.SourceFriendlyName}");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ExclusionsUIIsEnabled = true;
		}
	}

	#endregion

}
