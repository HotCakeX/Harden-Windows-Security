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
using System.IO;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.ViewModels;

internal sealed partial class CreatePolicyVM : ViewModelBase
{

	internal CreatePolicyVM()
	{
		AllowMSFTInfoBar = new InfoBarSettings(
			() => AllowMicrosoftSettingsInfoBarIsOpen, value => AllowMicrosoftSettingsInfoBarIsOpen = value,
			() => AllowMicrosoftSettingsInfoBarMessage, value => AllowMicrosoftSettingsInfoBarMessage = value,
			() => AllowMicrosoftSettingsInfoBarSeverity, value => AllowMicrosoftSettingsInfoBarSeverity = value,
			() => AllowMicrosoftSettingsInfoBarIsClosable, value => AllowMicrosoftSettingsInfoBarIsClosable = value,
			null, null);

		DefaultWinInfoBar = new InfoBarSettings(
			() => DefaultWindowsSettingsInfoBarIsOpen, value => DefaultWindowsSettingsInfoBarIsOpen = value,
			() => DefaultWindowsSettingsInfoBarMessage, value => DefaultWindowsSettingsInfoBarMessage = value,
			() => DefaultWindowsSettingsInfoBarSeverity, value => DefaultWindowsSettingsInfoBarSeverity = value,
			() => DefaultWindowsSettingsInfoBarIsClosable, value => DefaultWindowsSettingsInfoBarIsClosable = value,
			null, null);

		SignedAndRepInfoBar = new InfoBarSettings(
			() => SignedAndReputableSettingsInfoBarIsOpen, value => SignedAndReputableSettingsInfoBarIsOpen = value,
			() => SignedAndReputableSettingsInfoBarMessage, value => SignedAndReputableSettingsInfoBarMessage = value,
			() => SignedAndReputableSettingsInfoBarSeverity, value => SignedAndReputableSettingsInfoBarSeverity = value,
			() => SignedAndReputableSettingsInfoBarIsClosable, value => SignedAndReputableSettingsInfoBarIsClosable = value,
			null, null);

		KernelModeBlockListInfoBar = new InfoBarSettings(
			() => RecommendedDriverBlockRulesSettingsInfoBarIsOpen, value => RecommendedDriverBlockRulesSettingsInfoBarIsOpen = value,
			() => RecommendedDriverBlockRulesSettingsInfoBarMessage, value => RecommendedDriverBlockRulesSettingsInfoBarMessage = value,
			() => RecommendedDriverBlockRulesSettingsInfoBarSeverity, value => RecommendedDriverBlockRulesSettingsInfoBarSeverity = value,
			() => RecommendedDriverBlockRulesSettingsInfoBarIsClosable, value => RecommendedDriverBlockRulesSettingsInfoBarIsClosable = value,
			null, null);

		UserModeBlockListInfoBar = new InfoBarSettings(
			() => RecommendedUserModeBlockRulesSettingsInfoBarIsOpen, value => RecommendedUserModeBlockRulesSettingsInfoBarIsOpen = value,
			() => RecommendedUserModeBlockRulesSettingsInfoBarMessage, value => RecommendedUserModeBlockRulesSettingsInfoBarMessage = value,
			() => RecommendedUserModeBlockRulesSettingsInfoBarSeverity, value => RecommendedUserModeBlockRulesSettingsInfoBarSeverity = value,
			() => RecommendedUserModeBlockRulesSettingsInfoBarIsClosable, value => RecommendedUserModeBlockRulesSettingsInfoBarIsClosable = value,
			null, null);

		StrictKernelInfoBar = new InfoBarSettings(
			() => StrictKernelModesSettingsInfoBarIsOpen, value => StrictKernelModesSettingsInfoBarIsOpen = value,
			() => StrictKernelModesSettingsInfoBarMessage, value => StrictKernelModesSettingsInfoBarMessage = value,
			() => StrictKernelModesSettingsInfoBarSeverity, value => StrictKernelModesSettingsInfoBarSeverity = value,
			() => StrictKernelModesSettingsInfoBarIsClosable, value => StrictKernelModesSettingsInfoBarIsClosable = value,
			null, null);
	}

	private PolicyEditorVM PolicyEditorViewModel { get; } = App.AppHost.Services.GetRequiredService<PolicyEditorVM>();
	internal EventLogUtility EventLogsUtil { get; } = App.AppHost.Services.GetRequiredService<EventLogUtility>();

	#region Allow Microsoft

	internal bool AllowMicrosoftSectionIsEnabled
	{
		get;
		set
		{
			_ = SP(ref field, value);
			AllowMicrosoftLogSizeInputIsEnabled = field && AllowMicrosoftAudit;
		}
	} = true;

	internal Visibility AllowMicrosoftInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool AllowMicrosoftSettingsInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool AllowMicrosoftSettingsInfoBarIsClosable { get; set => SP(ref field, value); }
	internal InfoBarSeverity AllowMicrosoftSettingsInfoBarSeverity { get; set => SP(ref field, value); }
	internal string? AllowMicrosoftSettingsInfoBarMessage { get; set => SP(ref field, value); }
	internal bool AllowMicrosoftSettingsIsExpanded { get; set => SP(ref field, value); }

	private readonly InfoBarSettings AllowMSFTInfoBar;

	internal string? _policyPathAllowMicrosoft { get; set => SP(ref field, value); }
	internal bool AllowMicrosoftLogSizeInputIsEnabled { get; set => SP(ref field, value); }

	internal bool AllowMicrosoftAudit
	{
		get;
		set
		{
			_ = SP(ref field, value);
			AllowMicrosoftLogSizeInputIsEnabled = field;
		}
	}

	internal bool AllowMicrosoftRequireEVSigners { get; set => SP(ref field, value); }
	internal bool AllowMicrosoftEnableScriptEnforcement { get; set => SP(ref field, value); }
	internal bool AllowMicrosoftTestMode { get; set => SP(ref field, value); }
	internal bool AllowMicrosoftCreateAndDeploy { get; set => SP(ref field, value); }
	internal bool AllowMicrosoftNoBlockRules { get; set => SP(ref field, value); }

	/// <summary>
	/// Event handler for creating/deploying AllowMicrosoft policy
	/// </summary>
	internal async void AllowMicrosoftCreate_Click()
	{
		bool Error = false;

		try
		{
			AllowMicrosoftInfoBarActionButtonVisibility = Visibility.Collapsed;

			AllowMicrosoftSettingsInfoBarIsClosable = false;
			AllowMSFTInfoBar.WriteInfo(GlobalVars.Rizz.GetString("CreatingAllowMicrosoftBasePolicy"));

			AllowMicrosoftSettingsIsExpanded = true;

			// Disable the buttons to prevent multiple clicks
			AllowMicrosoftSectionIsEnabled = false;

			string stagingArea = StagingArea.NewStagingArea("BuildAllowMicrosoft").ToString();

			#region Only modify the log size if the element is enabled meaning the Toggle Switch is toggled
			ulong? logSize = null;

			// Only change the Log max size if Audit was enabled
			if (AllowMicrosoftAudit)
			{
				// Convert the value to ulong
				logSize = Convert.ToUInt64(EventLogsUtil.MaxSizeMB);
			}
			#endregion

			// Run background work using captured values
			_policyPathAllowMicrosoft = await Task.Run(() =>
			{
				return BasePolicyCreator.BuildAllowMSFT(
				StagingArea: stagingArea,
				IsAudit: AllowMicrosoftAudit,
				LogSize: logSize,
				deploy: AllowMicrosoftCreateAndDeploy,
				RequireEVSigners: AllowMicrosoftRequireEVSigners,
				EnableScriptEnforcement: AllowMicrosoftEnableScriptEnforcement,
				TestMode: AllowMicrosoftTestMode,
				deployAppControlSupplementalPolicy: AllowMicrosoftCreateAndDeploy,
				PolicyIDToUse: null,
				DeployMicrosoftRecommendedBlockRules: !AllowMicrosoftNoBlockRules
				);
			});
		}
		catch (Exception ex)
		{
			Error = true;
			AllowMSFTInfoBar.WriteError(ex);
		}
		finally
		{
			// Re-enable the buttons once the work is done
			AllowMicrosoftSectionIsEnabled = true;

			AllowMicrosoftSettingsInfoBarIsClosable = true;

			if (!Error)
			{
				AllowMicrosoftInfoBarActionButtonVisibility = Visibility.Visible;

				AllowMSFTInfoBar.WriteSuccess(AllowMicrosoftCreateAndDeploy ? GlobalVars.Rizz.GetString("SuccessfullyCreatedAndDeployedAllowMicrosoftBasePolicy") : GlobalVars.Rizz.GetString("SuccessfullyCreatedAllowMicrosoftBasePolicy"));
			}
		}
	}

	/// <summary>
	/// Event handler to open the created Allow Microsoft policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor_AllowMicrosoft()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_policyPathAllowMicrosoft);
	}

	#endregion

	#region Default Windows

	internal bool DefaultWindowsSectionIsEnabled
	{
		get;
		set
		{
			_ = SP(ref field, value);
			DefaultWindowsLogSizeInputIsEnabled = field && DefaultWindowsAudit;
		}
	} = true;

	internal Visibility DefaultWindowsInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal string? _policyPathDefaultWindows { get; set => SP(ref field, value); }

	internal bool DefaultWindowsSettingsInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool DefaultWindowsSettingsInfoBarIsClosable { get; set => SP(ref field, value); }
	internal InfoBarSeverity DefaultWindowsSettingsInfoBarSeverity { get; set => SP(ref field, value); }
	internal string? DefaultWindowsSettingsInfoBarMessage { get; set => SP(ref field, value); }
	internal bool DefaultWindowsSettingsIsExpanded { get; set => SP(ref field, value); }

	private readonly InfoBarSettings DefaultWinInfoBar;

	internal bool DefaultWindowsLogSizeInputIsEnabled { get; set => SP(ref field, value); }

	internal bool DefaultWindowsAudit
	{
		get;
		set
		{
			_ = SP(ref field, value);
			DefaultWindowsLogSizeInputIsEnabled = field;
		}
	}

	internal bool DefaultWindowsRequireEVSigners { get; set => SP(ref field, value); }
	internal bool DefaultWindowsEnableScriptEnforcement { get; set => SP(ref field, value); }
	internal bool DefaultWindowsTestMode { get; set => SP(ref field, value); }
	internal bool DefaultWindowsCreateAndDeploy { get; set => SP(ref field, value); }
	internal bool DefaultWindowsNoBlockRules { get; set => SP(ref field, value); }

	/// <summary>
	/// Event handler for creating/deploying DefaultWindows policy
	/// </summary>
	internal async void DefaultWindowsCreate_Click()
	{
		bool Error = false;

		DefaultWindowsInfoBarActionButtonVisibility = Visibility.Collapsed;

		try
		{
			DefaultWindowsSettingsInfoBarIsClosable = false;
			DefaultWinInfoBar.WriteInfo(GlobalVars.Rizz.GetString("CreatingDefaultWindowsBasePolicy"));

			DefaultWindowsSettingsIsExpanded = true;

			// Disable the buttons to prevent multiple clicks
			DefaultWindowsSectionIsEnabled = false;

			string stagingArea = StagingArea.NewStagingArea("BuildDefaultWindows").ToString();

			#region Only modify the log size if the element is enabled meaning the Toggle Switch is toggled
			ulong? logSize = null;

			if (DefaultWindowsAudit)
			{
				// Convert the value to ulong
				logSize = Convert.ToUInt64(EventLogsUtil.MaxSizeMB);
			}
			#endregion

			// Run background work using captured values
			_policyPathDefaultWindows = await Task.Run(() =>
			{
				return BasePolicyCreator.BuildDefaultWindows(
				StagingArea: stagingArea,
				IsAudit: DefaultWindowsAudit,
				LogSize: logSize,
				deploy: DefaultWindowsCreateAndDeploy,
				RequireEVSigners: DefaultWindowsRequireEVSigners,
				EnableScriptEnforcement: DefaultWindowsEnableScriptEnforcement,
				TestMode: DefaultWindowsTestMode,
				deployAppControlSupplementalPolicy: DefaultWindowsCreateAndDeploy,
				PolicyIDToUse: null,
				DeployMicrosoftRecommendedBlockRules: !DefaultWindowsNoBlockRules
				);
			});

		}
		catch (Exception ex)
		{
			Error = true;
			DefaultWinInfoBar.WriteError(ex);
		}
		finally
		{
			// Re-enable the buttons once the work is done
			DefaultWindowsSectionIsEnabled = true;

			DefaultWindowsSettingsInfoBarIsClosable = true;

			if (!Error)
			{
				DefaultWindowsInfoBarActionButtonVisibility = Visibility.Visible;
				DefaultWinInfoBar.WriteSuccess(DefaultWindowsCreateAndDeploy ? GlobalVars.Rizz.GetString("SuccessfullyCreatedAndDeployedDefaultWindowsBasePolicy") : GlobalVars.Rizz.GetString("SuccessfullyCreatedDefaultWindowsBasePolicy"));
			}
		}
	}

	/// <summary>
	/// Event handler to open the created Default Windows policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor_DefaultWindows()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_policyPathDefaultWindows);
	}

	#endregion

	#region Signed and Reputable

	internal bool SignedAndReputableSectionIsEnabled
	{
		get;
		set
		{
			_ = SP(ref field, value);
			SignedAndReputableLogSizeInputIsEnabled = field && SignedAndReputableAudit;
		}
	} = true;

	internal Visibility SignedAndReputableInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal string? _policyPathSignedAndReputable { get; set => SP(ref field, value); }

	internal bool SignedAndReputableSettingsInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool SignedAndReputableSettingsInfoBarIsClosable { get; set => SP(ref field, value); }
	internal InfoBarSeverity SignedAndReputableSettingsInfoBarSeverity { get; set => SP(ref field, value); }
	internal string? SignedAndReputableSettingsInfoBarMessage { get; set => SP(ref field, value); }
	internal bool SignedAndReputableSettingsIsExpanded { get; set => SP(ref field, value); }

	private readonly InfoBarSettings SignedAndRepInfoBar;

	internal bool SignedAndReputableLogSizeInputIsEnabled { get; set => SP(ref field, value); }

	internal bool SignedAndReputableAudit
	{
		get;
		set
		{
			_ = SP(ref field, value);
			SignedAndReputableLogSizeInputIsEnabled = field;
		}
	}

	internal bool SignedAndReputableRequireEVSigners { get; set => SP(ref field, value); }
	internal bool SignedAndReputableEnableScriptEnforcement { get; set => SP(ref field, value); }
	internal bool SignedAndReputableTestMode { get; set => SP(ref field, value); }
	internal bool SignedAndReputableCreateAndDeploy { get; set => SP(ref field, value); }
	internal bool SignedAndReputableNoBlockRules { get; set => SP(ref field, value); }

	/// <summary>
	/// Event handler for creating/deploying SignedAndReputable policy
	/// </summary>
	internal async void SignedAndReputableCreate_Click()
	{
		bool Error = false;

		SignedAndReputableInfoBarActionButtonVisibility = Visibility.Collapsed;

		try
		{
			SignedAndReputableSettingsInfoBarIsClosable = false;
			SignedAndRepInfoBar.WriteInfo(GlobalVars.Rizz.GetString("CreatingSignedAndReputableBasePolicy"));

			SignedAndReputableSettingsIsExpanded = true;

			// Disable the buttons
			SignedAndReputableSectionIsEnabled = false;

			string stagingArea = StagingArea.NewStagingArea("BuildSignedAndReputable").ToString();

			#region Only modify the log size if the element is enabled meaning the Toggle Switch is toggled
			ulong? logSize = null;

			if (SignedAndReputableAudit)
			{
				// Convert the value to ulong
				logSize = Convert.ToUInt64(EventLogsUtil.MaxSizeMB);
			}
			#endregion

			_policyPathSignedAndReputable = await Task.Run(() =>
			{
				return BasePolicyCreator.BuildSignedAndReputable(
				StagingArea: stagingArea,
				IsAudit: SignedAndReputableAudit,
				LogSize: logSize,
				deploy: SignedAndReputableCreateAndDeploy,
				RequireEVSigners: SignedAndReputableRequireEVSigners,
				EnableScriptEnforcement: SignedAndReputableEnableScriptEnforcement,
				TestMode: SignedAndReputableTestMode,
				deployAppControlSupplementalPolicy: SignedAndReputableCreateAndDeploy,
				PolicyIDToUse: null,
				DeployMicrosoftRecommendedBlockRules: !SignedAndReputableNoBlockRules
				);
			});
		}
		catch (Exception ex)
		{
			Error = true;
			SignedAndRepInfoBar.WriteError(ex);
		}
		finally
		{
			SignedAndReputableSectionIsEnabled = true;

			SignedAndReputableSettingsInfoBarIsClosable = true;

			if (!Error)
			{
				SignedAndReputableInfoBarActionButtonVisibility = Visibility.Visible;
				SignedAndRepInfoBar.WriteSuccess(SignedAndReputableCreateAndDeploy ? GlobalVars.Rizz.GetString("SuccessfullyCreatedAndDeployedSignedAndReputableBasePolicy") : GlobalVars.Rizz.GetString("SuccessfullyCreatedSignedAndReputableBasePolicy"));
			}
		}
	}

	/// <summary>
	/// Event handler to open the created Signed and Reputable policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor_SignedAndReputable()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_policyPathSignedAndReputable);
	}

	#endregion

	#region Microsoft Recommended Drivers Block Rule

	internal string? _policyPathMSFTRecommendedDriverBlockRules { get; set => SP(ref field, value); }

	internal bool RecommendedDriverBlockRulesSectionIsEnabled { get; set => SP(ref field, value); } = true;

	internal Visibility RecommendedDriverBlockRulesInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal string? _policyPathRecommendedDriverBlockRules { get; set => SP(ref field, value); }

	internal bool RecommendedDriverBlockRulesSettingsInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool RecommendedDriverBlockRulesSettingsInfoBarIsClosable { get; set => SP(ref field, value); }
	internal InfoBarSeverity RecommendedDriverBlockRulesSettingsInfoBarSeverity { get; set => SP(ref field, value); }
	internal string? RecommendedDriverBlockRulesSettingsInfoBarMessage { get; set => SP(ref field, value); }
	internal bool RecommendedDriverBlockRulesSettingsIsExpanded { get; set => SP(ref field, value); }

	private readonly InfoBarSettings KernelModeBlockListInfoBar;

	internal bool RecommendedDriverBlockRulesCreateAndDeploy { get; set => SP(ref field, value); }

	internal string? RecommendedDriverBlockRulesVersionTextBlock { get; set => SP(ref field, value); } = "N/A";

	/// <summary>
	/// Event handler for creating/deploying Microsoft recommended driver block rules policy
	/// </summary>
	internal async void RecommendedDriverBlockRulesCreate_Click()
	{
		bool error = false;

		RecommendedDriverBlockRulesSettingsIsExpanded = true;

		RecommendedDriverBlockRulesVersionTextBlock = "N/A";

		try
		{
			// Disable the buttons
			RecommendedDriverBlockRulesSectionIsEnabled = false;

			RecommendedDriverBlockRulesInfoBarActionButtonVisibility = Visibility.Collapsed;
			RecommendedDriverBlockRulesSettingsInfoBarIsClosable = false;
			KernelModeBlockListInfoBar.WriteInfo(GlobalVars.Rizz.GetString("CreatingRecommendedDriverBlockRulesPolicy"));

			string stagingArea = StagingArea.NewStagingArea("BuildRecommendedDriverBlockRules").ToString();

			(string?, string?) results = (null, null);

			await Task.Run(() =>
			{
				if (RecommendedDriverBlockRulesCreateAndDeploy)
				{
					results = BasePolicyCreator.DeployDriversBlockRules(stagingArea);
				}
				else
				{
					results = BasePolicyCreator.GetDriversBlockRules(stagingArea);

					_policyPathMSFTRecommendedDriverBlockRules = results.Item1;
				}
			});

			RecommendedDriverBlockRulesVersionTextBlock = results.Item2;
		}
		catch (Exception ex)
		{
			error = true;
			KernelModeBlockListInfoBar.WriteError(ex);
		}
		finally
		{
			RecommendedDriverBlockRulesSectionIsEnabled = true;

			RecommendedDriverBlockRulesSettingsInfoBarIsClosable = true;

			if (!error)
			{
				KernelModeBlockListInfoBar.WriteSuccess(GlobalVars.Rizz.GetString("SuccessfullyCreatedRecommendedDriverBlockRulesPolicy"));

				if (!RecommendedDriverBlockRulesCreateAndDeploy)
				{
					RecommendedDriverBlockRulesInfoBarActionButtonVisibility = Visibility.Visible;
				}
			}
		}
	}

	/// <summary>
	/// Event handler for Auto Update button
	/// </summary>
	internal async void RecommendedDriverBlockRulesScheduledAutoUpdate_Click()
	{
		bool errorsOccurred = false;

		try
		{
			RecommendedDriverBlockRulesSectionIsEnabled = false;

			RecommendedDriverBlockRulesInfoBarActionButtonVisibility = Visibility.Collapsed;

			// Expand the settings card to make the InfoBar visible
			RecommendedDriverBlockRulesSettingsIsExpanded = true;

			RecommendedDriverBlockRulesSettingsInfoBarIsClosable = false;
			KernelModeBlockListInfoBar.WriteInfo(GlobalVars.Rizz.GetString("ConfiguringAutoUpdate"));

			await Task.Run(BasePolicyCreator.SetAutoUpdateDriverBlockRules);
		}
		catch (Exception ex)
		{
			errorsOccurred = true;
			KernelModeBlockListInfoBar.WriteError(ex, GlobalVars.Rizz.GetString("AutoUpdateError"));
		}
		finally
		{
			RecommendedDriverBlockRulesSectionIsEnabled = true;
			RecommendedDriverBlockRulesSettingsInfoBarIsClosable = true;

			if (!errorsOccurred)
			{
				KernelModeBlockListInfoBar.WriteSuccess(GlobalVars.Rizz.GetString("AutoUpdateConfigured"));
			}
		}
	}

	/// <summary>
	/// Event handler to open the created Microsoft Recommended driver block rules policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor_RecommendedDriverBlockRules()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_policyPathMSFTRecommendedDriverBlockRules);
	}

	#endregion

	#region Microsoft Recommended Block Rule

	internal string? _policyPathRecommendedUserModeBlockRules { get; set => SP(ref field, value); }

	internal bool RecommendedUserModeBlockRulesSectionIsEnabled { get; set => SP(ref field, value); } = true;

	internal bool RecommendedUserModeBlockRulesCreateAndDeploy { get; set => SP(ref field, value); }

	internal Visibility RecommendedUserModeBlockRulesInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool RecommendedUserModeBlockRulesSettingsInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool RecommendedUserModeBlockRulesSettingsInfoBarIsClosable { get; set => SP(ref field, value); }
	internal InfoBarSeverity RecommendedUserModeBlockRulesSettingsInfoBarSeverity { get; set => SP(ref field, value); }
	internal string? RecommendedUserModeBlockRulesSettingsInfoBarMessage { get; set => SP(ref field, value); }
	internal bool RecommendedUserModeBlockRulesSettingsIsExpanded { get; set => SP(ref field, value); }

	private readonly InfoBarSettings UserModeBlockListInfoBar;

	/// <summary>
	/// Event handler for creating/deploying Microsoft recommended user-mode block rules policy
	/// </summary>
	internal async void RecommendedUserModeBlockRulesCreate_Click()
	{
		bool error = false;

		try
		{
			RecommendedUserModeBlockRulesInfoBarActionButtonVisibility = Visibility.Collapsed;

			_policyPathRecommendedUserModeBlockRules = null;

			// Disable the buttons
			RecommendedUserModeBlockRulesSectionIsEnabled = false;

			RecommendedUserModeBlockRulesSettingsIsExpanded = true;

			RecommendedUserModeBlockRulesSettingsInfoBarIsClosable = false;

			UserModeBlockListInfoBar.WriteInfo(GlobalVars.Rizz.GetString("CreatingUserModeBlockRules"));

			string stagingArea = StagingArea.NewStagingArea("BuildRecommendedUserModeBlockRules").ToString();

			await Task.Run(() =>
			{
				_policyPathRecommendedUserModeBlockRules = BasePolicyCreator.GetBlockRules(stagingArea, RecommendedUserModeBlockRulesCreateAndDeploy);
			});
		}
		catch (Exception ex)
		{
			error = true;
			UserModeBlockListInfoBar.WriteError(ex);
		}
		finally
		{
			RecommendedUserModeBlockRulesSettingsInfoBarIsClosable = true;

			// Re-enable buttons
			RecommendedUserModeBlockRulesSectionIsEnabled = true;

			if (!error)
			{
				RecommendedUserModeBlockRulesInfoBarActionButtonVisibility = Visibility.Visible;
				UserModeBlockListInfoBar.WriteSuccess(GlobalVars.Rizz.GetString("SuccessfullyCreatedUserModeBlockRules"));
			}
		}
	}

	/// <summary>
	/// Event handler to open the created Microsoft Recommended User Mode block rules policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor_RecommendedUserModeBlockRules()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_policyPathRecommendedUserModeBlockRules);
	}

	#endregion

	#region Strict Kernel Mode

	internal Visibility StrictKernelModeInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal string? _policyPathStrictKernelMode { get; set => SP(ref field, value); }

	internal bool StrictKernelModeSectionIsEnabled { get; set => SP(ref field, value); } = true;

	internal bool StrictKernelModesCreateAndDeploy { get; set => SP(ref field, value); }

	internal bool StrictKernelModesAudit { get; set => SP(ref field, value); }
	internal bool StrictKernelModeNoFlightRoots { get; set => SP(ref field, value); }

	internal bool StrictKernelModesSettingsInfoBarIsOpen { get; set => SP(ref field, value); }
	internal bool StrictKernelModesSettingsInfoBarIsClosable { get; set => SP(ref field, value); }
	internal InfoBarSeverity StrictKernelModesSettingsInfoBarSeverity { get; set => SP(ref field, value); }
	internal string? StrictKernelModesSettingsInfoBarMessage { get; set => SP(ref field, value); }
	internal bool StrictKernelModesSettingsIsExpanded { get; set => SP(ref field, value); }

	private readonly InfoBarSettings StrictKernelInfoBar;

	/// <summary>
	/// Event handler to prepare the system for Strict Kernel-mode policy
	/// </summary>
	internal async void StrictKernelModePolicyCreateButton_Click()
	{
		bool errorsOccurred = false;

		try
		{
			StrictKernelModesSettingsIsExpanded = true;

			StrictKernelModeInfoBarActionButtonVisibility = Visibility.Collapsed;

			StrictKernelModeSectionIsEnabled = false;
			StrictKernelModesSettingsInfoBarIsClosable = false;

			StrictKernelInfoBar.WriteInfo(GlobalVars.Rizz.GetString("CreatingPolicy"));

			_policyPathStrictKernelMode = await Task.Run(() =>
			{
				DirectoryInfo stagingArea = StagingArea.NewStagingArea("Strict Kernel-Mode policy Prepare");

				return BasePolicyCreator.BuildStrictKernelMode(stagingArea.FullName, StrictKernelModesAudit, StrictKernelModeNoFlightRoots, StrictKernelModesCreateAndDeploy);
			});
		}
		catch (Exception ex)
		{
			errorsOccurred = true;
			StrictKernelInfoBar.WriteError(ex, GlobalVars.Rizz.GetString("PolicyCreationError"));
		}
		finally
		{
			if (!errorsOccurred)
			{
				StrictKernelModeInfoBarActionButtonVisibility = Visibility.Visible;

				StrictKernelInfoBar.WriteSuccess(GlobalVars.Rizz.GetString("PolicyCreatedSuccessfully"));
			}

			StrictKernelModesSettingsInfoBarIsClosable = true;
			StrictKernelModeSectionIsEnabled = true;
		}
	}

	/// <summary>
	/// Event handler to open the created Strict Kernel-mode policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor_StrictKernelModePolicy()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_policyPathStrictKernelMode);
	}

	#endregion

}
