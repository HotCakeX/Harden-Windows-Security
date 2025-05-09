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

			AllowMicrosoftSettingsInfoBarIsOpen = true;
			AllowMicrosoftSettingsInfoBarIsClosable = false;
			AllowMicrosoftSettingsInfoBarSeverity = InfoBarSeverity.Informational;
			AllowMicrosoftSettingsInfoBarMessage = "Creating the Allow Microsoft base policy";
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
		catch
		{
			Error = true;
			throw;
		}
		finally
		{
			// Re-enable the buttons once the work is done
			AllowMicrosoftSectionIsEnabled = true;

			AllowMicrosoftSettingsInfoBarIsClosable = true;

			AllowMicrosoftInfoBarActionButtonVisibility = Visibility.Visible;

			if (!Error)
			{
				AllowMicrosoftSettingsInfoBarSeverity = InfoBarSeverity.Success;
				AllowMicrosoftSettingsInfoBarMessage = AllowMicrosoftCreateAndDeploy ? "Successfully created and deployed the Allow Microsoft base policy" : "Successfully created the Allow Microsoft base policy";
			}
			else
			{
				AllowMicrosoftSettingsInfoBarSeverity = InfoBarSeverity.Error;
				AllowMicrosoftSettingsInfoBarMessage = "There was an error while creating the Allow Microsoft base policy";
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
			DefaultWindowsSettingsInfoBarIsOpen = true;
			DefaultWindowsSettingsInfoBarIsClosable = false;
			DefaultWindowsSettingsInfoBarSeverity = InfoBarSeverity.Informational;
			DefaultWindowsSettingsInfoBarMessage = "Creating the Default Windows base policy";
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
		catch
		{
			Error = true;
			throw;
		}
		finally
		{
			// Re-enable the buttons once the work is done
			DefaultWindowsSectionIsEnabled = true;

			DefaultWindowsInfoBarActionButtonVisibility = Visibility.Visible;

			DefaultWindowsSettingsInfoBarIsClosable = true;

			if (!Error)
			{
				DefaultWindowsSettingsInfoBarSeverity = InfoBarSeverity.Success;
				DefaultWindowsSettingsInfoBarMessage = DefaultWindowsCreateAndDeploy ? "Successfully created and deployed the Default Windows base policy" : "Successfully created the Default Windows base policy";
			}
			else
			{
				DefaultWindowsSettingsInfoBarSeverity = InfoBarSeverity.Error;
				DefaultWindowsSettingsInfoBarMessage = "There was an error while creating the Default Windows base policy";
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
			SignedAndReputableSettingsInfoBarIsOpen = true;
			SignedAndReputableSettingsInfoBarIsClosable = false;
			SignedAndReputableSettingsInfoBarSeverity = InfoBarSeverity.Informational;
			SignedAndReputableSettingsInfoBarMessage = "Creating the Signed and Reputable base policy";
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
		catch
		{
			Error = true;
			throw;
		}
		finally
		{
			SignedAndReputableSectionIsEnabled = true;

			SignedAndReputableSettingsInfoBarIsClosable = true;

			SignedAndReputableInfoBarActionButtonVisibility = Visibility.Visible;

			if (!Error)
			{
				SignedAndReputableSettingsInfoBarSeverity = InfoBarSeverity.Success;
				SignedAndReputableSettingsInfoBarMessage = SignedAndReputableCreateAndDeploy ? "Successfully created and deployed the Signed and Reputable base policy" : "Successfully created the Signed and Reputable base policy";
			}
			else
			{
				SignedAndReputableSettingsInfoBarSeverity = InfoBarSeverity.Error;
				SignedAndReputableSettingsInfoBarMessage = "There was an error while creating the Signed and Reputable base policy";
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
			RecommendedDriverBlockRulesSettingsInfoBarIsOpen = true;
			RecommendedDriverBlockRulesSettingsInfoBarSeverity = InfoBarSeverity.Informational;
			RecommendedDriverBlockRulesSettingsInfoBarMessage = "Creating the Microsoft Recommended Driver Block Rules policy";

			string stagingArea = StagingArea.NewStagingArea("BuildRecommendedDriverBlockRules").ToString();

			(string?, string?) results = (null, null);

			// Run the background operation using captured values
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

			RecommendedDriverBlockRulesSettingsInfoBarIsClosable = true;
			RecommendedDriverBlockRulesSettingsInfoBarIsOpen = true;
			RecommendedDriverBlockRulesSettingsInfoBarSeverity = InfoBarSeverity.Error;
			RecommendedDriverBlockRulesSettingsInfoBarMessage = $"There was a problem creating the Microsoft Recommended Driver Block Rules policy: {ex.Message}";

			throw;
		}
		finally
		{
			if (!error)
			{
				RecommendedDriverBlockRulesSettingsInfoBarIsClosable = true;
				RecommendedDriverBlockRulesSettingsInfoBarIsOpen = true;
				RecommendedDriverBlockRulesSettingsInfoBarSeverity = InfoBarSeverity.Success;
				RecommendedDriverBlockRulesSettingsInfoBarMessage = "Successfully created the Microsoft Recommended Driver Block Rules policy";
			}

			// Re-enable buttons
			RecommendedDriverBlockRulesSectionIsEnabled = true;

			if (!RecommendedDriverBlockRulesCreateAndDeploy && !error)
			{
				RecommendedDriverBlockRulesInfoBarActionButtonVisibility = Visibility.Visible;
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

			RecommendedDriverBlockRulesSettingsInfoBarIsClosable = false;
			RecommendedDriverBlockRulesSettingsInfoBarIsOpen = true;
			RecommendedDriverBlockRulesSettingsInfoBarSeverity = InfoBarSeverity.Informational;
			RecommendedDriverBlockRulesSettingsInfoBarMessage = GlobalVars.Rizz.GetString("ConfiguringAutoUpdate");

			await Task.Run(BasePolicyCreator.SetAutoUpdateDriverBlockRules);
		}
		catch
		{
			errorsOccurred = true;
			throw;
		}
		finally
		{
			RecommendedDriverBlockRulesSettingsInfoBarIsClosable = true;

			// Expand the settings card to make the InfoBar visible
			RecommendedDriverBlockRulesSettingsIsExpanded = true;

			if (errorsOccurred)
			{
				RecommendedDriverBlockRulesSettingsInfoBarSeverity = InfoBarSeverity.Error;
				RecommendedDriverBlockRulesSettingsInfoBarMessage = GlobalVars.Rizz.GetString("AutoUpdateError");
			}
			else
			{
				RecommendedDriverBlockRulesSettingsInfoBarSeverity = InfoBarSeverity.Success;
				RecommendedDriverBlockRulesSettingsInfoBarMessage = GlobalVars.Rizz.GetString("AutoUpdateConfigured");
			}

			RecommendedDriverBlockRulesSectionIsEnabled = true;
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

	internal bool RecommendedUserModeBlockRulesSectionIsEnabled { get; set => SP(ref field, value); } = true;

	internal bool RecommendedUserModeBlockRulesCreateAndDeploy { get; set => SP(ref field, value); }

	/// <summary>
	/// Event handler for creating/deploying Microsoft recommended user-mode block rules policy
	/// </summary>
	internal async void RecommendedUserModeBlockRulesCreate_Click()
	{
		try
		{
			// Disable the buttons
			RecommendedUserModeBlockRulesSectionIsEnabled = false;

			string stagingArea = StagingArea.NewStagingArea("BuildRecommendedUserModeBlockRules").ToString();

			// Run the background operation using captured values
			await Task.Run(() =>
			{
				BasePolicyCreator.GetBlockRules(stagingArea, RecommendedUserModeBlockRulesCreateAndDeploy);
			});
		}
		finally
		{
			// Re-enable buttons
			RecommendedUserModeBlockRulesSectionIsEnabled = true;
		}
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

	/// <summary>
	/// Event handler to prepare the system for Strict Kernel-mode policy
	/// </summary>
	internal async void StrictKernelModePolicyCreateButton_Click()
	{
		StrictKernelModeSectionIsEnabled = false;
		StrictKernelModesSettingsInfoBarIsClosable = false;
		StrictKernelModesSettingsInfoBarIsOpen = true;
		StrictKernelModesSettingsIsExpanded = true;

		StrictKernelModeInfoBarActionButtonVisibility = Visibility.Collapsed;

		bool errorsOccurred = false;

		try
		{
			StrictKernelModesSettingsInfoBarMessage = GlobalVars.Rizz.GetString("CreatingPolicy");
			Logger.Write(GlobalVars.Rizz.GetString("CreatingPolicy"));
			StrictKernelModesSettingsInfoBarSeverity = InfoBarSeverity.Informational;

			_policyPathStrictKernelMode = await Task.Run(() =>
			{
				DirectoryInfo stagingArea = StagingArea.NewStagingArea("Strict Kernel-Mode policy Prepare");

				return BasePolicyCreator.BuildStrictKernelMode(stagingArea.FullName, StrictKernelModesAudit, StrictKernelModeNoFlightRoots, StrictKernelModesCreateAndDeploy);
			});
		}
		catch (Exception ex)
		{
			StrictKernelModesSettingsInfoBarSeverity = InfoBarSeverity.Error;

			StrictKernelModesSettingsInfoBarMessage = GlobalVars.Rizz.GetString("PolicyCreationError") + ex.Message;

			errorsOccurred = true;

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				StrictKernelModesSettingsInfoBarSeverity = InfoBarSeverity.Success;
				StrictKernelModesSettingsInfoBarMessage = GlobalVars.Rizz.GetString("PolicyCreatedSuccessfully");
				Logger.Write(GlobalVars.Rizz.GetString("PolicyCreatedSuccessfully"));
			}

			StrictKernelModesSettingsInfoBarIsClosable = true;
			StrictKernelModeSectionIsEnabled = true;

			StrictKernelModeInfoBarActionButtonVisibility = Visibility.Visible;
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
