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

using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.Pages;
using AppControlManager.SiPolicy;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

internal sealed partial class CreatePolicyVM : ViewModelBase
{
	private ConfigurePolicyRuleOptionsVM ConfigurePolicyRuleOptionsViewModel => ViewModelProvider.ConfigurePolicyRuleOptionsVM;
	internal EventLogUtility EventLogsUtil => ViewModelProvider.EventLogUtility;

	#region Allow Microsoft

	internal bool AllowMicrosoftSectionIsEnabled
	{
		get; set
		{
			_ = SP(ref field, value);
			AllowMicrosoftLogSizeInputIsEnabled = field && AllowMicrosoftAudit;
		}
	} = true;

	internal Visibility AllowMicrosoftInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool AllowMicrosoftSettingsIsExpanded { get; set => SP(ref field, value); }

	internal readonly InfoBarSettings AllowMSFTInfoBar = new();

	internal SiPolicy.PolicyFileRepresent? _policyPathAllowMicrosoft { get; set => SP(ref field, value); }
	internal bool AllowMicrosoftLogSizeInputIsEnabled { get; set => SP(ref field, value); }

	internal bool AllowMicrosoftAudit
	{
		get; set
		{
			_ = SP(ref field, value);
			AllowMicrosoftLogSizeInputIsEnabled = field;
		}
	}

	internal bool AllowMicrosoftAppIDTaggingToggle { get; set => SP(ref field, value); }
	internal bool AllowMicrosoftRequireEVSigners { get; set => SP(ref field, value); }
	internal bool AllowMicrosoftEnableScriptEnforcement { get; set => SP(ref field, value); } = true;
	internal bool AllowMicrosoftTestMode { get; set => SP(ref field, value); }
	internal bool AllowMicrosoftCreateAndDeploy { get; set => SP(ref field, value); }
	internal bool AllowMicrosoftNoBlockRules { get; set => SP(ref field, value); }

	/// <summary>
	/// Event handler for creating/deploying AllowMicrosoft policy
	/// </summary>
	internal async void AllowMicrosoftCreate_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{
		try
		{
			AllowMicrosoftInfoBarActionButtonVisibility = Visibility.Collapsed;

			AllowMSFTInfoBar.IsClosable = false;
			AllowMSFTInfoBar.WriteInfo(Atlas.GetStr("CreatingAllowMicrosoftBasePolicy"));

			AllowMicrosoftSettingsIsExpanded = true;

			// Disable the buttons to prevent multiple clicks
			AllowMicrosoftSectionIsEnabled = false;

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
				IsAudit: AllowMicrosoftAudit,
				LogSize: logSize,
				deploy: AllowMicrosoftCreateAndDeploy,
				RequireEVSigners: AllowMicrosoftRequireEVSigners,
				EnableScriptEnforcement: AllowMicrosoftEnableScriptEnforcement,
				TestMode: AllowMicrosoftTestMode,
				deployAppControlSupplementalPolicy: AllowMicrosoftCreateAndDeploy,
				PolicyIDToUse: null,
				DeployMicrosoftRecommendedBlockRules: !AllowMicrosoftNoBlockRules,
				IsAppIDTagging: AllowMicrosoftAppIDTaggingToggle
				);
			});

			// Assign the created policy to the Sidebar
			ViewModelProvider.MainWindowVM.AssignToSidebar(_policyPathAllowMicrosoft);

			AppControlManager.MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

			AllowMicrosoftInfoBarActionButtonVisibility = Visibility.Visible;
			AllowMSFTInfoBar.WriteSuccess(AllowMicrosoftCreateAndDeploy ? Atlas.GetStr("SuccessfullyCreatedAndDeployedAllowMicrosoftBasePolicy") : Atlas.GetStr("SuccessfullyCreatedAllowMicrosoftBasePolicy"));
		}
		catch (Exception ex)
		{
			AllowMSFTInfoBar.WriteError(ex);
		}
		finally
		{
			// Re-enable the buttons once the work is done
			AllowMicrosoftSectionIsEnabled = true;
			AllowMSFTInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Event handler to open the created Allow Microsoft policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor_AllowMicrosoft() => await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(_policyPathAllowMicrosoft);

	internal async void OpenInDefaultFileHandler_AllowMicrosoft() => await PolicyFileRepresent.OpenInDefaultFileHandler(_policyPathAllowMicrosoft);

	internal async void OpenInConfigurePolicyRuleOptions_AllowMicrosoft() => await ConfigurePolicyRuleOptionsViewModel.OpenInConfigurePolicyRuleOptions(_policyPathAllowMicrosoft);

	#endregion

	#region Default Windows

	internal bool DefaultWindowsSectionIsEnabled
	{
		get; set
		{
			_ = SP(ref field, value);
			DefaultWindowsLogSizeInputIsEnabled = field && DefaultWindowsAudit;
		}
	} = true;

	internal Visibility DefaultWindowsInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal SiPolicy.PolicyFileRepresent? _policyPathDefaultWindows { get; set => SP(ref field, value); }

	internal bool DefaultWindowsSettingsIsExpanded { get; set => SP(ref field, value); }

	internal readonly InfoBarSettings DefaultWinInfoBar = new();

	internal bool DefaultWindowsLogSizeInputIsEnabled { get; set => SP(ref field, value); }

	internal bool DefaultWindowsAudit
	{
		get; set
		{
			_ = SP(ref field, value);
			DefaultWindowsLogSizeInputIsEnabled = field;
		}
	}

	internal bool DefaultWindowsAppIDTaggingToggle { get; set => SP(ref field, value); }
	internal bool DefaultWindowsRequireEVSigners { get; set => SP(ref field, value); }
	internal bool DefaultWindowsEnableScriptEnforcement { get; set => SP(ref field, value); } = true;
	internal bool DefaultWindowsTestMode { get; set => SP(ref field, value); }
	internal bool DefaultWindowsCreateAndDeploy { get; set => SP(ref field, value); }
	internal bool DefaultWindowsNoBlockRules { get; set => SP(ref field, value); }

	/// <summary>
	/// Event handler for creating/deploying DefaultWindows policy
	/// </summary>
	internal async void DefaultWindowsCreate_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{
		DefaultWindowsInfoBarActionButtonVisibility = Visibility.Collapsed;

		try
		{
			DefaultWinInfoBar.IsClosable = false;
			DefaultWinInfoBar.WriteInfo(Atlas.GetStr("CreatingDefaultWindowsBasePolicy"));

			DefaultWindowsSettingsIsExpanded = true;

			// Disable the buttons to prevent multiple clicks
			DefaultWindowsSectionIsEnabled = false;

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
				IsAudit: DefaultWindowsAudit,
				LogSize: logSize,
				deploy: DefaultWindowsCreateAndDeploy,
				RequireEVSigners: DefaultWindowsRequireEVSigners,
				EnableScriptEnforcement: DefaultWindowsEnableScriptEnforcement,
				TestMode: DefaultWindowsTestMode,
				deployAppControlSupplementalPolicy: DefaultWindowsCreateAndDeploy,
				PolicyIDToUse: null,
				DeployMicrosoftRecommendedBlockRules: !DefaultWindowsNoBlockRules,
				IsAppIDTagging: DefaultWindowsAppIDTaggingToggle
				);
			});

			// Assign the created policy to the Sidebar
			ViewModelProvider.MainWindowVM.AssignToSidebar(_policyPathDefaultWindows);

			AppControlManager.MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

			DefaultWindowsInfoBarActionButtonVisibility = Visibility.Visible;
			DefaultWinInfoBar.WriteSuccess(DefaultWindowsCreateAndDeploy ? Atlas.GetStr("SuccessfullyCreatedAndDeployedDefaultWindowsBasePolicy") : Atlas.GetStr("SuccessfullyCreatedDefaultWindowsBasePolicy"));
		}
		catch (Exception ex)
		{
			DefaultWinInfoBar.WriteError(ex);
		}
		finally
		{
			// Re-enable the buttons once the work is done
			DefaultWindowsSectionIsEnabled = true;
			DefaultWinInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Event handler to open the created Default Windows policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor_DefaultWindows() => await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(_policyPathDefaultWindows);

	internal async void OpenInDefaultFileHandler_DefaultWindows() => await PolicyFileRepresent.OpenInDefaultFileHandler(_policyPathDefaultWindows);

	internal async void OpenInConfigurePolicyRuleOptions_DefaultWindows() => await ConfigurePolicyRuleOptionsViewModel.OpenInConfigurePolicyRuleOptions(_policyPathDefaultWindows);

	#endregion

	#region Signed and Reputable

	internal bool SignedAndReputableSectionIsEnabled
	{
		get; set
		{
			_ = SP(ref field, value);
			SignedAndReputableLogSizeInputIsEnabled = field && SignedAndReputableAudit;
		}
	} = true;

	internal Visibility SignedAndReputableInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal SiPolicy.PolicyFileRepresent? _policyPathSignedAndReputable { get; set => SP(ref field, value); }

	internal bool SignedAndReputableSettingsIsExpanded { get; set => SP(ref field, value); }

	internal readonly InfoBarSettings SignedAndRepInfoBar = new();

	internal bool SignedAndReputableLogSizeInputIsEnabled { get; set => SP(ref field, value); }

	internal bool SignedAndReputableAudit
	{
		get; set
		{
			_ = SP(ref field, value);
			SignedAndReputableLogSizeInputIsEnabled = field;
		}
	}

	internal bool SignedAndReputableRequireEVSigners { get; set => SP(ref field, value); }
	internal bool SignedAndReputableEnableScriptEnforcement { get; set => SP(ref field, value); } = true;
	internal bool SignedAndReputableTestMode { get; set => SP(ref field, value); }
	internal bool SignedAndReputableCreateAndDeploy { get; set => SP(ref field, value); }
	internal bool SignedAndReputableNoBlockRules { get; set => SP(ref field, value); }

	/// <summary>
	/// Event handler for creating/deploying SignedAndReputable policy
	/// </summary>
	internal async void SignedAndReputableCreate_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{
		SignedAndReputableInfoBarActionButtonVisibility = Visibility.Collapsed;

		try
		{
			SignedAndRepInfoBar.IsClosable = false;
			SignedAndRepInfoBar.WriteInfo(Atlas.GetStr("CreatingSignedAndReputableBasePolicy"));

			SignedAndReputableSettingsIsExpanded = true;

			// Disable the buttons
			SignedAndReputableSectionIsEnabled = false;

			#region Only modify the log size if the element is enabled meaning the Toggle Switch is toggled
			ulong? logSize = null;

			if (SignedAndReputableAudit)
			{
				// Convert the value to ulong
				logSize = Convert.ToUInt64(EventLogsUtil.MaxSizeMB);
			}
			#endregion

			_policyPathSignedAndReputable = await Task.Run(async () =>
			{
				return await BasePolicyCreator.BuildSignedAndReputable(
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

			// Assign the created policy to the Sidebar
			ViewModelProvider.MainWindowVM.AssignToSidebar(_policyPathSignedAndReputable);

			AppControlManager.MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

			SignedAndReputableInfoBarActionButtonVisibility = Visibility.Visible;
			SignedAndRepInfoBar.WriteSuccess(SignedAndReputableCreateAndDeploy ? Atlas.GetStr("SuccessfullyCreatedAndDeployedSignedAndReputableBasePolicy") : Atlas.GetStr("SuccessfullyCreatedSignedAndReputableBasePolicy"));
		}
		catch (Exception ex)
		{
			SignedAndRepInfoBar.WriteError(ex);
		}
		finally
		{
			SignedAndReputableSectionIsEnabled = true;
			SignedAndRepInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Event handler to open the created Signed and Reputable policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor_SignedAndReputable() => await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(_policyPathSignedAndReputable);

	internal async void OpenInDefaultFileHandler_SignedAndReputable() => await PolicyFileRepresent.OpenInDefaultFileHandler(_policyPathSignedAndReputable);

	internal async void OpenInConfigurePolicyRuleOptions_SignedAndReputable() => await ConfigurePolicyRuleOptionsViewModel.OpenInConfigurePolicyRuleOptions(_policyPathSignedAndReputable);

	#endregion

	#region Microsoft Recommended Drivers Block Rule

	internal SiPolicy.PolicyFileRepresent? _policyPathMSFTRecommendedDriverBlockRules { get; set => SP(ref field, value); }

	internal bool RecommendedDriverBlockRulesSectionIsEnabled { get; set => SP(ref field, value); } = true;

	internal Visibility RecommendedDriverBlockRulesInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool RecommendedDriverBlockRulesSettingsIsExpanded { get; set => SP(ref field, value); }

	internal readonly InfoBarSettings KernelModeBlockListInfoBar = new();

	internal bool RecommendedDriverBlockRulesCreateAndDeploy { get; set => SP(ref field, value); }

	/// <summary>
	/// Event handler for creating/deploying Microsoft recommended driver block rules policy
	/// </summary>
	internal async void RecommendedDriverBlockRulesCreate_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{
		RecommendedDriverBlockRulesSettingsIsExpanded = true;

		try
		{
			// Disable the buttons
			RecommendedDriverBlockRulesSectionIsEnabled = false;

			RecommendedDriverBlockRulesInfoBarActionButtonVisibility = Visibility.Collapsed;
			KernelModeBlockListInfoBar.IsClosable = false;
			KernelModeBlockListInfoBar.WriteInfo(Atlas.GetStr("CreatingRecommendedDriverBlockRulesPolicy"));

			_policyPathMSFTRecommendedDriverBlockRules = await Task.Run(() =>
			{
				if (RecommendedDriverBlockRulesCreateAndDeploy)
				{
					return BasePolicyCreator.DeployDriversBlockRules();
				}
				else
				{
					return BasePolicyCreator.GetDriversBlockRules();
				}
			});

			// Assign the created policy to the Sidebar
			ViewModelProvider.MainWindowVM.AssignToSidebar(_policyPathMSFTRecommendedDriverBlockRules);

			AppControlManager.MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

			KernelModeBlockListInfoBar.WriteSuccess(Atlas.GetStr("SuccessfullyCreatedRecommendedDriverBlockRulesPolicy"));

			if (!RecommendedDriverBlockRulesCreateAndDeploy)
			{
				RecommendedDriverBlockRulesInfoBarActionButtonVisibility = Visibility.Visible;
			}
		}
		catch (Exception ex)
		{
			KernelModeBlockListInfoBar.WriteError(ex);
		}
		finally
		{
			RecommendedDriverBlockRulesSectionIsEnabled = true;
			KernelModeBlockListInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Event handler for Auto Update button
	/// </summary>
	internal async void RecommendedDriverBlockRulesScheduledAutoUpdate_Click()
	{
		try
		{
			RecommendedDriverBlockRulesSectionIsEnabled = false;

			RecommendedDriverBlockRulesInfoBarActionButtonVisibility = Visibility.Collapsed;

			// Expand the settings card to make the InfoBar visible
			RecommendedDriverBlockRulesSettingsIsExpanded = true;

			KernelModeBlockListInfoBar.IsClosable = false;
			KernelModeBlockListInfoBar.WriteInfo(Atlas.GetStr("ConfiguringAutoUpdate"));

			await Task.Run(BasePolicyCreator.SetAutoUpdateDriverBlockRules);

			KernelModeBlockListInfoBar.WriteSuccess(Atlas.GetStr("AutoUpdateConfigured"));
		}
		catch (Exception ex)
		{
			KernelModeBlockListInfoBar.WriteError(ex, Atlas.GetStr("AutoUpdateError"));
		}
		finally
		{
			RecommendedDriverBlockRulesSectionIsEnabled = true;
			KernelModeBlockListInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Event handler to open the created Microsoft Recommended driver block rules policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor_RecommendedDriverBlockRules() => await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(_policyPathMSFTRecommendedDriverBlockRules);

	internal async void OpenInDefaultFileHandler_RecommendedDriverBlockRules() => await PolicyFileRepresent.OpenInDefaultFileHandler(_policyPathMSFTRecommendedDriverBlockRules);

	internal async void OpenInConfigurePolicyRuleOptions_RecommendedDriverBlockRules() => await ConfigurePolicyRuleOptionsViewModel.OpenInConfigurePolicyRuleOptions(_policyPathMSFTRecommendedDriverBlockRules);

	#endregion

	#region Microsoft Recommended Block Rule

	internal SiPolicy.PolicyFileRepresent? _policyPathRecommendedUserModeBlockRules { get; set => SP(ref field, value); }

	internal bool RecommendedUserModeBlockRulesSectionIsEnabled { get; set => SP(ref field, value); } = true;

	internal bool RecommendedUserModeBlockRulesCreateAndDeploy { get; set => SP(ref field, value); }

	internal Visibility RecommendedUserModeBlockRulesInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool RecommendedUserModeBlockRulesSettingsIsExpanded { get; set => SP(ref field, value); }

	internal readonly InfoBarSettings UserModeBlockListInfoBar = new();

	/// <summary>
	/// Event handler for creating/deploying Microsoft recommended user-mode block rules policy
	/// </summary>
	internal async void RecommendedUserModeBlockRulesCreate_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{
		try
		{
			RecommendedUserModeBlockRulesInfoBarActionButtonVisibility = Visibility.Collapsed;

			_policyPathRecommendedUserModeBlockRules = null;

			// Disable the buttons
			RecommendedUserModeBlockRulesSectionIsEnabled = false;

			RecommendedUserModeBlockRulesSettingsIsExpanded = true;

			UserModeBlockListInfoBar.IsClosable = false;

			UserModeBlockListInfoBar.WriteInfo(Atlas.GetStr("CreatingUserModeBlockRules"));

			_policyPathRecommendedUserModeBlockRules = await Task.Run(() =>
			{
				return BasePolicyCreator.GetBlockRules(RecommendedUserModeBlockRulesCreateAndDeploy);
			});

			// Assign the created policy to the Sidebar
			ViewModelProvider.MainWindowVM.AssignToSidebar(_policyPathRecommendedUserModeBlockRules);

			AppControlManager.MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

			RecommendedUserModeBlockRulesInfoBarActionButtonVisibility = Visibility.Visible;
			UserModeBlockListInfoBar.WriteSuccess(Atlas.GetStr("SuccessfullyCreatedUserModeBlockRules"));
		}
		catch (Exception ex)
		{
			UserModeBlockListInfoBar.WriteError(ex);
		}
		finally
		{
			UserModeBlockListInfoBar.IsClosable = true;

			// Re-enable buttons
			RecommendedUserModeBlockRulesSectionIsEnabled = true;
		}
	}

	/// <summary>
	/// Event handler to open the created Microsoft Recommended User Mode block rules policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor_RecommendedUserModeBlockRules() => await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(_policyPathRecommendedUserModeBlockRules);

	internal async void OpenInDefaultFileHandler_RecommendedUserModeBlockRules() => await PolicyFileRepresent.OpenInDefaultFileHandler(_policyPathRecommendedUserModeBlockRules);

	internal async void OpenInConfigurePolicyRuleOptions_RecommendedUserModeBlockRules() => await ConfigurePolicyRuleOptionsViewModel.OpenInConfigurePolicyRuleOptions(_policyPathRecommendedUserModeBlockRules);

	#endregion

	#region Strict Kernel Mode

	internal Visibility StrictKernelModeInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal SiPolicy.PolicyFileRepresent? _policyPathStrictKernelMode { get; set => SP(ref field, value); }

	internal bool StrictKernelModeSectionIsEnabled { get; set => SP(ref field, value); } = true;

	internal bool StrictKernelModesCreateAndDeploy { get; set => SP(ref field, value); }

	internal bool StrictKernelModesAudit { get; set => SP(ref field, value); } = true;
	internal bool StrictKernelModeNoFlightRoots { get; set => SP(ref field, value); }

	internal bool StrictKernelModesSettingsIsExpanded { get; set => SP(ref field, value); }

	internal readonly InfoBarSettings StrictKernelInfoBar = new();

	/// <summary>
	/// Event handler to prepare the system for Strict Kernel-mode policy
	/// </summary>
	internal async void StrictKernelModePolicyCreateButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{
		try
		{
			StrictKernelModesSettingsIsExpanded = true;

			StrictKernelModeInfoBarActionButtonVisibility = Visibility.Collapsed;

			StrictKernelModeSectionIsEnabled = false;
			StrictKernelInfoBar.IsClosable = false;

			StrictKernelInfoBar.WriteInfo(Atlas.GetStr("CreatingPolicy"));

			_policyPathStrictKernelMode = await Task.Run(() =>
			{
				return BasePolicyCreator.BuildStrictKernelMode(StrictKernelModesAudit, StrictKernelModeNoFlightRoots, StrictKernelModesCreateAndDeploy);
			});

			// Assign the created policy to the Sidebar
			ViewModelProvider.MainWindowVM.AssignToSidebar(_policyPathStrictKernelMode);

			AppControlManager.MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

			StrictKernelModeInfoBarActionButtonVisibility = Visibility.Visible;

			StrictKernelInfoBar.WriteSuccess(Atlas.GetStr("PolicyCreatedSuccessfully"));
		}
		catch (Exception ex)
		{
			StrictKernelInfoBar.WriteError(ex, Atlas.GetStr("PolicyCreationError"));
		}
		finally
		{
			StrictKernelInfoBar.IsClosable = true;
			StrictKernelModeSectionIsEnabled = true;
		}
	}

	/// <summary>
	/// Event handler to open the created Strict Kernel-mode policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor_StrictKernelModePolicy() => await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(_policyPathStrictKernelMode);

	internal async void OpenInDefaultFileHandler_StrictKernelModePolicy() => await PolicyFileRepresent.OpenInDefaultFileHandler(_policyPathStrictKernelMode);

	internal async void OpenInConfigurePolicyRuleOptions_StrictKernelModePolicy() => await ConfigurePolicyRuleOptionsViewModel.OpenInConfigurePolicyRuleOptions(_policyPathStrictKernelMode);

	#endregion

	#region RMM Blocking

	internal Visibility RMMBlockingInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal SiPolicy.PolicyFileRepresent? _policyPathRMMBlocking { get; set => SP(ref field, value); }

	internal bool RMMBlockingSectionIsEnabled { get; set => SP(ref field, value); } = true;

	internal bool RMMBlockingCreateAndDeploy { get; set => SP(ref field, value); }

	internal bool RMMBlockingAudit { get; set => SP(ref field, value); }

	internal bool RMMBlockingSettingsIsExpanded { get; set => SP(ref field, value); }

	internal readonly InfoBarSettings RMMBlockingInfoBar = new();

	/// <summary>
	/// Event handler to prepare the RMM Blocking policy
	/// </summary>
	internal async void RMMBlockingPolicyCreateButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) => await RMMBlockingPolicyCreateButton_Private(sender);


	private async Task RMMBlockingPolicyCreateButton_Private(object? sender)
	{
		try
		{
			RMMBlockingSettingsIsExpanded = true;

			RMMBlockingInfoBarActionButtonVisibility = Visibility.Collapsed;

			RMMBlockingSectionIsEnabled = false;
			RMMBlockingInfoBar.IsClosable = false;

			RMMBlockingInfoBar.WriteInfo(Atlas.GetStr("CreatingPolicyRMMBlocking"));

			_policyPathRMMBlocking = await Task.Run(() =>
			{
				return BasePolicyCreator.BuildRMMBlocking(RMMBlockingAudit, RMMBlockingCreateAndDeploy);
			});

			// Assign the created policy to the Sidebar
			ViewModelProvider.MainWindowVM.AssignToSidebar(_policyPathRMMBlocking);

			if (sender is not null)
				AppControlManager.MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

			RMMBlockingInfoBarActionButtonVisibility = Visibility.Visible;

			RMMBlockingInfoBar.WriteSuccess(Atlas.GetStr("RMMBlockingPolicyCreatedSuccessfully"));
		}
		catch (Exception ex)
		{
			RMMBlockingInfoBar.WriteError(ex);
		}
		finally
		{
			RMMBlockingInfoBar.IsClosable = true;
			RMMBlockingSectionIsEnabled = true;
		}
	}

	/// <summary>
	/// Event handler to open the created RMM Blocking policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor_RMMBlockingPolicy() => await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(_policyPathRMMBlocking);

	internal async void OpenInDefaultFileHandler_RMMBlockingPolicy() => await PolicyFileRepresent.OpenInDefaultFileHandler(_policyPathRMMBlocking);

	internal async void OpenInConfigurePolicyRuleOptions_RMMBlockingPolicy() => await ConfigurePolicyRuleOptionsViewModel.OpenInConfigurePolicyRuleOptions(_policyPathRMMBlocking);

	/// <summary>
	/// The method used to open the <see cref="CreatePolicy"/> page from other parts of the application.
	/// </summary>
	/// <param name="type"></param>
	/// <returns></returns>
	internal async Task OpenInCreatePolicy(LaunchProtocolActions type)
	{
		try
		{
			ViewModelProvider.NavigationService.Navigate(typeof(CreatePolicy), null);

			switch (type)
			{
				case LaunchProtocolActions.DeployRMMAuditPolicy:
					{
						RMMBlockingCreateAndDeploy = true;
						RMMBlockingAudit = true;
						await RMMBlockingPolicyCreateButton_Private(null);
						break;
					}
				case LaunchProtocolActions.DeployRMMBlockPolicy:
					{
						RMMBlockingCreateAndDeploy = true;
						RMMBlockingAudit = false;
						await RMMBlockingPolicyCreateButton_Private(null);
						break;
					}
				case LaunchProtocolActions.PolicyEditor:
				case LaunchProtocolActions.FileSignature:
				case LaunchProtocolActions.FileHashes:
				default:
					break;
			}
		}
		catch (Exception ex)
		{
			RMMBlockingInfoBar.WriteError(ex);
		}
	}

	#endregion

	#region Downloads Defense Measures

	internal Visibility DownloadsDefenseMeasureInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal SiPolicy.PolicyFileRepresent? _policyPathDownloadsDefenseMeasure { get; set => SP(ref field, value); }

	internal bool DownloadsDefenseMeasureSectionIsEnabled { get; set => SP(ref field, value); } = true;

	internal bool DownloadsDefenseMeasureCreateAndDeploy { get; set => SP(ref field, value); }

	internal bool DownloadsDefenseMeasureAudit { get; set => SP(ref field, value); }

	internal bool DownloadsDefenseMeasureSettingsIsExpanded { get; set => SP(ref field, value); }

	internal readonly InfoBarSettings DownloadsDefenseMeasureInfoBar = new();

	/// <summary>
	/// Event handler to prepare the Downloads Defense Measures policy
	/// </summary>
	internal async void DownloadsDefenseMeasurePolicyCreateButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) =>
		await DownloadsDefenseMeasurePolicyCreateButton_Private(sender);

	private async Task DownloadsDefenseMeasurePolicyCreateButton_Private(object? sender)
	{
		try
		{
			DownloadsDefenseMeasureSettingsIsExpanded = true;

			DownloadsDefenseMeasureInfoBarActionButtonVisibility = Visibility.Collapsed;

			DownloadsDefenseMeasureSectionIsEnabled = false;
			DownloadsDefenseMeasureInfoBar.IsClosable = false;

			DownloadsDefenseMeasureInfoBar.WriteInfo(Atlas.GetStr("CreatingPolicyDownloadsDefenseMeasure"));

			_policyPathDownloadsDefenseMeasure = await Task.Run(() =>
			{
				return BasePolicyCreator.BuildDownloadsDefenseMeasures(DownloadsDefenseMeasureAudit, DownloadsDefenseMeasureCreateAndDeploy);
			});

			// Assign the created policy to the Sidebar
			ViewModelProvider.MainWindowVM.AssignToSidebar(_policyPathDownloadsDefenseMeasure);

			if (sender is not null)
				AppControlManager.MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

			DownloadsDefenseMeasureInfoBarActionButtonVisibility = Visibility.Visible;

			DownloadsDefenseMeasureInfoBar.WriteSuccess(Atlas.GetStr("DownloadsDefenseMeasurePolicyCreatedSuccessfully"));
		}
		catch (Exception ex)
		{
			DownloadsDefenseMeasureInfoBar.WriteError(ex);
		}
		finally
		{
			DownloadsDefenseMeasureInfoBar.IsClosable = true;
			DownloadsDefenseMeasureSectionIsEnabled = true;
		}
	}

	/// <summary>
	/// Event handler to open the created Downloads Defense Measures policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor_DownloadsDefenseMeasurePolicy() => await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(_policyPathDownloadsDefenseMeasure);

	internal async void OpenInDefaultFileHandler_DownloadsDefenseMeasurePolicy() => await PolicyFileRepresent.OpenInDefaultFileHandler(_policyPathDownloadsDefenseMeasure);

	internal async void OpenInConfigurePolicyRuleOptions_DownloadsDefenseMeasurePolicy() => await ConfigurePolicyRuleOptionsViewModel.OpenInConfigurePolicyRuleOptions(_policyPathDownloadsDefenseMeasure);

	#endregion

	#region Dangerous Script Hosts Blocking

	internal Visibility DangerousScriptHostsBlockingInfoBarActionButtonVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal SiPolicy.PolicyFileRepresent? _policyPathDangerousScriptHostsBlocking { get; set => SP(ref field, value); }

	internal bool DangerousScriptHostsBlockingSectionIsEnabled { get; set => SP(ref field, value); } = true;

	internal bool DangerousScriptHostsBlockingCreateAndDeploy { get; set => SP(ref field, value); }

	internal bool DangerousScriptHostsBlockingAudit { get; set => SP(ref field, value); }

	internal bool DangerousScriptHostsBlockingSettingsIsExpanded { get; set => SP(ref field, value); }

	internal readonly InfoBarSettings DangerousScriptHostsBlockingInfoBar = new();

	/// <summary>
	/// Event handler to prepare the Dangerous Script Hosts Blocking policy
	/// </summary>
	internal async void DangerousScriptHostsBlockingPolicyCreateButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e) =>
		await DangerousScriptHostsBlockingPolicyCreateButton_Private(sender);

	private async Task DangerousScriptHostsBlockingPolicyCreateButton_Private(object? sender)
	{
		try
		{
			DangerousScriptHostsBlockingSettingsIsExpanded = true;

			DangerousScriptHostsBlockingInfoBarActionButtonVisibility = Visibility.Collapsed;

			DangerousScriptHostsBlockingSectionIsEnabled = false;
			DangerousScriptHostsBlockingInfoBar.IsClosable = false;

			DangerousScriptHostsBlockingInfoBar.WriteInfo(Atlas.GetStr("CreatingPolicyDangerousScriptHostsBlocking"));

			_policyPathDangerousScriptHostsBlocking = await Task.Run(() =>
			{
				return BasePolicyCreator.BuildDangerousScriptBlockingPolicy(DangerousScriptHostsBlockingAudit, DangerousScriptHostsBlockingCreateAndDeploy);
			});

			// Assign the created policy to the Sidebar
			ViewModelProvider.MainWindowVM.AssignToSidebar(_policyPathDangerousScriptHostsBlocking);

			if (sender is not null)
				AppControlManager.MainWindow.TriggerTransferIconAnimationStatic((UIElement)sender);

			DangerousScriptHostsBlockingInfoBarActionButtonVisibility = Visibility.Visible;

			DangerousScriptHostsBlockingInfoBar.WriteSuccess(Atlas.GetStr("DangerousScriptHostsBlockingPolicyCreatedSuccessfully"));
		}
		catch (Exception ex)
		{
			DangerousScriptHostsBlockingInfoBar.WriteError(ex);
		}
		finally
		{
			DangerousScriptHostsBlockingInfoBar.IsClosable = true;
			DangerousScriptHostsBlockingSectionIsEnabled = true;
		}
	}

	/// <summary>
	/// Event handler to open the created Dangerous Script Hosts Blocking policy in the Policy Editor
	/// </summary>
	internal async void OpenInPolicyEditor_DangerousScriptHostsBlockingPolicy() => await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(_policyPathDangerousScriptHostsBlocking);

	internal async void OpenInDefaultFileHandler_DangerousScriptHostsBlockingPolicy() => await PolicyFileRepresent.OpenInDefaultFileHandler(_policyPathDangerousScriptHostsBlocking);

	internal async void OpenInConfigurePolicyRuleOptions_DangerousScriptHostsBlockingPolicy() => await ConfigurePolicyRuleOptionsViewModel.OpenInConfigurePolicyRuleOptions(_policyPathDangerousScriptHostsBlocking);

	#endregion

}
