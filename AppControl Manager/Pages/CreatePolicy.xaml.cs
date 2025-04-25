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
using AppControlManager.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Initializes the CreatePolicy component, disabling log size inputs and maintaining navigation state.
/// of various policies.
/// </summary>
internal sealed partial class CreatePolicy : Page
{

#pragma warning disable CA1822
	private PolicyEditorVM PolicyEditorViewModel { get; } = App.AppHost.Services.GetRequiredService<PolicyEditorVM>();
	private CreatePolicyVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<CreatePolicyVM>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
#pragma warning restore CA1822

	/// <summary>
	/// Initializes the CreatePolicy component and sets various log size inputs to disabled. Maintains navigation state.
	/// </summary>
	internal CreatePolicy()
	{
		this.InitializeComponent();

		this.DataContext = ViewModel;

		// Initially set it to disabled until the switch is toggled
		AllowMicrosoftLogSizeInput.IsEnabled = false;

		// Initially set it to disabled until the switch is toggled
		DefaultWindowsLogSizeInput.IsEnabled = false;

		// Initially set it to disabled until the switch is toggled
		SignedAndReputableLogSizeInput.IsEnabled = false;

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Required;
	}

	#region For Allow Microsoft Policy

	private string? _policyPathAllowMicrosoft;

	/// <summary>
	/// Event handler for creating/deploying AllowMicrosoft policy
	/// </summary>
	private async void AllowMicrosoftCreate_Click()
	{
		bool Error = false;

		// Capture UI values
		bool auditEnabled = AllowMicrosoftAudit.IsOn;
		bool requireEVSigners = AllowMicrosoftRequireEVSigners.IsOn;
		bool enableScriptEnforcement = AllowMicrosoftEnableScriptEnforcement.IsOn;
		bool testMode = AllowMicrosoftTestMode.IsOn;
		bool shouldDeploy = AllowMicrosoftCreateAndDeploy.IsChecked ?? false;
		bool DeployMSRecommendedBlockRules = !AllowMicrosoftNoBlockRules.IsOn;

		try
		{

			ViewModel.AllowMicrosoftInfoBarActionButtonVisibility = Visibility.Collapsed;

			AllowMicrosoftSettingsInfoBar.IsOpen = true;
			AllowMicrosoftSettingsInfoBar.IsClosable = false;
			AllowMicrosoftSettingsInfoBar.Severity = InfoBarSeverity.Informational;
			AllowMicrosoftSettingsInfoBar.Message = "Creating the Allow Microsoft base policy";
			AllowMicrosoftSettings.IsExpanded = true;

			// Disable the buttons to prevent multiple clicks
			AllowMicrosoftCreate.IsEnabled = false;

			string stagingArea = StagingArea.NewStagingArea("BuildAllowMicrosoft").ToString();

			#region Only modify the log size if the element is enabled meaning the Toggle Switch is toggled
			ulong? logSize = null;

			if (AllowMicrosoftLogSizeInput.IsEnabled)
			{
				// Get the NumberBox value which is a double (entered in megabytes)
				double inputValue = AllowMicrosoftLogSizeInput.Value;

				// Convert the value from megabytes to bytes
				double bytesValue = inputValue * 1024 * 1024;

				// Convert the value to ulong
				logSize = Convert.ToUInt64(bytesValue);
			}
			#endregion

			// Run background work using captured values
			_policyPathAllowMicrosoft = await Task.Run(() =>
			{
				return BasePolicyCreator.BuildAllowMSFT(
				StagingArea: stagingArea,
				IsAudit: auditEnabled,
				LogSize: logSize,
				deploy: shouldDeploy,
				RequireEVSigners: requireEVSigners,
				EnableScriptEnforcement: enableScriptEnforcement,
				TestMode: testMode,
				deployAppControlSupplementalPolicy: shouldDeploy,
				PolicyIDToUse: null,
				DeployMicrosoftRecommendedBlockRules: DeployMSRecommendedBlockRules
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
			AllowMicrosoftCreate.IsEnabled = true;

			AllowMicrosoftSettingsInfoBar.IsClosable = true;

			ViewModel.AllowMicrosoftInfoBarActionButtonVisibility = Visibility.Visible;

			if (!Error)
			{
				AllowMicrosoftSettingsInfoBar.Severity = InfoBarSeverity.Success;
				AllowMicrosoftSettingsInfoBar.Message = shouldDeploy ? "Successfully created and deployed the Allow Microsoft base policy" : "Successfully created the Allow Microsoft base policy";
			}
			else
			{
				AllowMicrosoftSettingsInfoBar.Severity = InfoBarSeverity.Error;
				AllowMicrosoftSettingsInfoBar.Message = "There was an error while creating the Allow Microsoft base policy";
			}
		}
	}


	/// <summary>
	/// Event handler for the ToggleSwitch to enable/disable the log size input
	/// </summary>
	private void AllowMicrosoftLogSizeInputEnabled_Toggled()
	{
		if (AllowMicrosoftLogSizeInputEnabled.IsOn)
		{
			AllowMicrosoftLogSizeInput.IsEnabled = true;
		}
		else
		{
			AllowMicrosoftLogSizeInput.IsEnabled = false;
		}
	}


	private void AllowMicrosoftAudit_Toggled(object sender, RoutedEventArgs e)
	{
		AllowMicrosoftLogSizeInput.IsEnabled = ((ToggleSwitch)sender).IsOn;
		AllowMicrosoftLogSizeInputEnabled.IsEnabled = ((ToggleSwitch)sender).IsOn;
	}

	/// <summary>
	/// Event handler to open the created Allow Microsoft policy in the Policy Editor
	/// </summary>
	private async void OpenInPolicyEditor_AllowMicrosoft()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_policyPathAllowMicrosoft);
	}

	#endregion


	#region For Default Windows Policy

	private string? _policyPathDefaultWindows;

	/// <summary>
	/// Event handler for creating/deploying DefaultWindows policy
	/// </summary>
	private async void DefaultWindowsCreate_Click()
	{

		bool Error = false;

		ViewModel.DefaultWindowsInfoBarActionButtonVisibility = Visibility.Collapsed;

		// Capture UI values
		bool auditEnabled = DefaultWindowsAudit.IsOn;
		bool requireEVSigners = DefaultWindowsRequireEVSigners.IsOn;
		bool enableScriptEnforcement = DefaultWindowsEnableScriptEnforcement.IsOn;
		bool testMode = DefaultWindowsTestMode.IsOn;
		bool shouldDeploy = DefaultWindowsCreateAndDeploy.IsChecked ?? false;
		bool DeployMSRecommendedBlockRules = !DefaultWindowsNoBockRules.IsOn;

		try
		{

			DefaultWindowsSettingsInfoBar.IsOpen = true;
			DefaultWindowsSettingsInfoBar.IsClosable = false;
			DefaultWindowsSettingsInfoBar.Severity = InfoBarSeverity.Informational;
			DefaultWindowsSettingsInfoBar.Message = "Creating the Default Windows base policy";
			DefaultWindowsSettings.IsExpanded = true;

			// Disable the buttons to prevent multiple clicks
			DefaultWindowsCreate.IsEnabled = false;

			string stagingArea = StagingArea.NewStagingArea("BuildDefaultWindows").ToString();

			#region Only modify the log size if the element is enabled meaning the Toggle Switch is toggled
			ulong? logSize = null;

			if (DefaultWindowsLogSizeInput.IsEnabled)
			{
				// Get the NumberBox value which is a double (entered in megabytes)
				double inputValue = DefaultWindowsLogSizeInput.Value;

				// Convert the value from megabytes to bytes
				double bytesValue = inputValue * 1024 * 1024;

				// Convert the value to ulong
				logSize = Convert.ToUInt64(bytesValue);
			}
			#endregion

			// Run background work using captured values
			_policyPathDefaultWindows = await Task.Run(() =>
			{
				return BasePolicyCreator.BuildDefaultWindows(
				StagingArea: stagingArea,
				IsAudit: auditEnabled,
				LogSize: logSize,
				deploy: shouldDeploy,
				RequireEVSigners: requireEVSigners,
				EnableScriptEnforcement: enableScriptEnforcement,
				TestMode: testMode,
				deployAppControlSupplementalPolicy: shouldDeploy,
				PolicyIDToUse: null,
				DeployMicrosoftRecommendedBlockRules: DeployMSRecommendedBlockRules
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
			DefaultWindowsCreate.IsEnabled = true;

			ViewModel.DefaultWindowsInfoBarActionButtonVisibility = Visibility.Visible;

			DefaultWindowsSettingsInfoBar.IsClosable = true;

			if (!Error)
			{
				DefaultWindowsSettingsInfoBar.Severity = InfoBarSeverity.Success;
				DefaultWindowsSettingsInfoBar.Message = shouldDeploy ? "Successfully created and deployed the Default Windows base policy" : "Successfully created the Default Windows base policy";
			}
			else
			{
				DefaultWindowsSettingsInfoBar.Severity = InfoBarSeverity.Error;
				DefaultWindowsSettingsInfoBar.Message = "There was an error while creating the Default Windows base policy";
			}
		}
	}


	/// <summary>
	/// Event handler for the ToggleSwitch to enable/disable the log size input
	/// </summary>
	private void DefaultWindowsLogSizeInputEnabled_Toggled()
	{
		if (DefaultWindowsLogSizeInputEnabled.IsOn)
		{
			DefaultWindowsLogSizeInput.IsEnabled = true;
		}
		else
		{
			DefaultWindowsLogSizeInput.IsEnabled = false;
		}
	}


	private void DefaultWindowsAudit_Toggled(object sender, RoutedEventArgs e)
	{
		DefaultWindowsLogSizeInput.IsEnabled = ((ToggleSwitch)sender).IsOn;
		DefaultWindowsLogSizeInputEnabled.IsEnabled = ((ToggleSwitch)sender).IsOn;
	}


	/// <summary>
	/// Event handler to open the created Default Windows policy in the Policy Editor
	/// </summary>
	private async void OpenInPolicyEditor_DefaultWindows()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_policyPathDefaultWindows);
	}

	#endregion


	#region For Signed and Reputable Policy

	private string? _policyPathSignedAndReputable;

	/// <summary>
	/// Event handler for creating/deploying SignedAndReputable policy
	/// </summary>
	private async void SignedAndReputableCreate_Click()
	{

		bool Error = false;

		ViewModel.SignedAndReputableInfoBarActionButtonVisibility = Visibility.Collapsed;

		// Capture the values from UI
		bool auditEnabled = SignedAndReputableAudit.IsOn;
		bool requireEVSigners = SignedAndReputableRequireEVSigners.IsOn;
		bool enableScriptEnforcement = SignedAndReputableEnableScriptEnforcement.IsOn;
		bool testMode = SignedAndReputableTestMode.IsOn;
		bool shouldDeploy = SignedAndReputableCreateAndDeploy.IsChecked ?? false;
		bool DeployMSRecommendedBlockRules = !SignedAndReputableNoBockRules.IsOn;

		try
		{

			SignedAndReputableSettingsInfoBar.IsOpen = true;
			SignedAndReputableSettingsInfoBar.IsClosable = false;
			SignedAndReputableSettingsInfoBar.Severity = InfoBarSeverity.Informational;
			SignedAndReputableSettingsInfoBar.Message = "Creating the Signed and Reputable base policy";
			SignedAndReputableSettings.IsExpanded = true;

			// Disable the buttons
			SignedAndReputableCreate.IsEnabled = false;

			string stagingArea = StagingArea.NewStagingArea("BuildSignedAndReputable").ToString();

			#region Only modify the log size if the element is enabled meaning the Toggle Switch is toggled
			ulong? logSize = null;

			if (SignedAndReputableLogSizeInput.IsEnabled)
			{
				// Get the NumberBox value which is a double (entered in megabytes)
				double inputValue = SignedAndReputableLogSizeInput.Value;

				// Convert the value from megabytes to bytes
				double bytesValue = inputValue * 1024 * 1024;

				// Convert the value to ulong
				logSize = Convert.ToUInt64(bytesValue);
			}
			#endregion

			_policyPathSignedAndReputable = await Task.Run(() =>
			{
				return BasePolicyCreator.BuildSignedAndReputable(
				StagingArea: stagingArea,
				IsAudit: auditEnabled,
				LogSize: logSize,
				deploy: shouldDeploy,
				RequireEVSigners: requireEVSigners,
				EnableScriptEnforcement: enableScriptEnforcement,
				TestMode: testMode,
				deployAppControlSupplementalPolicy: shouldDeploy,
				PolicyIDToUse: null,
				DeployMicrosoftRecommendedBlockRules: DeployMSRecommendedBlockRules
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
			SignedAndReputableCreate.IsEnabled = true;

			SignedAndReputableSettingsInfoBar.IsClosable = true;

			ViewModel.SignedAndReputableInfoBarActionButtonVisibility = Visibility.Visible;

			if (!Error)
			{
				SignedAndReputableSettingsInfoBar.Severity = InfoBarSeverity.Success;
				SignedAndReputableSettingsInfoBar.Message = shouldDeploy ? "Successfully created and deployed the Signed and Reputable base policy" : "Successfully created the Signed and Reputable base policy";
			}
			else
			{
				SignedAndReputableSettingsInfoBar.Severity = InfoBarSeverity.Error;
				SignedAndReputableSettingsInfoBar.Message = "There was an error while creating the Signed and Reputable base policy";
			}
		}
	}


	/// <summary>
	/// Event handler for the ToggleSwitch to enable/disable the log size input
	/// </summary>
	private void SignedAndReputableLogSizeInputEnabled_Toggled()
	{
		if (SignedAndReputableLogSizeInputEnabled.IsOn)
		{
			SignedAndReputableLogSizeInput.IsEnabled = true;
		}
		else
		{
			SignedAndReputableLogSizeInput.IsEnabled = false;
		}
	}


	private void SignedAndReputableAudit_Toggled(object sender, RoutedEventArgs e)
	{
		SignedAndReputableLogSizeInput.IsEnabled = ((ToggleSwitch)sender).IsOn;
		SignedAndReputableLogSizeInputEnabled.IsEnabled = ((ToggleSwitch)sender).IsOn;
	}


	/// <summary>
	/// Event handler to open the created Signed and Reputable policy in the Policy Editor
	/// </summary>
	private async void OpenInPolicyEditor_SignedAndReputable()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_policyPathSignedAndReputable);
	}


	#endregion


	#region For Microsoft Recommended Driver Block Rules

	private string? _policyPathMSFTRecommendedDriverBlockRules;


	/// <summary>
	/// Event handler for creating/deploying Microsoft recommended driver block rules policy
	/// </summary>
	private async void RecommendedDriverBlockRulesCreate_Click()
	{

		bool shouldDeploy = RecommendedDriverBlockRulesCreateAndDeploy.IsChecked ?? false;

		bool error = false;

		RecommendedDriverBlockRulesSettings.IsExpanded = true;

		try
		{

			// Disable the buttons
			RecommendedDriverBlockRulesCreate.IsEnabled = false;

			ViewModel.MSFTRecommendedDriverBlockRulesInfoBarActionButtonVisibility = Visibility.Collapsed;

			RecommendedDriverBlockRulesInfoBar.IsClosable = false;
			RecommendedDriverBlockRulesInfoBar.IsOpen = true;
			RecommendedDriverBlockRulesInfoBar.Severity = InfoBarSeverity.Informational;
			RecommendedDriverBlockRulesInfoBar.Message = "Creating the Microsoft Recommended Driver Block Rules policy";

			string stagingArea = StagingArea.NewStagingArea("BuildRecommendedDriverBlockRules").ToString();

			(string?, string?) results = (null, null);

			// Run the background operation using captured values
			await Task.Run(() =>
			{
				if (shouldDeploy)
				{
					BasePolicyCreator.DeployDriversBlockRules(stagingArea);
				}
				else
				{
					results = BasePolicyCreator.GetDriversBlockRules(stagingArea);


					_policyPathMSFTRecommendedDriverBlockRules = results.Item1;
				}
			});


			RecommendedDriverBlockRulesVersionTextBlock.Text = results.Item2;
		}
		catch (Exception ex)
		{
			error = true;

			RecommendedDriverBlockRulesInfoBar.IsClosable = true;
			RecommendedDriverBlockRulesInfoBar.IsOpen = true;
			RecommendedDriverBlockRulesInfoBar.Severity = InfoBarSeverity.Error;
			RecommendedDriverBlockRulesInfoBar.Message = $"There was a problem creating the Microsoft Recommended Driver Block Rules policy: {ex.Message}";

			throw;
		}
		finally
		{

			if (!error)
			{

				RecommendedDriverBlockRulesInfoBar.IsClosable = true;
				RecommendedDriverBlockRulesInfoBar.IsOpen = true;
				RecommendedDriverBlockRulesInfoBar.Severity = InfoBarSeverity.Success;
				RecommendedDriverBlockRulesInfoBar.Message = "Successfully created the Microsoft Recommended Driver Block Rules policy";
			}

			// Re-enable buttons
			RecommendedDriverBlockRulesCreate.IsEnabled = true;

			if (!shouldDeploy && !error)
			{
				ViewModel.MSFTRecommendedDriverBlockRulesInfoBarActionButtonVisibility = Visibility.Visible;
			}
		}
	}


	/// <summary>
	/// Event handler for Auto Update button
	/// </summary>
	private async void RecommendedDriverBlockRulesScheduledAutoUpdate_Click()
	{

		bool errorsOccurred = false;

		try
		{
			RecommendedDriverBlockRulesScheduledAutoUpdate.IsEnabled = false;

			RecommendedDriverBlockRulesInfoBar.IsClosable = false;
			RecommendedDriverBlockRulesInfoBar.IsOpen = true;
			RecommendedDriverBlockRulesInfoBar.Severity = InfoBarSeverity.Informational;
			RecommendedDriverBlockRulesInfoBar.Message = GlobalVars.Rizz.GetString("ConfiguringAutoUpdate");

			await Task.Run(BasePolicyCreator.SetAutoUpdateDriverBlockRules);
		}
		catch
		{
			errorsOccurred = true;
			throw;
		}
		finally
		{
			RecommendedDriverBlockRulesInfoBar.IsClosable = true;

			// Expand the settings card to make the InfoBar visible
			RecommendedDriverBlockRulesSettings.IsExpanded = true;

			if (errorsOccurred)
			{
				RecommendedDriverBlockRulesInfoBar.Severity = InfoBarSeverity.Error;
				RecommendedDriverBlockRulesInfoBar.Message = GlobalVars.Rizz.GetString("AutoUpdateError");
			}
			else
			{
				RecommendedDriverBlockRulesInfoBar.Severity = InfoBarSeverity.Success;
				RecommendedDriverBlockRulesInfoBar.Message = GlobalVars.Rizz.GetString("AutoUpdateConfigured");
			}

			RecommendedDriverBlockRulesScheduledAutoUpdate.IsEnabled = true;
		}
	}


	/// <summary>
	/// Event handler to open the created Microsoft Recommended driver block rules policy in the Policy Editor
	/// </summary>
	private async void OpenInPolicyEditor_RecommendedDriverBlockRules()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_policyPathMSFTRecommendedDriverBlockRules);
	}

	#endregion


	#region For Microsoft Recommended User Mode Block Rules

	/// <summary>
	/// Event handler for creating/deploying Microsoft recommended user-mode block rules policy
	/// </summary>
	private async void RecommendedUserModeBlockRulesCreate_Click()
	{
		try
		{
			// Disable the buttons
			RecommendedUserModeBlockRulesCreate.IsEnabled = false;

			bool shouldDeploy = RecommendedUserModeBlockRulesCreateAndDeploy.IsChecked ?? false;

			string stagingArea = StagingArea.NewStagingArea("BuildRecommendedUserModeBlockRules").ToString();

			// Run the background operation using captured values
			await Task.Run(() =>
			{
				BasePolicyCreator.GetBlockRules(stagingArea, shouldDeploy);

			});
		}
		finally
		{
			// Re-enable buttons
			RecommendedUserModeBlockRulesCreate.IsEnabled = true;
		}
	}

	#endregion


	#region For Strict Kernel-mode policy

	private string? _policyPathStrictKernelMode;

	/// <summary>
	/// Event handler to prepare the system for Strict Kernel-mode policy
	/// </summary>
	private async void StrictKernelModePolicyCreateButton_Click()
	{
		StrictKernelModePolicyCreateButton.IsEnabled = false;
		StrictKernelModePolicyToggleButtonForDeploy.IsEnabled = false;
		StrictKernelModePolicyInfoBar.IsClosable = false;
		StrictKernelModePolicyInfoBar.IsOpen = true;
		StrictKernelModePolicySection.IsExpanded = true;

		ViewModel.StrictKernelModeInfoBarActionButtonVisibility = Visibility.Collapsed;

		bool useNoFlightRoots = StrictKernelModePolicyUseNoFlightRootsToggleSwitch.IsOn;
		bool deploy = StrictKernelModePolicyToggleButtonForDeploy.IsChecked ?? false;
		bool audit = StrictKernelModePolicyAudit.IsOn;
		bool errorsOccurred = false;

		try
		{
			StrictKernelModePolicyInfoBar.Message = GlobalVars.Rizz.GetString("CreatingPolicy");
			Logger.Write(GlobalVars.Rizz.GetString("CreatingPolicy"));
			StrictKernelModePolicyInfoBar.Severity = InfoBarSeverity.Informational;

			_policyPathStrictKernelMode = await Task.Run(() =>
			{
				DirectoryInfo stagingArea = StagingArea.NewStagingArea("Strict Kernel-Mode policy Prepare");

				return BasePolicyCreator.BuildStrictKernelMode(stagingArea.FullName, audit, useNoFlightRoots, deploy);
			});
		}
		catch (Exception ex)
		{
			StrictKernelModePolicyInfoBar.Severity = InfoBarSeverity.Error;

			StrictKernelModePolicyInfoBar.Message = GlobalVars.Rizz.GetString("PolicyCreationError") + ex.Message;

			errorsOccurred = true;

			throw;
		}
		finally
		{
			if (!errorsOccurred)
			{
				StrictKernelModePolicyInfoBar.Severity = InfoBarSeverity.Success;
				StrictKernelModePolicyInfoBar.Message = GlobalVars.Rizz.GetString("PolicyCreatedSuccessfully");
				Logger.Write(GlobalVars.Rizz.GetString("PolicyCreatedSuccessfully"));
			}

			StrictKernelModePolicyInfoBar.IsClosable = true;
			StrictKernelModePolicyCreateButton.IsEnabled = true;
			StrictKernelModePolicyToggleButtonForDeploy.IsEnabled = true;

			ViewModel.StrictKernelModeInfoBarActionButtonVisibility = Visibility.Visible;
		}
	}


	/// <summary>
	/// Event handler to open the created Strict Kernel-mode policy in the Policy Editor
	/// </summary>
	private async void OpenInPolicyEditor_StrictKernelModePolicy()
	{
		await PolicyEditorViewModel.OpenInPolicyEditor(_policyPathStrictKernelMode);
	}

	#endregion

}
