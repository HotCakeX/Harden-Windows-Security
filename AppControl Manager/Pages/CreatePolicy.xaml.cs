using System;
using System.IO;
using System.Threading.Tasks;
using AppControlManager.Main;
using AppControlManager.Others;
using CommunityToolkit.WinUI.Controls;
using Microsoft.UI;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Documents;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

public sealed partial class CreatePolicy : Page
{
	public CreatePolicy()
	{
		this.InitializeComponent();

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


	/// <summary>
	/// Event handler for creating/deploying AllowMicrosoft policy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void AllowMicrosoftCreate_Click(object sender, RoutedEventArgs e)
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
			await Task.Run(() =>
			{
				BasePolicyCreator.BuildAllowMSFT(stagingArea,
					auditEnabled,
					logSize,
					shouldDeploy,
					requireEVSigners,
					enableScriptEnforcement,
					testMode,
					true,
					null,
					DeployMSRecommendedBlockRules
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

	// Event handler for the ToggleSwitch to enable/disable the log size input
	private void AllowMicrosoftLogSizeInputEnabled_Toggled(object sender, RoutedEventArgs e)
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

	#endregion


	#region For Default Windows Policy

	/// <summary>
	/// Event handler for creating/deploying DefaultWindows policy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void DefaultWindowsCreate_Click(object sender, RoutedEventArgs e)
	{

		bool Error = false;

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
			await Task.Run(() =>
			{
				BasePolicyCreator.BuildDefaultWindows(stagingArea,
					auditEnabled,
					logSize,
					shouldDeploy,
					requireEVSigners,
					enableScriptEnforcement,
					testMode,
					true,
					null,
					DeployMSRecommendedBlockRules
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

	// Event handler for the ToggleSwitch to enable/disable the log size input
	private void DefaultWindowsLogSizeInputEnabled_Toggled(object sender, RoutedEventArgs e)
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

	#endregion


	#region For Signed and Reputable Policy


	/// <summary>
	/// Event handler for creating/deploying SignedAndReputable policy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void SignedAndReputableCreate_Click(object sender, RoutedEventArgs e)
	{

		bool Error = false;

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

			await Task.Run(() =>
			{
				BasePolicyCreator.BuildSignedAndReputable(stagingArea,
					auditEnabled,
					logSize,
					shouldDeploy,
					requireEVSigners,
					enableScriptEnforcement,
					testMode,
					true,
					null,
					DeployMSRecommendedBlockRules
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

	// Event handler for the ToggleSwitch to enable/disable the log size input
	private void SignedAndReputableLogSizeInputEnabled_Toggled(object sender, RoutedEventArgs e)
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

	#endregion


	#region For Microsoft Recommended Drivers Block Rules

	/// <summary>
	/// Method to dynamically add a TextBlock with formatted content
	/// </summary>
	/// <returns></returns>
	private async Task AddDriverBlockRulesInfo()
	{
		// Create a new TextBlock
		TextBlock formattedTextBlock = new();

		// Gather driver block list info asynchronously
		BasePolicyCreator.DriverBlockListInfo? driverBlockListInfo = await Task.Run(BasePolicyCreator.DriversBlockListInfoGathering);

		// Prepare the text to display
		if (driverBlockListInfo is not null)
		{
			// Create the formatted content for version and last updated date
			Span versionSpan = new()
			{
				Inlines =
		{
			new Run { Text = GlobalVars.Rizz.GetString("VersionLabel"), FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(Colors.Violet) },
			new Run { Text = $"{driverBlockListInfo.Version}\n", Foreground = new SolidColorBrush(Colors.Violet) }
		}
			};

			Span lastUpdatedSpan = new()
			{
				Inlines =
		{
			new Run { Text = GlobalVars.Rizz.GetString("LastUpdatedLabel"), FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(Colors.HotPink) },
			new Run { Text = $"{driverBlockListInfo.LastUpdated:MMMM dd, yyyy}\n", Foreground = new SolidColorBrush(Colors.HotPink) }
		}
			};

			// Add content to the TextBlock
			formattedTextBlock.Inlines.Add(versionSpan);
			formattedTextBlock.Inlines.Add(lastUpdatedSpan);

		}
		else
		{
			// Handle the case when driver block list info is null
			Run errorRun = new()
			{
				Text = GlobalVars.Rizz.GetString("DriverBlockListError"),
				Foreground = new SolidColorBrush(Colors.Yellow)
			};
			formattedTextBlock.Inlines.Add(errorRun);
		}

		// Find the SettingsCard by its Header
		foreach (var child in RecommendedDriverBlockRulesSettings.Items)
		{
			if (child is SettingsCard settingsCard && string.Equals(settingsCard.Header.ToString(), "Info", StringComparison.OrdinalIgnoreCase))
			{
				// Insert the TextBlock into the SettingsCard's content area
				settingsCard.Content = formattedTextBlock;
			}
		}
	}


	/// <summary>
	/// Event handler for creating/deploying Microsoft recommended driver block rules policy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void RecommendedDriverBlockRulesCreate_Click(object sender, RoutedEventArgs e)
	{
		try
		{

			// Disable the buttons
			RecommendedDriverBlockRulesCreate.IsEnabled = false;

			bool shouldDeploy = RecommendedDriverBlockRulesCreateAndDeploy.IsChecked ?? false;

			string stagingArea = StagingArea.NewStagingArea("BuildRecommendedDriverBlockRules").ToString();

			// Run the background operation using captured values
			await Task.Run(() =>
			{
				if (shouldDeploy)
				{
					BasePolicyCreator.DeployDriversBlockRules(stagingArea);
				}
				else
				{
					BasePolicyCreator.GetDriversBlockRules(stagingArea);
				}
			});

			// Dynamically add the formatted TextBlock after gathering block list info
			// Can remove await and the info will populate after policy is created which is fine too
			await AddDriverBlockRulesInfo();
		}

		finally
		{
			// Re-enable buttons
			RecommendedDriverBlockRulesCreate.IsEnabled = true;
		}
	}


	/// <summary>
	/// Event handler for Auto Update button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void RecommendedDriverBlockRulesScheduledAutoUpdate_Click(object sender, RoutedEventArgs e)
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

	#endregion


	#region For Microsoft Recommended User Mode Block Rules

	/// <summary>
	/// Event handler for creating/deploying Microsoft recommended user-mode block rules policy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void RecommendedUserModeBlockRulesCreate_Click(object sender, RoutedEventArgs e)
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

	/// <summary>
	/// Event handler to prepare the system for Strict Kernel-mode policy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void StrictKernelModePolicyCreateButton_Click(object sender, RoutedEventArgs e)
	{
		StrictKernelModePolicyCreateButton.IsEnabled = false;
		StrictKernelModePolicyToggleButtonForDeploy.IsEnabled = false;
		StrictKernelModePolicyInfoBar.IsClosable = false;
		StrictKernelModePolicyInfoBar.IsOpen = true;
		StrictKernelModePolicySection.IsExpanded = true;

		bool useNoFlightRoots = StrictKernelModePolicyUseNoFlightRootsToggleSwitch.IsOn;
		bool deploy = StrictKernelModePolicyToggleButtonForDeploy.IsChecked ?? false;
		bool audit = StrictKernelModePolicyAudit.IsOn;
		bool errorsOccurred = false;

		try
		{
			StrictKernelModePolicyInfoBar.Message = GlobalVars.Rizz.GetString("CreatingPolicy");
			Logger.Write(GlobalVars.Rizz.GetString("CreatingPolicy"));
			StrictKernelModePolicyInfoBar.Severity = InfoBarSeverity.Informational;

			await Task.Run(() =>
			{
				DirectoryInfo stagingArea = StagingArea.NewStagingArea("Strict Kernel-Mode policy Prepare");

				BasePolicyCreator.BuildStrictKernelMode(stagingArea.FullName, audit, useNoFlightRoots, deploy);
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
		}
	}

	private void StrictKernelModePolicyUseNoFlightRootsToggleSwitchSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		StrictKernelModePolicyUseNoFlightRootsToggleSwitch.IsOn = !StrictKernelModePolicyUseNoFlightRootsToggleSwitch.IsOn;
	}


	private void StrictKernelModePolicyAuditSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		StrictKernelModePolicyAudit.IsOn = !StrictKernelModePolicyAudit.IsOn;
	}

	#endregion

}
