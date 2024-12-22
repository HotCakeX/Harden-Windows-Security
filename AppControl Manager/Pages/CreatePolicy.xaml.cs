using System;
using System.Threading.Tasks;
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
		this.NavigationCacheMode = NavigationCacheMode.Enabled;

	}

	#region Methods so that only 1 Deploy button will be available at any time to prevent conflicts

	private void DisableDeployButtons()
	{
		AllowMicrosoftCreateAndDeploy.IsEnabled = false;
		DefaultWindowsCreateAndDeploy.IsEnabled = false;
		SignedAndReputableCreateAndDeploy.IsEnabled = false;
		RecommendedDriverBlockRulesCreateAndDeploy.IsEnabled = false;
		RecommendedUserModeBlockRulesCreateAndDeploy.IsEnabled = false;
	}

	private void EnableDeployButtons()
	{
		AllowMicrosoftCreateAndDeploy.IsEnabled = true;
		DefaultWindowsCreateAndDeploy.IsEnabled = true;
		SignedAndReputableCreateAndDeploy.IsEnabled = true;
		RecommendedDriverBlockRulesCreateAndDeploy.IsEnabled = true;
		RecommendedUserModeBlockRulesCreateAndDeploy.IsEnabled = true;
	}
	#endregion


	#region For Allow Microsoft Policy

	// Event handler for creating AllowMicrosoft policy
	private async void AllowMicrosoftCreate_Click(object sender, RoutedEventArgs e)
	{

		try
		{

			// Disable the buttons to prevent multiple clicks (on the UI thread)
			AllowMicrosoftCreate.IsEnabled = false;
			AllowMicrosoftCreateAndDeploy.IsEnabled = false;

			string stagingArea = StagingArea.NewStagingArea("BuildAllowMicrosoft").ToString();

			// Capture the values from the UI elements (on the UI thread)
			bool auditEnabled = AllowMicrosoftAudit.IsOn;
			bool requireEVSigners = AllowMicrosoftRequireEVSigners.IsOn;
			bool enableScriptEnforcement = AllowMicrosoftEnableScriptEnforcement.IsOn;
			bool testMode = AllowMicrosoftTestMode.IsOn;

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

			// Run the background operation using captured values
			await Task.Run(() =>
			{
				BasePolicyCreator.BuildAllowMSFT(stagingArea,
					auditEnabled,
					logSize,
					false, // Do not deploy, only create
					requireEVSigners,
					enableScriptEnforcement,
					testMode,
					false
				);
			});

		}

		finally
		{

			// Re-enable the buttons once the work is done (back on the UI thread)
			AllowMicrosoftCreate.IsEnabled = true;
			AllowMicrosoftCreateAndDeploy.IsEnabled = true;
		}
	}


	// Event handler for creating & deploying AllowMicrosoft policy
	private async void AllowMicrosoftCreateAndDeploy_Click(object sender, RoutedEventArgs e)
	{

		try
		{

			// Disable the buttons to prevent multiple clicks
			AllowMicrosoftCreate.IsEnabled = false;
			DisableDeployButtons();

			string stagingArea = StagingArea.NewStagingArea("BuildAllowMicrosoft").ToString();

			// Capture UI values
			bool auditEnabled = AllowMicrosoftAudit.IsOn;
			bool requireEVSigners = AllowMicrosoftRequireEVSigners.IsOn;
			bool enableScriptEnforcement = AllowMicrosoftEnableScriptEnforcement.IsOn;
			bool testMode = AllowMicrosoftTestMode.IsOn;

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
					true, // Deploy it as well
					requireEVSigners,
					enableScriptEnforcement,
					testMode,
					true
				);

			});

		}
		finally
		{

			// Re-enable the buttons once the work is done
			AllowMicrosoftCreate.IsEnabled = true;
			EnableDeployButtons();

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

	// Event handler for creating DefaultWindows policy
	private async void DefaultWindowsCreate_Click(object sender, RoutedEventArgs e)
	{

		try
		{

			// Disable the buttons to prevent multiple clicks (on the UI thread)
			DefaultWindowsCreate.IsEnabled = false;
			DefaultWindowsCreateAndDeploy.IsEnabled = false;

			string stagingArea = StagingArea.NewStagingArea("BuildDefaultWindows").ToString();

			// Capture the values from the UI elements (on the UI thread)
			bool auditEnabled = DefaultWindowsAudit.IsOn;
			bool requireEVSigners = DefaultWindowsRequireEVSigners.IsOn;
			bool enableScriptEnforcement = DefaultWindowsEnableScriptEnforcement.IsOn;
			bool testMode = DefaultWindowsTestMode.IsOn;

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

			// Run the background operation using captured values
			await Task.Run(() =>
			{
				BasePolicyCreator.BuildDefaultWindows(stagingArea,
					auditEnabled,
					logSize,
					false, // Do not deploy, only create
					requireEVSigners,
					enableScriptEnforcement,
					testMode,
					false
				);
			});

		}

		finally
		{

			// Re-enable the buttons once the work is done (back on the UI thread)
			DefaultWindowsCreate.IsEnabled = true;
			DefaultWindowsCreateAndDeploy.IsEnabled = true;
		}
	}


	// Event handler for creating & deploying DefaultWindows policy
	private async void DefaultWindowsCreateAndDeploy_Click(object sender, RoutedEventArgs e)
	{

		try
		{

			// Disable the buttons to prevent multiple clicks
			DefaultWindowsCreate.IsEnabled = false;
			DisableDeployButtons();

			string stagingArea = StagingArea.NewStagingArea("BuildDefaultWindows").ToString();

			// Capture UI values
			bool auditEnabled = DefaultWindowsAudit.IsOn;
			bool requireEVSigners = DefaultWindowsRequireEVSigners.IsOn;
			bool enableScriptEnforcement = DefaultWindowsEnableScriptEnforcement.IsOn;
			bool testMode = DefaultWindowsTestMode.IsOn;

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
					true, // Deploy it as well
					requireEVSigners,
					enableScriptEnforcement,
					testMode,
					true
				);

			});

		}
		finally
		{

			// Re-enable the buttons once the work is done
			DefaultWindowsCreate.IsEnabled = true;
			EnableDeployButtons();

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

	// Event handler for creating SignedAndReputable policy
	private async void SignedAndReputableCreate_Click(object sender, RoutedEventArgs e)
	{
		try
		{

			// Disable the buttons
			SignedAndReputableCreate.IsEnabled = false;
			SignedAndReputableCreateAndDeploy.IsEnabled = false;

			string stagingArea = StagingArea.NewStagingArea("BuildSignedAndReputable").ToString();

			// Capture the values from the UI elements
			bool auditEnabled = SignedAndReputableAudit.IsOn;
			bool requireEVSigners = SignedAndReputableRequireEVSigners.IsOn;
			bool enableScriptEnforcement = SignedAndReputableEnableScriptEnforcement.IsOn;
			bool testMode = SignedAndReputableTestMode.IsOn;

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

			// Run the background operation using captured values
			await Task.Run(() =>
			{
				BasePolicyCreator.BuildSignedAndReputable(stagingArea,
					auditEnabled,
					logSize,
					false, // Do not deploy, only create
					requireEVSigners,
					enableScriptEnforcement,
					testMode,
					false
				);
			});

		}

		finally
		{

			// Re-enable buttons
			SignedAndReputableCreate.IsEnabled = true;
			SignedAndReputableCreateAndDeploy.IsEnabled = true;
		}
	}


	// Event handler for creating & deploying SignedAndReputable policy
	private async void SignedAndReputableCreateAndDeploy_Click(object sender, RoutedEventArgs e)
	{

		try
		{

			// Disable the buttons
			SignedAndReputableCreate.IsEnabled = false;
			DisableDeployButtons();

			string stagingArea = StagingArea.NewStagingArea("BuildSignedAndReputable").ToString();

			// Capture the values from UI
			bool auditEnabled = SignedAndReputableAudit.IsOn;
			bool requireEVSigners = SignedAndReputableRequireEVSigners.IsOn;
			bool enableScriptEnforcement = SignedAndReputableEnableScriptEnforcement.IsOn;
			bool testMode = SignedAndReputableTestMode.IsOn;

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
					true, // Deploy it as well
					requireEVSigners,
					enableScriptEnforcement,
					testMode,
					true
				);

			});
		}
		finally
		{
			SignedAndReputableCreate.IsEnabled = true;
			EnableDeployButtons();
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
			new Run { Text = "Version: ", FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(Colors.Violet) },
			new Run { Text = $"{driverBlockListInfo.Version}\n", Foreground = new SolidColorBrush(Colors.Violet) }
		}
			};

			Span lastUpdatedSpan = new()
			{
				Inlines =
		{
			new Run { Text = "Last Updated: ", FontWeight = FontWeights.Bold, Foreground = new SolidColorBrush(Colors.HotPink) },
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
				Text = "Error retrieving driver block list information.",
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




	// Event handler for creating SignedAndReputable policy
	private async void RecommendedDriverBlockRulesCreate_Click(object sender, RoutedEventArgs e)
	{
		try
		{

			// Disable the buttons
			RecommendedDriverBlockRulesCreate.IsEnabled = false;
			RecommendedDriverBlockRulesCreateAndDeploy.IsEnabled = false;

			string stagingArea = StagingArea.NewStagingArea("BuildRecommendedDriverBlockRules").ToString();

			// Run the background operation using captured values
			await Task.Run(() =>
			{
				BasePolicyCreator.GetDriversBlockRules(stagingArea);
			});

			// Dynamically add the formatted TextBlock after gathering block list info
			// Can remove await and the info will populate after policy is created which is fine too
			await AddDriverBlockRulesInfo();

		}

		finally
		{

			// Re-enable buttons
			RecommendedDriverBlockRulesCreate.IsEnabled = true;
			RecommendedDriverBlockRulesCreateAndDeploy.IsEnabled = true;
		}
	}


	// Event handler for creating SignedAndReputable policy
	private async void RecommendedDriverBlockRulesCreateAndDeploy_Click(object sender, RoutedEventArgs e)
	{
		try
		{

			// Disable the buttons
			RecommendedDriverBlockRulesCreate.IsEnabled = false;
			DisableDeployButtons();

			string stagingArea = StagingArea.NewStagingArea("BuildRecommendedDriverBlockRules").ToString();

			// Run the background operation using captured values
			await Task.Run(() =>
			{
				BasePolicyCreator.DeployDriversBlockRules(stagingArea);
			});

			// Dynamically add the formatted TextBlock after gathering block list info
			// Can remove await and the info will populate after policy is created which is fine too
			await AddDriverBlockRulesInfo();
		}

		finally
		{

			// Re-enable buttons
			RecommendedDriverBlockRulesCreate.IsEnabled = true;
			EnableDeployButtons();
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
			RecommendedDriverBlockRulesInfoBar.IsClosable = false;
			RecommendedDriverBlockRulesInfoBar.IsOpen = true;
			RecommendedDriverBlockRulesInfoBar.Severity = InfoBarSeverity.Informational;
			RecommendedDriverBlockRulesInfoBar.Message = "Configuring Scheduled task for auto update";

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
				RecommendedDriverBlockRulesInfoBar.Message = $"An error occurred.";
			}
			else
			{
				RecommendedDriverBlockRulesInfoBar.Severity = InfoBarSeverity.Success;
				RecommendedDriverBlockRulesInfoBar.Message = "Successfully configured scheduled task to keep the Microsoft Drivers Block Rules up to date";
			}

		}

	}


	#endregion


	#region For Microsoft Recommended User Mode Block Rules

	// Event handler for creating SignedAndReputable policy
	private async void RecommendedUserModeBlockRulesCreate_Click(object sender, RoutedEventArgs e)
	{
		try
		{

			// Disable the buttons
			RecommendedUserModeBlockRulesCreate.IsEnabled = false;
			RecommendedUserModeBlockRulesCreateAndDeploy.IsEnabled = false;

			string stagingArea = StagingArea.NewStagingArea("BuildRecommendedUserModeBlockRules").ToString();

			// Run the background operation using captured values
			await Task.Run(() =>
			{
				BasePolicyCreator.GetBlockRules(stagingArea, false);
			});

		}

		finally
		{

			// Re-enable buttons
			RecommendedUserModeBlockRulesCreate.IsEnabled = true;
			RecommendedUserModeBlockRulesCreateAndDeploy.IsEnabled = true;
		}
	}


	// Event handler for creating SignedAndReputable policy
	private async void RecommendedUserModeBlockRulesCreateAndDeploy_Click(object sender, RoutedEventArgs e)
	{
		try
		{

			// Disable the buttons
			RecommendedUserModeBlockRulesCreate.IsEnabled = false;
			DisableDeployButtons();

			string stagingArea = StagingArea.NewStagingArea("BuildRecommendedUserModeBlockRules").ToString();

			// Run the background operation using captured values
			await Task.Run(() =>
			{
				BasePolicyCreator.GetBlockRules(stagingArea, true);

			});

		}

		finally
		{

			// Re-enable buttons
			RecommendedUserModeBlockRulesCreate.IsEnabled = true;
			EnableDeployButtons();
		}
	}




	#endregion


}
