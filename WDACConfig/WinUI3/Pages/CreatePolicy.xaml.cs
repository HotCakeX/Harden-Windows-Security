using Microsoft.UI.Xaml.Controls;
using System;
using System.Threading.Tasks;

namespace WDACConfig.Pages
{
    public sealed partial class CreatePolicy : Page
    {
        public CreatePolicy()
        {
            this.InitializeComponent();

            // Initially set it to disabled until the switch is toggled
            AllowMicrosoftLogSizeInput.IsEnabled = false;

            // Initially set it to disabled until the switch is toggled
            SignedAndReputableLogSizeInput.IsEnabled = false;

            // Make sure navigating to/from this page maintains its state
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Enabled;

        }


        #region For Allow Microsoft Policy

        // Event handler for creating AllowMicrosoft policy
        private async void AllowMicrosoftCreate_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
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
                        testMode
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
        private async void AllowMicrosoftCreateAndDeploy_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {

            try
            {

                // Disable the buttons to prevent multiple clicks
                AllowMicrosoftCreate.IsEnabled = false;
                AllowMicrosoftCreateAndDeploy.IsEnabled = false;

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
                        testMode
                    );
                });

            }
            finally
            {

                // Re-enable the buttons once the work is done
                AllowMicrosoftCreate.IsEnabled = true;
                AllowMicrosoftCreateAndDeploy.IsEnabled = true;

            }
        }

        // Event handler for the ToggleSwitch to enable/disable the log size input
        private void AllowMicrosoftLogSizeInputEnabled_Toggled(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
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

        #endregion


        #region For Signed and Reputable Policy

        // Event handler for creating SignedAndReputable policy
        private async void SignedAndReputableCreate_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
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
                        testMode
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
        private async void SignedAndReputableCreateAndDeploy_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {

            try
            {

                // Disable the buttons
                SignedAndReputableCreate.IsEnabled = false;
                SignedAndReputableCreateAndDeploy.IsEnabled = false;

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
                        testMode
                    );
                });
            }
            finally
            {
                SignedAndReputableCreate.IsEnabled = true;
                SignedAndReputableCreateAndDeploy.IsEnabled = true;
            }
        }

        // Event handler for the ToggleSwitch to enable/disable the log size input
        private void SignedAndReputableLogSizeInputEnabled_Toggled(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
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

        #endregion
    }
}
