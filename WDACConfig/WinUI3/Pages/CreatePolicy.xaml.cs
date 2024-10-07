using Microsoft.UI.Xaml.Controls;
using System;
using System.IO;

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
        private void AllowMicrosoftCreate_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {

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

            BasePolicyCreator.BuildAllowMSFT(stagingArea,
                AllowMicrosoftAudit.IsOn,
                logSize,
                false, // Do not deploy, only create
                AllowMicrosoftRequireEVSigners.IsOn,
                AllowMicrosoftEnableScriptEnforcement.IsOn,
                AllowMicrosoftTestMode.IsOn
                );
        }


        // Event handler for creating & deploying AllowMicrosoft policy
        private void AllowMicrosoftCreateAndDeploy_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {
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

            BasePolicyCreator.BuildAllowMSFT(stagingArea,
                AllowMicrosoftAudit.IsOn,
                logSize,
                true, // Deploy it as well
                AllowMicrosoftRequireEVSigners.IsOn,
                AllowMicrosoftEnableScriptEnforcement.IsOn,
                AllowMicrosoftTestMode.IsOn
                );
        }



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
        private void SignedAndReputableCreate_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {

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

            BasePolicyCreator.BuildSignedAndReputable(stagingArea,
                SignedAndReputableAudit.IsOn,
                logSize,
                false, // Do not deploy, only create
                SignedAndReputableRequireEVSigners.IsOn,
                SignedAndReputableEnableScriptEnforcement.IsOn,
                SignedAndReputableTestMode.IsOn
                );
        }


        // Event handler for creating & deploying SignedAndReputable policy
        private void SignedAndReputableCreateAndDeploy_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {
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

            BasePolicyCreator.BuildSignedAndReputable(stagingArea,
                SignedAndReputableAudit.IsOn,
                logSize,
                false, // Do not deploy, only create
                SignedAndReputableRequireEVSigners.IsOn,
                SignedAndReputableEnableScriptEnforcement.IsOn,
                SignedAndReputableTestMode.IsOn
                );
        }



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
