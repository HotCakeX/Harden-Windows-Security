using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using System;
using System.Threading.Tasks;
using Windows.ApplicationModel;

namespace WDACConfig.Pages
{

    public sealed partial class Update : Page
    {
        public Update()
        {
            this.InitializeComponent();

            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Enabled;
        }

        private async void CheckForUpdateButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {

            try
            {

                CheckForUpdateButton.IsEnabled = false;
                UpdateStatusInfoBar.IsOpen = true;
                UpdateStatusInfoBar.Message = "Checking for update and installing the new version if available. Please keep the app open.";
                UpdateStatusInfoBar.Severity = InfoBarSeverity.Informational;

                // To save the output of the PowerShell
                string? psOutput = null;

                // Run the update check in a separate thread and asynchronously wait for its completion
                await Task.Run(() =>
                 {
                     // Get the current app's version
                     PackageVersion packageVersion = Package.Current.Id.Version;

                     // Convert it to a normal Version object
                     Version currentAppVersion = new(packageVersion.Major, packageVersion.Minor, packageVersion.Build, packageVersion.Revision);

                     // Run the PowerShell script to check for updates and save the output code
                     psOutput = PowerShellExecutor.ExecuteScript($"""
$VerbosePreference = 'Continue';
(irm 'https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/Harden-Windows-Security.ps1')+'AppControl -CheckForUpdate {currentAppVersion}'|iex
""", true);
                 });


                if (psOutput is not null && string.Equals(psOutput, "420", StringComparison.OrdinalIgnoreCase))
                {
                    UpdateStatusInfoBar.Message = "The current version is already up to date.";
                    UpdateStatusInfoBar.Severity = InfoBarSeverity.Success;
                }
                else if (psOutput is not null && string.Equals(psOutput, "8200", StringComparison.OrdinalIgnoreCase))
                {
                    UpdateStatusInfoBar.Message = "Successfully installed the latest version. Please close and reopen the AppControl Manager to use the new version.";
                    UpdateStatusInfoBar.Severity = InfoBarSeverity.Success;
                }
                else
                {
                    UpdateStatusInfoBar.Message = psOutput;
                    UpdateStatusInfoBar.Severity = InfoBarSeverity.Warning;
                }

            }

            catch
            {
                UpdateStatusInfoBar.Severity = InfoBarSeverity.Error;
                UpdateStatusInfoBar.Message = "An error occurred while checking for update.";
                throw;
            }

            finally
            {
                UpdateStatusInfoBar.IsClosable = true;

                CheckForUpdateButton.IsEnabled = true;
            }

        }


        #region
        private void CheckForUpdateButton_PointerEntered(object sender, PointerRoutedEventArgs e)
        {
            CheckForUpdateButtonTeachingTip.IsOpen = true;
        }

        private void CheckForUpdateButton_PointerExited(object sender, PointerRoutedEventArgs e)
        {
            CheckForUpdateButtonTeachingTip.IsOpen = false;
        }

        private void CheckForUpdateButton_PointerPressed(object sender, PointerRoutedEventArgs e)
        {
            CheckForUpdateButtonTeachingTip.IsOpen = false;
        }
        #endregion
    }
}
