using Microsoft.UI.Xaml.Controls;
using System;
using System.Globalization;

#nullable enable

namespace WDACConfig.Pages
{
    public sealed partial class Settings : Page
    {
        public Settings()
        {
            this.InitializeComponent();

            // Make sure navigating to/from this page maintains its state
            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Enabled;
        }

        // When the button to get the user configurations on the settings card is pressed
        private void GetConfigurationButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {
            var userConfig = WDACConfig.UserConfiguration.Get();

            SignedPolicyPathTextBox.Text = userConfig.SignedPolicyPath ?? string.Empty;
            UnsignedPolicyPathTextBox.Text = userConfig.UnsignedPolicyPath ?? string.Empty;
            SignToolCustomPathTextBox.Text = userConfig.SignToolCustomPath ?? string.Empty;
            CertificateCommonNameTextBox.Text = userConfig.CertificateCommonName ?? string.Empty;
            CertificatePathTextBox.Text = userConfig.CertificatePath ?? string.Empty;
            StrictKernelPolicyGUIDTextBox.Text = userConfig.StrictKernelPolicyGUID?.ToString() ?? string.Empty;
            StrictKernelNoFlightRootsPolicyGUIDTextBox.Text = userConfig.StrictKernelNoFlightRootsPolicyGUID?.ToString() ?? string.Empty;
            LastUpdateCheckTextBox.Text = userConfig.LastUpdateCheck?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? string.Empty;
            StrictKernelModePolicyTimeTextBox.Text = userConfig.StrictKernelModePolicyTimeOfDeployment?.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) ?? string.Empty;
        }

        // When the edit button of any field is pressed
        private void EditButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {
            var button = sender as Button;
            string? fieldName = button!.Tag.ToString();
            string? newValue = null;

            // Determine the new value based on the associated TextBox
            switch (fieldName)
            {
                case "SignedPolicyPath":
                    newValue = SignedPolicyPathTextBox.Text;
                    break;
                case "UnsignedPolicyPath":
                    newValue = UnsignedPolicyPathTextBox.Text;
                    break;
                case "SignToolCustomPath":
                    newValue = SignToolCustomPathTextBox.Text;
                    break;
                case "CertificateCommonName":
                    newValue = CertificateCommonNameTextBox.Text;
                    break;
                case "CertificatePath":
                    newValue = CertificatePathTextBox.Text;
                    break;
                case "StrictKernelPolicyGUID":
                    newValue = StrictKernelPolicyGUIDTextBox.Text;
                    break;
                case "StrictKernelNoFlightRootsPolicyGUID":
                    newValue = StrictKernelNoFlightRootsPolicyGUIDTextBox.Text;
                    break;
                case "LastUpdateCheck":
                    newValue = LastUpdateCheckTextBox.Text;
                    break;
                case "StrictKernelModePolicyTime":
                    newValue = StrictKernelModePolicyTimeTextBox.Text;
                    break;
                default:
                    break;
            }

            _ = WDACConfig.UserConfiguration.Set(
                fieldName == "SignedPolicyPath" ? newValue : null,
                fieldName == "UnsignedPolicyPath" ? newValue : null,
                fieldName == "SignToolCustomPath" ? newValue : null,
                fieldName == "CertificateCommonName" ? newValue : null,
                fieldName == "CertificatePath" ? newValue : null,
                fieldName == "StrictKernelPolicyGUID" ? TryParseGuid(newValue) : null,
                fieldName == "StrictKernelNoFlightRootsPolicyGUID" ? TryParseGuid(newValue) : null,
                fieldName == "LastUpdateCheck" ? TryParseDateTime(newValue) : null,
                fieldName == "StrictKernelModePolicyTime" ? TryParseDateTime(newValue) : null
            );

            Logger.Write($"Edited {fieldName} to {newValue}");
        }

        // When the clear button of any field is pressed
        private void ClearButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {
            var button = sender as Button;
            string? fieldName = button!.Tag.ToString();

            WDACConfig.UserConfiguration.Remove(
                fieldName == "SignedPolicyPath",
                fieldName == "UnsignedPolicyPath",
                fieldName == "SignToolCustomPath",
                fieldName == "CertificateCommonName",
                fieldName == "CertificatePath",
                fieldName == "StrictKernelPolicyGUID",
                fieldName == "StrictKernelNoFlightRootsPolicyGUID",
                fieldName == "LastUpdateCheck",
                fieldName == "StrictKernelModePolicyTime"
            );

            switch (fieldName)
            {
                case "SignedPolicyPath":
                    SignedPolicyPathTextBox.Text = string.Empty;
                    break;
                case "UnsignedPolicyPath":
                    UnsignedPolicyPathTextBox.Text = string.Empty;
                    break;
                case "SignToolCustomPath":
                    SignToolCustomPathTextBox.Text = string.Empty;
                    break;
                case "CertificateCommonName":
                    CertificateCommonNameTextBox.Text = string.Empty;
                    break;
                case "CertificatePath":
                    CertificatePathTextBox.Text = string.Empty;
                    break;
                case "StrictKernelPolicyGUID":
                    StrictKernelPolicyGUIDTextBox.Text = string.Empty;
                    break;
                case "StrictKernelNoFlightRootsPolicyGUID":
                    StrictKernelNoFlightRootsPolicyGUIDTextBox.Text = string.Empty;
                    break;
                case "LastUpdateCheck":
                    LastUpdateCheckTextBox.Text = string.Empty;
                    break;
                case "StrictKernelModePolicyTime":
                    StrictKernelModePolicyTimeTextBox.Text = string.Empty;
                    break;
                default:
                    break;
            }

            Logger.Write($"Cleared {fieldName}");
        }


        #region Methods to parse the input values without throwing errors
        private static Guid? TryParseGuid(string? input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return null;

            return Guid.TryParse(input, out var result) ? result : null;
        }

        private static DateTime? TryParseDateTime(string? input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return null;

            return DateTime.TryParse(input, CultureInfo.InvariantCulture, DateTimeStyles.None, out var result) ? result : null;
        }
        #endregion


        // When the browse button of any field is pressed
        private void BrowseButton_Click(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
        {
            var button = sender as Button;
            string? fieldName = button!.Tag.ToString();

            switch (fieldName)
            {
                case "SignedPolicyPath":
                    SignedPolicyPathTextBox.Text = FileSystemPicker.ShowFilePicker("Choose a Signed Policy XML File path", ("XML Files", "*.xml"));
                    break;
                case "UnsignedPolicyPath":
                    UnsignedPolicyPathTextBox.Text = FileSystemPicker.ShowFilePicker("Choose an Unsigned Policy XML File path", ("XML Files", "*.xml"));
                    break;
                case "SignToolCustomPath":
                    SignToolCustomPathTextBox.Text = FileSystemPicker.ShowFilePicker("Choose the SignTool.exe path", ("Exe Files", "*.exe"));
                    break;
                case "CertificatePath":
                    CertificatePathTextBox.Text = FileSystemPicker.ShowFilePicker("Choose the Certificate file path", ("Cert Files", "*.cer"));
                    break;
                default:
                    break;
            }

        }
    }
}
