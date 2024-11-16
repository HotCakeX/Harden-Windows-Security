using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Globalization;
using static WDACConfig.AppSettings;

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

            // Set the version in the settings card to the current app version
            VersionTextBlock.Text = $"Version {App.currentAppVersion}";

            // Set the year for the copyright section
            CopyRightSettingsExpander.Description = $"� {DateTime.Now.Year}. All rights reserved.";


            #region Load the user configurations in the UI elements

            NavigationViewBackgroundToggle.IsOn = AppSettings.GetSetting<bool>(SettingKeys.NavViewBackground);

            SoundToggleSwitch.IsOn = AppSettings.GetSetting<bool>(SettingKeys.SoundSetting);

            BackgroundComboBox.SelectedIndex = (AppSettings.GetSetting<string>(SettingKeys.BackDropBackground)) switch
            {
                "MicaAlt" => 0,
                "Mica" => 1,
                "Acrylic" => 2,
                _ => 0
            };


            ThemeComboBox.SelectedIndex = (AppSettings.GetSetting<string>(SettingKeys.AppTheme)) switch
            {
                "Use System Setting" => 0,
                "Dark" => 1,
                "Light" => 2,
                _ => 0
            };

            #endregion


            // Instead of defining the events in the XAML, defining them here after performing changes on the UI elements based on the saved settings
            // This way we don't trigger the event handlers just by changing UI element values
            // Since queries for saved settings already happen in the Main Window, App and other respective places
            // This also Prevents a dark flash when using brighter theme because of triggering events twice unnecessarily.
            NavigationViewBackgroundToggle.Toggled += NavigationViewBackground_Toggled;
            BackgroundComboBox.SelectionChanged += BackgroundComboBox_SelectionChanged;
            ThemeComboBox.SelectionChanged += ThemeComboBox_SelectionChanged;
            NavigationMenuLocation.SelectionChanged += NavigationViewLocationComboBox_SelectionChanged;
            SoundToggleSwitch.Toggled += SoundToggleSwitch_Toggled;

        }


        /// <summary>
        /// Event handler for the Background ComboBox selection change event.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void BackgroundComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Get the ComboBox that triggered the event
            ComboBox? comboBox = sender as ComboBox;

            // Get the selected item from the ComboBox
            string? selectedBackdrop = (comboBox?.SelectedItem as ComboBoxItem)?.Content.ToString();

            if (selectedBackdrop is not null)
            {
                // Raise the global BackgroundChanged event
                ThemeManager.OnBackgroundChanged(selectedBackdrop);
            }

            AppSettings.SaveSetting(AppSettings.SettingKeys.BackDropBackground, selectedBackdrop);
        }




        /// <summary>
        /// Event handler for the NavigationViewLocation ComboBox selection change event.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void NavigationViewLocationComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            // Get the ComboBox that triggered the event
            ComboBox? comboBox = sender as ComboBox;

            // Get the selected item from the ComboBox
            string? selectedLocation = (comboBox?.SelectedItem as ComboBoxItem)?.Content?.ToString();

            if (selectedLocation is not null)
            {
                // Raise the global OnNavigationViewLocationChanged event
                NavigationViewLocationManager.OnNavigationViewLocationChanged(selectedLocation);
            }
        }



        /// <summary>
        /// Event handler for the Theme ComboBox selection change event.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void ThemeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {

            // Get the ComboBox that triggered the event
            ComboBox? comboBox = sender as ComboBox;

            // Get the selected item from the ComboBox
            string? selectedTheme = (comboBox?.SelectedItem as ComboBoxItem)?.Content?.ToString();

            if (selectedTheme is not null)
            {
                // Raise the global BackgroundChanged event
                AppThemeManager.OnAppThemeChanged(selectedTheme);
            }


            AppSettings.SaveSetting(AppSettings.SettingKeys.AppTheme, selectedTheme);
        }


        /// <summary>
        /// Event handler for the NavigationViewBackground toggle switch change event.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void NavigationViewBackground_Toggled(object sender, RoutedEventArgs e)
        {
            // Get the ToggleSwitch that triggered the event
            ToggleSwitch? toggleSwitch = sender as ToggleSwitch;

            // Get the state of the ToggleSwitch
            // Use false as a fallback if toggleSwitch is null
            bool isBackgroundOn = toggleSwitch?.IsOn ?? false;

            // Notify NavigationBackgroundManager when the toggle switch is changed
            NavigationBackgroundManager.OnNavigationBackgroundChanged(isBackgroundOn);

            AppSettings.SaveSetting(AppSettings.SettingKeys.NavViewBackground, isBackgroundOn);
        }



        /// <summary>
        /// Event handler for the Sound toggle switch change event.
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void SoundToggleSwitch_Toggled(object sender, RoutedEventArgs e)
        {
            // Get the state of the toggle switch (on or off)
            var toggleSwitch = sender as ToggleSwitch;
            bool isSoundOn = toggleSwitch?.IsOn ?? false;

            // Raise the event to notify the app of the sound setting change
            SoundManager.OnSoundSettingChanged(isSoundOn);

            // Save the sound setting to the local app settings
            AppSettings.SaveSetting(AppSettings.SettingKeys.SoundSetting, isSoundOn);
        }


        // When the button to get the user configurations on the settings card is pressed
        private void GetConfigurationButton_Click(object sender, RoutedEventArgs e)
        {
            UserConfiguration userConfig = UserConfiguration.Get();

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
        private void EditButton_Click(object sender, RoutedEventArgs e)
        {
            Button? button = sender as Button;
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

            _ = UserConfiguration.Set(
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
        private void ClearButton_Click(object sender, RoutedEventArgs e)
        {
            Button? button = sender as Button;
            string? fieldName = button!.Tag.ToString();

            UserConfiguration.Remove(
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
        private void BrowseButton_Click(object sender, RoutedEventArgs e)
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
