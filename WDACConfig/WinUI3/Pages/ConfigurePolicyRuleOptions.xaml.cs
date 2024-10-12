using CommunityToolkit.WinUI.Controls;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using System;
using System.Collections.Generic;
using System.Linq;
using static WDACConfig.CiRuleOptions;

namespace WDACConfig.Pages
{
    public sealed partial class ConfigurePolicyRuleOptions : Page
    {
        // Property to hold the keys of the PolicyRuleOptionsActual dictionary
        public List<string> PolicyRuleOptionsKeys { get; set; }

        public ConfigurePolicyRuleOptions()
        {
            this.InitializeComponent();

            this.NavigationCacheMode = Microsoft.UI.Xaml.Navigation.NavigationCacheMode.Enabled;

            // Initialize the keys property with dictionary keys
            PolicyRuleOptionsKeys = WDACConfig.CiRuleOptions.PolicyRuleOptionsActual.Keys.ToList();

            // Call the method to generate SettingsCards dynamically
            GenerateSettingsCards();

            // Register click events for buttons
            ResetSelections.Click += ResetSelections_Click;
            Add.Click += Add_Click;
            Remove.Click += Remove_Click;

            // Register the click event for the new Set button in the PolicyTemplate section
            SetPolicyTemplate.Click += SetPolicyTemplate_Click;

            // Register the click event for the new Select All button
            SelectAll.Click += SelectAll_Click;
        }

        // Method to dynamically create SettingsCards based on the dictionary keys
        private void GenerateSettingsCards()
        {
            foreach (var key in PolicyRuleOptionsKeys)
            {
                // Create a new SettingsCard
                var settingsCard = new SettingsCard
                {
                    ContentAlignment = CommunityToolkit.WinUI.Controls.ContentAlignment.Left
                };

                // Create a new CheckBox
                var checkBox = new CheckBox
                {
                    // Set the content to the key from the dictionary
                    Content = key
                };

                // Add the CheckBox to the SettingsCard
                settingsCard.Content = checkBox;

                // Add the SettingsCard to the SettingsExpander.Items collection
                PolicyRuleExpander.Items.Add(settingsCard);
            }
        }

        // Event handler for the browse button
        private void PickPolicyFileButton_Click(object sender, RoutedEventArgs e)
        {
            string? selectedFile = WDACConfig.FileSystemPicker.ShowFilePicker(
                "Choose a Configuration File", ("XML Files", "*.xml"));

            if (!string.IsNullOrEmpty(selectedFile))
            {
                // Handle file processing here
                SelectedFilePath.Text = selectedFile;
            }
        }


        // Event handler for the ResetSelections button click
        private void ResetSelections_Click(object sender, RoutedEventArgs e)
        {
            // Iterate through each SettingsCard in the PolicyRuleExpander
            foreach (var item in PolicyRuleExpander.Items)
            {
                if (item is SettingsCard settingsCard && settingsCard.Content is CheckBox checkBox)
                {
                    // Uncheck the CheckBox
                    checkBox.IsChecked = false;
                }
            }
        }


        // Event handler for the Add button click
        private void Add_Click(object sender, RoutedEventArgs e)
        {
            // Get the path of the selected file
            string filePath = SelectedFilePath.Text;

            if (string.IsNullOrWhiteSpace(filePath))
            {
                ShowMessage("Please select a policy file before adding options.");
                return;
            }

            // Gather selected rules to add
            var selectedOptions = GetSelectedPolicyRuleOptions();

            // Call the Set method with selected options to add
            WDACConfig.CiRuleOptions.Set(filePath, rulesToAdd: selectedOptions);
        }


        // Event handler for the Remove button click
        private void Remove_Click(object sender, RoutedEventArgs e)
        {
            // Get the path of the selected file
            string filePath = SelectedFilePath.Text;

            if (string.IsNullOrWhiteSpace(filePath))
            {
                ShowMessage("Please select a policy file before removing options.");
                return;
            }

            // Gather selected rules to remove
            var selectedOptions = GetSelectedPolicyRuleOptions();

            // Call the Set method with selected options to remove
            WDACConfig.CiRuleOptions.Set(filePath, rulesToRemove: selectedOptions);
        }


        // Event handler for the Set button click in the PolicyTemplate section
        private void SetPolicyTemplate_Click(object sender, RoutedEventArgs e)
        {
            // Get the path of the selected file
            string filePath = SelectedFilePath.Text;

            if (string.IsNullOrWhiteSpace(filePath))
            {
                ShowMessage("Please select a policy file before setting a template.");
                return;
            }

            // Retrieve the selected item from the ComboBox
            ComboBoxItem? selectedComboBoxItem = PolicyTemplatesComboBox.SelectedItem as ComboBoxItem;

            if (selectedComboBoxItem == null)
            {
                ShowMessage("Please select a policy template from the dropdown.");
                return;
            }

            // Convert the ComboBoxItem content to the corresponding PolicyTemplate enum value
            PolicyTemplate template;
            if (!Enum.TryParse(selectedComboBoxItem.Content.ToString(), out template))
            {
                ShowMessage("Invalid policy template selected. Please choose a valid option.");
                return;
            }

            // Call the Set method with only the filePath and template parameters
            WDACConfig.CiRuleOptions.Set(filePath, template: template);
        }


        // Helper method to get selected policy rule options from the UI checkboxes
        private PolicyRuleOptions[] GetSelectedPolicyRuleOptions()
        {
            var selectedRules = new List<PolicyRuleOptions>();

            // Iterate through each SettingsCard in the PolicyRuleExpander
            foreach (var item in PolicyRuleExpander.Items)
            {
                if (item is SettingsCard settingsCard && settingsCard.Content is CheckBox checkBox && checkBox.IsChecked == true)
                {
                    // Get the content of the checkbox, which is the dictionary key
                    string? key = checkBox.Content?.ToString();

                    if (!string.IsNullOrEmpty(key) && WDACConfig.CiRuleOptions.PolicyRuleOptionsActual.TryGetValue(key, out int value))
                    {
                        // Convert to PolicyRuleOptions enum and add to the list
                        selectedRules.Add((PolicyRuleOptions)value);
                    }
                }
            }

            return selectedRules.ToArray();
        }


        // Event handler for the "Select All" button click
        private void SelectAll_Click(object sender, RoutedEventArgs e)
        {
            // Iterate through each SettingsCard in the PolicyRuleExpander
            foreach (var item in PolicyRuleExpander.Items)
            {
                if (item is SettingsCard settingsCard && settingsCard.Content is CheckBox checkBox)
                {
                    // Set the CheckBox to checked
                    checkBox.IsChecked = true;
                }
            }
        }


        // Helper method to show a simple message dialog
        private async void ShowMessage(string message)
        {
            var dialog = new ContentDialog
            {
                Title = "Information",
                Content = message,
                CloseButtonText = "OK",
                XamlRoot = this.Content.XamlRoot
            };
            _ = await dialog.ShowAsync();
        }
    }
}
