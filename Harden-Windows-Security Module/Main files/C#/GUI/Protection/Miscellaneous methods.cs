using System;
using System.Linq;
using System.Windows.Controls;

#nullable enable

namespace HardenWindowsSecurity
{
    public static partial class GUIProtectWinSecurity
    {

        /// <summary>
        /// A method to update sub-category items based on the checked categories
        /// </summary>
        public static void UpdateSubCategories()
        {
            // Disable all sub-category items first
            foreach (var item in GUIProtectWinSecurity.subCategories!.Items)
            {
                ((ListViewItem)item).IsEnabled = false;
            }

            // Get all checked categories
            var checkedCategories = GUIProtectWinSecurity.categories!.Items
                .Cast<ListViewItem>()
                .Where(item => ((CheckBox)item.Content).IsChecked == true)
                .ToList();

            // Enable the corresponding sub-category items
            foreach (var categoryItem in checkedCategories)
            {
                string categoryContent = ((CheckBox)categoryItem.Content).Name;
                if (GUIProtectWinSecurity.correlation.Contains(categoryContent))
                {
                    if (GUIProtectWinSecurity.correlation[categoryContent] is string[] subCategoryNames)
                    {
                        foreach (string subCategoryName in subCategoryNames)
                        {
                            foreach (var item in GUIProtectWinSecurity.subCategories.Items)
                            {
                                ListViewItem subCategoryItem = (ListViewItem)item;
                                if (((CheckBox)subCategoryItem.Content).Name == subCategoryName)
                                {
                                    subCategoryItem.IsEnabled = true;
                                }
                            }
                        }
                    }
                }
            }

            // Uncheck sub-category items whose category is not selected
            foreach (var item in GUIProtectWinSecurity.subCategories.Items)
            {
                ListViewItem subCategoryItem = (ListViewItem)item;
                if (!subCategoryItem.IsEnabled)
                {
                    ((CheckBox)subCategoryItem.Content).IsChecked = false;
                }
            }

            if (HardenWindowsSecurity.GlobalVars.HardeningCategorieX is null)
            {
                throw new System.ArgumentNullException("GlobalVars.HardeningCategorieX cannot be null.");
            }

            // Disable categories that are not valid for the current session
            foreach (var item in GUIProtectWinSecurity.categories.Items)
            {
                ListViewItem categoryItem = (ListViewItem)item;
                if (!HardenWindowsSecurity.GlobalVars.HardeningCategorieX.Contains(((CheckBox)categoryItem.Content).Name))
                {
                    categoryItem.IsEnabled = false;
                }
            }
        }


        // Method to disable the Offline Mode configuration inputs
        public static void DisableOfflineModeConfigInputs()
        {
            GUIProtectWinSecurity.microsoftSecurityBaselineZipButton!.IsEnabled = false;
            GUIProtectWinSecurity.microsoftSecurityBaselineZipTextBox!.IsEnabled = false;
            GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipButton!.IsEnabled = false;
            GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipTextBox!.IsEnabled = false;
            GUIProtectWinSecurity.lgpoZipButton!.IsEnabled = false;
            GUIProtectWinSecurity.lgpoZipTextBox!.IsEnabled = false;
        }

        /// <summary>
        /// When the execute button is pressed, this method is called to gather the selected categories and sub-categories
        /// </summary>
        public static void ExecuteButtonPress()
        {

#nullable disable

            // Clear the categories and sub-categories lists from the saved variables
            HardenWindowsSecurity.GUIProtectWinSecurity.SelectedCategories = new System.Collections.Concurrent.ConcurrentQueue<string>();
            HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories = new System.Collections.Concurrent.ConcurrentQueue<string>();

            // Gather the selected categories and sub-categories and store them in the GlobalVars hashtable
            System.Collections.IEnumerable categoriesItems = HardenWindowsSecurity.GUIProtectWinSecurity.categories!.Items;
            System.Collections.IEnumerable subCategoriesItems = HardenWindowsSecurity.GUIProtectWinSecurity.subCategories!.Items;

            // Get the Categories status and add them to the variables
            foreach (System.Windows.Controls.ListBoxItem categoryItem in categoriesItems)
            {
                if ((bool)((CheckBox)categoryItem.Content).IsChecked)
                {
                    string categoryName = ((CheckBox)categoryItem.Content).Name;
                    HardenWindowsSecurity.GUIProtectWinSecurity.SelectedCategories.Enqueue(categoryName);
                }
            }

            // Get the Sub-Categories status and add them to the variables
            foreach (System.Windows.Controls.ListBoxItem subCategoryItem in subCategoriesItems)
            {
                if ((bool)((CheckBox)subCategoryItem.Content).IsChecked)
                {
                    string subCategoryName = ((CheckBox)subCategoryItem.Content).Name;
                    HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Enqueue(subCategoryName);
                }
            }

#nullable enable
        }
    }
}
