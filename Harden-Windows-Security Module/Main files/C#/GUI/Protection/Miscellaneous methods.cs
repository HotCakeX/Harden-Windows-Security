using System;
using System.IO;
using System.Collections;
using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Markup;
using System.Xml;
using System.Windows.Media.Imaging;
using System.Linq;
using System.Windows.Forms;
using System.Collections.Concurrent;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Effects;
using System.Windows.Threading;
using System.Runtime.CompilerServices;
using System.Diagnostics;
using System.ComponentModel;
using System.Threading;
using System.Windows.Automation;
using System.Windows.Controls.Ribbon;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Forms.Integration;
using System.Windows.Ink;
using System.Windows.Media.Animation;
using System.Windows.Media.Media3D;
using System.Windows.Media.TextFormatting;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Windows.Shell;
using System.Threading.Tasks;
using System.Text;

#nullable enable

namespace HardenWindowsSecurity
{
    public partial class GUIProtectWinSecurity
    {

        /// <summary>
        /// A method to update sub-category items based on the checked categories
        /// </summary>
        private static void UpdateSubCategories()
        {
            // Disable all sub-category items first
            foreach (var item in GUIProtectWinSecurity.subCategories!.Items)
            {
                ((System.Windows.Controls.ListViewItem)item).IsEnabled = false;
            }

            // Get all checked categories
            var checkedCategories = GUIProtectWinSecurity.categories!.Items
                .Cast<System.Windows.Controls.ListViewItem>()
                .Where(item => ((System.Windows.Controls.CheckBox)item.Content).IsChecked == true)
                .ToList();

            // Enable the corresponding sub-category items
            foreach (var categoryItem in checkedCategories)
            {
                string categoryContent = ((System.Windows.Controls.CheckBox)categoryItem.Content).Name;
                if (GUIProtectWinSecurity.correlation.Contains(categoryContent))
                {
                    if (GUIProtectWinSecurity.correlation[categoryContent] is string[] subCategoryNames)
                    {
                        foreach (string subCategoryName in subCategoryNames)
                        {
                            foreach (var item in GUIProtectWinSecurity.subCategories.Items)
                            {
                                System.Windows.Controls.ListViewItem subCategoryItem = (System.Windows.Controls.ListViewItem)item;
                                if (((System.Windows.Controls.CheckBox)subCategoryItem.Content).Name == subCategoryName)
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
                System.Windows.Controls.ListViewItem subCategoryItem = (System.Windows.Controls.ListViewItem)item;
                if (!subCategoryItem.IsEnabled)
                {
                    ((System.Windows.Controls.CheckBox)subCategoryItem.Content).IsChecked = false;
                }
            }

            if (HardenWindowsSecurity.GlobalVars.HardeningCategorieX == null)
            {
                throw new System.ArgumentNullException("GlobalVars.HardeningCategorieX cannot be null.");
            }

            // Disable categories that are not valid for the current session
            foreach (var item in GUIProtectWinSecurity.categories.Items)
            {
                System.Windows.Controls.ListViewItem categoryItem = (System.Windows.Controls.ListViewItem)item;
                if (!HardenWindowsSecurity.GlobalVars.HardeningCategorieX.Contains(((System.Windows.Controls.CheckBox)categoryItem.Content).Name))
                {
                    categoryItem.IsEnabled = false;
                }
            }
        }


        // Method to disable the Offline Mode configuration inputs
        private static void DisableOfflineModeConfigInputs()
        {
            GUIProtectWinSecurity.microsoftSecurityBaselineZipButton!.IsEnabled = false;
            GUIProtectWinSecurity.microsoftSecurityBaselineZipTextBox!.IsEnabled = false;
            GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipButton!.IsEnabled = false;
            GUIProtectWinSecurity.microsoft365AppsSecurityBaselineZipTextBox!.IsEnabled = false;
            GUIProtectWinSecurity.lgpoZipButton!.IsEnabled = false;
            GUIProtectWinSecurity.lgpoZipTextBox!.IsEnabled = false;
        }

    }
}
