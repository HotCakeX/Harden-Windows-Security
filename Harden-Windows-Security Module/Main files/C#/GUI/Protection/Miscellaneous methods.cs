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
using System.Reflection.PortableExecutable;

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

        /// <summary>
        /// This method runs at the end after execute button is pressed
        /// </summary>
        public static void EnableUIElements()
        {
            HardenWindowsSecurity.GUIProtectWinSecurity.window!.Dispatcher.Invoke(() =>
            {
                // Enable the disabled UI elements once all of the commands have been executed
                // Manually trigger the ToggleButton to be unchecked
                HardenWindowsSecurity.GUIProtectWinSecurity.ExecuteButton!.IsChecked = false;
                HardenWindowsSecurity.GUIProtectWinSecurity.ExecuteButton.IsEnabled = true;
                HardenWindowsSecurity.GUIProtectWinSecurity.mainTabControlToggle!.IsEnabled = true;
                HardenWindowsSecurity.GUIProtectWinSecurity.logPath!.IsEnabled = true;
                HardenWindowsSecurity.GUIProtectWinSecurity.loggingViewBox!.IsEnabled = true;

                // Only enable the log file path textbox if the log toggle button is toggled
                if (GUIProtectWinSecurity.log!.IsChecked == true)
                {
                    HardenWindowsSecurity.GUIProtectWinSecurity.txtFilePath!.IsEnabled = true;
                }

                HardenWindowsSecurity.GUIProtectWinSecurity.mainProgressBar!.Visibility = Visibility.Collapsed;
            });
        }

        /// <summary>
        /// This method runs at the beginning when execute button is pressed
        /// </summary>
        public static void DisableUIElements()
        {
            HardenWindowsSecurity.GUIProtectWinSecurity.window!.Dispatcher.Invoke(() =>
            {
                // Disable Important elements while commands are being executed
                HardenWindowsSecurity.GUIProtectWinSecurity.ExecuteButton!.IsEnabled = false;
                HardenWindowsSecurity.GUIProtectWinSecurity.mainTabControlToggle!.IsEnabled = false;
                HardenWindowsSecurity.GUIProtectWinSecurity.logPath!.IsEnabled = false;
                HardenWindowsSecurity.GUIProtectWinSecurity.loggingViewBox!.IsEnabled = false;
                HardenWindowsSecurity.GUIProtectWinSecurity.txtFilePath!.IsEnabled = false;
                HardenWindowsSecurity.GUIProtectWinSecurity.mainProgressBar!.Visibility = Visibility.Visible;
            });
        }

        /// <summary>
        /// When the execute button is pressed, this method is called
        /// </summary>
        public static void ExecuteButtonPress()
        {

#nullable disable

            // Clear the categories and sub-categories lists
            HardenWindowsSecurity.GUIProtectWinSecurity.SelectedCategories = new System.Collections.Concurrent.ConcurrentQueue<string>();
            HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories = new System.Collections.Concurrent.ConcurrentQueue<string>();

            // Gather selected categories and sub-categories and store them in the GlobalVars hashtable
            System.Collections.IEnumerable categoriesItems = HardenWindowsSecurity.GUIProtectWinSecurity.categories!.Items;
            System.Collections.IEnumerable subCategoriesItems = HardenWindowsSecurity.GUIProtectWinSecurity.subCategories!.Items;

            foreach (System.Windows.Controls.ListBoxItem categoryItem in categoriesItems)
            {
                if ((bool)((System.Windows.Controls.CheckBox)categoryItem.Content).IsChecked)
                {
                    string categoryName = ((System.Windows.Controls.CheckBox)categoryItem.Content).Name;
                    HardenWindowsSecurity.GUIProtectWinSecurity.SelectedCategories.Enqueue(categoryName);
                }
            }

            foreach (System.Windows.Controls.ListBoxItem subCategoryItem in subCategoriesItems)
            {
                if ((bool)((System.Windows.Controls.CheckBox)subCategoryItem.Content).IsChecked)
                {
                    string subCategoryName = ((System.Windows.Controls.CheckBox)subCategoryItem.Content).Name;
                    HardenWindowsSecurity.GUIProtectWinSecurity.SelectedSubCategories.Enqueue(subCategoryName);
                }
            }

#nullable enable
        }
    }
}
