// MIT License
//
// Copyright (c) 2023-Present - Violet Hansen - (aka HotCakeX on GitHub) - Email Address: spynetgirl@outlook.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// See here for more information: https://github.com/HotCakeX/Harden-Windows-Security/blob/main/LICENSE
//

using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Windows.Controls;

namespace HardenWindowsSecurity;

internal static partial class GUIProtectWinSecurity
{

	/// <summary>
	/// A method to update sub-category items based on the checked categories
	/// </summary>
	internal static void UpdateSubCategories()
	{
		// Disable all sub-category items first
		foreach (ListViewItem item in subCategories!.Items)
		{
			item.IsEnabled = false;
		}

		// Get all checked categories
		List<ListViewItem> checkedCategories = [.. categories!.Items
			.Cast<ListViewItem>()
			.Where(item => ((CheckBox)item.Content).IsChecked == true)];

		// Enable the corresponding sub-category items
		foreach (ListViewItem categoryItem in checkedCategories)
		{
			string categoryContent = ((CheckBox)categoryItem.Content).Name;
			if (correlation.Contains(categoryContent))
			{
				if (correlation[categoryContent] is string[] subCategoryNames)
				{
					foreach (string subCategoryName in subCategoryNames)
					{
						foreach (ListViewItem subCategoryItem in subCategories.Items)
						{
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
		foreach (ListViewItem subCategoryItem in subCategories.Items)
		{
			if (!subCategoryItem.IsEnabled)
			{
				((CheckBox)subCategoryItem.Content).IsChecked = false;
			}
		}

		if (GlobalVars.HardeningCategorieX is null)
		{
			throw new ArgumentNullException("GlobalVars.HardeningCategorieX cannot be null.");
		}

		// Disable categories that are not valid for the current session
		foreach (ListViewItem categoryItem in categories.Items)
		{
			if (!GlobalVars.HardeningCategorieX.Contains(((CheckBox)categoryItem.Content).Name))
			{
				categoryItem.IsEnabled = false;
			}
		}
	}

	// Method to disable the Offline Mode configuration inputs
	internal static void DisableOfflineModeConfigInputs()
	{
		microsoftSecurityBaselineZipButton!.IsEnabled = false;
		microsoftSecurityBaselineZipTextBox!.IsEnabled = false;
		microsoft365AppsSecurityBaselineZipButton!.IsEnabled = false;
		microsoft365AppsSecurityBaselineZipTextBox!.IsEnabled = false;
		lgpoZipButton!.IsEnabled = false;
		lgpoZipTextBox!.IsEnabled = false;
	}

	/// <summary>
	/// When the execute button is pressed, this method is called to gather the selected categories and sub-categories
	/// </summary>
	internal static void ExecuteButtonPress()
	{

		// Clear the categories and sub-categories lists from the saved variables
		SelectedCategories = new ConcurrentQueue<string>();
		SelectedSubCategories = new ConcurrentQueue<string>();

		// Gather the selected categories and sub-categories and store them in the GlobalVars HashTable
		IEnumerable categoriesItems = categories!.Items;
		IEnumerable subCategoriesItems = subCategories!.Items;

		// Get the Categories status and add them to the variables
		foreach (ListBoxItem categoryItem in categoriesItems)
		{
			if ((bool)((CheckBox)categoryItem.Content).IsChecked!)
			{
				string categoryName = ((CheckBox)categoryItem.Content).Name;
				SelectedCategories.Enqueue(categoryName);
			}
		}

		// Get the Sub-Categories status and add them to the variables
		foreach (ListBoxItem subCategoryItem in subCategoriesItems)
		{
			if ((bool)((CheckBox)subCategoryItem.Content).IsChecked!)
			{
				string subCategoryName = ((CheckBox)subCategoryItem.Content).Name;
				SelectedSubCategories.Enqueue(subCategoryName);
			}
		}
	}
}
