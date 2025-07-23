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
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using HardenWindowsSecurity.Protect;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Imaging;

namespace HardenWindowsSecurity.ViewModels;

internal sealed partial class ProtectVM : ViewModelBase
{
	internal ProtectVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			null, null);

		// Initial protections category population
		ProtectionCategoriesListItemsSource = CreateProtectionCategories();
		SelectAllItemsInListView();
	}

	/// <summary>
	/// The order of these must match the order of the Categories Enum.
	/// </summary>
	private readonly BitmapImage[] CategoryImages = [
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/Microsoft-Security-Baseline.png")),
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/Microsoft-365-Apps-Security-Baselines.png")),
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/WindowsDefender.png")),
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/ASRrules.png")),
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/Bitlocker.png")), // 4
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/TLS.png")), // 5
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/LockScreen.png")),
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/UAC.png")), // 7
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/DeviceGuard.png")), // 8
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/Firewall.png")), // 9
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/OptionalFeatures.png")), // 10
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/Networking.png")), // 11
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/MiscellaneousCommands.png")), // 12
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/WindowsUpdate.png")), // 13
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/EdgeBrowser.png")), // 14
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/Certificate.png")), // 15
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/CountryIPBlocking.png")), // 16
		new BitmapImage(new Uri("ms-appx:///Assets/ProtectionCategoriesIcons/NonAdmin.png")) // 17
	];

	/// <summary>
	/// The main InfoBar for the Protect VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	/// <summary>
	/// Selected index for the preset comboBox.
	/// </summary>
	internal int ProtectionPresetsSelectedIndex
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProtectionCategoriesListItemsSource = CreateProtectionCategories();
				SelectAllItemsInListView();
			}
		}
	} = 1;

	/// <summary>
	/// Items Source of the ListView that displays the list of Protection Categories.
	/// </summary>
	internal ObservableCollection<GroupInfoListForProtectionCategories> ProtectionCategoriesListItemsSource { get; set => SP(ref field, value); } = [];

	/// <summary>
	/// Selected Items list in the ListView.
	/// </summary>
	internal List<ProtectionCategoryListViewItem> ProtectionCategoriesListItemsSourceSelectedItems = [];

	/// <summary>
	/// A flag to make sure only one method is adding/removing items between ListView and the ProtectionCategoriesListItemsSourceSelectedItems.
	/// </summary>
	private volatile bool IsAdding;

	/// <summary>
	/// ListView reference of the UI.
	/// </summary>
	internal volatile ListViewBase? UIListView;

	/// <summary>
	/// To select all of the items in the ListView.
	/// </summary>
	private void SelectAllItemsInListView()
	{
		if (IsAdding) return;

		try
		{
			IsAdding = true;

			foreach (ProtectionCategoryListViewItem item in ProtectionCategoriesListItemsSourceSelectedItems)
			{
				UIListView?.SelectedItems.Add(item);
			}
		}
		finally
		{
			IsAdding = false;
		}
	}

	/// <summary>
	/// Event handler for the SelectionChanged event of the ListView.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void ListView_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		if (IsAdding) return;

		try
		{
			IsAdding = true;

			foreach (ProtectionCategoryListViewItem item in e.AddedItems.Cast<ProtectionCategoryListViewItem>())
			{
				ProtectionCategoriesListItemsSourceSelectedItems.Add(item);
			}

			foreach (ProtectionCategoryListViewItem item in e.RemovedItems.Cast<ProtectionCategoryListViewItem>())
			{
				_ = ProtectionCategoriesListItemsSourceSelectedItems.Remove(item);
			}
		}
		finally
		{
			IsAdding = false;
		}
	}

	/// <summary>
	/// When the ListView is loaded or page is navigated to/from, this runs to check all of the items that were previously checked.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void ProtectionCategoriesListView_Loaded(object sender, RoutedEventArgs e)
	{
		if (IsAdding) return;

		try
		{
			IsAdding = true;

			ListView lv = (ListView)sender;

			foreach (ProtectionCategoryListViewItem item in ProtectionCategoriesListItemsSourceSelectedItems)
			{
				lv.SelectedItems.Add(item);
			}
		}
		finally
		{
			IsAdding = false;
		}
	}

	/// <summary>
	/// Generates Protection categories based on the selected preset.
	/// </summary>
	/// <param name="Preset"></param>
	/// <returns></returns>
	/// <exception cref="ArgumentOutOfRangeException"></exception>
	private List<ProtectionCategoryListViewItem> GenerateCategories(int Preset)
	{
		List<ProtectionCategoryListViewItem> output = [];

		switch (Preset)
		{
			case 0:
				{
					// 1
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MicrosoftSecurityBaseline,
						title: GlobalVars.GetStr("ProtectCategory_MSFTSecBaseline"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_MSFTSecBaseline"),
						logo: CategoryImages[(int)Categories.MicrosoftSecurityBaseline],
						subCategories: []
						));

					// 2
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.Microsoft365AppsSecurityBaseline,
						title: GlobalVars.GetStr("ProtectCategory_MSFT365AppsSecBaseline"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_MSFT365AppsSecBaseline"),
						logo: CategoryImages[(int)Categories.Microsoft365AppsSecurityBaseline],
						subCategories: []
						));

					// 3
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MicrosoftDefender,
						title: GlobalVars.GetStr("ProtectCategory_MSFTDefender"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_MSFTDefender"),
						logo: CategoryImages[(int)Categories.MicrosoftDefender],
						subCategories: []
						));

					// 9
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.DeviceGuard,
						title: GlobalVars.GetStr("ProtectCategory_DeviceGuard"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_DeviceGuard"),
						logo: CategoryImages[(int)Categories.DeviceGuard],
						subCategories: []
						));

					// 11
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.OptionalWindowsFeatures,
						title: GlobalVars.GetStr("ProtectCategory_OptionalWinFeatures"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_OptionalWinFeatures"),
						logo: CategoryImages[(int)Categories.OptionalWindowsFeatures],
						subCategories: []
						));

					// 18
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.NonAdminCommands,
						title: GlobalVars.GetStr("ProtectCategory_NonAdmin"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_NonAdmin"),
						logo: CategoryImages[(int)Categories.NonAdminCommands],
						subCategories: []
						));

					break;
				}
			case 1:
				{
					// 1
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MicrosoftSecurityBaseline,
						title: GlobalVars.GetStr("ProtectCategory_MSFTSecBaseline"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_MSFTSecBaseline"),
						logo: CategoryImages[(int)Categories.MicrosoftSecurityBaseline],
						subCategories: []
						));

					// 2
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.Microsoft365AppsSecurityBaseline,
						title: GlobalVars.GetStr("ProtectCategory_MSFT365AppsSecBaseline"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_MSFT365AppsSecBaseline"),
						logo: CategoryImages[(int)Categories.Microsoft365AppsSecurityBaseline],
						subCategories: []
						));

					// 3
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MicrosoftDefender,
						title: GlobalVars.GetStr("ProtectCategory_MSFTDefender"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_MSFTDefender"),
						logo: CategoryImages[(int)Categories.MicrosoftDefender],
						subCategories: []
						));

					// 4
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.AttackSurfaceReductionRules,
						title: GlobalVars.GetStr("ProtectCategory_ASRRules"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_ASRRules"),
						logo: CategoryImages[(int)Categories.AttackSurfaceReductionRules],
						subCategories: []
						));

					// 5
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.BitLockerSettings,
						title: GlobalVars.GetStr("ProtectCategory_BitLocker"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_BitLocker"),
						logo: CategoryImages[(int)Categories.BitLockerSettings],
						subCategories: []
						));

					// 6
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.TLSSecurity,
						title: GlobalVars.GetStr("ProtectCategory_TLS"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_TLS"),
						logo: CategoryImages[(int)Categories.TLSSecurity],
						subCategories: []
						));

					// 7
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.LockScreen,
						title: GlobalVars.GetStr("ProtectCategory_LockScreen"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_LockScreen"),
						logo: CategoryImages[(int)Categories.LockScreen],
						subCategories: []
						));

					// 8
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.UserAccountControl,
						title: GlobalVars.GetStr("ProtectCategory_UAC"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_UAC"),
						logo: CategoryImages[(int)Categories.UserAccountControl],
						subCategories: []
						));

					// 9
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.DeviceGuard,
						title: GlobalVars.GetStr("ProtectCategory_DeviceGuard"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_DeviceGuard"),
						logo: CategoryImages[(int)Categories.DeviceGuard],
						subCategories: []
						));

					// 10
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.WindowsFirewall,
						title: GlobalVars.GetStr("ProtectCategory_WindowsFirewall"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_WindowsFirewall"),
						logo: CategoryImages[(int)Categories.WindowsFirewall],
						subCategories: []
						));

					// 11
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.OptionalWindowsFeatures,
						title: GlobalVars.GetStr("ProtectCategory_OptionalWinFeatures"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_OptionalWinFeatures"),
						logo: CategoryImages[(int)Categories.OptionalWindowsFeatures],
						subCategories: []
						));

					// 12
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.WindowsNetworking,
						title: GlobalVars.GetStr("ProtectCategory_WindowsNetworking"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_WindowsNetworking"),
						logo: CategoryImages[(int)Categories.WindowsNetworking],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.WindowsNetworking_BlockNTLM,
							description: GlobalVars.GetStr("ProtectSubCategory_BlockNTLM"))
							]
						));

					// 13
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MiscellaneousConfigurations,
						title: GlobalVars.GetStr("ProtectCategory_MiscellaneousConfig"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_MiscellaneousConfig"),
						logo: CategoryImages[(int)Categories.MiscellaneousConfigurations],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.MiscellaneousConfigurations_EnableLongPathSupport,
							description: GlobalVars.GetStr("ProtectSubCategory_EnableLongPathSupport"))
							]
						));

					// 14
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.WindowsUpdateConfigurations,
						title: GlobalVars.GetStr("ProtectCategory_WindowsUpdate"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_WindowsUpdate"),
						logo: CategoryImages[(int)Categories.WindowsUpdateConfigurations],
						subCategories: []
						));

					// 15
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.EdgeBrowserConfigurations,
						title: GlobalVars.GetStr("ProtectCategory_Edge"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_Edge"),
						logo: CategoryImages[(int)Categories.EdgeBrowserConfigurations],
						subCategories: []
						));

					// 18
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.NonAdminCommands,
						title: GlobalVars.GetStr("ProtectCategory_NonAdmin"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_NonAdmin"),
						logo: CategoryImages[(int)Categories.NonAdminCommands],
						subCategories: []
						));

					break;
				}
			case 2:
				{
					// 1
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MicrosoftSecurityBaseline,
						title: GlobalVars.GetStr("ProtectCategory_MSFTSecBaseline"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_MSFTSecBaseline"),
						logo: CategoryImages[(int)Categories.MicrosoftSecurityBaseline],
						subCategories: []
						));

					// 2
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.Microsoft365AppsSecurityBaseline,
						title: GlobalVars.GetStr("ProtectCategory_MSFT365AppsSecBaseline"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_MSFT365AppsSecBaseline"),
						logo: CategoryImages[(int)Categories.Microsoft365AppsSecurityBaseline],
						subCategories: []
						));

					// 3
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MicrosoftDefender,
						title: GlobalVars.GetStr("ProtectCategory_MSFTDefender"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_MSFTDefender"),
						logo: CategoryImages[(int)Categories.MicrosoftDefender],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.MSDefender_SmartAppControl,
							description: GlobalVars.GetStr("ProtectSubCategory_SmartAppControl")),

							new SubCategoryDefinition(
							subCategory:SubCategories.MSDefender_BetaUpdateChannelsForDefender,
							description: GlobalVars.GetStr("ProtectSubCategory_BetaUpdateChannels"))
							]
						));

					// 4
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.AttackSurfaceReductionRules,
						title: GlobalVars.GetStr("ProtectCategory_ASRRules"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_ASRRules"),
						logo: CategoryImages[(int)Categories.AttackSurfaceReductionRules],
						subCategories: []
						));

					// 5
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.BitLockerSettings,
						title: GlobalVars.GetStr("ProtectCategory_BitLocker"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_BitLocker"),
						logo: CategoryImages[(int)Categories.BitLockerSettings],
						subCategories: []
						));

					// 6
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.TLSSecurity,
						title: GlobalVars.GetStr("ProtectCategory_TLS"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_TLS"),
						logo: CategoryImages[(int)Categories.TLSSecurity],
						subCategories: []
						));

					// 7
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.LockScreen,
						title: GlobalVars.GetStr("ProtectCategory_LockScreen"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_LockScreen"),
						logo: CategoryImages[(int)Categories.LockScreen],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.LockScreen_NoLastSignedIn,
							description: GlobalVars.GetStr("ProtectSubCategory_NoLastSignedIn")),

							new SubCategoryDefinition(
							subCategory:SubCategories.LockScreen_RequireCTRLAltDel,
							description: GlobalVars.GetStr("ProtectSubCategory_RequireCTRLAltDel"))
							]
						));

					// 8
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.UserAccountControl,
						title: GlobalVars.GetStr("ProtectCategory_UAC"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_UAC"),
						logo: CategoryImages[(int)Categories.UserAccountControl],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.UAC_NoFastUserSwitching,
							description: GlobalVars.GetStr("ProtectSubCategory_NoFastUserSwitching")),

							new SubCategoryDefinition(
							subCategory:SubCategories.UAC_OnlyElevateSigned,
							description: GlobalVars.GetStr("ProtectSubCategory_OnlyElevateSigned"))
							]
						));

					// 9
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.DeviceGuard,
						title: GlobalVars.GetStr("ProtectCategory_DeviceGuard"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_DeviceGuard"),
						logo: CategoryImages[(int)Categories.DeviceGuard],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.DeviceGuard_MandatoryModeForVBS,
							description: GlobalVars.GetStr("ProtectSubCategory_MandatoryModeForVBS"))
							]
						));

					// 10
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.WindowsFirewall,
						title: GlobalVars.GetStr("ProtectCategory_WindowsFirewall"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_WindowsFirewall"),
						logo: CategoryImages[(int)Categories.WindowsFirewall],
						subCategories: []
						));

					// 11
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.OptionalWindowsFeatures,
						title: GlobalVars.GetStr("ProtectCategory_OptionalWinFeatures"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_OptionalWinFeatures"),
						logo: CategoryImages[(int)Categories.OptionalWindowsFeatures],
						subCategories: []
						));

					// 12
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.WindowsNetworking,
						title: GlobalVars.GetStr("ProtectCategory_WindowsNetworking"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_WindowsNetworking"),
						logo: CategoryImages[(int)Categories.WindowsNetworking],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.WindowsNetworking_BlockNTLM,
							description: GlobalVars.GetStr("ProtectSubCategory_BlockNTLM"))
							]
						));

					// 13
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.MiscellaneousConfigurations,
						title: GlobalVars.GetStr("ProtectCategory_MiscellaneousConfig"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_MiscellaneousConfig"),
						logo: CategoryImages[(int)Categories.MiscellaneousConfigurations],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.MiscellaneousConfigurations_ForceStrongKeyProtection,
							description: GlobalVars.GetStr("ProtectSubCategory_ForceStrongKeyProtection")),

							new SubCategoryDefinition(
							subCategory:SubCategories.MiscellaneousConfigurations_EnableWindowsProtectedPrint,
							description: GlobalVars.GetStr("ProtectSubCategory_EnableWindowsProtectedPrint")),

							new SubCategoryDefinition(
							subCategory:SubCategories.MiscellaneousConfigurations_EnableLongPathSupport,
							description: GlobalVars.GetStr("ProtectSubCategory_EnableLongPathSupport"))
							]
						));

					// 14
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.WindowsUpdateConfigurations,
						title: GlobalVars.GetStr("ProtectCategory_WindowsUpdate"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_WindowsUpdate"),
						logo: CategoryImages[(int)Categories.WindowsUpdateConfigurations],
						subCategories: []
						));

					// 15
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.EdgeBrowserConfigurations,
						title: GlobalVars.GetStr("ProtectCategory_Edge"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_Edge"),
						logo: CategoryImages[(int)Categories.EdgeBrowserConfigurations],
						subCategories: []
						));

					// 16
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.CertificateChecking,
						title: GlobalVars.GetStr("ProtectCategory_CertificateCheck"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_CertificateCheck"),
						logo: CategoryImages[(int)Categories.CertificateChecking],
						subCategories: []
						));

					// 17
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.CountryIPBlocking,
						title: GlobalVars.GetStr("ProtectCategory_CountryIPBlock"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_CountryIPBlock"),
						logo: CategoryImages[(int)Categories.CountryIPBlocking],
						subCategories: [
							new SubCategoryDefinition(
							subCategory:SubCategories.CountryIPBlocking_BlockOFACSanctionedCountries,
							description: GlobalVars.GetStr("ProtectSubCategory_BlockOFACSanctionedCountries"))
							]
						));

					// 18
					output.Add(new ProtectionCategoryListViewItem(
						category: Categories.NonAdminCommands,
						title: GlobalVars.GetStr("ProtectCategory_NonAdmin"),
						subTitle: GlobalVars.GetStr("ProtectCategory_Description_NonAdmin"),
						logo: CategoryImages[(int)Categories.NonAdminCommands],
						subCategories: []
						));

					break;
				}
			default:
				throw new ArgumentOutOfRangeException(nameof(Preset), "Invalid preset selected.");
		}

		// Add the same items to the List so we can mark them as selected in the ListView.
		ProtectionCategoriesListItemsSourceSelectedItems = output;

		return output;
	}

	// To create a collection of grouped items, create a query that groups
	// an existing list, or returns a grouped collection from a database.
	// The following method is used to create the ItemsSource for our CollectionViewSource that is defined in XAML
	internal ObservableCollection<GroupInfoListForProtectionCategories> CreateProtectionCategories()
	{
		// Grab Protection Categories objects
		IEnumerable<GroupInfoListForProtectionCategories> query = from item in GenerateCategories(ProtectionPresetsSelectedIndex)

																	  // Group the items returned from the query, sort and select the ones you want to keep
																  group item by item.Title[..1].ToUpper() into g
																  orderby g.Key

																  // GroupInfoListForProtectionCategories is a simple custom class that has an IEnumerable type attribute, and
																  // a key attribute. The IGrouping-typed variable g now holds the App objects,
																  // and these objects will be used to create a new GroupInfoListForProtectionCategories object.
																  select new GroupInfoListForProtectionCategories(items: g, key: g.Key);

		return new(query);
	}
}
