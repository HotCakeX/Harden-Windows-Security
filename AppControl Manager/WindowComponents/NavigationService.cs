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

using System.Collections.Generic;
using System.Linq;
using AppControlManager.ViewModels;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Navigation;
using Windows.Graphics;
using WinRT;

#if APP_CONTROL_MANAGER
namespace AppControlManager.WindowComponents;
#endif
#if HARDEN_SYSTEM_SECURITY
using AppControlManager.WindowComponents;
using HardenSystemSecurity.ViewModels;
namespace HardenSystemSecurity.WindowComponents;
#endif

internal sealed class NavigationService
{
	internal readonly MainWindowVM mainWindowVM;
	private bool NavItemsHaveBeenCollected;

#if APP_CONTROL_MANAGER
	private readonly SidebarVM sidebarVM;

	internal NavigationService(MainWindowVM _MainWindowVM, SidebarVM _SidebarVM)
	{
		mainWindowVM = _MainWindowVM;
		sidebarVM = _SidebarVM;
	}
#endif

#if HARDEN_SYSTEM_SECURITY
	internal NavigationService(MainWindowVM _MainWindowVM)
	{
		mainWindowVM = _MainWindowVM;
	}
#endif

	private Frame? _frame;
	private NavigationView? MainNavigation;

	/// <summary>
	/// Called once (from MainWindow) to supply the necessary elements.
	/// </summary>
	internal void Initialize(Frame frame, NavigationView mainNavigation)
	{
		_frame = frame;
		MainNavigation = mainNavigation;

		if (!NavItemsHaveBeenCollected)
		{
			CollectNavigationItems();
			NavItemsHaveBeenCollected = true;
		}
		_frame.Navigated += UpdateHeaderFromCurrentPage;
	}

#if APP_CONTROL_MANAGER
	/// <summary>
	/// Event handler to change visibility of the AnimatedIcons on the currently visible page in the frame
	/// It is called by the Sidebar's Browse/Clear buttons' event handlers
	/// </summary>
	/// <param name="on"></param>
	internal void AffectPagesAnimatedIconsVisibilitiesEx(bool on)
	{
		// Decide the visibility to set the animated icons to based on the parameter
		Visibility visibility = on ? Visibility.Visible : Visibility.Collapsed;

		if (_frame is null || MainNavigation is null)
			throw new InvalidOperationException("NavigationService has not been initialized.");

		if (_frame.Content is IAnimatedIconsManager currentPage)
		{
			currentPage.SetVisibility(visibility);

			// Set the visibility of the AnimatedIcon on Sidebar's Select button for Unsigned policy
			sidebarVM.SidebarBasePolicySelectButtonLightAnimatedIconVisibility = visibility;
		}
	}

	/// <summary>
	/// This method is called via the methods responsible for Navigations.
	/// </summary>
	internal void AffectPagesAnimatedIconsVisibilities(Frame contentFrame)
	{

		// Check the unsigned base policy path on the Sidebar's textbox
		bool isUnsignedBasePolicyPathAvailable = !string.IsNullOrWhiteSpace(MainWindowVM.SidebarBasePolicyPathTextBoxTextStatic);

		sidebarVM.Nullify();

		// Check if the currently displayed content (page) in the ContentFrame implements the IAnimatedIconsManager interface.
		// If it does, cast ContentFrame.Content to IAnimatedIconsManager
		// And if the text box for unsigned policy path is also full then set the visibility of animated icons
		if (contentFrame.Content is IAnimatedIconsManager currentPage && isUnsignedBasePolicyPathAvailable)
		{
			if (isUnsignedBasePolicyPathAvailable)
			{
				currentPage.SetVisibility(Visibility.Visible);
				sidebarVM.SidebarBasePolicySelectButtonLightAnimatedIconVisibility = Visibility.Visible;
			}
			else
			{
				currentPage.SetVisibility(Visibility.Collapsed);
				sidebarVM.SidebarBasePolicySelectButtonLightAnimatedIconVisibility = Visibility.Collapsed;
			}
		}
		else
		{
			sidebarVM.SidebarBasePolicySelectButtonLightAnimatedIconVisibility = Visibility.Collapsed;
		}
	}
#endif

	/// <summary>
	/// Main navigation method that is used by the search bar, direct clicks on the main navigation items
	/// And by other methods throughout the app in order to navigate to sub-pages
	/// </summary>
	/// <param name="navPageType"></param>
	/// <param name="navItemTag"></param>
	internal async void Navigate(Type? navPageType, string? navItemTag = null)
	{

		if (_frame is null || MainNavigation is null)
			throw new InvalidOperationException("NavigationService has not been initialized.");

		// Get the page's type before navigation so we can prevent duplicate entries in the BackStack
		// This will prevent reloading the same page if we're already on it and works with sub-pages to navigate back to the main page
		Type preNavPageType = _frame.CurrentSourcePageType;

		// The next page that will be navigated to
		Type? nextNavPageType;

		// Check if the method was called by supplying page type and it's not the same page as the current page
		if (navPageType is not null && !Equals(preNavPageType, navPageType))
		{
			nextNavPageType = navPageType;
		}
		// Check if the method was called by a page's NavigationViewItem's content and it's not the same page as the current page - Used by the search bar
		// Others calls this method by supplying page's type instead
		// The dictionary used to find the page's type doesn't contain sub-pages for the reasons explained on dictionary definition.
		else if (navItemTag is not null && mainWindowVM.NavigationPageToItemContentMap.TryGetValue(navItemTag, out Type? page) && !Equals(page, preNavPageType))
		{
			nextNavPageType = page;
		}
		else
		{
			return;
		}

		if (nextNavPageType is null)
		{
			return;
		}

		// If not running as Admin
		if (!App.IsElevated)
		{
			// If the requested page requires elevation
			if (!mainWindowVM.UnelevatedPages.Contains(nextNavPageType))
			{
				// a StackPanel to hold the text and checkbox.
				StackPanel panel = new();

				// a TextBlock for the informational text.
				TextBlock infoText = new()
				{
					Text = GlobalVars.GetStr("AppElevationNoticeMain"),
					TextWrapping = TextWrapping.Wrap
				};
				panel.Children.Add(infoText);

				// a CheckBox for the extra input.
				CheckBox extraInfoCheckBox = new()
				{
					Content = GlobalVars.GetStr("AppElevationNoticeExtraPrompt"),
					Margin = new Thickness(0, 12, 0, 0)
				};
				panel.Children.Add(extraInfoCheckBox);

				// Create and configure the ContentDialog.
				using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
				{
					Title = GlobalVars.GetStr("AppElevationNoticeTitle"),
					Content = panel,
					CloseButtonText = GlobalVars.GetStr("Cancel"),
					SecondaryButtonText = GlobalVars.GetStr("AppElevationNoticeRelaunch"),
					FlowDirection = Enum.Parse<FlowDirection>(App.Settings.ApplicationGlobalFlowDirection),
					DefaultButton = ContentDialogButton.Secondary
				};

				// Show the dialog and wait for user response
				ContentDialogResult result = await dialog.ShowAsync();

				// If user chose to elevate to Admin
				if (result is ContentDialogResult.Secondary)
				{
					bool isChecked = extraInfoCheckBox.IsChecked ?? false;

					if (isChecked)
					{
						App.Settings.PromptForElevationOnStartup = true;
					}

					// Build navigation argument to restore this page after elevation.					
					string? navArg = null;

					// Attempt to find a tag for the page, only top-level pages that have a tab in MainWindow XAML work
					KeyValuePair<string, Type> taggedEntry = mainWindowVM.NavigationPageToItemContentMap
						.FirstOrDefault(kv => Equals(kv.Value, nextNavPageType));

					navArg = $"--navtag={taggedEntry.Key}";

					// Relaunch elevated with the navigation argument
					if (Relaunch.RelaunchAppElevated(App.AUMID, navArg))
					{
						Application.Current.Exit();
					}

					return;
				}
				else
				{
					// Settings page is not in the MainNavigation by default so we need to explicitly check for it
					// Casting MainNavigation.SettingsItem to <NavigationViewItem> in order to add it to allNavigationItems wouldn't work because it results in null
					if (Equals(preNavPageType, typeof(Pages.Settings)))
					{
						mainWindowVM.NavViewSelectedItem = MainNavigation.SettingsItem;
					}
					else
					{
						// The SelectedItem is automatically set to the page that is unavailable
						// But here we set it back to the last available page to make it a smooth experience
						mainWindowVM.NavViewSelectedItem = mainWindowVM.allNavigationItems.FirstOrDefault(x => string.Equals(x.Tag.ToString(), mainWindowVM.NavigationPageToItemContentMap.FirstOrDefault(x => Equals(x.Value, preNavPageType)).Key, StringComparison.OrdinalIgnoreCase));
					}
					return;
				}
			}
		}

		// Play a sound
		ElementSoundPlayer.Play(ElementSoundKind.MoveNext);

		// Navigate to the new page
		_ = _frame.Navigate(nextNavPageType, null, new DrillInNavigationTransitionInfo());

#if APP_CONTROL_MANAGER
		// For page Interface and light augmentation
		AffectPagesAnimatedIconsVisibilities(_frame);
#endif

		SetCrumbBar(nextNavPageType);
	}

	/// <summary>
	/// Updates the BreadCrumbBar in response to a page navigation in the app.
	/// </summary>
	/// <param name="currentPageType"></param>
	internal void SetCrumbBar(Type currentPageType)
	{
		// Get the item from BreadCrumb dictionary that belongs to the next page we navigated to
		if (mainWindowVM.breadCrumbMappingsV2.TryGetValue(currentPageType, out PageTitleMap? info))
		{
			// Get the index location of the page we navigated to in the list of pages
			int currentPageLocation = info.Pages.IndexOf(currentPageType);

			// Clear the breadcrumb bar's collection
			mainWindowVM.Breadcrumbs.Clear();

			// Add the breadcrumbs to the bar one by one, starting from the first item
			// Which is the main item in the main NavigationMenu all the way to the item that was selected
			// E.g, if there are 5 pages in one of the valid app navigation paths and the page user wants to navigate to is the 3rd one
			// Then the name of all the pages starting from index 0 to index 2 will be added to the breadcrumb bar (total of 3)
			for (int i = 0; i <= currentPageLocation; i++)
			{
				mainWindowVM.Breadcrumbs.Add(new Crumb(info.Titles[i], info.Pages[i]));
			}

			// Since settings page doesn't have content when it is in Top mode (it only has Tag property)
			// And also content for the auto-created Settings page varies based on localization, adding an explicit check for it here
			if (Equals(currentPageType, typeof(Pages.Settings)))
			{
				// Set the selected item in the MainNavigation to the Settings page
				mainWindowVM.NavViewSelectedItem = MainNavigation?.SettingsItem;
			}
			else
			{
				// Set the selected item in the MainNavigation to the next page by first detecting it via its NavigationViewItem's context set in XAML
				// info.Titles[0] ensures the selected item in the NavigationView will correctly be set to the main item in the menu even when the page being navigated to is a sub-page in that valid navigational path
				mainWindowVM.NavViewSelectedItem = mainWindowVM.allNavigationItems.First(x => string.Equals(x.Content.ToString(), info.Titles[0], StringComparison.OrdinalIgnoreCase));
			}
		}
	}

#if APP_CONTROL_MANAGER
	/// <summary>
	/// Event handler for the sidebar base policy browse button
	/// </summary>
	internal void SidebarBasePolicyBrowseButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			mainWindowVM.SidebarBasePolicyPathTextBoxText = selectedFile;

			// Show the animated icons on the currently visible page
			AffectPagesAnimatedIconsVisibilitiesEx(true);
		}
	}

	/// <summary>
	/// Event handler for the clear button in the sidebar for unsigned policy path
	/// </summary>
	internal void SidebarBasePolicyClearButton_Click()
	{
		// Clear the Sidebar text box
		mainWindowVM.SidebarBasePolicyPathTextBoxText = null;

		// Hide the animated icons on the currently visible page
		AffectPagesAnimatedIconsVisibilitiesEx(false);

		sidebarVM.Nullify();
	}
#endif

	/// <summary>
	/// Used to refresh the Settings page but re-navigating to it so we can display the new language after user changes app language.
	/// Settings page is the only point where language can be changed for the app.
	/// </summary>
	internal void RefreshSettingsPage()
	{
		if (_frame is null) return;

		_ = _frame.Navigate(typeof(Pages.Settings));

		// Remove the last navigation history because it will be the same Settings page due to in-place refresh.
		_frame.BackStack.RemoveAt(_frame.BackStack.Count - 1);

		// Update the Crumb Bar header title of the page with new localized texts.
		SetCrumbBar(typeof(Pages.Settings));
	}


	/// <summary>
	/// Main navigation event of the Nav View
	/// ItemInvoked event is much better than SelectionChanged because it allows click/tap on the same selected menu on main navigation
	/// which is necessary if the same main page is selected but user has navigated to inner pages and then wants to go back by selecting the already selected main navigation item again.
	/// The duplicate-loading logic is implemented manually in code behind.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	internal void MainNavigation_ItemInvoked(NavigationView sender, NavigationViewItemInvokedEventArgs? args)
	{
		// If any other page was invoked
		if (args?.InvokedItemContainer is not null)
		{
			// The "Content" property of the Settings page is null when NavigationView is in "Top" mode since it has no label/content on the UI
			// That is why we use the "IsSettingsInvoked" property to check for the Settings page click/tap.
			// Settings' content is also auto translated on different system localizations so this is also useful for those situations.
			// https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.controls.navigationviewiteminvokedeventargs.issettingsinvoked
			if (args.IsSettingsInvoked)
			{
				Navigate(typeof(Pages.Settings), null);
			}
			else
			{
				Navigate(null, args?.InvokedItemContainer.Tag.ToString());
			}
		}
	}

	/// <summary>
	/// Event handler for when the back button is pressed
	/// </summary>
	internal void BackButtonTitleBar_Click()
	{
		if (_frame is null) return;

		if (_frame.CanGoBack)
		{

			// Don't go back if the nav pane is overlayed.
			/*
                if (MainNavigation.IsPaneOpen &&
                    (MainNavigation.DisplayMode == NavigationViewDisplayMode.Compact ||
                     MainNavigation.DisplayMode == NavigationViewDisplayMode.Minimal))
                */

			// Play sound for back navigation
			ElementSoundPlayer.Play(ElementSoundKind.GoBack);

			// Go back to the previous page
			_frame.GoBack(new DrillInNavigationTransitionInfo());

			// Get the current page after navigating back
			Type currentPage = _frame.CurrentSourcePageType;

#if APP_CONTROL_MANAGER
			// For page Interface and light augmentation
			AffectPagesAnimatedIconsVisibilities(_frame);
#endif
			SetCrumbBar(currentPage);
		}
	}

	/// <summary>
	/// Event handler for the AutoSuggestBox text change event
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	internal void SearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
	{
		if (args.Reason == AutoSuggestionBoxTextChangeReason.UserInput)
		{
			ViewModelBase.EmitTypingSound();

			// Get the text user entered in the search box
			string query = sender.Text.Trim();

			// Filter menu items based on the search query
			List<string> suggestions = new(mainWindowVM.NavigationPageToItemContentMapForSearch.Keys.Where(name => name.Contains(query, StringComparison.OrdinalIgnoreCase)));

			// Set the filtered items as suggestions in the AutoSuggestBox
			sender.ItemsSource = suggestions;
		}
	}

	/// <summary>
	/// Event handler for when a suggestion is chosen in the AutoSuggestBox
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	internal void SearchBox_SuggestionChosen(AutoSuggestBox sender, AutoSuggestBoxSuggestionChosenEventArgs args)
	{
		// Get the selected item's name and find the corresponding NavigationViewItem
		string? chosenItemName = args.SelectedItem?.ToString();

		if (chosenItemName is not null && mainWindowVM.NavigationPageToItemContentMapForSearch.TryGetValue(chosenItemName, out Type? selectedItem))
		{
			Navigate(selectedItem, null);
		}
	}

	/// <summary>
	/// Event handler to run at Window launch to restore its size to the one before closing
	/// </summary>
	internal static void RestoreWindowSize(AppWindow m_AppWindow)
	{
		// Using .As<>() instead of direct cast because in NAOT mode direct cast would throw error for invalid cast operation. This is a bug in CsWinRT
		OverlappedPresenter presenter = m_AppWindow.Presenter.As<OverlappedPresenter>();

		try
		{
			// If the window was last maximized then restore it to maximized
			if (App.Settings.MainWindowIsMaximized)
			{
				Logger.Write(GlobalVars.GetStr("WindowMaximizedMsg"));

				// Set the presenter to maximized
				presenter.Maximize();

				return;
			}

			// If the previous window size was bigger than 700 pixels width/height use it.
			// Otherwise let the OS decide.
			if (App.Settings.MainWindowWidth > 700 && App.Settings.MainWindowHeight > 700)
			{
				Logger.Write(string.Format(GlobalVars.GetStr("SettingWindowSizeMessage"), App.Settings.MainWindowHeight, App.Settings.MainWindowWidth));

				// Apply to the current AppWindow
				m_AppWindow.Resize(new SizeInt32(App.Settings.MainWindowWidth, App.Settings.MainWindowHeight));
			}
		}
		finally
		{
			presenter.PreferredMinimumWidth = 700;
			presenter.PreferredMinimumHeight = 700;

			m_AppWindow.SetPresenter(presenter);
		}
	}

	/// <summary>
	/// Get all NavigationViewItem items in the MainNavigation, that includes MenuItems + any nested MenuItems + FooterMenuItems.
	/// Only needs to run once.
	/// </summary>
	internal void CollectNavigationItems()
	{
		if (MainNavigation is null) return;

		mainWindowVM.allNavigationItems =
			MainNavigation.MenuItems.OfType<NavigationViewItem>()
							 .SelectMany(GetAllChildren).Concat(MainNavigation.FooterMenuItems.OfType<NavigationViewItem>().SelectMany(GetAllChildren)).ToList();

		static IEnumerable<NavigationViewItem> GetAllChildren(NavigationViewItem parent) =>
			new[] { parent }.Concat(parent.MenuItems.OfType<NavigationViewItem>().SelectMany(GetAllChildren));
	}

	/// <summary>
	/// Event handler for the BreadCrumbBar's ItemClicked event
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	internal void BreadcrumbBar_ItemClicked(BreadcrumbBar sender, BreadcrumbBarItemClickedEventArgs args)
	{
		Crumb crumb = (Crumb)args.Item;

		Navigate(crumb.Page, null);
	}

	/// <summary>
	/// Updates ViewModel header props from the current Frame.Content if it implements IPageHeaderProvider.
	/// </summary>
	private void UpdateHeaderFromCurrentPage(object sender, NavigationEventArgs e)
	{
		_ = App.AppDispatcher.TryEnqueue(() =>
		{
			// Determine provider presence and update header content
			if (_frame?.Content is CommonCore.UI.IPageHeaderProvider provider)
			{
				mainWindowVM.PageHeaderTitle = provider.HeaderTitle;
				mainWindowVM.PageHeaderGuideUri = provider.HeaderGuideUri;
				mainWindowVM.HasPageHeader = true;
			}
			else
			{
				mainWindowVM.PageHeaderTitle = null;
				mainWindowVM.PageHeaderGuideUri = null;
				mainWindowVM.HasPageHeader = false;
			}

			// Compute layout once per navigation using current width
			bool wide = App.MainWindow?.AppWindow.Size.Width >= MainWindowVM.HeaderThresholdWidth;

			// Inline vs flyout header visibility depends on width and presence of a header
			mainWindowVM.HeaderInlineVisibility = (wide && mainWindowVM.HasPageHeader) ? Visibility.Visible : Visibility.Collapsed;
			mainWindowVM.HeaderFlyoutVisibility = (!wide && mainWindowVM.HasPageHeader) ? Visibility.Visible : Visibility.Collapsed;

			// Guide button must be invisible when URL is null
			mainWindowVM.GuideButtonVisibility = mainWindowVM.PageHeaderGuideUri is not null ? Visibility.Visible : Visibility.Collapsed;

			// Determine whether the crumb bar must be visible or not.
			mainWindowVM.IsCrumbBarVisible = _frame?.Content is CommonCore.UI.IInvisibleCrumbar ? Visibility.Collapsed : Visibility.Visible;
		});
	}
}
