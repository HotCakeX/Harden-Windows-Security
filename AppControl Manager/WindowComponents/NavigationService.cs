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
using System.Linq;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Animation;

#pragma warning disable CA1812

namespace AppControlManager.WindowComponents;

internal sealed class NavigationService
{
	private readonly MainWindowVM mainWindowVM;
	private readonly SidebarVM sidebarVM;

	internal NavigationService(MainWindowVM _MainWindowVM, SidebarVM _SidebarVM)
	{
		mainWindowVM = _MainWindowVM;
		sidebarVM = _SidebarVM;
	}

	private Frame? _frame;
	private NavigationView? MainNavigation;

	/// <summary>
	/// Called once (from MainWindow) to supply the necessary elements.
	/// </summary>
	internal void Initialize(Frame frame, NavigationView mainNavigation)
	{
		_frame = frame;
		MainNavigation = mainNavigation;
	}

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
			if (!mainWindowVM.UnelevatedPages.Contains(nextNavPageType))
			{
				// a StackPanel to hold the text and checkbox.
				StackPanel panel = new();

				// a TextBlock for the informational text.
				TextBlock infoText = new()
				{
					Text = GlobalVars.Rizz.GetString("AppElevationNotice/Main"),
					TextWrapping = TextWrapping.Wrap
				};
				panel.Children.Add(infoText);

				// a CheckBox for the extra input.
				CheckBox extraInfoCheckBox = new()
				{
					Content = GlobalVars.Rizz.GetString("AppElevationNotice/ExtraPrompt"),
					Margin = new Thickness(0, 12, 0, 0)
				};
				panel.Children.Add(extraInfoCheckBox);

				// Create and configure the ContentDialog.
				using CustomUIElements.ContentDialogV2 dialog = new()
				{
					Title = GlobalVars.Rizz.GetString("AppElevationNotice/Title"),
					Content = panel,
					CloseButtonText = GlobalVars.Rizz.GetString("Cancel"),
					SecondaryButtonText = GlobalVars.Rizz.GetString("AppElevationNotice/Relaunch")
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

					/*
					ProcessStartInfo processInfo = new()
					{
						FileName = Environment.ProcessPath,
						Verb = "runas",
						UseShellExecute = true
					};

					Process? processStartResult = null;

					try
					{
						processStartResult = Process.Start(processInfo);
					}

					// Error code 1223: The operation was canceled by the user.
					catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
					{
						// Do nothing if the user cancels the UAC prompt.
						Logger.Write("User canceled the UAC prompt.");
					}

					// Explicitly exit the current instance only after launching the elevated instance
					if (processStartResult is not null)
					{
						Application.Current.Exit();
					}

					return;

					*/

					if (ReLaunch.Action())
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

		// For page Interface and light augmentation
		AffectPagesAnimatedIconsVisibilities(_frame);

		// Get the item from BreadCrumb dictionary that belongs to the next page we navigated to
		_ = mainWindowVM.breadCrumbMappingsV2.TryGetValue(nextNavPageType, out PageTitleMap? info);

		if (info is not null)
		{
			// Get the index location of the page we navigated to in the list of pages
			int currentPageLocation = info.Pages.IndexOf(nextNavPageType);

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

			// Since settings page doesn't have content the way we define them in XAML, adding an explicit check for it here
			if (Equals(nextNavPageType, typeof(Pages.Settings)))
			{
				// Set the selected item in the MainNavigation to the Settings page
				mainWindowVM.NavViewSelectedItem = MainNavigation.SettingsItem;
			}
			else
			{
				// Set the selected item in the MainNavigation to the next page by first detecting it via its NavigationViewItem's context set in XAML
				// info.Titles[0] ensures the selected item in the NavigationView will correctly be set to the main item in the menu even when the page being navigated to is a sub-page in that valid navigational path
				mainWindowVM.NavViewSelectedItem = mainWindowVM.allNavigationItems.First(x => string.Equals(x.Content.ToString(), info.Titles[0], StringComparison.OrdinalIgnoreCase));
			}
		}
	}

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

	/// <summary>
	/// Used to refresh the Settings page but re-navigating to it so we can display the new language after user changes app language.
	/// Settings page is the only point where language can be changed for the app.
	/// </summary>
	internal void RefreshSettingsPage()
	{
		_ = _frame?.Navigate(typeof(Pages.Settings));

		// Clear navigation history because it will have the same Settings page assigned to it due to in-place refresh.
		_frame?.BackStack.Clear();
	}
}
