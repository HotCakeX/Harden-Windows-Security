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

using Microsoft.UI;
using Microsoft.UI.Input;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel;
using Windows.Graphics;
using AnimatedVisuals;
using Microsoft.UI.Xaml.Automation;
using CommonCore.AppSettings;
using Microsoft.UI.Xaml.Hosting;
using System.Numerics;
using Windows.Foundation;
using Microsoft.UI.Dispatching;
using System.Threading.Tasks;
using System.IO;
using System.Collections.Generic;
using AppControlManager.Others;
using Microsoft.UI.Xaml.Input;
using CommonCore.ToolKits;

#if APP_CONTROL_MANAGER
using AppControlManager.ViewModels;
using AppControlManager.XMLOps;
using AppControlManager.WindowComponents;
using AppControlManager.SiPolicy;
namespace AppControlManager;
#endif

#if HARDEN_SYSTEM_SECURITY
using HardenSystemSecurity.ViewModels;
using HardenSystemSecurity.WindowComponents;
namespace HardenSystemSecurity;
#endif

/// <summary>
/// MainWindow is a sealed class that represents the main application window, managing navigation, UI elements, and
/// event handling.
/// </summary>
internal sealed partial class MainWindow : Window
{
	private MainWindowVM ViewModel => ViewModelProvider.MainWindowVM;

#if APP_CONTROL_MANAGER

	private SidebarVM sidebarVM => ViewModelProvider.SidebarVM;

	// Animated ItemsRepeater fields
	private double AnimatedBtnHeight;
	private Thickness AnimatedBtnMargin;

	/// <summary>
	/// Track the currently selected sidebar item (The inner Grid 'ItemRoot') to apply styles
	/// </summary>
	private Grid? _lastSelectedSidebarGrid;

	/// <summary>
	/// Flag to ignore scroll-based selection updates when the user has explicitly clicked an item.
	/// This prevents the scroll logic from immediately overriding the user's selection.
	/// </summary>
	private bool _ignoreScrollUpdates;

	/// <summary>
	/// Timer to reset the scroll update lock after an animation completes.
	/// </summary>
	private readonly DispatcherQueueTimer? _resetScrollUpdateTimer;

#endif

	internal static Grid? RootGridPub { get; private set; }

	private NavigationService Nav => ViewModelProvider.NavigationService;

	/// <summary>
	/// Initializes the main window, sets up event handlers, and configures UI elements like the title bar and navigation
	/// items.
	/// </summary>
	internal MainWindow()
	{
		InitializeComponent();

		Nav.Initialize(ContentFrame, MainNavigation);

		RootGridPub = RootGrid;

		// Retrieve the window handle (HWND) of the main WinUI 3 window and store it in the global vars
		GlobalVars.hWnd = WinRT.Interop.WindowNative.GetWindowHandle(this);

		// Set the window display affinity upon window creation to exclude it from capture if ScreenShield is enabled, otherwise set it to
		WindowDisplayAffinity.SetWindowDisplayAffinity(GlobalVars.hWnd, ViewModel.AppSettings.ScreenShield ? WindowDisplayAffinity.DisplayAffinity.WDA_EXCLUDEFROMCAPTURE : WindowDisplayAffinity.DisplayAffinity.WDA_NONE);

		// https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.window.extendscontentintotitlebar
		// Make title bar Mica
		ExtendsContentIntoTitleBar = true;

		// Set the title bar's height style to tall
		AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;

		// Set the TitleBar title text to the app's display name
		TitleBarTextBlock.Text = AppInfo.Current.DisplayInfo.DisplayName;

		// https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.window.settitlebar
		// This is required. Without it, the page that has the TabView would make the App Window's TitleBar non-draggable.
		SetTitleBar(AppTitleBar);

		// Set the DataContext of the Grid to enable bindings in XAML
		RootGrid.DataContext = this;

		// Subscribe to the NavigationView Content background change event
		NavigationBackgroundManager.NavViewBackgroundChange += OnNavigationBackgroundChanged;

		// Subscribe to the global NavigationView location change event
		NavigationViewLocationManager.NavigationViewLocationChanged += OnNavigationViewLocationChanged;

		// Subscribe to the global App theme change event
		AppThemeManager.AppThemeChanged += OnAppThemeChanged;

		// Subscribe to the size changed of the AppWindow
		AppWindow.Changed += ViewModel.MainWindow_SizeChanged;

		// Subscribe to the AppWindow Closing event
		AppWindow.Closing += AppWindow_Closing;

		// Set the initial background setting based on the user's settings
		OnNavigationBackgroundChanged(null, new(GlobalVars.Settings.NavViewBackground));

		// Set the initial App Theme based on the user's settings
		OnAppThemeChanged(null, new(GlobalVars.Settings.AppTheme));

#if APP_CONTROL_MANAGER

		// Initialize the TransferIcon visual state here.
		// By setting Composition Opacity to 0 here (and keeping XAML Opacity at 1),
		// we ensure the render engine is aware of the element but it remains invisible
		// until we animate it. This fixes the issue where the animation fails on the first click.
		Microsoft.UI.Composition.Visual transferIconVisual = ElementCompositionPreview.GetElementVisual(TransferIcon);
		transferIconVisual.Opacity = 0.0f;

		// Initialize the timer for scroll locking
		_resetScrollUpdateTimer = DispatcherQueue.CreateTimer();
		_resetScrollUpdateTimer.Interval = TimeSpan.FromMilliseconds(600); // Slightly longer than standard animations (500ms)
		_resetScrollUpdateTimer.Tick += (s, e) =>
		{
			// Re-enable scroll-based updates after the "BringIntoView" animation is likely finished
			_ignoreScrollUpdates = false;
			_resetScrollUpdateTimer.Stop();
		};

#endif

	}

#if APP_CONTROL_MANAGER

	/// <summary>
	/// Static method to trigger the transfer icon animation from anywhere in the app.
	/// </summary>
	/// <param name="sourceElement">The UIElement that starts the animation.</param>
	internal static void TriggerTransferIconAnimationStatic(UIElement sourceElement)
	{
		_ = GlobalVars.AppDispatcher.TryEnqueue(() =>
		{
			((MainWindow)App.MainWindow!).TriggerTransferIconAnimation(sourceElement);
		});
	}

#endif

	/// <summary>
	/// Specifies the interactive (passthrough) regions of the title bar-including proper RTL mirroring.
	/// </summary>
	internal void SetRegionsForCustomTitleBar()
	{
		// Ensure all ActualWidth/Height and transforms are up to date
		AppTitleBar.UpdateLayout();

		double scale = AppTitleBar.XamlRoot.RasterizationScale;
		bool isRtl = MainWindowVM.IsWindowRTL();

		// Adjust padding columns
		if (isRtl)
		{
			LeftPaddingColumn.Width = new(AppWindow.TitleBar.RightInset / scale);
			RightPaddingColumn.Width = new(AppWindow.TitleBar.LeftInset / scale);
		}
		else
		{
			RightPaddingColumn.Width = new(AppWindow.TitleBar.RightInset / scale);
			LeftPaddingColumn.Width = new(AppWindow.TitleBar.LeftInset / scale);
		}

		// Compute each element's rect
		RectInt32 backRect = MainWindowVM.CalculatePixelRect(BackButtonTitleBar, scale);
		RectInt32 menuRect = MainWindowVM.CalculatePixelRect(HamburgerMenuButton, scale);
		RectInt32 searchRect = MainWindowVM.CalculatePixelRect(TitleBarSearchBox, scale);
		RectInt32 sidebarRect = MainWindowVM.CalculatePixelRect(SidebarButton, scale);

		// If RTL, flip X around the full window width in pixels
		double windowWidthPx = RootGrid.ActualWidth * scale;

		if (isRtl)
		{
			backRect = MainWindowVM.FlipHorizontally(backRect, windowWidthPx);
			menuRect = MainWindowVM.FlipHorizontally(menuRect, windowWidthPx);
			searchRect = MainWindowVM.FlipHorizontally(searchRect, windowWidthPx);
			sidebarRect = MainWindowVM.FlipHorizontally(sidebarRect, windowWidthPx);
		}

		InputNonClientPointerSource nonClient = InputNonClientPointerSource.GetForWindowId(AppWindow.Id);

		nonClient.ClearRegionRects(NonClientRegionKind.Passthrough);

		nonClient.SetRegionRects(
			NonClientRegionKind.Passthrough,
			[backRect, menuRect, searchRect, sidebarRect]
		);
	}

	/*

	 This will make keep the title bar text white even on light theme, making it unreadable
	 It's not even necessary to change the text based on Window being in focus or not

	/// <summary>
	/// Ensures the TitleBar's text follows the app's appearance when the window is in and out of focus
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void MainWindow_Activated(object sender, WindowActivatedEventArgs args)
	{
		if (args.WindowActivationState == WindowActivationState.Deactivated)
		{
			TitleBarTextBlock.Foreground =
				(SolidColorBrush)Application.Current.Resources["WindowCaptionForegroundDisabled"];
		}
		else
		{
			TitleBarTextBlock.Foreground =
				(SolidColorBrush)Application.Current.Resources["WindowCaptionForeground"];
		}
	}

	*/

	/*
	//This is already retrieved by m_AppWindow in the class, keeping it just in case
	private static AppWindow GetAppWindowForCurrentWindow()
	{
		WindowId windowId = Win32Interop.GetWindowIdFromWindow(GlobalVars.hWnd);
		return AppWindow.GetFromWindowId(windowId);
	}
	*/

	/// <summary>
	/// Event handler for the global NavigationView location change event
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void OnNavigationViewLocationChanged(object? sender, NavigationViewLocationChangedEventArgs e)
	{
		// Set the NavigationView's location based on the event
		switch (e.NewLocation)
		{
			case "Left":
				{
					// Set it to left once, regardless of whether it's already left or coming from top position
					MainNavigation.PaneDisplayMode = NavigationViewPaneDisplayMode.Left;

					// Set it to auto after setting it to left because we need the XAML-defined triggers for the pane to take control
					MainNavigation.PaneDisplayMode = NavigationViewPaneDisplayMode.Auto;

					// Set the main menu's button on the TitleBar visible since we'll need it for left navigation
					HamburgerMenuButton.Visibility = Visibility.Visible;

					break;
				}
			case "Top":
				{
					MainNavigation.PaneDisplayMode = NavigationViewPaneDisplayMode.Top;

					// Hide the main menu's button on the TitleBar since we don't need it in Top mode
					HamburgerMenuButton.Visibility = Visibility.Collapsed;

					break;
				}
			default:
				{
					HamburgerMenuButton.Visibility = Visibility.Visible;
					MainNavigation.PaneDisplayMode = NavigationViewPaneDisplayMode.Auto;
					break;
				}
		}
	}


	/// <summary>
	/// Note: Keeping it transparent would probably not be good for accessibility.
	/// Changing it during runtime is not possible without trigger a theme change: Light/Dark.
	/// Application.RequestedTheme is read-only, so we us RootGrid which is the origin of all other elements.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void OnNavigationBackgroundChanged(object? sender, NavigationBackgroundChangedEventArgs e)
	{
		// Get the current theme
		ElementTheme currentTheme = RootGrid.ActualTheme;

		// Calculate the opposite theme and switch to it
		RootGrid.RequestedTheme = currentTheme == ElementTheme.Dark ? ElementTheme.Light : ElementTheme.Dark;

		// Perform NavigationView background changes based on the settings' page's button
		if (e.IsBackgroundOn)
		{
			MainNavigation.Resources["NavigationViewContentBackground"] = new SolidColorBrush(Colors.Transparent);
		}
		else
		{
			_ = MainNavigation.Resources.Remove("NavigationViewContentBackground");
		}

		// Switch back to the current theme
		RootGrid.RequestedTheme = currentTheme;
	}


	/// <summary>
	/// Event handler for the global AppThemeChanged event
	/// Also changes the AnimatedIcons based on the theme to maintain their accessibility
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void OnAppThemeChanged(object? sender, AppThemeChangedEventArgs e)
	{
		// Get the current system color mode
		ElementTheme currentColorMode = Application.Current.RequestedTheme == ApplicationTheme.Dark
			? ElementTheme.Dark
			: ElementTheme.Light;

		// Set the requested theme based on the event
		// If "Use System Setting" is used, the current system color mode will be assigned which can be either light/dark
		// Also performs animated icon switch based on theme
		switch (e.NewTheme)
		{
			case "Light":
				{
					// Set the app's theme
					RootGrid.RequestedTheme = ElementTheme.Light;

					// Change the navigation icons based on dark/light theme only if "Animated" is the current icons style in use
					if (string.Equals(GlobalVars.Settings.IconsStyle, "Animated", StringComparison.OrdinalIgnoreCase))
					{
#if APP_CONTROL_MANAGER
						ViewModel.AllowNewAppsIcon = new AnimatedIcon
						{
							Margin = new(0, -6, -6, -6),
							Source = new StarBlack()
						};
#endif
						ViewModel.UpdateIcon = new AnimatedIcon
						{
							Margin = new(0, -25, -25, -25),
							Source = new HeartPulse()
						};

					}

					break;
				}
			case "Dark":
				{
					RootGrid.RequestedTheme = ElementTheme.Dark;

					// Change the navigation icons based on dark/light theme only if "Animated" is the current icons style in use
					if (string.Equals(GlobalVars.Settings.IconsStyle, "Animated", StringComparison.OrdinalIgnoreCase))
					{
#if APP_CONTROL_MANAGER
						ViewModel.AllowNewAppsIcon = new AnimatedIcon
						{
							Margin = new(0, -6, -6, -6),
							Source = new StarYellow()
						};
#endif
						ViewModel.UpdateIcon = new AnimatedIcon
						{
							Margin = new(0, -5, -5, -5),
							Source = new Heart()
						};

					}

					break;
				}

			// if System Theme is selected
			default:
				{
					RootGrid.RequestedTheme = currentColorMode;

					if (currentColorMode is ElementTheme.Dark)
					{
						// Change the navigation icons based on dark/light theme only if "Animated" is the current icons style in use
						if (string.Equals(GlobalVars.Settings.IconsStyle, "Animated", StringComparison.OrdinalIgnoreCase))
						{
#if APP_CONTROL_MANAGER
							ViewModel.AllowNewAppsIcon = new AnimatedIcon
							{
								Margin = new(0, -6, -6, -6),
								Source = new StarYellow()
							};
#endif
							ViewModel.UpdateIcon = new AnimatedIcon
							{
								Margin = new(0, -5, -5, -5),
								Source = new Heart()
							};

						}
					}
					else
					{
						// Change the navigation icons based on dark/light theme only if "Animated" is the current icons style in use
						if (string.Equals(GlobalVars.Settings.IconsStyle, "Animated", StringComparison.OrdinalIgnoreCase))
						{
#if APP_CONTROL_MANAGER
							ViewModel.AllowNewAppsIcon = new AnimatedIcon
							{
								Margin = new(0, -6, -6, -6),
								Source = new StarBlack()
							};
#endif
							ViewModel.UpdateIcon = new AnimatedIcon
							{
								Margin = new(0, -25, -25, -25),
								Source = new HeartPulse()
							};

						}
					}

					break;
				}
		}
	}

	/// <summary>
	/// Event handler for the AppWindow Closing event.
	/// Shows a confirmation dialog before closing the application.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private async void AppWindow_Closing(AppWindow sender, AppWindowClosingEventArgs args)
	{
		// If we should always ask for confirmation
		if (ViewModel.AppSettings.AppCloseConfirmationBehavior == 0)
		{
			// Do nothing and let the flow continue
		}
		// If we should automatically/conditionally ask for confirmation
		else if (ViewModel.AppSettings.AppCloseConfirmationBehavior == 1)
		{
			if (!TaskTracking.AppNeedsCloseConfirmation)
			{
				return;
			}
		}
		// If we should never ask for confirmation
		else if (ViewModel.AppSettings.AppCloseConfirmationBehavior == 2)
		{
			return;
		}

		// Cancel the closing operation immediately to allow for async confirmation
		args.Cancel = true;

		await DispatcherQueue.EnqueueAsync(async () =>
		{
			// If there is an existing content dialog open, close it
			if (GlobalVars.CurrentlyOpenContentDialog is ContentDialog existingDialog)
			{
				existingDialog.Hide();
				GlobalVars.CurrentlyOpenContentDialog = null;
			}

			using AppControlManager.CustomUIElements.ContentDialogV2 confirmCloseDialog = new()
			{
				Title = GlobalVars.GetStr("ConfirmExitTitle"),
#if APP_CONTROL_MANAGER
				// if there is no policy in the Policies library in the Sidebar or if there is but Persistence is enabled
				Content = (ViewModel.SidebarPoliciesLibrary.Count == 0 || GlobalVars.Settings.PersistentPoliciesLibrary) ? GlobalVars.GetStr("ConfirmExitMsg") : GlobalVars.GetStr("ConfirmExitForUnsavedPoliciesMsg"),
#else
				Content = GlobalVars.GetStr("ConfirmExitMsg"),
#endif
				PrimaryButtonText = GlobalVars.GetStr("Yes"),
				CloseButtonText = GlobalVars.GetStr("No"),
				DefaultButton = ContentDialogButton.Close
			};

			ContentDialogResult result = await confirmCloseDialog.ShowAsync();

			if (result == ContentDialogResult.Primary)
			{
				// Close without re-triggering the cancelable AppWindow.Closing event loop
				Application.Current.Exit();
			}
		});
	}

	/// <summary>
	/// a method to manually refresh localized text for all UI elements in the MainWindow.
	/// All of the elements in the window's XAML that use x:UID must have an x:Name to be easily referenced in this method.
	/// </summary>
	internal void RefreshLocalizedContent()
	{
		try
		{
			// Create a new Resource Loader after changing the language of the app
			Microsoft.Windows.ApplicationModel.Resources.ResourceLoader resourceLoader = new();

			// Assign it to the Rizz in GlobalVars so any subsequent calls to it will receive the new strings
			GlobalVars.Rizz = resourceLoader;

			// Rebuild the dictionaries related to UI elements
			// Anything else that will be added in the future that will store texts related to UI elements on the Window itself from the resw file will have to be updated as well.
			ViewModel.RebuildBreadcrumbMappings();
			ViewModel.RebuildNavigationPageToItemContentMapForSearch();

			HomeNavItem.Content = GlobalVars.GetStr("HomeNavItem/Content");
			AutomationProperties.SetHelpText(HomeNavItem, GlobalVars.GetStr("HomeNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(HomeNavItem, GlobalVars.GetStr("HomeNavItem/ToolTipService/ToolTip"));

			GitHubDocsNavItem.Content = GlobalVars.GetStr("GitHubDocsNavItem/Content");
			AutomationProperties.SetHelpText(GitHubDocsNavItem, GlobalVars.GetStr("GitHubDocsNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(GitHubDocsNavItem, GlobalVars.GetStr("GitHubDocsNavItem/ToolTipService/ToolTip"));

			LogsNavItem.Content = GlobalVars.GetStr("LogsNavItem/Content");
			AutomationProperties.SetHelpText(LogsNavItem, GlobalVars.GetStr("LogsNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(LogsNavItem, GlobalVars.GetStr("LogsNavItem/ToolTipService/ToolTip"));

			UpdateNavItem.Content = GlobalVars.GetStr("UpdateNavItem/Content");
			AutomationProperties.SetHelpText(UpdateNavItem, GlobalVars.GetStr("UpdateNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(UpdateNavItem, GlobalVars.GetStr("UpdateNavItem/ToolTipService/ToolTip"));

#if HARDEN_SYSTEM_SECURITY

			TitleBarSearchBox.PlaceholderText = GlobalVars.GetStr("MainSearchAutoSuggestBox/PlaceholderText");
			AutomationProperties.SetHelpText(TitleBarSearchBox, GlobalVars.GetStr("MainSearchAutoSuggestBox/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(TitleBarSearchBox, GlobalVars.GetStr("MainSearchAutoSuggestBox/ToolTipService/ToolTip"));

			// Main navigation items for Harden System Security
			ProtectNavigationViewItemHeader.Content = GlobalVars.GetStr("ProtectNavigationViewItemHeader/Content");

			ProtectNavItem.Content = GlobalVars.GetStr("ProtectNavigationViewItem/Content");
			AutomationProperties.SetHelpText(ProtectNavItem, GlobalVars.GetStr("ProtectNavigationViewItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(ProtectNavItem, GlobalVars.GetStr("ProtectNavigationViewItem/ToolTipService/ToolTip"));

			MicrosoftDefenderNavItem.Content = GlobalVars.GetStr("MicrosoftDefenderNavItem/Content");
			AutomationProperties.SetHelpText(MicrosoftDefenderNavItem, GlobalVars.GetStr("MicrosoftDefenderNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(MicrosoftDefenderNavItem, GlobalVars.GetStr("MicrosoftDefenderNavItem/ToolTipService/ToolTip"));

			ASRNavItem.Content = GlobalVars.GetStr("ASRNavItem/Content");
			AutomationProperties.SetHelpText(ASRNavItem, GlobalVars.GetStr("ASRNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(ASRNavItem, GlobalVars.GetStr("ASRNavItem/ToolTipService/ToolTip"));

			BitLockerNavItem.Content = GlobalVars.GetStr("BitLockerNavItem/Content");
			AutomationProperties.SetHelpText(BitLockerNavItem, GlobalVars.GetStr("BitLockerNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(BitLockerNavItem, GlobalVars.GetStr("BitLockerNavItem/ToolTipService/ToolTip"));

			TLSSecurityNavItem.Content = GlobalVars.GetStr("TLSSecurityNavItem/Content");
			AutomationProperties.SetHelpText(TLSSecurityNavItem, GlobalVars.GetStr("TLSSecurityNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(TLSSecurityNavItem, GlobalVars.GetStr("TLSSecurityNavItem/ToolTipService/ToolTip"));

			LockScreenNavItem.Content = GlobalVars.GetStr("LockScreenNavItem/Content");
			AutomationProperties.SetHelpText(LockScreenNavItem, GlobalVars.GetStr("LockScreenNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(LockScreenNavItem, GlobalVars.GetStr("LockScreenNavItem/ToolTipService/ToolTip"));

			UACNavItem.Content = GlobalVars.GetStr("UACNavItem/Content");
			AutomationProperties.SetHelpText(UACNavItem, GlobalVars.GetStr("UACNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(UACNavItem, GlobalVars.GetStr("UACNavItem/ToolTipService/ToolTip"));

			DeviceGuardNavItem.Content = GlobalVars.GetStr("DeviceGuardNavItem/Content");
			AutomationProperties.SetHelpText(DeviceGuardNavItem, GlobalVars.GetStr("DeviceGuardNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(DeviceGuardNavItem, GlobalVars.GetStr("DeviceGuardNavItem/ToolTipService/ToolTip"));

			WindowsFirewallNavItem.Content = GlobalVars.GetStr("WindowsFirewallNavItem/Content");
			AutomationProperties.SetHelpText(WindowsFirewallNavItem, GlobalVars.GetStr("WindowsFirewallNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(WindowsFirewallNavItem, GlobalVars.GetStr("WindowsFirewallNavItem/ToolTipService/ToolTip"));

			OptionalWindowsFeaturesNavItem.Content = GlobalVars.GetStr("OptionalWindowsFeaturesNavItem/Content");
			AutomationProperties.SetHelpText(OptionalWindowsFeaturesNavItem, GlobalVars.GetStr("OptionalWindowsFeaturesNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(OptionalWindowsFeaturesNavItem, GlobalVars.GetStr("OptionalWindowsFeaturesNavItem/ToolTipService/ToolTip"));

			WindowsNetworkingNavItem.Content = GlobalVars.GetStr("WindowsNetworkingNavItem/Content");
			AutomationProperties.SetHelpText(WindowsNetworkingNavItem, GlobalVars.GetStr("WindowsNetworkingNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(WindowsNetworkingNavItem, GlobalVars.GetStr("WindowsNetworkingNavItem/ToolTipService/ToolTip"));

			MiscellaneousNavItem.Content = GlobalVars.GetStr("MiscellaneousNavItem/Content");
			AutomationProperties.SetHelpText(MiscellaneousNavItem, GlobalVars.GetStr("MiscellaneousNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(MiscellaneousNavItem, GlobalVars.GetStr("MiscellaneousNavItem/ToolTipService/ToolTip"));

			WindowsUpdateNavItem.Content = GlobalVars.GetStr("WindowsUpdateNavItem/Content");
			AutomationProperties.SetHelpText(WindowsUpdateNavItem, GlobalVars.GetStr("WindowsUpdateNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(WindowsUpdateNavItem, GlobalVars.GetStr("WindowsUpdateNavItem/ToolTipService/ToolTip"));

			EdgeBrowserNavItem.Content = GlobalVars.GetStr("EdgeBrowserNavItem/Content");
			AutomationProperties.SetHelpText(EdgeBrowserNavItem, GlobalVars.GetStr("EdgeBrowserNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(EdgeBrowserNavItem, GlobalVars.GetStr("EdgeBrowserNavItem/ToolTipService/ToolTip"));

			CertificatesNavItem.Content = GlobalVars.GetStr("CertificatesNavItem/Content");
			AutomationProperties.SetHelpText(CertificatesNavItem, GlobalVars.GetStr("CertificatesNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(CertificatesNavItem, GlobalVars.GetStr("CertificatesNavItem/ToolTipService/ToolTip"));

			CountryIPBlockingNavItem.Content = GlobalVars.GetStr("CountryIPBlockingNavItem/Content");
			AutomationProperties.SetHelpText(CountryIPBlockingNavItem, GlobalVars.GetStr("CountryIPBlockingNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(CountryIPBlockingNavItem, GlobalVars.GetStr("CountryIPBlockingNavItem/ToolTipService/ToolTip"));

			NonAdminCommandsNavItem.Content = GlobalVars.GetStr("NonAdminCommandsNavItem/Content");
			AutomationProperties.SetHelpText(NonAdminCommandsNavItem, GlobalVars.GetStr("NonAdminCommandsNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(NonAdminCommandsNavItem, GlobalVars.GetStr("NonAdminCommandsNavItem/ToolTipService/ToolTip"));

			InstalledAppsManagementNavItem.Content = GlobalVars.GetStr("InstalledAppsManagementNavItem/Content");
			AutomationProperties.SetHelpText(InstalledAppsManagementNavItem, GlobalVars.GetStr("InstalledAppsManagementNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(InstalledAppsManagementNavItem, GlobalVars.GetStr("InstalledAppsManagementNavItem/ToolTipService/ToolTip"));

			FileReputationNavItem.Content = GlobalVars.GetStr("FileReputationNavItem/Content");
			AutomationProperties.SetHelpText(FileReputationNavItem, GlobalVars.GetStr("FileReputationNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(FileReputationNavItem, GlobalVars.GetStr("FileReputationNavItem/ToolTipService/ToolTip"));

			GroupPolicyEditorNavItem.Content = GlobalVars.GetStr("GroupPolicyEditorNavItem/Content");
			AutomationProperties.SetHelpText(GroupPolicyEditorNavItem, GlobalVars.GetStr("GroupPolicyEditorNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(GroupPolicyEditorNavItem, GlobalVars.GetStr("GroupPolicyEditorNavItem/ToolTipService/ToolTip"));

			DocumentationNavigationViewItemHeader.Content = GlobalVars.GetStr("DocumentationNavigationViewItemHeader/Content");

			SidebarTextBlock.Text = GlobalVars.GetStr("SidebarTextBlock/Text");

			SidebarMainCaptionTextBlock.Text = GlobalVars.GetStr("SidebarMainCaptionTextBlock/Text");

			SidebarHelpHyperlinkTextBlock.Text = GlobalVars.GetStr("SidebarHelpHyperlinkTextBlock/Text");

			MicrosoftSecurityBaselineNavItem.Content = GlobalVars.GetStr("MicrosoftSecurityBaselineNavItem/Content");
			AutomationProperties.SetHelpText(MicrosoftSecurityBaselineNavItem, GlobalVars.GetStr("MicrosoftSecurityBaselineNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(MicrosoftSecurityBaselineNavItem, GlobalVars.GetStr("MicrosoftSecurityBaselineNavItem/ToolTipService/ToolTip"));

			MicrosoftBaseLinesOverridesNavItem.Content = GlobalVars.GetStr("MicrosoftBaseLinesOverridesNavItem/Content");
			AutomationProperties.SetHelpText(MicrosoftBaseLinesOverridesNavItem, GlobalVars.GetStr("MicrosoftBaseLinesOverridesNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(MicrosoftBaseLinesOverridesNavItem, GlobalVars.GetStr("MicrosoftBaseLinesOverridesNavItem/ToolTipService/ToolTip"));

			Microsoft365AppsSecurityBaselineNavItem.Content = GlobalVars.GetStr("Microsoft365AppsSecurityBaselineNavItem/Content");
			AutomationProperties.SetHelpText(Microsoft365AppsSecurityBaselineNavItem, GlobalVars.GetStr("Microsoft365AppsSecurityBaselineNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(Microsoft365AppsSecurityBaselineNavItem, GlobalVars.GetStr("Microsoft365AppsSecurityBaselineNavItem/ToolTipService/ToolTip"));

			AuditPoliciesNavItem.Content = GlobalVars.GetStr("AuditPoliciesNavItem/Content");
			AutomationProperties.SetHelpText(AuditPoliciesNavItem, GlobalVars.GetStr("AuditPoliciesNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(AuditPoliciesNavItem, GlobalVars.GetStr("AuditPoliciesNavItem/ToolTipService/ToolTip"));

			CBOMNavItem.Content = GlobalVars.GetStr("CBOMNavItem/Content");
			AutomationProperties.SetHelpText(CBOMNavItem, GlobalVars.GetStr("CBOMNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(CBOMNavItem, GlobalVars.GetStr("CBOMNavItem/ToolTipService/ToolTip"));

			IntuneNavItem.Content = GlobalVars.GetStr("IntuneNavItem/Content");
			AutomationProperties.SetHelpText(IntuneNavItem, GlobalVars.GetStr("IntuneNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(IntuneNavItem, GlobalVars.GetStr("IntuneNavItem/ToolTipService/ToolTip"));

			CSPNavItem.Content = GlobalVars.GetStr("CSPNavItem/Content");
			AutomationProperties.SetHelpText(CSPNavItem, GlobalVars.GetStr("CSPNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(CSPNavItem, GlobalVars.GetStr("CSPNavItem/ToolTipService/ToolTip"));

			ExtraFeaturesNavigationViewItemHeader.Content = GlobalVars.GetStr("ExtraFeaturesNavigationViewItemHeader/Content");

			ExtrasNavigationViewItem.Content = GlobalVars.GetStr("ExtrasNavigationViewItem/Content");
			AutomationProperties.SetHelpText(ExtrasNavigationViewItem, GlobalVars.GetStr("ExtrasNavigationViewItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(ExtrasNavigationViewItem, GlobalVars.GetStr("ExtrasNavigationViewItem/ToolTipService/ToolTip"));

			DuplicatePhotosFinderNavigationViewItem.Content = GlobalVars.GetStr("DuplicatePhotosFinderNavigationViewItem/Content");
			AutomationProperties.SetHelpText(DuplicatePhotosFinderNavigationViewItem, GlobalVars.GetStr("DuplicatePhotosFinderNavigationViewItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(DuplicatePhotosFinderNavigationViewItem, GlobalVars.GetStr("DuplicatePhotosFinderNavigationViewItem/ToolTipService/ToolTip"));

			EXIFManagerNavigationViewItem.Content = GlobalVars.GetStr("EXIFManagerNavigationViewItem/Content");
			AutomationProperties.SetHelpText(EXIFManagerNavigationViewItem, GlobalVars.GetStr("EXIFManagerNavigationViewItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(EXIFManagerNavigationViewItem, GlobalVars.GetStr("EXIFManagerNavigationViewItem/ToolTipService/ToolTip"));

			ServiceManagerNavItem.Content = GlobalVars.GetStr("ServiceManagerNavItem/Content");
			AutomationProperties.SetHelpText(ServiceManagerNavItem, GlobalVars.GetStr("ServiceManagerNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(ServiceManagerNavItem, GlobalVars.GetStr("ServiceManagerNavItem/ToolTipService/ToolTip"));

#endif

#if APP_CONTROL_MANAGER
			CustomUIElements.CustomPatternBasedFilePath.PopulateFilePathPatternExamplesCollection();

			CreationNavigationViewItemHeader.Content = GlobalVars.GetStr("CreationNavigationViewItemHeader/Content");

			CreatePolicyNavItem.Content = GlobalVars.GetStr("CreatePolicyNavItem/Content");
			AutomationProperties.SetHelpText(CreatePolicyNavItem, GlobalVars.GetStr("CreatePolicyNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(CreatePolicyNavItem, GlobalVars.GetStr("CreatePolicyNavItem/ToolTipService/ToolTip"));

			CreateSupplementalPolicyNavItem.Content = GlobalVars.GetStr("CreateSupplementalPolicyNavItem/Content");
			AutomationProperties.SetHelpText(CreateSupplementalPolicyNavItem, GlobalVars.GetStr("CreateSupplementalPolicyNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(CreateSupplementalPolicyNavItem, GlobalVars.GetStr("CreateSupplementalPolicyNavItem/ToolTipService/ToolTip"));

			CreateDenyPolicyNavItem.Content = GlobalVars.GetStr("CreateDenyPolicyNavItem/Content");
			AutomationProperties.SetHelpText(CreateDenyPolicyNavItem, GlobalVars.GetStr("CreateDenyPolicyNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(CreateDenyPolicyNavItem, GlobalVars.GetStr("CreateDenyPolicyNavItem/ToolTipService/ToolTip"));

			CertificatesNavigationViewItemHeader.Content = GlobalVars.GetStr("CertificatesNavigationViewItemHeader/Content");

			BuildNewCertificateNavItem.Content = GlobalVars.GetStr("BuildNewCertificateNavItem/Content");
			AutomationProperties.SetHelpText(BuildNewCertificateNavItem, GlobalVars.GetStr("BuildNewCertificateNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(BuildNewCertificateNavItem, GlobalVars.GetStr("BuildNewCertificateNavItem/ToolTipService/ToolTip"));

			ViewFileCertificatesNavItem.Content = GlobalVars.GetStr("ViewFileCertificatesNavItem/Content");
			AutomationProperties.SetHelpText(ViewFileCertificatesNavItem, GlobalVars.GetStr("ViewFileCertificatesNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(ViewFileCertificatesNavItem, GlobalVars.GetStr("ViewFileCertificatesNavItem/ToolTipService/ToolTip"));

			LogsProcessingNavigationViewItemHeader.Content = GlobalVars.GetStr("LogsProcessingNavigationViewItemHeader/Content");

			CreatePolicyFromEventLogsNavItem.Content = GlobalVars.GetStr("CreatePolicyFromEventLogsNavItem/Content");
			AutomationProperties.SetHelpText(CreatePolicyFromEventLogsNavItem, GlobalVars.GetStr("CreatePolicyFromEventLogsNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(CreatePolicyFromEventLogsNavItem, GlobalVars.GetStr("CreatePolicyFromEventLogsNavItem/ToolTipService/ToolTip"));

			CreatePolicyFromMDEAHNavItem.Content = GlobalVars.GetStr("CreatePolicyFromMDEAHNavItem/Content");
			AutomationProperties.SetHelpText(CreatePolicyFromMDEAHNavItem, GlobalVars.GetStr("CreatePolicyFromMDEAHNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(CreatePolicyFromMDEAHNavItem, GlobalVars.GetStr("CreatePolicyFromMDEAHNavItem/ToolTipService/ToolTip"));

			TacticalNavigationViewItemHeader.Content = GlobalVars.GetStr("TacticalNavigationViewItemHeader/Content");

			AllowNewAppsNavItem.Content = GlobalVars.GetStr("AllowNewAppsNavItem/Content");
			AutomationProperties.SetHelpText(AllowNewAppsNavItem, GlobalVars.GetStr("AllowNewAppsNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(AllowNewAppsNavItem, GlobalVars.GetStr("AllowNewAppsNavItem/ToolTipService/ToolTip"));

			PolicyEditorNavItem.Content = GlobalVars.GetStr("PolicyEditorNavItem/Content");

			SimulationNavItem.Content = GlobalVars.GetStr("SimulationNavItem/Content");
			AutomationProperties.SetHelpText(SimulationNavItem, GlobalVars.GetStr("SimulationNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(SimulationNavItem, GlobalVars.GetStr("SimulationNavItem/ToolTipService/ToolTip"));

			InfoGatheringNavigationViewItemHeader.Content = GlobalVars.GetStr("InfoGatheringNavigationViewItemHeader/Content");

			SystemInformationNavItem.Content = GlobalVars.GetStr("SystemInformationNavItem/Content");
			AutomationProperties.SetHelpText(SystemInformationNavItem, GlobalVars.GetStr("SystemInformationNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(SystemInformationNavItem, GlobalVars.GetStr("SystemInformationNavItem/ToolTipService/ToolTip"));

			GetCodeIntegrityHashesNavItem.Content = GlobalVars.GetStr("GetCodeIntegrityHashesNavItem/Content");
			AutomationProperties.SetHelpText(GetCodeIntegrityHashesNavItem, GlobalVars.GetStr("GetCodeIntegrityHashesNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(GetCodeIntegrityHashesNavItem, GlobalVars.GetStr("GetCodeIntegrityHashesNavItem/ToolTipService/ToolTip"));

			GetSecurePolicySettingsNavItem.Content = GlobalVars.GetStr("GetSecurePolicySettingsNavItem/Content");
			AutomationProperties.SetHelpText(GetSecurePolicySettingsNavItem, GlobalVars.GetStr("GetSecurePolicySettingsNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(GetSecurePolicySettingsNavItem, GlobalVars.GetStr("GetSecurePolicySettingsNavItem/ToolTipService/ToolTip"));

			PolicyManagementNavigationViewItemHeader.Content = GlobalVars.GetStr("PolicyManagementNavigationViewItemHeader/Content");

			ConfigurePolicyRuleOptionsNavItem.Content = GlobalVars.GetStr("ConfigurePolicyRuleOptionsNavItem/Content");
			AutomationProperties.SetHelpText(ConfigurePolicyRuleOptionsNavItem, GlobalVars.GetStr("ConfigurePolicyRuleOptionsNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(ConfigurePolicyRuleOptionsNavItem, GlobalVars.GetStr("ConfigurePolicyRuleOptionsNavItem/ToolTipService/ToolTip"));

			MergePoliciesNavItem.Content = GlobalVars.GetStr("MergePoliciesNavItem/Content");
			AutomationProperties.SetHelpText(MergePoliciesNavItem, GlobalVars.GetStr("MergePoliciesNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(MergePoliciesNavItem, GlobalVars.GetStr("MergePoliciesNavItem/ToolTipService/ToolTip"));

			DeploymentNavItem.Content = GlobalVars.GetStr("DeploymentNavItem/Content");
			AutomationProperties.SetHelpText(DeploymentNavItem, GlobalVars.GetStr("DeploymentNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(DeploymentNavItem, GlobalVars.GetStr("DeploymentNavItem/ToolTipService/ToolTip"));

			ValidatePoliciesNavItem.Content = GlobalVars.GetStr("ValidatePoliciesNavItem/Content");
			AutomationProperties.SetHelpText(ValidatePoliciesNavItem, GlobalVars.GetStr("ValidatePoliciesNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(ValidatePoliciesNavItem, GlobalVars.GetStr("ValidatePoliciesNavItem/ToolTipService/ToolTip"));

			SidebarPoliciesLibraryTextBlock.Text = GlobalVars.GetStr("SidebarPoliciesLibraryTextBlock/Text");

			OpenConfigDirectoryButtonText.Text = GlobalVars.GetStr("OpenConfigDirectoryButtonText/Text");

			MSFTDocsNavItem.Content = GlobalVars.GetStr("MSFTDocsNavItem/Content");
			AutomationProperties.SetHelpText(MSFTDocsNavItem, GlobalVars.GetStr("MSFTDocsNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(MSFTDocsNavItem, GlobalVars.GetStr("MSFTDocsNavItem/ToolTipService/ToolTip"));

			AutomationProperties.SetHelpText(OpenConfigDirectoryButton, GlobalVars.GetStr("OpenConfigDirectoryButton/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(OpenConfigDirectoryButton, GlobalVars.GetStr("OpenConfigDirectoryButton/ToolTipService/ToolTip"));

			PersistentPoliciesLibraryToggleSwitch.OnContent = GlobalVars.GetStr("ToggleSwitchGeneral/OnContent");
			PersistentPoliciesLibraryToggleSwitch.OffContent = GlobalVars.GetStr("ToggleSwitchGeneral/OffContent");

			FirewallSentinelNavItem.Content = GlobalVars.GetStr("FirewallSentinelNavItem/Content");
			AutomationProperties.SetHelpText(FirewallSentinelNavItem, GlobalVars.GetStr("FirewallSentinelNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(FirewallSentinelNavItem, GlobalVars.GetStr("FirewallSentinelNavItem/ToolTipService/ToolTip"));

#endif

			Logger.Write("MainWindow localized text refreshed successfully");
		}
		catch (Exception ex)
		{
			Logger.Write($"Error refreshing localized text: {ex.Message}");
		}
	}

#if APP_CONTROL_MANAGER

	/// <summary>
	/// Handles clicking on a sidebar item.
	/// 1. Finds the parent Grid (ItemRoot).
	/// 2. Manually applies the active visual state (Border + Elevation).
	/// 3. Sets a lock (_ignoreScrollUpdates) so the scroll logic doesn't override this selection immediately.
	/// </summary>
	private void OnAnimatedItemClicked(object sender, RoutedEventArgs e)
	{
		Button button = (Button)sender;

		// Walk up the visual tree to find the root Grid of the DataTemplate (ItemRoot)
		// Structure: Button -> Grid (ItemRoot) -> SwipeControl
		Grid? itemRoot = null;

		DependencyObject parent = VisualTreeHelper.GetParent(button);
		while (parent != null)
		{
			if (parent is Grid grid && string.Equals(grid.Name, "ItemRoot", StringComparison.Ordinal))
			{
				itemRoot = grid;
				break;
			}
			parent = VisualTreeHelper.GetParent(parent);
		}

		if (itemRoot != null)
		{
			// Disable scroll-based auto-selection temporarily
			// This ensures that clicking an item (even in a small list where it doesn't move to center)
			// will still select it visually.
			_ignoreScrollUpdates = true;
			_resetScrollUpdateTimer?.Start();

			// Apply active visual state to the clicked item
			UpdateActiveSidebarItemVisuals(itemRoot);

			// Start the bring-into-view animation
			itemRoot.StartBringIntoView(new BringIntoViewOptions()
			{
				VerticalAlignmentRatio = 0.5,
				AnimationDesired = true,
			});
		}
	}

	/// <summary>
	/// Handles automatic selection of the center item during scrolling.
	/// respects the _ignoreScrollUpdates lock to prevent overriding explicit clicks.
	/// </summary>
	private void Animated_ScrollViewer_ViewChanged(object sender, ScrollViewerViewChangedEventArgs e)
	{
		// If the user just clicked an item, ignore scroll updates for a short time
		if (_ignoreScrollUpdates) return;

		// Ensure we have items
		if (animatedScrollRepeater.ItemsSource is not System.Collections.IEnumerable source || !source.GetEnumerator().MoveNext())
			return;

		// Calculate the vertical center of the viewport.
		// Since we will transform item coordinates directly to the ScrollViewer, we just need the center of the visible area (ViewportHeight / 2).
		double viewportCenterY = Animated_ScrollViewer.ViewportHeight / 2.0;

		double minDistance = double.MaxValue;
		Grid? closestElement = null;

		// Iterate through realized elements
		// Using FilteredSidebarPolicies because that's what the ItemsRepeater is bound to.
		for (int i = 0; i < ViewModel.FilteredSidebarPolicies.Count; i++)
		{
			// TryGetElement returns the Root of DataTemplate -> SwipeControl
			UIElement? element = animatedScrollRepeater.TryGetElement(i);

			if (element is SwipeControl swipeControl && swipeControl.Content is Grid itemRoot)
			{
				// Get position relative to the ScrollViewer directly.
				// This handles cases where the ItemsRepeater is centered inside the ScrollViewer (via Grid wrapper).
				GeneralTransform transform = swipeControl.TransformToVisual(Animated_ScrollViewer);
				Point position = transform.TransformPoint(new Point(0, 0));

				// Calculate the center Y of the item itself
				double itemCenterY = position.Y + (swipeControl.ActualSize.Y / 2.0);

				// Distance from viewport center
				double distance = Math.Abs(itemCenterY - viewportCenterY);

				if (distance < minDistance)
				{
					minDistance = distance;
					closestElement = itemRoot; // We still want to style the inner Grid
				}
			}
		}

		if (closestElement != null)
		{
			UpdateActiveSidebarItemVisuals(closestElement);
		}
	}

	/// <summary>
	/// Applies visual styles (Gradient Border + Elevation) to the target Grid.
	/// </summary>
	private void UpdateActiveSidebarItemVisuals(Grid newGrid)
	{
		// 1. Reset the previously selected item if it's different
		if (_lastSelectedSidebarGrid != null && _lastSelectedSidebarGrid != newGrid)
		{
			ResetSidebarItemVisuals(_lastSelectedSidebarGrid);
		}

		// Avoid unnecessary property setting if it's the same item
		if (_lastSelectedSidebarGrid == newGrid)
			return;

		// 2. Apply active styles

		// Elevation: Lift the Grid up by 32px on Z-axis to cast Shadow
		newGrid.Translation = new Vector3(0, 0, 32);

		// Gradient Border: Find the overlay border and set Opacity to 1
		// Visual Tree: Grid(ItemRoot) -> Children -> Border
		foreach (UIElement child in newGrid.Children)
		{
			if (child is Border border && string.Equals(border.Name, "HighlightBorder", StringComparison.Ordinal))
			{
				border.Opacity = 1.0;
				break;
			}
		}

		// 3. Update reference
		_lastSelectedSidebarGrid = newGrid;
	}

	/// <summary>
	/// Resets the visual state of a sidebar item to its default (inactive) state.
	/// </summary>
	private static void ResetSidebarItemVisuals(Grid grid)
	{
		// Reset Elevation
		grid.Translation = Vector3.Zero;

		// Hide Gradient Border
		foreach (UIElement child in grid.Children)
		{
			if (child is Border border && string.Equals(border.Name, "HighlightBorder", StringComparison.Ordinal))
			{
				border.Opacity = 0.0;
				break;
			}
		}
	}

	private void OnAnimatedItemGotFocus(object sender, RoutedEventArgs e)
	{
		// When the clicked item has been received, bring it to the middle of the viewport.
		((FrameworkElement)sender).StartBringIntoView(new BringIntoViewOptions()
		{
			VerticalAlignmentRatio = 0.5,
			AnimationDesired = true,
		});
	}

	/// <summary>
	/// Occurs each time an element is made ready for use, necessary for virtualization.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void OnElementPrepared(ItemsRepeater sender, ItemsRepeaterElementPreparedEventArgs args)
	{
		// Cache Height and Margin for optimization
		if (AnimatedBtnHeight == 0)
		{
			if (args.Element is Control control)
			{
				AnimatedBtnHeight = control.ActualHeight;
				AnimatedBtnMargin = control.Margin;
			}
		}

		// Handle Element Reset and Composition Animation
		// Root is SwipeControl
		if (args.Element is SwipeControl swipeControl)
		{
			// 1. Reset Visuals on Inner Grid
			if (swipeControl.Content is Grid itemRoot)
			{
				ResetSidebarItemVisuals(itemRoot);

				if (_lastSelectedSidebarGrid == itemRoot)
				{
					_lastSelectedSidebarGrid = null;
				}
			}

			// 2. Apply Composition Scaling Animation to the SwipeControl (Stable Root)
			Microsoft.UI.Composition.Visual item = ElementCompositionPreview.GetElementVisual(swipeControl);
			Microsoft.UI.Composition.Visual svVisual = ElementCompositionPreview.GetElementVisual(Animated_ScrollViewer);

			// We also need the ItemsRepeater visual to account for its Offset (Centering logic in XAML)
			Microsoft.UI.Composition.Visual repeaterVisual = ElementCompositionPreview.GetElementVisual(sender);

			Microsoft.UI.Composition.CompositionPropertySet scrollProperties = ElementCompositionPreview.GetScrollViewerManipulationPropertySet(Animated_ScrollViewer);

			Microsoft.UI.Composition.ExpressionAnimation scaleExpression = scrollProperties.Compositor.CreateExpressionAnimation();
			scaleExpression.SetReferenceParameter("svVisual", svVisual);
			scaleExpression.SetReferenceParameter("scrollProperties", scrollProperties);
			scaleExpression.SetReferenceParameter("item", item);
			scaleExpression.SetReferenceParameter("repeaterVisual", repeaterVisual);

			// Scale the item based on the distance of the item relative to the center of the viewport.
			// This operates on the Visual layer (Scale), while our active logic operates on Translation and Border Opacity.
			// Adding 'repeaterVisual.Offset.Y' to the item position calculation
			// So that when the list is short, the ItemsRepeater is centered in the Grid, creating a Y Offset.
			// We must add this offset to the item's local offset to get the true visual position relative to the ScrollViewer's content root.
			scaleExpression.Expression = "1 - abs((svVisual.Size.Y/2 - scrollProperties.Translation.Y) - (repeaterVisual.Offset.Y + item.Offset.Y + item.Size.Y/2))*(.25/(svVisual.Size.Y/2))";

			// Animate the item based on its distance to the center of the viewport.
			item.StartAnimation("Scale.X", scaleExpression);
			item.StartAnimation("Scale.Y", scaleExpression);
			Microsoft.UI.Composition.ExpressionAnimation centerPointExpression = scrollProperties.Compositor.CreateExpressionAnimation();
			centerPointExpression.SetReferenceParameter("item", item);
			centerPointExpression.Expression = "Vector3(item.Size.X/2, item.Size.Y/2, 0)";
			item.StartAnimation("CenterPoint", centerPointExpression);
		}
	}

	/// <summary>
	/// Triggers the transfer icon animation from any source UIElement to the SidebarButton.
	/// </summary>
	/// <param name="sourceElement">The element starting the animation.</param>
	internal void TriggerTransferIconAnimation(UIElement? sourceElement)
	{
		if (sourceElement == null || AnimationOverlay == null || SidebarButton == null || TransferIcon == null)
			return;

		// Get the visual of the TransferIcon icon
		Microsoft.UI.Composition.Visual transferIconVisual = ElementCompositionPreview.GetElementVisual(TransferIcon);
		Microsoft.UI.Composition.Compositor compositor = transferIconVisual.Compositor;

		// Calculate Start Position (Center of the source element)
		// We calculate relative to AnimationOverlay to ensure coordinates match the Canvas coordinate space directly
		GeneralTransform buttonTransform = sourceElement.TransformToVisual(AnimationOverlay);
		Point buttonPosition = buttonTransform.TransformPoint(new Point(0, 0));

		// Use ActualSize if available (FrameworkElement), otherwise 0
		double sourceWidth = (sourceElement as FrameworkElement)?.ActualWidth ?? 0;
		double sourceHeight = (sourceElement as FrameworkElement)?.ActualHeight ?? 0;

		float startX = (float)buttonPosition.X + (float)sourceWidth / 2 - (float)TransferIcon.ActualWidth / 2;
		float startY = (float)buttonPosition.Y + (float)sourceHeight / 2 - (float)TransferIcon.ActualHeight / 2;

		// Calculate End Position (Center of the SidebarButton in the TitleBar)
		GeneralTransform targetTransform = SidebarButton.TransformToVisual(AnimationOverlay);
		Point targetPosition = targetTransform.TransformPoint(new Point(0, 0));
		float endX = (float)targetPosition.X + (float)SidebarButton.ActualWidth / 2 - (float)TransferIcon.ActualWidth / 2;
		float endY = (float)targetPosition.Y + (float)SidebarButton.ActualHeight / 2 - (float)TransferIcon.ActualHeight / 2;

		// Reset visual state before starting animation
		transferIconVisual.Offset = new Vector3(startX, startY, 0);
		transferIconVisual.Opacity = 0.0f;
		transferIconVisual.Scale = new Vector3(1.0f, 1.0f, 1.0f); // Fixed size at 1.0

		// Create the easing function
		// Use a cubic bezier for a swoosh effect (starts slow, speeds up, slows down)
		Microsoft.UI.Composition.CubicBezierEasingFunction swooshEasing = compositor.CreateCubicBezierEasingFunction(new Vector2(0.55f, 0.055f), new Vector2(0.675f, 0.19f));

		// 1. Movement Animation (Vector3)
		Microsoft.UI.Composition.Vector3KeyFrameAnimation offsetAnimation = compositor.CreateVector3KeyFrameAnimation();
		offsetAnimation.InsertKeyFrame(0.0f, new Vector3(startX, startY, 0)); // Start at button
		offsetAnimation.InsertKeyFrame(1.0f, new Vector3(endX, endY, 0), swooshEasing);     // End at sidebar button
		offsetAnimation.Duration = TimeSpan.FromMilliseconds(800);

		// Set the target property for the offset animation
		offsetAnimation.Target = "Offset";

		// 2. Opacity Animation (Fade In then Fade Out)
		Microsoft.UI.Composition.ScalarKeyFrameAnimation opacityAnimation = compositor.CreateScalarKeyFrameAnimation();
		opacityAnimation.InsertKeyFrame(0.0f, 0.0f); // Invisible at start
		opacityAnimation.InsertKeyFrame(0.1f, 1.0f); // Quickly visible
		opacityAnimation.InsertKeyFrame(0.9f, 1.0f); // Stay visible until 90%
		opacityAnimation.InsertKeyFrame(1.0f, 0.0f); // Fade out rapidly at the very end
		opacityAnimation.Duration = TimeSpan.FromMilliseconds(800);

		// Set the target property for the opacity animation
		opacityAnimation.Target = "Opacity";

		// Create an Animation Group
		Microsoft.UI.Composition.CompositionAnimationGroup animationGroup = compositor.CreateAnimationGroup();
		animationGroup.Add(offsetAnimation);
		animationGroup.Add(opacityAnimation);

		// Start the animation
		// We use Offset for position relative to the Canvas parent
		// StartAnimationGroup expects animations inside to have their Target property set.
		transferIconVisual.StartAnimationGroup(animationGroup);
	}


	#region Event handlers for the Sidebar's Policies Library

	private async void OnSwipeSaveAsXML(SwipeItem sender, SwipeItemInvokedEventArgs args)
	{
		if (sender.CommandParameter is PolicyFileRepresent policyContext)
		{
			try
			{
				_ = await ExecuteSaveAsXML(policyContext);
			}
			catch (Exception ex)
			{
				ViewModel.MainInfoBar.WriteError(ex);
			}
		}
	}

	private async void OnSwipeSaveAsCIP(SwipeItem sender, SwipeItemInvokedEventArgs args)
	{
		if (sender.CommandParameter is PolicyFileRepresent policyContext)
		{
			try
			{
				await ExecuteSaveAsCIP(policyContext);
			}
			catch (Exception ex)
			{
				ViewModel.MainInfoBar.WriteError(ex);
			}
		}
	}

	private async void OnSwipeRemove(SwipeItem sender, SwipeItemInvokedEventArgs args)
	{
		if (sender.CommandParameter is PolicyFileRepresent policyContext)
		{
			await ExecuteRemove(policyContext);
		}
	}

	private async void OnSwipeOpenInPolicyEditor(SwipeItem sender, SwipeItemInvokedEventArgs args)
	{
		if (sender.CommandParameter is PolicyFileRepresent policyContext)
		{
			await ExecuteOpenInPolicyEditor(policyContext);
		}
	}

	private async void OnSaveAsXMLClicked(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { DataContext: PolicyFileRepresent policyContext })
		{
			try
			{
				_ = await ExecuteSaveAsXML(policyContext);
			}
			catch (Exception ex)
			{
				ViewModel.MainInfoBar.WriteError(ex);
			}
		}
	}

	private async void OnSaveAsCIPClicked(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { DataContext: PolicyFileRepresent policyContext })
		{
			try
			{
				await ExecuteSaveAsCIP(policyContext);
			}
			catch (Exception ex)
			{
				ViewModel.MainInfoBar.WriteError(ex);
			}
		}
	}

	private async void OnRemoveClicked(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { DataContext: PolicyFileRepresent policyContext })
		{
			await ExecuteRemove(policyContext);
		}
	}

	private async void OnOpenInPolicyEditorClicked(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { DataContext: PolicyFileRepresent policyContext })
		{
			await ExecuteOpenInPolicyEditor(policyContext);
		}
	}

	private async void OnConfigureRuleOptionsClicked(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { DataContext: PolicyFileRepresent policyContext })
		{
			try
			{
				await ViewModelProvider.ConfigurePolicyRuleOptionsVM.OpenInConfigurePolicyRuleOptions(policyContext);
			}
			catch (Exception ex)
			{
				ViewModel.MainInfoBar.WriteError(ex);
			}
		}
	}

	private async void OnDeployClicked(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { DataContext: PolicyFileRepresent policyContext })
		{
			try
			{
				await Task.Run(() =>
				{
					ViewModel.MainInfoBar.WriteInfo($"Deploying the policy: {policyContext.PolicyIdentifier}");

					PreDeploymentChecks.CheckForSignatureConflict(policyContext.PolicyObj);

					// If a base policy is being deployed, ensure it's supplemental policy for AppControl Manager also gets deployed
					if (SupplementalForSelf.IsEligible(policyContext.PolicyObj))
						SupplementalForSelf.Deploy(policyContext.PolicyObj.PolicyID);

					CiToolHelper.UpdatePolicy(Management.ConvertXMLToBinary(policyContext.PolicyObj));

					ViewModel.MainInfoBar.WriteSuccess($"Successfully deployed the policy: {policyContext.PolicyIdentifier}");
				});
			}
			catch (Exception ex)
			{
				ViewModel.MainInfoBar.WriteError(ex);
			}
		}
	}

	internal static async Task<string?> ExecuteSaveAsXML(PolicyFileRepresent policyContext)
	{
		string fileName = $"{policyContext.PolicyIdentifier}.xml";

		string? savePath = await GlobalVars.AppDispatcher.EnqueueAsync(() =>
			 FileDialogHelper.ShowSaveFileDialog(GlobalVars.XMLFilePickerFilter, fileName)
		);

		if (savePath is null)
			return null;

		// Ensure the file path ends with .xml
		if (!savePath.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
		{
			savePath += ".xml";
		}

		Management.SavePolicyToFile(policyContext.PolicyObj, savePath);

		return savePath;
	}

	private static async Task ExecuteSaveAsCIP(PolicyFileRepresent policyContext)
	{
		string fileName = $"{policyContext.PolicyIdentifier}.cip";

		string? savePath = await GlobalVars.AppDispatcher.EnqueueAsync(() =>
			FileDialogHelper.ShowSaveFileDialog(GlobalVars.CIPFilesPickerFilter, fileName)
		);

		if (savePath is null)
			return;

		// Ensure the file path ends with .cip
		if (!savePath.EndsWith(".cip", StringComparison.OrdinalIgnoreCase))
		{
			savePath += ".cip";
		}

		Management.ConvertXMLToBinary(policyContext.PolicyObj, savePath);
	}

	/// <summary>
	/// Used when searching for policies in the Policies Library local cache.
	/// </summary>
	private static readonly EnumerationOptions enumerationOptionsForPoliciesLibraryRemoval = new()
	{
		RecurseSubdirectories = false,
		MatchCasing = MatchCasing.CaseInsensitive
	};

	/// <summary>
	/// The only method that should ever remove policies from the Sidebar Library.
	/// </summary>
	/// <param name="policyContext"></param>
	/// <exception cref="InvalidOperationException"></exception>
	private async Task ExecuteRemove(PolicyFileRepresent policyContext)
	{
		await ViewModel.PoliciesLibraryCacheLock.WaitAsync();
		try
		{
			if (!ViewModel.SidebarPoliciesLibrary.Remove(policyContext))
			{
				throw new InvalidOperationException("Failed to remove the policy from the sidebar library.");
			}

			if (ViewModel.SidebarPoliciesLibrary.Count == 0)
			{
				// Hide the animated icons on the currently visible page
				Nav.AffectPagesAnimatedIconsVisibilitiesEx(false);

				sidebarVM.Nullify();
			}

			// If the library should be persistent
			if (ViewModel.AppSettings.PersistentPoliciesLibrary)
			{
				await Task.Run(() =>
				{
					IEnumerable<string> currentFiles = Directory.EnumerateFiles(MainWindowVM.SidebarPoliciesLibraryCache, $"{policyContext.UniqueObjID}.xml", enumerationOptionsForPoliciesLibraryRemoval);
					foreach (string file in currentFiles)
					{
						File.Delete(file);
					}
				});
			}
		}
		catch (Exception ex)
		{
			ViewModel.MainInfoBar.WriteError(ex);
		}
		finally
		{
			_ = ViewModel.PoliciesLibraryCacheLock.Release();
		}
	}

	/// <summary>
	/// Opens a policy from the Sidebar's Library in the Policy Editor.
	/// </summary>
	/// <param name="policyContext"></param>
	/// <returns></returns>
	private static async Task ExecuteOpenInPolicyEditor(PolicyFileRepresent policyContext)
	{
		try
		{
			await ViewModelProvider.PolicyEditorVM.OpenInPolicyEditor(policyContext);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	/// <summary>
	/// The method responsible for clearing the Sidebar's policies library.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void ClearPoliciesLibrary(object sender, RoutedEventArgs e)
	{
		await ViewModel.PoliciesLibraryCacheLock.WaitAsync();
		try
		{
			// If library is persistent then remove one by one from the cache first
			if (ViewModel.AppSettings.PersistentPoliciesLibrary)
			{
				// Get all of the files in the cache first
				IEnumerable<string> currentFiles = Directory.EnumerateFiles(MainWindowVM.SidebarPoliciesLibraryCache);

				// Loop over all of the policies in the in-memory library
				foreach (PolicyFileRepresent item in ViewModelProvider.MainWindowVM.SidebarPoliciesLibrary)
				{
					foreach (string file in currentFiles)
					{
						if (file.EndsWith($"{item.UniqueObjID}.xml", StringComparison.OrdinalIgnoreCase))
						{
							File.Delete(file);
						}
					}
				}
			}

			// Bulk remove from the in-memory library
			ViewModelProvider.MainWindowVM.SidebarPoliciesLibrary.Clear();

			// Hide the animated icons on the currently visible page
			Nav.AffectPagesAnimatedIconsVisibilitiesEx(false);

			sidebarVM.Nullify();
		}
		catch (Exception ex)
		{
			ViewModel.MainInfoBar.WriteError(ex);
		}
		finally
		{
			_ = ViewModel.PoliciesLibraryCacheLock.Release();
		}
	}

	/// <summary>
	/// The method responsible for backing up the entire Policies Library to XML files.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void BackupLibrary(object sender, RoutedEventArgs e)
	{
		await ViewModel.PoliciesLibraryCacheLock.WaitAsync();
		try
		{
			if (ViewModelProvider.MainWindowVM.SidebarPoliciesLibrary.Count is 0)
			{
				Logger.Write("The Policies Library is empty. Nothing to back up.");
				return;
			}

			Logger.Write("Backing up the Policies Library");

			string? selectedDirectory = FileDialogHelper.ShowDirectoryPickerDialog();

			if (selectedDirectory is null)
				return;

			await Task.Run(() =>
			{
				foreach (PolicyFileRepresent item in ViewModelProvider.MainWindowVM.SidebarPoliciesLibrary)
				{
					string savePath = Path.Combine(selectedDirectory, $"{item.UniqueObjID}.xml");

					Management.SavePolicyToFile(item.PolicyObj, savePath);
				}
			});
		}
		catch (Exception ex)
		{
			ViewModel.MainInfoBar.WriteError(ex);
		}
		finally
		{
			_ = ViewModel.PoliciesLibraryCacheLock.Release();
		}
	}

	/// <summary>
	/// Event handler for right-click context menu option for each policy in the library.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void OnCopyPolicyID(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { DataContext: PolicyFileRepresent policyContext })
		{
			ClipboardManagement.CopyText(policyContext.PolicyObj.PolicyID);
		}
	}

	/// <summary>
	/// Event handler for right-click context menu option for each policy in the library.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void OnCopyBasePolicyID(object sender, RoutedEventArgs e)
	{
		if (sender is FrameworkElement { DataContext: PolicyFileRepresent policyContext })
		{
			ClipboardManagement.CopyText(policyContext.PolicyObj.BasePolicyID);
		}
	}

	/// <summary>
	/// Event handler for when policies are dragged over the Sidebar's policies library.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void OnSidebarDragOver(object sender, DragEventArgs e)
	{
		e.AcceptedOperation = Windows.ApplicationModel.DataTransfer.DataPackageOperation.None;

		if (e.DataView.Contains(Windows.ApplicationModel.DataTransfer.StandardDataFormats.StorageItems))
		{
			e.AcceptedOperation = Windows.ApplicationModel.DataTransfer.DataPackageOperation.Copy;
			e.DragUIOverride.Caption = GlobalVars.GetStr("AddPoliciesMenuFlyoutSubItem/Text");
		}
	}

	/// <summary>
	/// Event handler for when policies are dropped over the Sidebar's policies library.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void OnSidebarDrop(object sender, DragEventArgs e)
	{
		try
		{
			if (e.DataView.Contains(Windows.ApplicationModel.DataTransfer.StandardDataFormats.StorageItems))
			{
				IReadOnlyList<Windows.Storage.IStorageItem> items = await e.DataView.GetStorageItemsAsync();
				List<string> validFiles = [];

				foreach (Windows.Storage.IStorageItem item in items)
				{
					if (item is Windows.Storage.StorageFile file)
					{
						string extension = file.FileType;
						if (string.Equals(extension, ".xml", StringComparison.OrdinalIgnoreCase) ||
							string.Equals(extension, ".cip", StringComparison.OrdinalIgnoreCase) ||
							string.Equals(extension, ".bin", StringComparison.OrdinalIgnoreCase) ||
							string.Equals(extension, ".p7b", StringComparison.OrdinalIgnoreCase))
						{
							validFiles.Add(file.Path);
						}
					}
				}

				await Nav.AddPoliciesFromPaths(validFiles);
			}
		}
		catch (Exception ex)
		{
			ViewModel.MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Event handler for the UI button that opens the location of the Policies Library cache on disk.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private async void OpenPoliciesLibraryCacheLocation(object sender, RoutedEventArgs e)
	{
		try
		{
			await ViewModels.ViewModelBase.OpenFileInDefaultFileHandler(MainWindowVM.SidebarPoliciesLibraryCache);
		}
		catch (Exception ex)
		{
			ViewModel.MainInfoBar.WriteError(ex);
		}
	}

	#endregion

#endif

	/// <summary>
	/// Event handler for the Ctrl+F keyboard accelerator.
	/// Focuses the search box when the accelerator is invoked.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void SearchAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		_ = TitleBarSearchBox.Focus(FocusState.Programmatic);
		args.Handled = true;
	}

	/// <summary>
	/// Helper function for XAML binding to toggle visibility based on text content.
	/// Used for the "Ctrl+F" overlay in the search box.
	/// </summary>
	/// <param name="text">The search query text</param>
	/// <returns>Visible if text is null/empty, otherwise Collapsed.</returns>
	internal Visibility IsSearchBoxEmpty(string? text) => string.IsNullOrEmpty(text) ? Visibility.Visible : Visibility.Collapsed;

}
