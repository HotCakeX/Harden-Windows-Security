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
using AnimatedVisuals;
using AppControlManager.AppSettings;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using AppControlManager.WindowComponents;
using Microsoft.UI;
using Microsoft.UI.Input;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.ApplicationModel;
using Windows.Graphics;
using Microsoft.UI.Xaml.Automation;

namespace AppControlManager;

/// <summary>
/// MainWindow is a sealed class that represents the main application window, managing navigation, UI elements, and
/// event handling.
/// </summary>
internal sealed partial class MainWindow : Window
{

#pragma warning disable CA1822
	private MainWindowVM ViewModel { get; } = ViewModelProvider.MainWindowVM;
	private AppSettings.Main AppSettings { get; } = App.Settings;
	private SidebarVM sidebarVM { get; } = ViewModelProvider.SidebarVM;
#pragma warning restore CA1822

	internal static Grid? RootGridPub { get; private set; }

	private NavigationService Nav => ViewModelProvider.NavigationService;

	/// <summary>
	/// Initializes the main window, sets up event handlers, and configures UI elements like the title bar and navigation
	/// items.
	/// </summary>
	internal MainWindow()
	{
		this.InitializeComponent();

		Nav.Initialize(this.ContentFrame, this.MainNavigation);

		RootGridPub = RootGrid;

		// Retrieve the window handle (HWND) of the main WinUI 3 window and store it in the global vars
		GlobalVars.hWnd = WinRT.Interop.WindowNative.GetWindowHandle(this);

		// Set the window display affinity upon window creation to exclude it from capture if ScreenShield is enabled, otherwise set it to 
		WindowDisplayAffinity.SetWindowDisplayAffinity(GlobalVars.hWnd, AppSettings.ScreenShield ? WindowDisplayAffinity.DisplayAffinity.WDA_EXCLUDEFROMCAPTURE : WindowDisplayAffinity.DisplayAffinity.WDA_NONE);

		// https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.window.extendscontentintotitlebar
		// Make title bar Mica
		ExtendsContentIntoTitleBar = true;

		// Set the title bar's height style to tall
		this.AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;

		// Set the TitleBar title text to the app's display name
		TitleBarTextBlock.Text = AppInfo.Current.DisplayInfo.DisplayName;

		// https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.window.settitlebar
		// This is required. Without it, the page that has the TabView would make the App Window's TitleBar non-draggable.
		this.SetTitleBar(AppTitleBar);

		// Set the DataContext of the Grid to enable bindings in XAML
		RootGrid.DataContext = this;

		// Subscribe to the NavigationView Content background change event
		NavigationBackgroundManager.NavViewBackgroundChange += OnNavigationBackgroundChanged;

		// Subscribe to the global NavigationView location change event
		NavigationViewLocationManager.NavigationViewLocationChanged += OnNavigationViewLocationChanged;

		// Subscribe to the global App theme change event
		AppThemeManager.AppThemeChanged += OnAppThemeChanged;

		// Set the initial background setting based on the user's settings
		OnNavigationBackgroundChanged(null, new(App.Settings.NavViewBackground));

		// Set the initial App Theme based on the user's settings
		OnAppThemeChanged(null, new(App.Settings.AppTheme));
	}

	/// <summary>
	/// Specifies the interactive (passthrough) regions of the title bar—including proper RTL mirroring.
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
			LeftPaddingColumn.Width = new GridLength(AppWindow.TitleBar.RightInset / scale);
			RightPaddingColumn.Width = new GridLength(AppWindow.TitleBar.LeftInset / scale);
		}
		else
		{
			RightPaddingColumn.Width = new GridLength(AppWindow.TitleBar.RightInset / scale);
			LeftPaddingColumn.Width = new GridLength(AppWindow.TitleBar.LeftInset / scale);
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

		InputNonClientPointerSource nonClient = InputNonClientPointerSource.GetForWindowId(this.AppWindow.Id);

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

		// Calculate the opposite theme
		ElementTheme oppositeTheme = currentTheme == ElementTheme.Dark ? ElementTheme.Light : ElementTheme.Dark;

		// Switch to opposite theme
		RootGrid.RequestedTheme = oppositeTheme;

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
		// UISettings uiSettings = new();
		// ElementTheme currentColorMode = uiSettings.GetColorValue(UIColorType.Background) == Colors.Black
		//  ? ElementTheme.Dark
		//  : ElementTheme.Light;


		// Better approach that doesn't require instantiating a new UISettings object
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
					if (string.Equals(App.Settings.IconsStyle, "Animated", StringComparison.OrdinalIgnoreCase))
					{
						ViewModel.AllowNewAppsIcon = new AnimatedIcon
						{
							Margin = new Thickness(0, -6, -6, -6),
							Source = new StarBlack()
						};

						ViewModel.UpdateIcon = new AnimatedIcon
						{
							Margin = new Thickness(0, -25, -25, -25),
							Source = new HeartPulse()
						};
					}

					break;
				}
			case "Dark":
				{
					RootGrid.RequestedTheme = ElementTheme.Dark;

					// Change the navigation icons based on dark/light theme only if "Animated" is the current icons style in use
					if (string.Equals(App.Settings.IconsStyle, "Animated", StringComparison.OrdinalIgnoreCase))
					{
						ViewModel.AllowNewAppsIcon = new AnimatedIcon
						{
							Margin = new Thickness(0, -6, -6, -6),
							Source = new StarYellow()
						};

						ViewModel.UpdateIcon = new AnimatedIcon
						{
							Margin = new Thickness(0, -5, -5, -5),
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
						if (string.Equals(App.Settings.IconsStyle, "Animated", StringComparison.OrdinalIgnoreCase))
						{
							ViewModel.AllowNewAppsIcon = new AnimatedIcon
							{
								Margin = new Thickness(0, -6, -6, -6),
								Source = new StarYellow()
							};

							ViewModel.UpdateIcon = new AnimatedIcon
							{
								Margin = new Thickness(0, -5, -5, -5),
								Source = new Heart()
							};
						}
					}
					else
					{
						// Change the navigation icons based on dark/light theme only if "Animated" is the current icons style in use
						if (string.Equals(App.Settings.IconsStyle, "Animated", StringComparison.OrdinalIgnoreCase))
						{
							ViewModel.AllowNewAppsIcon = new AnimatedIcon
							{
								Margin = new Thickness(0, -6, -6, -6),
								Source = new StarBlack()
							};

							ViewModel.UpdateIcon = new AnimatedIcon
							{
								Margin = new Thickness(0, -25, -25, -25),
								Source = new HeartPulse()
							};
						}
					}

					break;
				}
		}

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
			CustomUIElements.CustomPatternBasedFilePath.PopulateFilePathPatternExamplesCollection();

			TitleBarSearchBox.PlaceholderText = GlobalVars.Rizz.GetString("MainSearchAutoSuggestBox/PlaceholderText");
			AutomationProperties.SetHelpText(TitleBarSearchBox, GlobalVars.Rizz.GetString("MainSearchAutoSuggestBox/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(TitleBarSearchBox, GlobalVars.Rizz.GetString("MainSearchAutoSuggestBox/ToolTipService/ToolTip"));

			CreationNavigationViewItemHeader.Content = GlobalVars.Rizz.GetString("CreationNavigationViewItemHeader/Content");

			CreatePolicyNavItem.Content = GlobalVars.Rizz.GetString("CreatePolicyNavItem/Content");
			AutomationProperties.SetHelpText(CreatePolicyNavItem, GlobalVars.Rizz.GetString("CreatePolicyNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(CreatePolicyNavItem, GlobalVars.Rizz.GetString("CreatePolicyNavItem/ToolTipService/ToolTip"));

			CreateSupplementalPolicyNavItem.Content = GlobalVars.Rizz.GetString("CreateSupplementalPolicyNavItem/Content");
			AutomationProperties.SetHelpText(CreateSupplementalPolicyNavItem, GlobalVars.Rizz.GetString("CreateSupplementalPolicyNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(CreateSupplementalPolicyNavItem, GlobalVars.Rizz.GetString("CreateSupplementalPolicyNavItem/ToolTipService/ToolTip"));

			CreateDenyPolicyNavItem.Content = GlobalVars.Rizz.GetString("CreateDenyPolicyNavItem/Content");
			AutomationProperties.SetHelpText(CreateDenyPolicyNavItem, GlobalVars.Rizz.GetString("CreateDenyPolicyNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(CreateDenyPolicyNavItem, GlobalVars.Rizz.GetString("CreateDenyPolicyNavItem/ToolTipService/ToolTip"));

			CertificatesNavigationViewItemHeader.Content = GlobalVars.Rizz.GetString("CertificatesNavigationViewItemHeader/Content");

			BuildNewCertificateNavItem.Content = GlobalVars.Rizz.GetString("BuildNewCertificateNavItem/Content");
			AutomationProperties.SetHelpText(BuildNewCertificateNavItem, GlobalVars.Rizz.GetString("BuildNewCertificateNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(BuildNewCertificateNavItem, GlobalVars.Rizz.GetString("BuildNewCertificateNavItem/ToolTipService/ToolTip"));

			ViewFileCertificatesNavItem.Content = GlobalVars.Rizz.GetString("ViewFileCertificatesNavItem/Content");
			AutomationProperties.SetHelpText(ViewFileCertificatesNavItem, GlobalVars.Rizz.GetString("ViewFileCertificatesNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(ViewFileCertificatesNavItem, GlobalVars.Rizz.GetString("ViewFileCertificatesNavItem/ToolTipService/ToolTip"));

			LogsProcessingNavigationViewItemHeader.Content = GlobalVars.Rizz.GetString("LogsProcessingNavigationViewItemHeader/Content");

			CreatePolicyFromEventLogsNavItem.Content = GlobalVars.Rizz.GetString("CreatePolicyFromEventLogsNavItem/Content");
			AutomationProperties.SetHelpText(CreatePolicyFromEventLogsNavItem, GlobalVars.Rizz.GetString("CreatePolicyFromEventLogsNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(CreatePolicyFromEventLogsNavItem, GlobalVars.Rizz.GetString("CreatePolicyFromEventLogsNavItem/ToolTipService/ToolTip"));

			CreatePolicyFromMDEAHNavItem.Content = GlobalVars.Rizz.GetString("CreatePolicyFromMDEAHNavItem/Content");
			AutomationProperties.SetHelpText(CreatePolicyFromMDEAHNavItem, GlobalVars.Rizz.GetString("CreatePolicyFromMDEAHNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(CreatePolicyFromMDEAHNavItem, GlobalVars.Rizz.GetString("CreatePolicyFromMDEAHNavItem/ToolTipService/ToolTip"));

			TacticalNavigationViewItemHeader.Content = GlobalVars.Rizz.GetString("TacticalNavigationViewItemHeader/Content");

			AllowNewAppsNavItem.Content = GlobalVars.Rizz.GetString("AllowNewAppsNavItem/Content");
			AutomationProperties.SetHelpText(AllowNewAppsNavItem, GlobalVars.Rizz.GetString("AllowNewAppsNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(AllowNewAppsNavItem, GlobalVars.Rizz.GetString("AllowNewAppsNavItem/ToolTipService/ToolTip"));

			PolicyEditorNavItem.Content = GlobalVars.Rizz.GetString("PolicyEditorNavItem/Content");

			SimulationNavItem.Content = GlobalVars.Rizz.GetString("SimulationNavItem/Content");
			AutomationProperties.SetHelpText(SimulationNavItem, GlobalVars.Rizz.GetString("SimulationNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(SimulationNavItem, GlobalVars.Rizz.GetString("SimulationNavItem/ToolTipService/ToolTip"));

			InfoGatheringNavigationViewItemHeader.Content = GlobalVars.Rizz.GetString("InfoGatheringNavigationViewItemHeader/Content");

			SystemInformationNavItem.Content = GlobalVars.Rizz.GetString("SystemInformationNavItem/Content");
			AutomationProperties.SetHelpText(SystemInformationNavItem, GlobalVars.Rizz.GetString("SystemInformationNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(SystemInformationNavItem, GlobalVars.Rizz.GetString("SystemInformationNavItem/ToolTipService/ToolTip"));

			GetCodeIntegrityHashesNavItem.Content = GlobalVars.Rizz.GetString("GetCodeIntegrityHashesNavItem/Content");
			AutomationProperties.SetHelpText(GetCodeIntegrityHashesNavItem, GlobalVars.Rizz.GetString("GetCodeIntegrityHashesNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(GetCodeIntegrityHashesNavItem, GlobalVars.Rizz.GetString("GetCodeIntegrityHashesNavItem/ToolTipService/ToolTip"));

			GetSecurePolicySettingsNavItem.Content = GlobalVars.Rizz.GetString("GetSecurePolicySettingsNavItem/Content");
			AutomationProperties.SetHelpText(GetSecurePolicySettingsNavItem, GlobalVars.Rizz.GetString("GetSecurePolicySettingsNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(GetSecurePolicySettingsNavItem, GlobalVars.Rizz.GetString("GetSecurePolicySettingsNavItem/ToolTipService/ToolTip"));

			PolicyManagementNavigationViewItemHeader.Content = GlobalVars.Rizz.GetString("PolicyManagementNavigationViewItemHeader/Content");

			ConfigurePolicyRuleOptionsNavItem.Content = GlobalVars.Rizz.GetString("ConfigurePolicyRuleOptionsNavItem/Content");
			AutomationProperties.SetHelpText(ConfigurePolicyRuleOptionsNavItem, GlobalVars.Rizz.GetString("ConfigurePolicyRuleOptionsNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(ConfigurePolicyRuleOptionsNavItem, GlobalVars.Rizz.GetString("ConfigurePolicyRuleOptionsNavItem/ToolTipService/ToolTip"));

			MergePoliciesNavItem.Content = GlobalVars.Rizz.GetString("MergePoliciesNavItem/Content");
			AutomationProperties.SetHelpText(MergePoliciesNavItem, GlobalVars.Rizz.GetString("MergePoliciesNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(MergePoliciesNavItem, GlobalVars.Rizz.GetString("MergePoliciesNavItem/ToolTipService/ToolTip"));

			DeploymentNavItem.Content = GlobalVars.Rizz.GetString("DeploymentNavItem/Content");
			AutomationProperties.SetHelpText(DeploymentNavItem, GlobalVars.Rizz.GetString("DeploymentNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(DeploymentNavItem, GlobalVars.Rizz.GetString("DeploymentNavItem/ToolTipService/ToolTip"));

			ValidatePoliciesNavItem.Content = GlobalVars.Rizz.GetString("ValidatePoliciesNavItem/Content");
			AutomationProperties.SetHelpText(ValidatePoliciesNavItem, GlobalVars.Rizz.GetString("ValidatePoliciesNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(ValidatePoliciesNavItem, GlobalVars.Rizz.GetString("ValidatePoliciesNavItem/ToolTipService/ToolTip"));

			DocumentationNavigationViewItemHeader.Content = GlobalVars.Rizz.GetString("DocumentationNavigationViewItemHeader/Content");

			GitHubDocsNavItem.Content = GlobalVars.Rizz.GetString("GitHubDocsNavItem/Content");
			AutomationProperties.SetHelpText(GitHubDocsNavItem, GlobalVars.Rizz.GetString("GitHubDocsNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(GitHubDocsNavItem, GlobalVars.Rizz.GetString("GitHubDocsNavItem/ToolTipService/ToolTip"));

			MSFTDocsNavItem.Content = GlobalVars.Rizz.GetString("MSFTDocsNavItem/Content");
			AutomationProperties.SetHelpText(MSFTDocsNavItem, GlobalVars.Rizz.GetString("MSFTDocsNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(MSFTDocsNavItem, GlobalVars.Rizz.GetString("MSFTDocsNavItem/ToolTipService/ToolTip"));

			LogsNavItem.Content = GlobalVars.Rizz.GetString("LogsNavItem/Content");
			AutomationProperties.SetHelpText(LogsNavItem, GlobalVars.Rizz.GetString("LogsNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(LogsNavItem, GlobalVars.Rizz.GetString("LogsNavItem/ToolTipService/ToolTip"));

			UpdateNavItem.Content = GlobalVars.Rizz.GetString("UpdateNavItem/Content");
			AutomationProperties.SetHelpText(UpdateNavItem, GlobalVars.Rizz.GetString("UpdateNavItem/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(UpdateNavItem, GlobalVars.Rizz.GetString("UpdateNavItem/ToolTipService/ToolTip"));

			SidebarTextBlock.Text = GlobalVars.Rizz.GetString("SidebarTextBlock/Text");

			SidebarMainCaptionTextBlock.Text = GlobalVars.Rizz.GetString("SidebarMainCaptionTextBlock/Text");

			SidebarPinnedPolicyPathTextBlock.Text = GlobalVars.Rizz.GetString("SidebarPinnedPolicyPathTextBlock/Text");

			SidebarPolicyPathPlaceHolder.PlaceholderText = GlobalVars.Rizz.GetString("SidebarPolicyPathPlaceHolder/PlaceholderText");

			AutomationProperties.SetHelpText(SidebarBrowseButton, GlobalVars.Rizz.GetString("SidebarBrowseButton/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(SidebarBrowseButton, GlobalVars.Rizz.GetString("SidebarBrowseButton/ToolTipService/ToolTip"));

			BrowseTextBlock.Text = GlobalVars.Rizz.GetString("BrowseTextBlock/Text");

			AutomationProperties.SetHelpText(SidebarClearButton, GlobalVars.Rizz.GetString("SidebarClearButton/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(SidebarClearButton, GlobalVars.Rizz.GetString("SidebarClearButton/ToolTipService/ToolTip"));

			ClearTextBlock.Text = GlobalVars.Rizz.GetString("ClearTextBlock/Text");

			AutomationProperties.SetHelpText(SidebarPolicySelectAssignmentButton, GlobalVars.Rizz.GetString("SidebarPolicySelectAssignmentButton/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(SidebarPolicySelectAssignmentButton, GlobalVars.Rizz.GetString("SidebarPolicySelectAssignmentButton/ToolTipService/ToolTip"));

			SelectTextBlock.Text = GlobalVars.Rizz.GetString("SelectTextBlock/Text");

			SidebarAutomaticAssignmentSettingsCard.Header = GlobalVars.Rizz.GetString("SidebarAutomaticAssignmentSettingsCard/Header");
			SidebarAutomaticAssignmentSettingsCard.Description = GlobalVars.Rizz.GetString("SidebarAutomaticAssignmentSettingsCard/Description");
			AutomationProperties.SetHelpText(SidebarAutomaticAssignmentSettingsCard, GlobalVars.Rizz.GetString("SidebarAutomaticAssignmentSettingsCard/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(SidebarAutomaticAssignmentSettingsCard, GlobalVars.Rizz.GetString("SidebarAutomaticAssignmentSettingsCard/ToolTipService/ToolTip"));

			SidebarGuideHyperlinkButton.Content = GlobalVars.Rizz.GetString("SidebarGuideHyperlinkButton/Content");

			OpenConfigDirectoryButtonText.Text = GlobalVars.Rizz.GetString("OpenConfigDirectoryButtonText/Text");

			AutomationProperties.SetHelpText(OpenConfigDirectoryButton, GlobalVars.Rizz.GetString("OpenConfigDirectoryButton/AutomationProperties/HelpText"));
			ToolTipService.SetToolTip(OpenConfigDirectoryButton, GlobalVars.Rizz.GetString("OpenConfigDirectoryButton/ToolTipService/ToolTip"));

			SidebarHelpHyperlinkTextBlock.Text = GlobalVars.Rizz.GetString("SidebarHelpHyperlinkTextBlock/Text");

			AutomaticAssignmentSidebarToggleSwitch.OnContent = GlobalVars.Rizz.GetString("ToggleSwitchGeneral/OnContent");
			AutomaticAssignmentSidebarToggleSwitch.OffContent = GlobalVars.Rizz.GetString("ToggleSwitchGeneral/OffContent");

			Logger.Write("MainWindow localized text refreshed successfully");
		}
		catch (Exception ex)
		{
			Logger.Write($"Error refreshing localized text: {ex.Message}");
		}
	}

}
