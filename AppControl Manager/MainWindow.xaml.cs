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
using System.Linq;
using AnimatedVisuals;
using AppControlManager.AppSettings;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using AppControlManager.WindowComponents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI;
using Microsoft.UI.Input;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.ApplicationModel;
using Windows.Graphics;
using WinRT;
using Rect = Windows.Foundation.Rect;

namespace AppControlManager;

/// <summary>
/// MainWindow is a sealed class that represents the main application window, managing navigation, UI elements, and
/// event handling.
/// </summary>
internal sealed partial class MainWindow : Window
{

#pragma warning disable CA1822
	private MainWindowVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<MainWindowVM>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
	private SidebarVM sidebarVM { get; } = App.AppHost.Services.GetRequiredService<SidebarVM>();
#pragma warning restore CA1822

	private readonly AppWindow m_AppWindow;

	internal static Grid? RootGridPub { get; private set; }

	/// <summary>
	/// Event handler for the BreadCrumbBar's ItemClicked event
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void BreadcrumbBar_ItemClicked(BreadcrumbBar sender, BreadcrumbBarItemClickedEventArgs args)
	{
		Crumb crumb = (Crumb)args.Item;

		nav.Navigate(crumb.Page, null);
	}

	private readonly NavigationService nav;

	/// <summary>
	/// Initializes the main window, sets up event handlers, and configures UI elements like the title bar and navigation
	/// items.
	/// </summary>
	internal MainWindow()
	{
		this.InitializeComponent();

		// Grab the singleton navigation-service and give it the Frame
		nav = App.AppHost.Services.GetRequiredService<NavigationService>();
		nav.Initialize(this.ContentFrame, this.MainNavigation);

		RootGridPub = RootGrid;

		// Retrieve the window handle (HWND) of the main WinUI 3 window and store it in the global vars
		GlobalVars.hWnd = WinRT.Interop.WindowNative.GetWindowHandle(this);

		// Set the window display affinity upon window creation to exclude it from capture if ScreenShield is enabled, otherwise set it to 
		WindowDisplayAffinity.SetWindowDisplayAffinity(GlobalVars.hWnd, AppSettings.ScreenShield ? WindowDisplayAffinity.DisplayAffinity.WDA_EXCLUDEFROMCAPTURE : WindowDisplayAffinity.DisplayAffinity.WDA_NONE);

		// https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.window.extendscontentintotitlebar
		// Make title bar Mica
		ExtendsContentIntoTitleBar = true;

		// Get the app window and set it to a class variable
		m_AppWindow = this.AppWindow;

		// Set the title bar's height style to tall
		m_AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;

		this.SizeChanged += MainWindow_SizeChanged;

		// Set the TitleBar title text to the app's display name
		TitleBarTextBlock.Text = AppInfo.Current.DisplayInfo.DisplayName;

		// https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.window.settitlebar
		// This is required. Without it, the page that has the TabView would make the App Window's TitleBar non-draggable.
		this.SetTitleBar(AppTitleBar);

		// Get all NavigationViewItem items in the MainNavigation, that includes MenuItems + any nested MenuItems + FooterMenuItems
		ViewModel.allNavigationItems =
		[                 .. MainNavigation.MenuItems
							 .OfType<NavigationViewItem>()
							 .SelectMany(GetAllChildren)
,
			 .. MainNavigation.FooterMenuItems.OfType<NavigationViewItem>().SelectMany(GetAllChildren),
			];

		static IEnumerable<NavigationViewItem> GetAllChildren(NavigationViewItem parent) =>
			new[] { parent }.Concat(parent.MenuItems.OfType<NavigationViewItem>().SelectMany(GetAllChildren));


		// Subscribe to the NavigationView Content background change event
		NavigationBackgroundManager.NavViewBackgroundChange += OnNavigationBackgroundChanged;

		// Subscribe to the global NavigationView location change event
		NavigationViewLocationManager.NavigationViewLocationChanged += OnNavigationViewLocationChanged;

		// Subscribe to the global App theme change event
		AppThemeManager.AppThemeChanged += OnAppThemeChanged;

		// Set the DataContext of the Grid to enable bindings in XAML
		RootGrid.DataContext = this;

		// Set the initial background setting based on the user's settings
		OnNavigationBackgroundChanged(null, new(App.Settings.NavViewBackground));

		// Set the initial App Theme based on the user's settings
		OnAppThemeChanged(null, new(App.Settings.AppTheme));

		// Restore window size on startup
		RestoreWindowSize();

		// Set the initial Icons styles abased on the user's settings
		ViewModel.OnIconsStylesChanged(App.Settings.IconsStyle);
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
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(TitleBarSearchBox, GlobalVars.Rizz.GetString("MainSearchAutoSuggestBox/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(TitleBarSearchBox, GlobalVars.Rizz.GetString("MainSearchAutoSuggestBox/ToolTipService/ToolTip"));

			CreationNavigationViewItemHeader.Content = GlobalVars.Rizz.GetString("CreationNavigationViewItemHeader/Content");

			CreatePolicyNavItem.Content = GlobalVars.Rizz.GetString("CreatePolicyNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(CreatePolicyNavItem, GlobalVars.Rizz.GetString("CreatePolicyNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(CreatePolicyNavItem, GlobalVars.Rizz.GetString("CreatePolicyNavItem/ToolTipService/ToolTip"));

			CreateSupplementalPolicyNavItem.Content = GlobalVars.Rizz.GetString("CreateSupplementalPolicyNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(CreateSupplementalPolicyNavItem, GlobalVars.Rizz.GetString("CreateSupplementalPolicyNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(CreateSupplementalPolicyNavItem, GlobalVars.Rizz.GetString("CreateSupplementalPolicyNavItem/ToolTipService/ToolTip"));

			CreateDenyPolicyNavItem.Content = GlobalVars.Rizz.GetString("CreateDenyPolicyNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(CreateDenyPolicyNavItem, GlobalVars.Rizz.GetString("CreateDenyPolicyNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(CreateDenyPolicyNavItem, GlobalVars.Rizz.GetString("CreateDenyPolicyNavItem/ToolTipService/ToolTip"));

			CertificatesNavigationViewItemHeader.Content = GlobalVars.Rizz.GetString("CertificatesNavigationViewItemHeader/Content");

			BuildNewCertificateNavItem.Content = GlobalVars.Rizz.GetString("BuildNewCertificateNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(BuildNewCertificateNavItem, GlobalVars.Rizz.GetString("BuildNewCertificateNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(BuildNewCertificateNavItem, GlobalVars.Rizz.GetString("BuildNewCertificateNavItem/ToolTipService/ToolTip"));

			ViewFileCertificatesNavItem.Content = GlobalVars.Rizz.GetString("ViewFileCertificatesNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(ViewFileCertificatesNavItem, GlobalVars.Rizz.GetString("ViewFileCertificatesNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(ViewFileCertificatesNavItem, GlobalVars.Rizz.GetString("ViewFileCertificatesNavItem/ToolTipService/ToolTip"));

			LogsProcessingNavigationViewItemHeader.Content = GlobalVars.Rizz.GetString("LogsProcessingNavigationViewItemHeader/Content");

			CreatePolicyFromEventLogsNavItem.Content = GlobalVars.Rizz.GetString("CreatePolicyFromEventLogsNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(CreatePolicyFromEventLogsNavItem, GlobalVars.Rizz.GetString("CreatePolicyFromEventLogsNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(CreatePolicyFromEventLogsNavItem, GlobalVars.Rizz.GetString("CreatePolicyFromEventLogsNavItem/ToolTipService/ToolTip"));

			CreatePolicyFromMDEAHNavItem.Content = GlobalVars.Rizz.GetString("CreatePolicyFromMDEAHNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(CreatePolicyFromMDEAHNavItem, GlobalVars.Rizz.GetString("CreatePolicyFromMDEAHNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(CreatePolicyFromMDEAHNavItem, GlobalVars.Rizz.GetString("CreatePolicyFromMDEAHNavItem/ToolTipService/ToolTip"));

			TacticalNavigationViewItemHeader.Content = GlobalVars.Rizz.GetString("TacticalNavigationViewItemHeader/Content");

			AllowNewAppsNavItem.Content = GlobalVars.Rizz.GetString("AllowNewAppsNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(AllowNewAppsNavItem, GlobalVars.Rizz.GetString("AllowNewAppsNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(AllowNewAppsNavItem, GlobalVars.Rizz.GetString("AllowNewAppsNavItem/ToolTipService/ToolTip"));

			PolicyEditorNavItem.Content = GlobalVars.Rizz.GetString("PolicyEditorNavItem/Content");

			SimulationNavItem.Content = GlobalVars.Rizz.GetString("SimulationNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(SimulationNavItem, GlobalVars.Rizz.GetString("SimulationNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(SimulationNavItem, GlobalVars.Rizz.GetString("SimulationNavItem/ToolTipService/ToolTip"));

			InfoGatheringNavigationViewItemHeader.Content = GlobalVars.Rizz.GetString("InfoGatheringNavigationViewItemHeader/Content");

			SystemInformationNavItem.Content = GlobalVars.Rizz.GetString("SystemInformationNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(SystemInformationNavItem, GlobalVars.Rizz.GetString("SystemInformationNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(SystemInformationNavItem, GlobalVars.Rizz.GetString("SystemInformationNavItem/ToolTipService/ToolTip"));

			GetCodeIntegrityHashesNavItem.Content = GlobalVars.Rizz.GetString("GetCodeIntegrityHashesNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(GetCodeIntegrityHashesNavItem, GlobalVars.Rizz.GetString("GetCodeIntegrityHashesNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(GetCodeIntegrityHashesNavItem, GlobalVars.Rizz.GetString("GetCodeIntegrityHashesNavItem/ToolTipService/ToolTip"));

			GetSecurePolicySettingsNavItem.Content = GlobalVars.Rizz.GetString("GetSecurePolicySettingsNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(GetSecurePolicySettingsNavItem, GlobalVars.Rizz.GetString("GetSecurePolicySettingsNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(GetSecurePolicySettingsNavItem, GlobalVars.Rizz.GetString("GetSecurePolicySettingsNavItem/ToolTipService/ToolTip"));

			PolicyManagementNavigationViewItemHeader.Content = GlobalVars.Rizz.GetString("PolicyManagementNavigationViewItemHeader/Content");

			ConfigurePolicyRuleOptionsNavItem.Content = GlobalVars.Rizz.GetString("ConfigurePolicyRuleOptionsNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(ConfigurePolicyRuleOptionsNavItem, GlobalVars.Rizz.GetString("ConfigurePolicyRuleOptionsNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(ConfigurePolicyRuleOptionsNavItem, GlobalVars.Rizz.GetString("ConfigurePolicyRuleOptionsNavItem/ToolTipService/ToolTip"));

			MergePoliciesNavItem.Content = GlobalVars.Rizz.GetString("MergePoliciesNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(MergePoliciesNavItem, GlobalVars.Rizz.GetString("MergePoliciesNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(MergePoliciesNavItem, GlobalVars.Rizz.GetString("MergePoliciesNavItem/ToolTipService/ToolTip"));

			DeploymentNavItem.Content = GlobalVars.Rizz.GetString("DeploymentNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(DeploymentNavItem, GlobalVars.Rizz.GetString("DeploymentNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(DeploymentNavItem, GlobalVars.Rizz.GetString("DeploymentNavItem/ToolTipService/ToolTip"));

			ValidatePoliciesNavItem.Content = GlobalVars.Rizz.GetString("ValidatePoliciesNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(ValidatePoliciesNavItem, GlobalVars.Rizz.GetString("ValidatePoliciesNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(ValidatePoliciesNavItem, GlobalVars.Rizz.GetString("ValidatePoliciesNavItem/ToolTipService/ToolTip"));

			DocumentationNavigationViewItemHeader.Content = GlobalVars.Rizz.GetString("DocumentationNavigationViewItemHeader/Content");

			GitHubDocsNavItem.Content = GlobalVars.Rizz.GetString("GitHubDocsNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(GitHubDocsNavItem, GlobalVars.Rizz.GetString("GitHubDocsNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(GitHubDocsNavItem, GlobalVars.Rizz.GetString("GitHubDocsNavItem/ToolTipService/ToolTip"));

			MSFTDocsNavItem.Content = GlobalVars.Rizz.GetString("MSFTDocsNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(MSFTDocsNavItem, GlobalVars.Rizz.GetString("MSFTDocsNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(MSFTDocsNavItem, GlobalVars.Rizz.GetString("MSFTDocsNavItem/ToolTipService/ToolTip"));

			LogsNavItem.Content = GlobalVars.Rizz.GetString("LogsNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(LogsNavItem, GlobalVars.Rizz.GetString("LogsNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(LogsNavItem, GlobalVars.Rizz.GetString("LogsNavItem/ToolTipService/ToolTip"));

			UpdateNavItem.Content = GlobalVars.Rizz.GetString("UpdateNavItem/Content");
			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(UpdateNavItem, GlobalVars.Rizz.GetString("UpdateNavItem/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(UpdateNavItem, GlobalVars.Rizz.GetString("UpdateNavItem/ToolTipService/ToolTip"));

			SidebarTextBlock.Text = GlobalVars.Rizz.GetString("SidebarTextBlock/Text");

			SidebarMainCaptionTextBlock.Text = GlobalVars.Rizz.GetString("SidebarMainCaptionTextBlock/Text");

			SidebarPinnedPolicyPathTextBlock.Text = GlobalVars.Rizz.GetString("SidebarPinnedPolicyPathTextBlock/Text");

			SidebarPolicyPathPlaceHolder.PlaceholderText = GlobalVars.Rizz.GetString("SidebarPolicyPathPlaceHolder/PlaceholderText");

			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(SidebarBrowseButton, GlobalVars.Rizz.GetString("SidebarBrowseButton/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(SidebarBrowseButton, GlobalVars.Rizz.GetString("SidebarBrowseButton/ToolTipService/ToolTip"));

			BrowseTextBlock.Text = GlobalVars.Rizz.GetString("BrowseTextBlock/Text");

			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(SidebarClearButton, GlobalVars.Rizz.GetString("SidebarClearButton/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(SidebarClearButton, GlobalVars.Rizz.GetString("SidebarClearButton/ToolTipService/ToolTip"));

			ClearTextBlock.Text = GlobalVars.Rizz.GetString("ClearTextBlock/Text");

			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(SidebarPolicySelectAssignmentButton, GlobalVars.Rizz.GetString("SidebarPolicySelectAssignmentButton/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(SidebarPolicySelectAssignmentButton, GlobalVars.Rizz.GetString("SidebarPolicySelectAssignmentButton/ToolTipService/ToolTip"));

			SelectTextBlock.Text = GlobalVars.Rizz.GetString("SelectTextBlock/Text");

			SidebarAutomaticAssignmentSettingsCard.Header = GlobalVars.Rizz.GetString("SidebarAutomaticAssignmentSettingsCard/Header");

			SidebarGuideHyperlinkButton.Content = GlobalVars.Rizz.GetString("SidebarGuideHyperlinkButton/Content");

			OpenConfigDirectoryButtonText.Text = GlobalVars.Rizz.GetString("OpenConfigDirectoryButtonText/Text");

			Microsoft.UI.Xaml.Automation.AutomationProperties.SetHelpText(OpenConfigDirectoryButton, GlobalVars.Rizz.GetString("OpenConfigDirectoryButton/AutomationProperties/HelpText"));
			Microsoft.UI.Xaml.Controls.ToolTipService.SetToolTip(OpenConfigDirectoryButton, GlobalVars.Rizz.GetString("OpenConfigDirectoryButton/ToolTipService/ToolTip"));

			Logger.Write("MainWindow localized text refreshed successfully");
		}
		catch (Exception ex)
		{
			Logger.Write($"Error refreshing localized text: {ex.Message}");
		}
	}

	/// <summary>
	/// Specifies the interactive regions of the title bar in the AppTitleBar Grid.
	/// </summary>
	private void SetRegionsForCustomTitleBar()
	{
		double scaleAdjustment = AppTitleBar.XamlRoot.RasterizationScale;

		RightPaddingColumn.Width = new GridLength(m_AppWindow.TitleBar.RightInset / scaleAdjustment);
		LeftPaddingColumn.Width = new GridLength(m_AppWindow.TitleBar.LeftInset / scaleAdjustment);


		// For the main back button
		GeneralTransform transform = BackButtonTitleBar.TransformToVisual(null);
		Rect bounds = transform.TransformBounds(new Rect(0, 0,
													BackButtonTitleBar.ActualWidth,
													BackButtonTitleBar.ActualHeight));
		RectInt32 backButtonRect = GetRect(bounds, scaleAdjustment);


		// For the hamburger main menu button
		transform = HamburgerMenuButton.TransformToVisual(null);
		bounds = transform.TransformBounds(new Rect(0, 0,
												   HamburgerMenuButton.ActualWidth,
												   HamburgerMenuButton.ActualHeight));
		RectInt32 hamburgerMenuButtonRect = GetRect(bounds, scaleAdjustment);


		// Get the rectangle around the AutoSuggestBox control.
		transform = TitleBarSearchBox.TransformToVisual(null);
		bounds = transform.TransformBounds(new Rect(0, 0,
														TitleBarSearchBox.ActualWidth,
														TitleBarSearchBox.ActualHeight));
		RectInt32 SearchBoxRect = GetRect(bounds, scaleAdjustment);


		// Get the rectangle around the Sidebar button.
		transform = SidebarButton.TransformToVisual(null);
		bounds = transform.TransformBounds(new Rect(0, 0,
													SidebarButton.ActualWidth,
													SidebarButton.ActualHeight));
		RectInt32 PersonPicRect = GetRect(bounds, scaleAdjustment);

		// Put all items in an array
		RectInt32[] rectArray = [backButtonRect, hamburgerMenuButtonRect, SearchBoxRect, PersonPicRect];

		InputNonClientPointerSource nonClientInputSrc =
			InputNonClientPointerSource.GetForWindowId(this.AppWindow.Id);
		nonClientInputSrc.SetRegionRects(NonClientRegionKind.Passthrough, rectArray);
	}


	private static RectInt32 GetRect(Rect bounds, double scale)
	{
		return new RectInt32(
			_X: (int)Math.Round(bounds.X * scale),
			_Y: (int)Math.Round(bounds.Y * scale),
			_Width: (int)Math.Round(bounds.Width * scale),
			_Height: (int)Math.Round(bounds.Height * scale)
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

	/// <summary>
	/// Event handler to run at Window launch to restore its size to the one before closing
	/// </summary>
	private void RestoreWindowSize()
	{

		// If the window was last maximized then restore it to maximized
		if (App.Settings.MainWindowIsMaximized)
		{

			Logger.Write(GlobalVars.Rizz.GetString("WindowMaximizedMsg"));

			// Using .As<>() instead of direct cast because in NAOT mode direct cast would throw error for invalid cast operation. This is a bug in CsWinRT
			OverlappedPresenter presenter = m_AppWindow.Presenter.As<OverlappedPresenter>();

			// Set the presenter to maximized
			presenter.Maximize();
		}

		// Else set its size to its previous size before closing
		else
		{
			// If the previous window size was smaller than 200 pixels width/height then do not use it, let it use the natural window size
			if (App.Settings.MainWindowWidth > 200 && App.Settings.MainWindowHeight > 200)
			{

				Logger.Write(string.Format(GlobalVars.Rizz.GetString("SettingWindowSizeMessage"), App.Settings.MainWindowHeight, App.Settings.MainWindowWidth));

				// Apply to the current AppWindow
				m_AppWindow?.Resize(new SizeInt32(App.Settings.MainWindowWidth, App.Settings.MainWindowHeight));
			}
		}
	}

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


#pragma warning disable CA1822

	/// <summary>
	/// Event handler for the AutoSuggestBox text change event
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void SearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
	{
		if (args.Reason == AutoSuggestionBoxTextChangeReason.UserInput)
		{
			// Get the text user entered in the search box
			string query = sender.Text.Trim();

			// Filter menu items based on the search query
			List<string> suggestions = new(ViewModel.NavigationPageToItemContentMapForSearch.Keys.Where(name => name.Contains(query, StringComparison.OrdinalIgnoreCase)));

			// Set the filtered items as suggestions in the AutoSuggestBox
			sender.ItemsSource = suggestions;
		}
	}

#pragma warning restore CA1822


	/// <summary>
	/// Event handler for when a suggestion is chosen in the AutoSuggestBox
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void SearchBox_SuggestionChosen(AutoSuggestBox sender, AutoSuggestBoxSuggestionChosenEventArgs args)
	{
		// Get the selected item's name and find the corresponding NavigationViewItem
		string? chosenItemName = args.SelectedItem?.ToString();

		if (chosenItemName is not null && ViewModel.NavigationPageToItemContentMapForSearch.TryGetValue(chosenItemName, out Type? selectedItem))
		{
			nav.Navigate(selectedItem, null);
		}
	}


	/// <summary>
	/// Main navigation event of the Nav View
	/// ItemInvoked event is much better than SelectionChanged because it allows click/tap on the same selected menu on main navigation
	/// which is necessary if the same main page is selected but user has navigated to inner pages and then wants to go back by selecting the already selected main navigation item again.
	/// The duplicate-loading logic is implemented manually in code behind.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void MainNavigation_ItemInvoked(NavigationView sender, NavigationViewItemInvokedEventArgs? args)
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
				nav.Navigate(typeof(Pages.Settings), null);
			}
			else
			{
				nav.Navigate(null, args?.InvokedItemContainer.Tag.ToString());
			}
		}
	}


	/// <summary>
	/// Event handler for when the back button is pressed
	/// </summary>
	private void BackButtonTitleBar_Click()
	{
		if (ContentFrame.CanGoBack)
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
			ContentFrame.GoBack(new DrillInNavigationTransitionInfo());

			// Get the current page after navigating back
			Type currentPage = ContentFrame.CurrentSourcePageType;

			// For page Interface and light augmentation
			nav.AffectPagesAnimatedIconsVisibilities(ContentFrame);

			_ = ViewModel.breadCrumbMappingsV2.TryGetValue(currentPage, out PageTitleMap? info);

			if (info is not null)
			{
				int currentPageLocation = info.Pages.IndexOf(currentPage);

				ViewModel.Breadcrumbs.Clear();

				for (int i = 0; i <= currentPageLocation; i++)
				{
					ViewModel.Breadcrumbs.Add(new Crumb(info.Titles[i], info.Pages[i]));
				}

				// Since settings page doesn't have content when it is in Top mode (it only has Tag property)
				// And also content for the auto-created Settings page varies based on localization, adding an explicit check for it here
				if (Equals(currentPage, typeof(Pages.Settings)))
				{
					ViewModel.NavViewSelectedItem = MainNavigation.SettingsItem;
				}
				else
				{
					// info.Titles[0] ensures the selected item in the NavigationView will correctly be set to the main item in the menu even when the page being navigated to is a sub-page in that valid navigational path
					ViewModel.NavViewSelectedItem = ViewModel.allNavigationItems.First(x => string.Equals(x.Content.ToString(), info.Titles[0], StringComparison.OrdinalIgnoreCase));
				}
			}
		}
	}

	/// <summary>
	/// Event handler for when the main app window's size changes
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void MainWindow_SizeChanged(object sender, WindowSizeChangedEventArgs args)
	{
		double mainWindowWidth = args.Size.Width; // Width of the main window

		// Hide TitleColumn if width is less than 200, Restore the TitleColumn if width is 200 or more
		ViewModel.TitleColumnWidth = mainWindowWidth < 750 ? new GridLength(0) : GridLength.Auto;
	}
}
