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
using System.Threading.Tasks;
using AnimatedVisuals;
using AppControlManager.AppSettings;
using AppControlManager.Others;
using AppControlManager.Sidebar;
using AppControlManager.ViewModels;
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
	private PolicyEditorVM PolicyEditorViewModel { get; } = App.AppHost.Services.GetRequiredService<PolicyEditorVM>();
#pragma warning restore CA1822

	private readonly AppWindow m_AppWindow;

	internal readonly Grid RootGridPub;

	/// <summary>
	/// Used for the BreadCrumBar's data to define valid navigational paths in the app
	/// </summary>
	private sealed class PageTitleMap
	{
		internal required List<string> Titles { get; set; }
		internal required List<Type> Pages { get; set; }
	}

	// a list of all the NavigationViewItem in the Main NavigationViewItem
	// It is populated in the class initializer
	// Since the app uses it multiple times, we only populate this list once to reuse it in subsequent calls
	private readonly IEnumerable<NavigationViewItem> allNavigationItems = [];

	/// <summary>
	/// Pages that are allowed to run when running without Administrator privileges
	/// </summary>
	private static readonly IEnumerable<Type> UnelevatedPages = [
		typeof(Pages.ValidatePolicy),
		typeof(Pages.GitHubDocumentation),
		typeof(Pages.MicrosoftDocumentation),
		typeof(Pages.Logs),
		typeof(Pages.GetCIHashes),
		typeof(Pages.PolicyEditor),
		typeof(Pages.MergePolicies),
		typeof(Pages.Settings),
		typeof(Pages.ConfigurePolicyRuleOptions)
		];


	/// <summary>
	/// Every page in the application must be defined in this dictionary.
	/// It is used by the BreadCrumbBar.
	/// Sub-pages must use the same value as their main page in the dictionary.
	/// </summary>
	private static readonly Dictionary<Type, PageTitleMap> breadCrumbMappingsV2 = new()
	{
		[typeof(Pages.CreatePolicy)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("CreatePolicyNavItem/Content")],
			Pages = [typeof(Pages.CreatePolicy)]
		},
		[typeof(Pages.GetCIHashes)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("GetCodeIntegrityHashesNavItem/Content")],
			Pages = [typeof(Pages.GetCIHashes)]
		},
		[typeof(Pages.GitHubDocumentation)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("GitHubDocsNavItem/Content")],
			Pages = [typeof(Pages.GitHubDocumentation)]
		},
		[typeof(Pages.MicrosoftDocumentation)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("MSFTDocsNavItem/Content")],
			Pages = [typeof(Pages.MicrosoftDocumentation)]
		},
		[typeof(Pages.GetSecurePolicySettings)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("GetSecurePolicySettingsNavItem/Content")],
			Pages = [typeof(Pages.GetSecurePolicySettings)]
		},
		[typeof(Pages.Settings)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("SettingsNavItem/Content")],
			Pages = [typeof(Pages.Settings)]
		},
		[typeof(Pages.SystemInformation)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("SystemInformationNavItem/Content")],
			Pages = [typeof(Pages.SystemInformation)]
		},
		[typeof(Pages.ConfigurePolicyRuleOptions)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("ConfigurePolicyRuleOptionsNavItem/Content")],
			Pages = [typeof(Pages.ConfigurePolicyRuleOptions)]
		},
		[typeof(Pages.Logs)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("LogsNavItem/Content")],
			Pages = [typeof(Pages.Logs)]
		},
		[typeof(Pages.Simulation)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("SimulationNavItem/Content")],
			Pages = [typeof(Pages.Simulation)]
		},
		[typeof(Pages.UpdatePage)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("UpdateNavItem/Content"), "Custom MSIXBundle Path"],
			Pages = [typeof(Pages.UpdatePage), typeof(Pages.UpdatePageCustomMSIXPath)]
		},
		[typeof(Pages.UpdatePageCustomMSIXPath)] = new PageTitleMap // sub-page
		{
			Titles = [GlobalVars.Rizz.GetString("UpdateNavItem/Content"), "Custom MSIXBundle Path"],
			Pages = [typeof(Pages.UpdatePage), typeof(Pages.UpdatePageCustomMSIXPath)]
		},
		[typeof(Pages.DeploymentPage)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("DeploymentNavItem/Content")],
			Pages = [typeof(Pages.DeploymentPage)]
		},
		[typeof(Pages.EventLogsPolicyCreation)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("CreatePolicyFromEventLogsNavItem/Content")],
			Pages = [typeof(Pages.EventLogsPolicyCreation)]
		},
		[typeof(Pages.MDEAHPolicyCreation)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("CreatePolicyFromMDEAHNavItem/Content")],
			Pages = [typeof(Pages.MDEAHPolicyCreation)]
		},
		[typeof(Pages.AllowNewApps)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("AllowNewAppsNavItem/Content")],
			Pages = [typeof(Pages.AllowNewApps)]
		},
		[typeof(Pages.BuildNewCertificate)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("BuildNewCertificateNavItem/Content")],
			Pages = [typeof(Pages.BuildNewCertificate)]
		},
		[typeof(Pages.MergePolicies)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("MergePoliciesNavItem/Content")],
			Pages = [typeof(Pages.MergePolicies)]
		},
		[typeof(Pages.CreateSupplementalPolicy)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("CreateSupplementalPolicyNavItem/Content"), GlobalVars.Rizz.GetString("ScanResults")],
			Pages = [typeof(Pages.CreateSupplementalPolicy), typeof(Pages.CreateSupplementalPolicyFilesAndFoldersScanResults)]
		},
		[typeof(Pages.CreateSupplementalPolicyFilesAndFoldersScanResults)] = new PageTitleMap // sub-page
		{
			Titles = [GlobalVars.Rizz.GetString("CreateSupplementalPolicyNavItem/Content"), GlobalVars.Rizz.GetString("ScanResults")],
			Pages = [typeof(Pages.CreateSupplementalPolicy), typeof(Pages.CreateSupplementalPolicyFilesAndFoldersScanResults)]
		},
		[typeof(Pages.StrictKernelPolicyScanResults)] = new PageTitleMap // sub-page
		{
			Titles = [GlobalVars.Rizz.GetString("CreateSupplementalPolicyNavItem/Content"), GlobalVars.Rizz.GetString("ScanResults")],
			Pages = [typeof(Pages.CreateSupplementalPolicy), typeof(Pages.StrictKernelPolicyScanResults)]
		},
		[typeof(Pages.CreateDenyPolicy)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("CreateDenyPolicyNavItem/Content"), GlobalVars.Rizz.GetString("ScanResults")],
			Pages = [typeof(Pages.CreateDenyPolicy), typeof(Pages.CreateDenyPolicyFilesAndFoldersScanResults)]
		},
		[typeof(Pages.CreateDenyPolicyFilesAndFoldersScanResults)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("CreateDenyPolicyNavItem/Content"), GlobalVars.Rizz.GetString("ScanResults")],
			Pages = [typeof(Pages.CreateDenyPolicy), typeof(Pages.CreateDenyPolicyFilesAndFoldersScanResults)]
		},
		[typeof(Pages.ValidatePolicy)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("ValidatePoliciesNavItem/Content")],
			Pages = [typeof(Pages.ValidatePolicy)]
		},
		[typeof(Pages.ViewFileCertificates)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("ViewFileCertificatesNavItem/Content")],
			Pages = [typeof(Pages.ViewFileCertificates)]
		},
		[typeof(Pages.PolicyEditor)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("PolicyEditorNavItem/Content")],
			Pages = [typeof(Pages.PolicyEditor)]
		}
	};


	// This collection is bound to the BreadCrumbBar's ItemsSource in the XAML
	// initially adding the default page that loads when the app is loaded to the collection
	private readonly ObservableCollection<Crumb> Breadcrumbs = App.IsElevated ? [new Crumb(GlobalVars.Rizz.GetString("CreatePolicyNavItem/Content"), typeof(Pages.CreatePolicy))] :
		[new Crumb(GlobalVars.Rizz.GetString("PolicyEditorNavItem/Content"), typeof(Pages.PolicyEditor))];

	/// <summary>
	/// Event handler for the BreadCrumbBar's ItemClicked event
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void BreadcrumbBar_ItemClicked(BreadcrumbBar sender, BreadcrumbBarItemClickedEventArgs args)
	{
		Crumb crumb = (Crumb)args.Item;

		NavView_Navigate(crumb.Page, null);
	}


	/// <summary>
	/// Dictionary of all the main pages in the app, used for the main navigation.
	/// Keys are the Navigation Item tags (non-localized) and values are the page types.
	/// Sub-pages should only be added if they don't rely on/access the the instance of any page that might not be initialized.
	/// </summary>
	private static readonly Dictionary<string, Type> NavigationPageToItemContentMap = new()
	{
		{ "CreatePolicy", typeof(Pages.CreatePolicy) },
		{ "GetCodeIntegrityHashes", typeof(Pages.GetCIHashes) },
		{ "GitHubDocs", typeof(Pages.GitHubDocumentation) },
		{ "MSFTDocs", typeof(Pages.MicrosoftDocumentation) },
		{ "GetSecurePolicySettings", typeof(Pages.GetSecurePolicySettings) },
		{ "Settings", typeof(Pages.Settings) },
		{ "SystemInformation", typeof(Pages.SystemInformation) },
		{ "ConfigurePolicyRuleOptions", typeof(Pages.ConfigurePolicyRuleOptions) },
		{ "Logs", typeof(Pages.Logs) },
		{ "Simulation", typeof(Pages.Simulation) },
		{ "Deployment", typeof(Pages.DeploymentPage) },
		{ "CreatePolicyFromEventLogs", typeof(Pages.EventLogsPolicyCreation) },
		{ "CreatePolicyFromMDEAH", typeof(Pages.MDEAHPolicyCreation) },
		{ "AllowNewApps", typeof(Pages.AllowNewApps) },
		{ "BuildNewCertificate", typeof(Pages.BuildNewCertificate) },
		{ "CreateSupplementalPolicy", typeof(Pages.CreateSupplementalPolicy) },
		{ "MergePolicies", typeof(Pages.MergePolicies) },
		{ "CreateDenyPolicy", typeof(Pages.CreateDenyPolicy) },
		{ "ValidatePolicies", typeof(Pages.ValidatePolicy) },
		{ "ViewFileCertificates", typeof(Pages.ViewFileCertificates) },
		{ "PolicyEditor", typeof(Pages.PolicyEditor) },
		{ "Update", typeof(Pages.UpdatePage) }
	};


	/// <summary>
	/// Dictionary of all the main pages in the app, used for the search bar.
	/// Keys are page contents which are localized and values are page types.
	/// </summary>
	private static readonly Dictionary<string, Type> NavigationPageToItemContentMapForSearch = new()
	{
		{ GlobalVars.Rizz.GetString("CreatePolicyNavItem/Content"), typeof(Pages.CreatePolicy) },
		{ GlobalVars.Rizz.GetString("GetCodeIntegrityHashesNavItem/Content"), typeof(Pages.GetCIHashes) },
		{ GlobalVars.Rizz.GetString("GitHubDocsNavItem/Content"), typeof(Pages.GitHubDocumentation) },
		{ GlobalVars.Rizz.GetString("MSFTDocsNavItem/Content"), typeof(Pages.MicrosoftDocumentation) },
		{ GlobalVars.Rizz.GetString("GetSecurePolicySettingsNavItem/Content"), typeof(Pages.GetSecurePolicySettings) },
		{ GlobalVars.Rizz.GetString("SettingsNavItem/Content"), typeof(Pages.Settings) },
		{ GlobalVars.Rizz.GetString("SystemInformationNavItem/Content"), typeof(Pages.SystemInformation) },
		{ GlobalVars.Rizz.GetString("ConfigurePolicyRuleOptionsNavItem/Content"), typeof(Pages.ConfigurePolicyRuleOptions) },
		{ GlobalVars.Rizz.GetString("LogsNavItem/Content"), typeof(Pages.Logs) },
		{ GlobalVars.Rizz.GetString("SimulationNavItem/Content"), typeof(Pages.Simulation) },
		{ GlobalVars.Rizz.GetString("DeploymentNavItem/Content"), typeof(Pages.DeploymentPage) },
		{ GlobalVars.Rizz.GetString("CreatePolicyFromEventLogsNavItem/Content"), typeof(Pages.EventLogsPolicyCreation) },
		{ GlobalVars.Rizz.GetString("CreatePolicyFromMDEAHNavItem/Content"), typeof(Pages.MDEAHPolicyCreation) },
		{ GlobalVars.Rizz.GetString("AllowNewAppsNavItem/Content"), typeof(Pages.AllowNewApps) },
		{ GlobalVars.Rizz.GetString("BuildNewCertificateNavItem/Content"), typeof(Pages.BuildNewCertificate) },
		{ GlobalVars.Rizz.GetString("CreateSupplementalPolicyNavItem/Content"), typeof(Pages.CreateSupplementalPolicy) },
		{ GlobalVars.Rizz.GetString("MergePoliciesNavItem/Content"), typeof(Pages.MergePolicies) },
		{ GlobalVars.Rizz.GetString("CreateDenyPolicyNavItem/Content"), typeof(Pages.CreateDenyPolicy) },
		{ GlobalVars.Rizz.GetString("ValidatePoliciesNavItem/Content"), typeof(Pages.ValidatePolicy) },
		{ GlobalVars.Rizz.GetString("ViewFileCertificatesNavItem/Content"), typeof(Pages.ViewFileCertificates) },
		{ GlobalVars.Rizz.GetString("PolicyEditorNavItem/Content"), typeof(Pages.PolicyEditor) }
	};


	/// <summary>
	/// A static instance of the MainWindow class which will hold the single, shared instance of it
	/// </summary>
	private static MainWindow? _instance;

	/// <summary>
	/// Initializes the main window, sets up event handlers, and configures UI elements like the title bar and navigation
	/// items.
	/// </summary>
	internal MainWindow()
	{
		// Only make the update page available through search if the app was installed from GitHub source
		if (App.PackageSource is 0)
		{
			NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("UpdateNavItem/Content")] = typeof(Pages.UpdatePage);
		}

		this.InitializeComponent();

		// Assign this instance to the static field
		_instance = this;

		this.RootGridPub = RootGrid;

		// Retrieve the window handle (HWND) of the main WinUI 3 window and store it in the global vars
		GlobalVars.hWnd = WinRT.Interop.WindowNative.GetWindowHandle(this);

		// https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.window.extendscontentintotitlebar
		// Make title bar Mica
		ExtendsContentIntoTitleBar = true;

		// Get the app window and set it to a class variable
		m_AppWindow = this.AppWindow;

		// Some event handlers
		AppTitleBar.SizeChanged += AppTitleBar_SizeChanged;
		AppTitleBar.Loaded += AppTitleBar_Loaded;

		// Set the title bar's height style to tall
		m_AppWindow.TitleBar.PreferredHeightOption = TitleBarHeightOption.Tall;

		this.SizeChanged += MainWindow_SizeChanged;

		// Set the TitleBar title text to the app's display name
		TitleBarTextBlock.Text = AppInfo.Current.DisplayInfo.DisplayName;

		// https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.window.settitlebar
		// This is required. Without it, the page that has the TabView would make the App Window's TitleBar non-draggable.
		this.SetTitleBar(AppTitleBar);

		// Get all NavigationViewItem items in the MainNavigation, that includes MenuItems + any nested MenuItems + FooterMenuItems
		allNavigationItems =
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
		RootGrid.DataContext = ViewModel;

		#region Start up update check

		if (App.PackageSource is 0)
		{
			_ = Task.Run(() =>
			{
				try
				{

					// If AutoCheckForUpdateAtStartup is enabled in the app settings, checks for updates on startup and displays a dot on the Update page in the navigation
					// If a new version is available.
					// Will also check for update if it's null meaning user hasn't configured the auto update check yet
					if (App.Settings.AutoCheckForUpdateAtStartup)
					{

						Logger.Write("Checking for update on startup");

						// Start the update check
						UpdateCheckResponse updateCheckResponse = AppUpdate.Check();
					}
				}
				catch (Exception ex)
				{
					Logger.Write("Error checking for update on startup: " + ex.Message);
				}
			});
		}

		#endregion


		#region Initial navigation and file activation processing


		if (!string.IsNullOrWhiteSpace(AppSettings.FileActivatedLaunchArg))
		{
			Logger.Write($"The app was launched with file activation for the following file: {AppSettings.FileActivatedLaunchArg}");

			// Set the "Policy Editor" item as selected in the NavigationView
			MainNavigation.SelectedItem = allNavigationItems
				.First(item => string.Equals(item.Tag.ToString(), "PolicyEditor", StringComparison.OrdinalIgnoreCase));

			try
			{
				_ = PolicyEditorViewModel.OpenInPolicyEditor(AppSettings.FileActivatedLaunchArg);
			}
			catch (Exception ex)
			{
				Logger.Write($"There was an error launching the Policy Editor with the selected file: {ex.Message}");

				// Continue doing the normal navigation if there was a problem
				InitialNav();
			}
			finally
			{
				// Clear the file activated launch args after it's been used
				AppSettings.FileActivatedLaunchArg = string.Empty;
			}
		}
		else
		{
			InitialNav();
		}

		#endregion

		// Set the initial background setting based on the user's settings
		OnNavigationBackgroundChanged(null, new(App.Settings.NavViewBackground));

		// Set the initial App Theme based on the user's settings
		OnAppThemeChanged(null, new(App.Settings.AppTheme));

		// Restore window size on startup
		RestoreWindowSize();

		// Subscribe to Closed event of the main Window
		this.Closed += MainWindow_Closed;

		// Subscribing to the event that is fired when User Configuration changes for Unsigned policy path to that the Sidebar can be updated accordingly
		Events.UnsignedPolicyManager.UnsignedPolicyInUserConfigChanged += SidebarOnUnsignedPolicyChanged;

		// Set the initial Icons styles abased on the user's settings
		ViewModel.OnIconsStylesChanged(App.Settings.IconsStyle);
	}


	/// <summary>
	/// internal property to access the singleton instance from other classes
	/// </summary>
	internal static MainWindow Instance => _instance ?? throw new InvalidOperationException("MainWindow is not initialized.");


	private void InitialNav()
	{
		if (App.IsElevated)
		{
			// Navigate to the CreatePolicy page when the window is loaded
			_ = ContentFrame.Navigate(typeof(Pages.CreatePolicy));

			// Set the "Create Policy" item as selected in the NavigationView
			MainNavigation.SelectedItem = allNavigationItems
				.First(item => string.Equals(item.Tag.ToString(), "CreatePolicy", StringComparison.OrdinalIgnoreCase));
		}
		else
		{
			_ = ContentFrame.Navigate(typeof(Pages.PolicyEditor));

			// Set the "Policy Editor" item as selected in the NavigationView
			MainNavigation.SelectedItem = allNavigationItems
				.First(item => string.Equals(item.Tag.ToString(), "PolicyEditor", StringComparison.OrdinalIgnoreCase));
		}
	}


	/// <summary>
	/// Event handler for when the AppTitleBar Grid is loaded
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void AppTitleBar_Loaded(object sender, RoutedEventArgs e)
	{
		// Set the initial interactive regions.
		SetRegionsForCustomTitleBar();
	}


	/// <summary>
	/// Event handler for when the AppTitleBar Grid's size changes
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void AppTitleBar_SizeChanged(object sender, SizeChangedEventArgs e)
	{
		// Update interactive regions if the size of the window changes.
		SetRegionsForCustomTitleBar();
	}


	/// <summary>
	/// Specifies the interactive regions of the title bar in the AppTitleBar Grid
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
	/// Main Window close event
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="args"></param>
	private void MainWindow_Closed(object sender, WindowEventArgs args)
	{
		try
		{
			// Get the current size of the window
			SizeInt32 size = m_AppWindow.Size;

			// Save to window width and height to the app settings
			App.Settings.MainWindowWidth = size.Width;
			App.Settings.MainWindowHeight = size.Height;

			Win32InteropInternal.WINDOWPLACEMENT windowPlacement = new();

			// Check if the window is maximized
			_ = Win32InteropInternal.GetWindowPlacement(GlobalVars.hWnd, ref windowPlacement);

			// Save the maximized status of the window before closing to the app settings
			App.Settings.MainWindowIsMaximized = windowPlacement.showCmd is Win32InteropInternal.ShowWindowCommands.SW_SHOWMAXIMIZED;
		}
		catch (Exception ex)
		{
			Logger.Write($"There was a program saving the window size when closing the app: {ex.Message}");
		}
	}


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

				Logger.Write($"Setting the window size back to what it was when the app was closed. Height: {App.Settings.MainWindowHeight} - Width: {App.Settings.MainWindowWidth}");

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
					// MainNavigation has no margins by default when it's on the left side
					MainNavigation.Margin = new Thickness(0);

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
					MainNavigation.Margin = new Thickness(0);

					MainNavigation.PaneDisplayMode = NavigationViewPaneDisplayMode.Top;

					// Hide the main menu's button on the TitleBar since we don't need it in Top mode
					HamburgerMenuButton.Visibility = Visibility.Collapsed;

					break;
				}
			default:
				{
					// MainNavigation has no margins by default
					MainNavigation.Margin = new Thickness(0);
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
			List<string> suggestions = new(NavigationPageToItemContentMapForSearch.Keys.Where(name => name.Contains(query, StringComparison.OrdinalIgnoreCase)));

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

		if (chosenItemName is not null && NavigationPageToItemContentMapForSearch.TryGetValue(chosenItemName, out Type? selectedItem))
		{
			NavView_Navigate(selectedItem, null);
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
				NavView_Navigate(typeof(Pages.Settings), args?.RecommendedNavigationTransitionInfo, null);
			}
			else
			{
				NavView_Navigate(null, args?.RecommendedNavigationTransitionInfo, args?.InvokedItemContainer.Tag.ToString());
			}
		}
	}


	/// <summary>
	/// Main navigation method that is used by the search bar, direct clicks on the main navigation items
	/// And by other methods throughout the app in order to navigate to sub-pages
	/// </summary>
	/// <param name="navPageType"></param>
	/// <param name="transitionInfo"></param>
	/// <param name="navItemTag"></param>
	internal async void NavView_Navigate(Type? navPageType, NavigationTransitionInfo? transitionInfo = null, string? navItemTag = null)
	{
		// Get the page's type before navigation so we can prevent duplicate entries in the BackStack
		// This will prevent reloading the same page if we're already on it and works with sub-pages to navigate back to the main page
		Type preNavPageType = ContentFrame.CurrentSourcePageType;

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
		else if (navItemTag is not null && NavigationPageToItemContentMap.TryGetValue(navItemTag, out Type? page) && !Equals(page, preNavPageType))
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
			if (!UnelevatedPages.Contains(nextNavPageType))
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
				CustomUIElements.ContentDialogV2 dialog = new()
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
						MainNavigation.SelectedItem = MainNavigation.SettingsItem;
					}
					else
					{
						// The SelectedItem is automatically set to the page that is unavailable
						// But here we set it back to the last available page to make it a smooth experience
						MainNavigation.SelectedItem = allNavigationItems.FirstOrDefault(x => string.Equals(x.Tag.ToString(), NavigationPageToItemContentMap.FirstOrDefault(x => Equals(x.Value, preNavPageType)).Key, StringComparison.OrdinalIgnoreCase));
					}
					return;
				}
			}
		}


		// Play a sound
		ElementSoundPlayer.Play(ElementSoundKind.MoveNext);

		// Navigate to the new page
		_ = ContentFrame.Navigate(nextNavPageType, null, transitionInfo);

		// For page Interface and light augmentation
		AffectPagesAnimatedIconsVisibilities(ContentFrame);

		// Get the item from BreadCrumb dictionary that belongs to the next page we navigated to
		_ = breadCrumbMappingsV2.TryGetValue(nextNavPageType, out PageTitleMap? info);

		if (info is not null)
		{
			// Get the index location of the page we navigated to in the list of pages
			int currentPageLocation = info.Pages.IndexOf(nextNavPageType);

			// Clear the breadcrumb bar's collection
			Breadcrumbs.Clear();

			// Add the breadcrumbs to the bar one by one, starting from the first item
			// Which is the main item in the main NavigationMenu all the way to the item that was selected
			// E.g, if there are 5 pages in one of the valid app navigation paths and the page user wants to navigate to is the 3rd one
			// Then the name of all the pages starting from index 0 to index 2 will be added to the breadcrumb bar (total of 3)
			for (int i = 0; i <= currentPageLocation; i++)
			{
				Breadcrumbs.Add(new Crumb(info.Titles[i], info.Pages[i]));
			}

			// Since settings page doesn't have content the way we define them in XAML, adding an explicit check for it here
			if (Equals(nextNavPageType, typeof(Pages.Settings)))
			{
				// Set the selected item in the MainNavigation to the Settings page
				MainNavigation.SelectedItem = MainNavigation.SettingsItem;
			}
			else
			{
				// Set the selected item in the MainNavigation to the next page by first detecting it via its NavigationViewItem's context set in XAML
				// info.Titles[0] ensures the selected item in the NavigationView will correctly be set to the main item in the menu even when the page being navigated to is a sub-page in that valid navigational path
				MainNavigation.SelectedItem = allNavigationItems.First(x => string.Equals(x.Content.ToString(), info.Titles[0], StringComparison.OrdinalIgnoreCase));
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
			ContentFrame.GoBack();

			// Get the current page after navigating back
			Type currentPage = ContentFrame.CurrentSourcePageType;

			// For page Interface and light augmentation
			AffectPagesAnimatedIconsVisibilities(ContentFrame);

			_ = breadCrumbMappingsV2.TryGetValue(currentPage, out PageTitleMap? info);

			if (info is not null)
			{
				int currentPageLocation = info.Pages.IndexOf(currentPage);

				Breadcrumbs.Clear();

				for (int i = 0; i <= currentPageLocation; i++)
				{
					Breadcrumbs.Add(new Crumb(info.Titles[i], info.Pages[i]));
				}


				// Since settings page doesn't have content when it is in Top mode (it only has Tag property)
				// And also content for the auto-created Settings page varies based on localization, adding an explicit check for it here
				if (Equals(currentPage, typeof(Pages.Settings)))
				{
					MainNavigation.SelectedItem = MainNavigation.SettingsItem;
				}
				else
				{
					// info.Titles[0] ensures the selected item in the NavigationView will correctly be set to the main item in the menu even when the page being navigated to is a sub-page in that valid navigational path
					MainNavigation.SelectedItem = allNavigationItems.First(x => string.Equals(x.Content.ToString(), info.Titles[0], StringComparison.OrdinalIgnoreCase));
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

		if (mainWindowWidth < 750)
		{
			ViewModel.TitleColumnWidth = new GridLength(0); // Hide TitleColumn if width is less than 200
		}
		else
		{
			ViewModel.TitleColumnWidth = GridLength.Auto; // Restore the TitleColumn if width is 200 or more
		}
	}


	/// <summary>
	/// Event handler to change visibility of the AnimatedIcons on the currently visible page in the frame
	/// It is called by the Sidebar's Browse/Clear buttons' event handlers
	/// </summary>
	/// <param name="on"></param>
	internal void AffectPagesAnimatedIconsVisibilities(bool on)
	{

		// Decide the visibility to set the animated icons to based on the parameter
		Visibility visibility = on ? Visibility.Visible : Visibility.Collapsed;

		if (ContentFrame.Content is IAnimatedIconsManager currentPage)
		{
			currentPage.SetVisibility(visibility, ViewModel.SidebarBasePolicyPathTextBoxText, SidebarUnsignedBasePolicyConnect1, SidebarUnsignedBasePolicyConnect2, SidebarUnsignedBasePolicyConnect3, SidebarUnsignedBasePolicyConnect4, SidebarUnsignedBasePolicyConnect5);

			// Set the visibility of the AnimatedIcon on Sidebar's Select button for Unsigned policy
			SidebarBasePolicySelectButtonLightAnimatedIcon.Visibility = visibility;
		}

	}


	/// <summary>
	/// This method is called via the methods responsible for Navigations.
	/// </summary>
	internal void AffectPagesAnimatedIconsVisibilities(Frame contentFrame)
	{
		// Check the unsigned base policy path on the Sidebar's textbox
		bool isUnsignedBasePolicyPathAvailable = !string.IsNullOrWhiteSpace(ViewModel.SidebarBasePolicyPathTextBoxText);

		// Unsubscribe all the event handlers from the sidebar's select buttons for unsigned policies
		// This way the new page that user navigates to can set unique event handler to them if it implements the interface
		if (EventHandlersTracking.SidebarUnsignedBasePolicyConnect1EventHandler is not null)
		{
			SidebarUnsignedBasePolicyConnect1.Click -= EventHandlersTracking.SidebarUnsignedBasePolicyConnect1EventHandler;
		}
		if (EventHandlersTracking.SidebarUnsignedBasePolicyConnect2EventHandler is not null)
		{
			SidebarUnsignedBasePolicyConnect2.Click -= EventHandlersTracking.SidebarUnsignedBasePolicyConnect2EventHandler;
		}
		if (EventHandlersTracking.SidebarUnsignedBasePolicyConnect3EventHandler is not null)
		{
			SidebarUnsignedBasePolicyConnect3.Click -= EventHandlersTracking.SidebarUnsignedBasePolicyConnect3EventHandler;
		}

		// Remove the content of the sidebar buttons
		SidebarUnsignedBasePolicyConnect1.Content = null;
		SidebarUnsignedBasePolicyConnect2.Content = null;
		SidebarUnsignedBasePolicyConnect3.Content = null;
		SidebarUnsignedBasePolicyConnect4.Content = null;
		SidebarUnsignedBasePolicyConnect5.Content = null;

		// Collapse the sidebar buttons
		// The following actions happen because we don't know the next page user visits implements the interface or not
		// Not all pages are eligible for this augmentation
		SidebarUnsignedBasePolicyConnect1.Visibility = Visibility.Collapsed;
		SidebarUnsignedBasePolicyConnect2.Visibility = Visibility.Collapsed;
		SidebarUnsignedBasePolicyConnect3.Visibility = Visibility.Collapsed;
		SidebarUnsignedBasePolicyConnect4.Visibility = Visibility.Collapsed;
		SidebarUnsignedBasePolicyConnect5.Visibility = Visibility.Collapsed;

		// Check if the currently displayed content (page) in the ContentFrame implements the IAnimatedIconsManager interface.
		// If it does, cast ContentFrame.Content to IAnimatedIconsManager
		// And if the text box for unsigned policy path is also full then set the visibility of animated icons
		if (contentFrame.Content is IAnimatedIconsManager currentPage)
		{
			if (isUnsignedBasePolicyPathAvailable)
			{
				currentPage.SetVisibility(Visibility.Visible, ViewModel.SidebarBasePolicyPathTextBoxText, SidebarUnsignedBasePolicyConnect1, SidebarUnsignedBasePolicyConnect2, SidebarUnsignedBasePolicyConnect3, SidebarUnsignedBasePolicyConnect4, SidebarUnsignedBasePolicyConnect5);
				SidebarBasePolicySelectButtonLightAnimatedIcon.Visibility = Visibility.Visible;
			}
			else
			{
				currentPage.SetVisibility(Visibility.Collapsed, ViewModel.SidebarBasePolicyPathTextBoxText, SidebarUnsignedBasePolicyConnect1, SidebarUnsignedBasePolicyConnect2, SidebarUnsignedBasePolicyConnect3, SidebarUnsignedBasePolicyConnect4, SidebarUnsignedBasePolicyConnect5);
				SidebarBasePolicySelectButtonLightAnimatedIcon.Visibility = Visibility.Collapsed;
			}
		}
		else
		{
			SidebarBasePolicySelectButtonLightAnimatedIcon.Visibility = Visibility.Collapsed;
		}
	}


	/// <summary>
	/// Event handler for when the event that changes unsigned policy path in user configurations is fired
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SidebarOnUnsignedPolicyChanged(object? sender, Events.UnsignedPolicyInUserConfigChangedEventArgs e)
	{
		ViewModel.SidebarBasePolicyPathTextBoxText = e.UnsignedPolicyInUserConfig;
	}

}
