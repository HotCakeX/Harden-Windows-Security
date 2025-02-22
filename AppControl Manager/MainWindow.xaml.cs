using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using System.Numerics;
using System.Threading.Tasks;
using AnimatedVisuals;
using AppControlManager.AppSettings;
using AppControlManager.Main;
using AppControlManager.Others;
using AppControlManager.Sidebar;
using Microsoft.UI;
using Microsoft.UI.Composition.SystemBackdrops;
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

// https://learn.microsoft.com/en-us/windows/apps/design/controls/breadcrumbbar#itemssource
// Represents an item in the BreadCrumBar's ItemsSource collection
public readonly struct Crumb(String label, Type page)
{
	public string Label { get; } = label;
	public Type Page { get; } = page;
	public override string ToString() => Label;
}


public sealed partial class MainWindow : Window
{

	public MainWindowViewModel ViewModel { get; }

	private readonly AppWindow m_AppWindow;

	internal readonly Frame AppFrame;

	// Used for the BreadCrumBar's data to define valid navigational paths in the app
	internal sealed class PageTitleMap
	{
		internal required List<string> Titles { get; set; }
		internal required List<Type> Pages { get; set; }
	}

	// a list of all the NavigationViewItem in the Main NavigationViewItem
	// It is populated in the class initializer
	// Since the app uses it multiple times, we only populate this list once to reuse it in subsequent calls
	private readonly IEnumerable<NavigationViewItem> allNavigationItems = [];

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
			Titles = ["GitHub Documentation"],
			Pages = [typeof(Pages.GitHubDocumentation)]
		},
		[typeof(Pages.MicrosoftDocumentation)] = new PageTitleMap
		{
			Titles = ["Microsoft Documentation"],
			Pages = [typeof(Pages.MicrosoftDocumentation)]
		},
		[typeof(Pages.GetSecurePolicySettings)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("GetSecurePolicySettingsNavItem/Content")],
			Pages = [typeof(Pages.GetSecurePolicySettings)]
		},
		[typeof(Pages.Settings)] = new PageTitleMap
		{
			Titles = ["Settings"],
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
			Titles = ["Logs"],
			Pages = [typeof(Pages.Logs)]
		},
		[typeof(Pages.Simulation)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("SimulationNavItem/Content")],
			Pages = [typeof(Pages.Simulation)]
		},
		[typeof(Pages.UpdatePage)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("Update"), "Custom MSIXBundle Path"],
			Pages = [typeof(Pages.UpdatePage), typeof(Pages.UpdatePageCustomMSIXPath)]
		},
		[typeof(Pages.UpdatePageCustomMSIXPath)] = new PageTitleMap // sub-page
		{
			Titles = [GlobalVars.Rizz.GetString("Update"), "Custom MSIXBundle Path"],
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
		}
	};


	// This collection is bound to the BreadCrumbBar's ItemsSource in the XAML
	// initially adding the default page that loads when the app is loaded to the collection
	private readonly ObservableCollection<Crumb> Breadcrumbs = [new Crumb(GlobalVars.Rizz.GetString("CreatePolicyNavItem/Content"), typeof(Pages.CreatePolicy))];

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


	// Dictionary of all the main pages in the app, used by the search bar
	// Sub-pages should only be added if they don't rely on/access the the instance of any page that might not be initialized
	private static readonly Dictionary<string, Type> NavigationPageToItemContentMap = new()
	{
		{ "Create Policy", typeof(Pages.CreatePolicy) },
		{ "Get Code Integrity Hashes", typeof(Pages.GetCIHashes) },
		{ "GitHub Documentation", typeof(Pages.GitHubDocumentation) },
		{ "Microsoft Documentation", typeof(Pages.MicrosoftDocumentation) },
		{ "Get Secure Policy Settings", typeof(Pages.GetSecurePolicySettings) },
		{ "Settings", typeof(Pages.Settings) },
		{ "System Information", typeof(Pages.SystemInformation) },
		{ "Configure Policy Rule Options", typeof(Pages.ConfigurePolicyRuleOptions) },
		{ "Logs", typeof(Pages.Logs) },
		{ "Simulation", typeof(Pages.Simulation) },
		{ "Update", typeof(Pages.UpdatePage) },
		{ "Deploy App Control Policy", typeof(Pages.DeploymentPage) },
		{ "Create policy from Event Logs", typeof(Pages.EventLogsPolicyCreation) },
		{ "MDE Advanced Hunting", typeof(Pages.MDEAHPolicyCreation) },
		{ "Allow New Apps", typeof(Pages.AllowNewApps) },
		{ "Build New Certificate", typeof(Pages.BuildNewCertificate) },
		{ "Create Supplemental Policy", typeof(Pages.CreateSupplementalPolicy) },
		{ "Merge App Control Policies", typeof(Pages.MergePolicies) },
		{ "Create Deny Policy", typeof(Pages.CreateDenyPolicy) },
		{ "Validate Policies", typeof(Pages.ValidatePolicy) },
		{ "View File Certificates", typeof(Pages.ViewFileCertificates) }
	};


	// A static instance of the MainWindow class which will hold the single, shared instance of it
	private static MainWindow? _instance;


	public MainWindow()
	{
		this.InitializeComponent();

		// Assign this instance to the static field
		_instance = this;

		AppFrame = ContentFrame;

		// Retrieve the window handle (HWND) of the main WinUI 3 window and store it in the global vars
		GlobalVars.hWnd = WinRT.Interop.WindowNative.GetWindowHandle(this);

		// https://learn.microsoft.com/en-us/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.window.extendscontentintotitlebar
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

		// Subscribe to the global BackDrop change event
		ThemeManager.BackDropChanged += OnBackgroundChanged;


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

		// Subscribe to the global Icons Styles change event
		IconsStyleManager.IconsStyleChanged += OnIconsStylesChanged;

		#region

		// Use the singleton instance of AppUpdate class
		AppUpdate updateService = AppUpdate.Instance;

		// Pass the AppUpdate class instance to MainWindowViewModel
		ViewModel = new MainWindowViewModel(updateService);

		// Set the DataContext of the Grid to enable bindings in XAML
		RootGrid.DataContext = ViewModel;

		_ = Task.Run(() =>
		   {

			   // If AutoCheckForUpdateAtStartup is enabled in the app settings, checks for updates on startup and displays a dot on the Update page in the navigation
			   // If a new version is available.
			   // Will also check for update if it's null meaning user hasn't configured the auto update check yet
			   if (AppSettingsCls.TryGetSetting<bool?>(AppSettingsCls.SettingKeys.AutoCheckForUpdateAtStartup) ?? true)
			   {

				   Logger.Write("Checking for update on startup");

				   // Start the update check
				   UpdateCheckResponse updateCheckResponse = updateService.Check();

				   // If a new version is available
				   if (updateCheckResponse.IsNewVersionAvailable)
				   {
					   // Set the text for the button in the update page
					   GlobalVars.updateButtonTextOnTheUpdatePage = $"Install version {updateCheckResponse.OnlineVersion}";
				   }
				   else
				   {
					   Logger.Write("No new version of the AppControl Manager is available.");
				   }
			   }

		   });

		#endregion


		// Navigate to the CreatePolicy page when the window is loaded
		_ = ContentFrame.Navigate(typeof(Pages.CreatePolicy));

		// Set the "Create Policy" item as selected in the NavigationView
		MainNavigation.SelectedItem = allNavigationItems
			.First(item => string.Equals(item.Content.ToString(), "Create Policy", StringComparison.OrdinalIgnoreCase));

		// Set the initial background setting based on the user's settings
		OnNavigationBackgroundChanged(null, new(AppSettingsCls.GetSetting<bool>(AppSettingsCls.SettingKeys.NavViewBackground)));

		// Set the initial BackDrop setting based on the user's settings
		OnBackgroundChanged(null, new(AppSettingsCls.GetSetting<string>(AppSettingsCls.SettingKeys.BackDropBackground)));

		// Set the initial App Theme based on the user's settings
		OnAppThemeChanged(null, new(AppSettingsCls.GetSetting<string>(AppSettingsCls.SettingKeys.AppTheme)));

		// Set the initial Icons styles abased on the user's settings
		OnIconsStylesChanged(null, new(AppSettingsCls.GetSetting<string>(AppSettingsCls.SettingKeys.IconsStyle)));

		// Restore window size on startup
		RestoreWindowSize();

		// Subscribe to Closed event of the main Window
		this.Closed += MainWindow_Closed;


		// Subscribing to the event that is fired when User Configuration changes for Unsigned policy path to that the Sidebar can be updated accordingly
		Events.UnsignedPolicyManager.UnsignedPolicyInUserConfigChanged += SidebarOnUnsignedPolicyChanged;
	}

	// Public property to access the singleton instance from other classes
	public static MainWindow Instance => _instance ?? throw new InvalidOperationException("MainWindow is not initialized.");


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
		// Get the current size of the window
		SizeInt32 size = m_AppWindow.Size;

		// Save to window width and height to the app settings
		AppSettingsCls.SaveSetting(AppSettingsCls.SettingKeys.MainWindowWidth, size.Width);
		AppSettingsCls.SaveSetting(AppSettingsCls.SettingKeys.MainWindowHeight, size.Height);

		Win32InteropInternal.WINDOWPLACEMENT windowPlacement = new();

		// Check if the window is maximized
		_ = Win32InteropInternal.GetWindowPlacement(GlobalVars.hWnd, ref windowPlacement);

		// Save the maximized status of the window before closing to the app settings
		if (windowPlacement.showCmd is Win32InteropInternal.ShowWindowCommands.SW_SHOWMAXIMIZED)
		{
			AppSettingsCls.SaveSetting(AppSettingsCls.SettingKeys.MainWindowIsMaximized, true);
		}
		else
		{
			AppSettingsCls.SaveSetting(AppSettingsCls.SettingKeys.MainWindowIsMaximized, false);
		}
	}


	/// <summary>
	/// Event handler to run at Window launch to restore its size to the one before closing
	/// </summary>
	private void RestoreWindowSize()
	{

		// If the window was last maximized then restore it to maximized
		if (AppSettingsCls.GetSetting<bool>(AppSettingsCls.SettingKeys.MainWindowIsMaximized))
		{

			Logger.Write("Window was maximized when the app closed last time, setting it to maximized now");

			// Using .As<>() instead of direct cast because in NAOT mode direct cast would throw error for invalid cast operation. This is a bug in CsWinRT
			OverlappedPresenter presenter = m_AppWindow.Presenter.As<OverlappedPresenter>();

			// Set the presenter to maximized
			presenter.Maximize();
		}

		// Else set its size to its previous size before closing
		else
		{
			// Retrieve stored values
			int width = AppSettingsCls.GetSetting<int>(AppSettingsCls.SettingKeys.MainWindowWidth);
			int height = AppSettingsCls.GetSetting<int>(AppSettingsCls.SettingKeys.MainWindowHeight);

			Logger.Write($"Setting the window size back to what it was when the app was closed. Height: {height} - Width: {width}");

			// If the previous window size was smaller than 200 pixels width/height then do not use it, let it use the natural window size
			if (width > 200 && height > 200)
			{
				// Apply to the current AppWindow
				m_AppWindow?.Resize(new SizeInt32(width, height));
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
	/// Event handler for the global Icons Style change event
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void OnIconsStylesChanged(object? sender, IconsStyleChangedEventArgs e)
	{

		// Get the current theme
		ElementTheme currentTheme = RootGrid.ActualTheme;

		// Set the Icons Style
		switch (e.NewIconsStyle)
		{
			case "Animated":
				{
					// Create Policy
					CreatePolicyNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(-10, -35, -35, -35),
						Source = new Blueprint()
					};

					// System Information
					SystemInformationNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(0, -6, -6, -6),
						Source = new View()
					};

					// Configure Policy Rule Options
					ConfigurePolicyRuleOptionsNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Configure()
					};

					// Simulation
					SimulationNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Simulation()
					};

					// Allow New Apps
					if (currentTheme is ElementTheme.Dark)
					{
						AllowNewAppsNavItem.Icon = new AnimatedIcon
						{
							Margin = new Thickness(0, -6, -6, -6),
							Source = new StarYellow()
						};
					}
					else
					{
						AllowNewAppsNavItem.Icon = new AnimatedIcon
						{
							Margin = new Thickness(0, -6, -6, -6),
							Source = new StarBlack()

						};
					}

					// Create Policy from Event Logs
					CreatePolicyFromEventLogsNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Scan()
					};

					// MDE Advanced Hunting
					CreatePolicyFromMDEAHNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new MDE()
					};

					// Get Code Integrity Hashes
					GetCodeIntegrityHashesNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Hash()
					};

					// Get Secure Policy Settings
					GetSecurePolicySettingsNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(0, -6, -6, -6),
						Source = new Shield()
					};

					// Logs
					LogsNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new AnimatedVisuals.Timeline()
					};

					// GitHub Documentation
					GitHubDocsNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(0, -11, -11, -11),
						Source = new GitHub()
					};

					// Microsoft Documentation
					MSFTDocsNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(0, -9, -9, -9),
						Source = new Document()
					};

					// Update
					if (currentTheme is ElementTheme.Dark)
					{
						UpdateNavItem.Icon = new AnimatedIcon
						{
							Margin = new Thickness(0, -5, -5, -5),
							Source = new Heart()
						};
					}
					else
					{
						UpdateNavItem.Icon = new AnimatedIcon
						{
							Margin = new Thickness(0, -25, -25, -25),
							Source = new HeartPulse()
						};
					}

					// Build New Certificate
					BuildNewCertificateNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Certificate()
					};

					// Deployment
					DeploymentNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Deployment()
					};

					// Create Supplemental Policy
					CreateSupplementalPolicyNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(-5, -28, -28, -28),
						Source = new SupplementalPolicy()
					};

					// Merge App Control Policies
					MergePoliciesNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(0, -9, -9, -9),
						Source = new Merge()
					};

					// Create Deny Policy
					CreateDenyPolicyNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(0, -9, -9, -9),
						Source = new Deny()
					};

					// Validate Policies
					ValidatePoliciesNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(0, -9, -9, -9),
						Source = new Validate()
					};

					// View File Certificates
					ViewFileCertificatesNavItem.Icon = new AnimatedIcon
					{
						Margin = new Thickness(0, -9, -9, -9),
						Source = new ViewAllCertificates()
					};

					break;
				}
			case "Windows Accent":
				{
					// Get the accent color brush
					Brush accentBrush = (Brush)Application.Current.Resources["SystemControlHighlightAccentBrush"];

					// Create Policy
					CreatePolicyNavItem.Icon = new FontIcon
					{
						Glyph = "\uE83D",
						Foreground = accentBrush
					};

					// System Information
					SystemInformationNavItem.Icon = new FontIcon
					{
						Glyph = "\uE7C1",
						Foreground = accentBrush
					};

					// Configure Policy Rule Options
					ConfigurePolicyRuleOptionsNavItem.Icon = new FontIcon
					{
						Glyph = "\uEEA3",
						Foreground = accentBrush
					};

					// Simulation
					SimulationNavItem.Icon = new FontIcon
					{
						Glyph = "\uE835",
						Foreground = accentBrush
					};

					// Allow New Apps
					AllowNewAppsNavItem.Icon = new FontIcon
					{
						Glyph = "\uED35",
						Foreground = accentBrush
					};

					// Create Policy from Event Logs
					CreatePolicyFromEventLogsNavItem.Icon = new FontIcon
					{
						Glyph = "\uEA18",
						Foreground = accentBrush
					};

					// MDE Advanced Hunting
					CreatePolicyFromMDEAHNavItem.Icon = new FontIcon
					{
						Glyph = "\uEB44",
						Foreground = accentBrush
					};

					// Get Code Integrity Hashes
					GetCodeIntegrityHashesNavItem.Icon = new FontIcon
					{
						Glyph = "\uE950",
						Foreground = accentBrush
					};

					// Get Secure Policy Settings
					GetSecurePolicySettingsNavItem.Icon = new FontIcon
					{
						Glyph = "\uEEA3",
						Foreground = accentBrush
					};

					// Logs
					LogsNavItem.Icon = new FontIcon
					{
						Glyph = "\uF5A0",
						Foreground = accentBrush
					};

					// GitHub Documentation
					GitHubDocsNavItem.Icon = new FontIcon
					{
						Glyph = "\uE8A5",
						Foreground = accentBrush
					};

					// Microsoft Documentation
					MSFTDocsNavItem.Icon = new FontIcon
					{
						Glyph = "\uE8A5",
						Foreground = accentBrush
					};

					// Update
					UpdateNavItem.Icon = new FontIcon
					{
						Glyph = "\uEB52",
						Foreground = accentBrush
					};

					// Build New Certificate
					BuildNewCertificateNavItem.Icon = new FontIcon
					{
						Glyph = "\uEB95",
						Foreground = accentBrush
					};

					// Deployment
					DeploymentNavItem.Icon = new FontIcon
					{
						Glyph = "\uF32A",
						Foreground = accentBrush
					};

					// Create Supplemental Policy
					CreateSupplementalPolicyNavItem.Icon = new FontIcon
					{
						Glyph = "\uE8F9",
						Foreground = accentBrush
					};

					// Merge App Control Policies
					MergePoliciesNavItem.Icon = new FontIcon
					{
						Glyph = "\uEE49",
						Foreground = accentBrush
					};

					// Create Deny Policy
					CreateDenyPolicyNavItem.Icon = new FontIcon
					{
						Glyph = "\uE8D0",
						Foreground = accentBrush
					};

					// Validate Policies
					ValidatePoliciesNavItem.Icon = new FontIcon
					{
						Glyph = "\uED5E",
						Foreground = accentBrush
					};

					// View File Certificates
					ViewFileCertificatesNavItem.Icon = new FontIcon
					{
						Glyph = "\uEBD2",
						Foreground = accentBrush
					};

					break;
				}

			// The default behavior and when user selects Monochromatic style
			case "Monochromatic":
			default:
				{

					// Create Policy
					CreatePolicyNavItem.Icon = new FontIcon
					{
						Glyph = "\uE83D"
					};

					// System Information
					SystemInformationNavItem.Icon = new FontIcon
					{
						Glyph = "\uE7C1"
					};

					// Configure Policy Rule Options
					ConfigurePolicyRuleOptionsNavItem.Icon = new FontIcon
					{
						Glyph = "\uEEA3"
					};

					// Simulation
					SimulationNavItem.Icon = new FontIcon
					{
						Glyph = "\uE835"
					};

					// Allow New Apps
					AllowNewAppsNavItem.Icon = new FontIcon
					{
						Glyph = "\uED35"
					};

					// Create Policy from Event Logs
					CreatePolicyFromEventLogsNavItem.Icon = new FontIcon
					{
						Glyph = "\uEA18"
					};

					// MDE Advanced Hunting
					CreatePolicyFromMDEAHNavItem.Icon = new FontIcon
					{
						Glyph = "\uEB44"
					};

					// Get Code Integrity Hashes
					GetCodeIntegrityHashesNavItem.Icon = new FontIcon
					{
						Glyph = "\uE950"
					};

					// Get Secure Policy Settings
					GetSecurePolicySettingsNavItem.Icon = new FontIcon
					{
						Glyph = "\uEEA3"
					};

					// Logs
					LogsNavItem.Icon = new FontIcon
					{
						Glyph = "\uF5A0"
					};

					// GitHub Documentation
					GitHubDocsNavItem.Icon = new FontIcon
					{
						Glyph = "\uE8A5"
					};

					// Microsoft Documentation
					MSFTDocsNavItem.Icon = new FontIcon
					{
						Glyph = "\uE8A5"
					};

					// Update
					UpdateNavItem.Icon = new FontIcon
					{
						Glyph = "\uEB52"
					};

					// Build New Certificate
					BuildNewCertificateNavItem.Icon = new FontIcon
					{
						Glyph = "\uEB95"
					};

					// Deployment
					DeploymentNavItem.Icon = new FontIcon
					{
						Glyph = "\uF32A"
					};

					// Create Supplemental Policy
					CreateSupplementalPolicyNavItem.Icon = new FontIcon
					{
						Glyph = "\uE8F9"
					};

					// Merge App Control Policies
					MergePoliciesNavItem.Icon = new FontIcon
					{
						Glyph = "\uEE49"
					};

					// Create Deny Policy
					CreateDenyPolicyNavItem.Icon = new FontIcon
					{
						Glyph = "\uE8D0"
					};

					// Validate Policies
					ValidatePoliciesNavItem.Icon = new FontIcon
					{
						Glyph = "\uED5E"
					};

					// View File Certificates
					ViewFileCertificatesNavItem.Icon = new FontIcon
					{
						Glyph = "\uEBD2"
					};

					break;
				}
		}
	}


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
	/// Event handler for the global BackgroundChanged event. When user selects a different background for the app, this will be triggered.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void OnBackgroundChanged(object? sender, BackgroundChangedEventArgs e)
	{

		// Update the SystemBackdrop based on the selected background
		// The Default is set in the XAML
		switch (e.NewBackground)
		{
			case "MicaAlt":
				this.SystemBackdrop = new MicaBackdrop { Kind = MicaKind.BaseAlt };
				break;
			case "Mica":
				this.SystemBackdrop = new MicaBackdrop { Kind = MicaKind.Base };
				break;
			case "Acrylic":
				this.SystemBackdrop = new DesktopAcrylicBackdrop();
				break;
			default:
				break;
		}
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
					if (string.Equals(AppSettingsCls.GetSetting<string>(AppSettingsCls.SettingKeys.IconsStyle), "Animated", StringComparison.OrdinalIgnoreCase))
					{

						AllowNewAppsNavItem.Icon = new AnimatedIcon
						{
							Margin = new Thickness(0, -6, -6, -6),
							Source = new StarBlack()

						};

						UpdateNavItem.Icon = new AnimatedIcon
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
					if (string.Equals(AppSettingsCls.GetSetting<string>(AppSettingsCls.SettingKeys.IconsStyle), "Animated", StringComparison.OrdinalIgnoreCase))
					{

						AllowNewAppsNavItem.Icon = new AnimatedIcon
						{
							Margin = new Thickness(0, -6, -6, -6),
							Source = new StarYellow()
						};

						UpdateNavItem.Icon = new AnimatedIcon
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
						if (string.Equals(AppSettingsCls.GetSetting<string>(AppSettingsCls.SettingKeys.IconsStyle), "Animated", StringComparison.OrdinalIgnoreCase))
						{

							AllowNewAppsNavItem.Icon = new AnimatedIcon
							{
								Margin = new Thickness(0, -6, -6, -6),
								Source = new StarYellow()
							};

							UpdateNavItem.Icon = new AnimatedIcon
							{
								Margin = new Thickness(0, -5, -5, -5),
								Source = new Heart()
							};

						}

					}
					else
					{
						// Change the navigation icons based on dark/light theme only if "Animated" is the current icons style in use
						if (string.Equals(AppSettingsCls.GetSetting<string>(AppSettingsCls.SettingKeys.IconsStyle), "Animated", StringComparison.OrdinalIgnoreCase))
						{

							AllowNewAppsNavItem.Icon = new AnimatedIcon
							{
								Margin = new Thickness(0, -6, -6, -6),
								Source = new StarBlack()

							};

							UpdateNavItem.Icon = new AnimatedIcon
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
			string query = sender.Text.ToLowerInvariant().Trim();

			// Filter menu items based on the search query
			List<string> suggestions = [.. NavigationPageToItemContentMap.Keys.Where(name => name.Contains(query, StringComparison.OrdinalIgnoreCase))];

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

		if (chosenItemName is not null && NavigationPageToItemContentMap.TryGetValue(chosenItemName, out Type? selectedItem))
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
			// https://learn.microsoft.com/en-us/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.controls.navigationviewiteminvokedeventargs.issettingsinvoked
			if (args.IsSettingsInvoked)
			{
				NavView_Navigate(typeof(Pages.Settings), args?.RecommendedNavigationTransitionInfo, null);
			}
			else
			{
				NavView_Navigate(null, args?.RecommendedNavigationTransitionInfo, args?.InvokedItemContainer.Content.ToString());
			}
		}
	}


	/// <summary>
	/// Main navigation method that is used by the search bar, direct clicks on the main navigation items
	/// And by other methods throughout the app in order to navigate to sub-pages
	/// </summary>
	/// <param name="navPageType"></param>
	/// <param name="transitionInfo"></param>
	/// <param name="navItemName"></param>
	internal void NavView_Navigate(Type? navPageType, NavigationTransitionInfo? transitionInfo = null, string? navItemName = null)
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
		else if (navItemName is not null && NavigationPageToItemContentMap.TryGetValue(navItemName, out Type? page) && !Equals(page, preNavPageType))
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
	/// Event handler for the main Sidebar button click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SidebarButton_Click(object sender, RoutedEventArgs e)
	{
		// Get the current state of the sidebar closed/open
		bool sidePaneStat = MainSidebar.IsPaneOpen;

		// Set the close/open state of the sidebar to the opposite state
		MainSidebar.IsPaneOpen = !sidePaneStat;
	}


	/// <summary>
	/// Event handler for when the back button is pressed
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void BackButtonTitleBar_Click(object sender, RoutedEventArgs e)
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
	/// Event handler for the hamburger/main menu button click
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void HamburgerMenuButton_Click(object sender, RoutedEventArgs e)
	{
		MainNavigation.IsPaneOpen = !MainNavigation.IsPaneOpen;
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
			TitleColumn.Width = new GridLength(0); // Hide TitleColumn if width is less than 200
		}
		else
		{
			TitleColumn.Width = GridLength.Auto; // Restore the TitleColumn if width is 200 or more
		}
	}


	/// <summary>
	/// Event handler for the sidebar base policy browse button
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SidebarBasePolicyBrowseButton_Click(object sender, RoutedEventArgs e)
	{

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			SidebarBasePolicyPathTextBox.Text = selectedFile;

			// Show the animated icons on the currently visible page
			AffectPagesAnimatedIconsVisibilities(true);
		}
	}


	/// <summary>
	/// Event handler to change visibility of the AnimatedIcons on the currently visible page in the frame
	/// It is called by the Sidebar's Browse/Clear buttons' event handlers
	/// </summary>
	/// <param name="on"></param>
	private void AffectPagesAnimatedIconsVisibilities(bool on)
	{

		// Decide the visibility to set the animated icons to based on the parameter
		Visibility visibility = on ? Visibility.Visible : Visibility.Collapsed;

		if (ContentFrame.Content is IAnimatedIconsManager currentPage)
		{
			currentPage.SetVisibility(visibility, SidebarBasePolicyPathTextBox.Text, SidebarUnsignedBasePolicyConnect1, SidebarUnsignedBasePolicyConnect2, SidebarUnsignedBasePolicyConnect3, SidebarUnsignedBasePolicyConnect4, SidebarUnsignedBasePolicyConnect5);

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
		bool isUnsignedBasePolicyPathAvailable = !string.IsNullOrWhiteSpace(SidebarBasePolicyPathTextBox.Text);

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
				currentPage.SetVisibility(Visibility.Visible, SidebarBasePolicyPathTextBox.Text, SidebarUnsignedBasePolicyConnect1, SidebarUnsignedBasePolicyConnect2, SidebarUnsignedBasePolicyConnect3, SidebarUnsignedBasePolicyConnect4, SidebarUnsignedBasePolicyConnect5);
				SidebarBasePolicySelectButtonLightAnimatedIcon.Visibility = Visibility.Visible;
			}
			else
			{
				currentPage.SetVisibility(Visibility.Collapsed, SidebarBasePolicyPathTextBox.Text, SidebarUnsignedBasePolicyConnect1, SidebarUnsignedBasePolicyConnect2, SidebarUnsignedBasePolicyConnect3, SidebarUnsignedBasePolicyConnect4, SidebarUnsignedBasePolicyConnect5);
				SidebarBasePolicySelectButtonLightAnimatedIcon.Visibility = Visibility.Collapsed;
			}
		}
		else
		{
			SidebarBasePolicySelectButtonLightAnimatedIcon.Visibility = Visibility.Collapsed;
		}
	}


	/// <summary>
	/// Event handler for the clear button in the sidebar for unsigned policy path
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SidebarBasePolicyClearButton_Click(object sender, RoutedEventArgs e)
	{
		// Clear the Sidebar text box
		SidebarBasePolicyPathTextBox.Text = null;

		// Hide the animated icons on the currently visible page
		AffectPagesAnimatedIconsVisibilities(false);
	}


	/// <summary>
	/// Event handler for when the RootGrid of the window is loaded
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void RootGrid_Loaded(object sender, RoutedEventArgs e)
	{
		// Adjust the elevation of the border to achieve the shadow effect
		Border1.Translation += new Vector3(0, 0, 500);

		// Get the user configuration for unsigned policy path and fill in the text box for sidebar
		SidebarBasePolicyPathTextBox.Text = UserConfiguration.Get().UnsignedPolicyPath;

		// Set the status of the sidebar toggle switch for auto assignment by getting it from saved app settings
		AutomaticAssignmentSidebarToggleSwitch.IsOn = AppSettingsCls.TryGetSetting<bool?>(AppSettingsCls.SettingKeys.AutomaticAssignmentSidebar) ?? true;
	}


	/// <summary>
	/// Event handler for when the event that changes unsigned policy path in user configurations is fired
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void SidebarOnUnsignedPolicyChanged(object? sender, Events.UnsignedPolicyInUserConfigChangedEventArgs e)
	{
		SidebarBasePolicyPathTextBox.Text = e.UnsignedPolicyInUserConfig;
	}


	/// <summary>
	/// Method used by other methods that create base policies so they can assign the path to the sidebar after creation
	/// If the toggle switch for automatic assignment is on
	/// </summary>
	/// <param name="unsignedPolicyPath"></param>
	internal void AssignToSidebar(string unsignedPolicyPath)
	{
		_ = DispatcherQueue.TryEnqueue(() =>
			{
				if (AutomaticAssignmentSidebarToggleSwitch.IsOn)
				{
					SidebarBasePolicyPathTextBox.Text = unsignedPolicyPath;
				}
			});
	}


	/// <summary>
	/// Event handler for sidebar settings cards for auto assignment
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void AutomaticAssignmentSidebarSettingsCard_Click(object sender, RoutedEventArgs e)
	{
		AutomaticAssignmentSidebarToggleSwitch.IsOn = !AutomaticAssignmentSidebarToggleSwitch.IsOn;

		// Save the status in app settings
		AppSettingsCls.SaveSetting(AppSettingsCls.SettingKeys.AutomaticAssignmentSidebar, AutomaticAssignmentSidebarToggleSwitch.IsOn);
	}


	/// <summary>
	/// Event handler for the sidebar toggle button for auto assignment
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void AutomaticAssignmentSidebarToggleSwitch_Toggled(object sender, RoutedEventArgs e)
	{
		// Save the status in app settings
		AppSettingsCls.SaveSetting(AppSettingsCls.SettingKeys.AutomaticAssignmentSidebar, AutomaticAssignmentSidebarToggleSwitch.IsOn);
	}


	/// <summary>
	/// Event handler for the Sidebar button to open the user config directory
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void OpenConfigDirectoryButton_Click(object sender, RoutedEventArgs e)
	{
		_ = Process.Start(new ProcessStartInfo
		{
			FileName = GlobalVars.UserConfigDir,
			UseShellExecute = true
		});
	}
}
