using AnimatedVisuals;
using AppControlManager.Logging;
using Microsoft.UI;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Windows.Graphics;

namespace AppControlManager
{

    public sealed partial class MainWindow : Window
    {

        public MainWindowViewModel ViewModel { get; }

        // Dictionary to store the display names and associated NavigationViewItems
        private readonly Dictionary<string, NavigationViewItem> menuItems = [];


        // Static pre-made dictionary for navigation page-to-item content mapping
        // Used for the back button in order to set the correct header
        private static readonly Dictionary<Type, string> NavigationPageToItemContentMap = new()
        {
            { typeof(Pages.CreatePolicy), "Create Policy" },
            { typeof(Pages.GetCIHashes), "Get Code Integrity Hashes" },
            { typeof(Pages.GitHubDocumentation), "GitHub Documentation" },
            { typeof(Pages.MicrosoftDocumentation), "Microsoft Documentation" },
            { typeof(Pages.GetSecurePolicySettings), "Get Secure Policy Settings" },
            { typeof(Pages.Settings), "Settings" },
            { typeof(Pages.SystemInformation), "System Information" },
            { typeof(Pages.ConfigurePolicyRuleOptions), "Configure Policy Rule Options" },
            { typeof(Pages.Logs), "Logs" },
            { typeof(Pages.Simulation), "Simulation" },
            { typeof(Pages.Update), "Update" },
            { typeof(Pages.Deployment), "Deploy App Control Policy" },
            { typeof(Pages.EventLogsPolicyCreation), "Create policy from Event Logs" },
            { typeof(Pages.MDEAHPolicyCreation), "MDE Advanced Hunting" },
            { typeof(Pages.AllowNewApps), "Allow New Apps" },
            { typeof(Pages.BuildNewCertificate), "Build New Certificate" },
            { typeof(Pages.UpdatePageCustomMSIXPath), "Custom MSIX Path" }, // sub-page
            { typeof(Pages.CreateSupplementalPolicy), "Create Supplemental Policy" },
            { typeof(Pages.CreateSupplementalPolicyFilesAndFoldersScanResults), "Scan Results" }, // sub-page
            { typeof(Pages.MergePolicies), "Merge App Control Policies" }
        };


        // A static instance of the MainWindow class which will hold the single, shared instance of it
        private static MainWindow? _instance;


        public MainWindow()
        {
            this.InitializeComponent();

            // Assign this instance to the static field
            _instance = this;

            // Retrieve the window handle (HWND) of the main WinUI 3 window and store it in the global vars
            GlobalVars.hWnd = WinRT.Interop.WindowNative.GetWindowHandle(this);

            // https://learn.microsoft.com/en-us/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.window.extendscontentintotitlebar
            // Make title bar Mica
            ExtendsContentIntoTitleBar = true;

            // Subscribe to the global BackDrop change event
            ThemeManager.BackDropChanged += OnBackgroundChanged;

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

                   // If AutoUpdateCheck is enabled in the user configurations, checks for updates on startup and displays a dot on the Update page in the navigation
                   // If a new version is available.
                   if (UserConfiguration.Get().AutoUpdateCheck == true)
                   {

                       Logger.Write("Checking for update on startup because AutoUpdateCheck is enabled");

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

            // Set the "CreatePolicy" item as selected in the NavigationView
            MainNavigation.SelectedItem = MainNavigation.MenuItems.OfType<NavigationViewItem>()
                .First(item => item.Tag.ToString() == "CreatePolicy");

            // Set the initial NavigationView header
            MainNavigation.Header = "Create Policy";

            PopulateMenuItems();


            // Set the initial background setting based on the user's settings
            OnNavigationBackgroundChanged(null, new(AppSettings.GetSetting<bool>(AppSettings.SettingKeys.NavViewBackground)));

            // Set the initial BackDrop setting based on the user's settings
            OnBackgroundChanged(null, new(AppSettings.GetSetting<string>(AppSettings.SettingKeys.BackDropBackground)));

            // Set the initial App Theme based on the user's settings
            OnAppThemeChanged(null, new(AppSettings.GetSetting<string>(AppSettings.SettingKeys.AppTheme)));

            // Set the initial Icons styles abased on the user's settings
            OnIconsStylesChanged(null, new(AppSettings.GetSetting<string>(AppSettings.SettingKeys.IconsStyle)));

            // Restore window size on startup
            RestoreWindowSize();

            // Subscribe to Closed event of the main Window
            this.Closed += MainWindow_Closed;
        }

        // Public property to access the singleton instance from other classes
        public static MainWindow Instance => _instance ?? throw new InvalidOperationException("MainWindow is not initialized.");


        /// <summary>
        /// Main Window close event
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        private void MainWindow_Closed(object sender, WindowEventArgs args)
        {
            // Get the AppWindow from the current Window
            AppWindow appWindow = GetAppWindowForCurrentWindow();

            // Get the current size of the window
            SizeInt32 size = appWindow.Size;

            // Save to window width and height to the app settings
            AppSettings.SaveSetting(AppSettings.SettingKeys.MainWindowWidth, size.Width);
            AppSettings.SaveSetting(AppSettings.SettingKeys.MainWindowHeight, size.Height);

            Win32InteropInternal.WINDOWPLACEMENT windowPlacement = new();

            // Check if the window is maximized
            _ = Win32InteropInternal.GetWindowPlacement(GlobalVars.hWnd, ref windowPlacement);

            // Save the maximized status of the window before closing to the app settings
            if (windowPlacement.showCmd is Win32InteropInternal.ShowWindowCommands.SW_SHOWMAXIMIZED)
            {
                AppSettings.SaveSetting(AppSettings.SettingKeys.MainWindowIsMaximized, true);
            }
            else
            {
                AppSettings.SaveSetting(AppSettings.SettingKeys.MainWindowIsMaximized, false);
            }
        }


        /// <summary>
        /// Event handler to run at Window launch to restore its size to the one before closing
        /// </summary>
        private static void RestoreWindowSize()
        {

            AppWindow appWindow = GetAppWindowForCurrentWindow();

            // If the window was last maximized then restore it to maximized
            if (AppSettings.GetSetting<bool>(AppSettings.SettingKeys.MainWindowIsMaximized))
            {
                // Set the presenter to maximized
                ((OverlappedPresenter)appWindow.Presenter).Maximize();
            }

            // Else set its size to its previous size before closing
            else
            {
                // Retrieve stored values
                int width = AppSettings.GetSetting<int>(AppSettings.SettingKeys.MainWindowWidth);
                int height = AppSettings.GetSetting<int>(AppSettings.SettingKeys.MainWindowHeight);

                // If the previous window size was smaller than 200 pixels width/height then do not use it, let it use the natural window size
                if (width > 200 && height > 200)
                {
                    // Apply to the current AppWindow
                    appWindow?.Resize(new SizeInt32(width, height));
                }
            }
        }


        private static AppWindow GetAppWindowForCurrentWindow()
        {
            WindowId windowId = Win32Interop.GetWindowIdFromWindow(GlobalVars.hWnd);
            return AppWindow.GetFromWindowId(windowId);
        }



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

                        break;
                    }
            };
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

                        MainNavigation.PaneDisplayMode = NavigationViewPaneDisplayMode.Left;
                        break;
                    }
                case "Top":
                    {
                        // Needs some top margin when it's set to top
                        MainNavigation.Margin = new Thickness(0, 40, 0, 0);

                        MainNavigation.PaneDisplayMode = NavigationViewPaneDisplayMode.Top;
                        break;
                    }
                default:
                    {
                        // MainNavigation has no margins by default
                        MainNavigation.Margin = new Thickness(0);
                        break;
                    }
            };

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
                        if (string.Equals(AppSettings.GetSetting<string>(AppSettings.SettingKeys.IconsStyle), "Animated", StringComparison.OrdinalIgnoreCase))
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
                        if (string.Equals(AppSettings.GetSetting<string>(AppSettings.SettingKeys.IconsStyle), "Animated", StringComparison.OrdinalIgnoreCase))
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
                            if (string.Equals(AppSettings.GetSetting<string>(AppSettings.SettingKeys.IconsStyle), "Animated", StringComparison.OrdinalIgnoreCase))
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
                            if (string.Equals(AppSettings.GetSetting<string>(AppSettings.SettingKeys.IconsStyle), "Animated", StringComparison.OrdinalIgnoreCase))
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


        /// <summary>
        /// Populate the dictionary with menu items for search purposes
        /// </summary>
        private void PopulateMenuItems()
        {
            foreach (NavigationViewItem item in MainNavigation.MenuItems.OfType<NavigationViewItem>())
            {
                menuItems[item.Content.ToString()!] = item;

                // If there are sub-items, add those as well
                if (item.MenuItems is not null && item.MenuItems.Count > 0)
                {
                    foreach (NavigationViewItem subItem in item.MenuItems.OfType<NavigationViewItem>())
                    {
                        menuItems[subItem.Content.ToString()!] = subItem;
                    }
                }
            }
        }

        /// <summary>
        /// Event handler for the AutoSuggestBox text change event
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        private void SearchBox_TextChanged(AutoSuggestBox sender, AutoSuggestBoxTextChangedEventArgs args)
        {
            if (args.Reason == AutoSuggestionBoxTextChangeReason.UserInput)
            {
                string query = sender.Text.ToLowerInvariant();

                // Filter menu items based on the search query
                List<string> suggestions = [.. menuItems.Keys.Where(name => name.Contains(query, StringComparison.OrdinalIgnoreCase))];


                // Set the filtered items as suggestions in the AutoSuggestBox
                sender.ItemsSource = suggestions;
            }
        }

        /// <summary>
        /// Event handler for when a suggestion is chosen in the AutoSuggestBox
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        private void SearchBox_SuggestionChosen(AutoSuggestBox sender, AutoSuggestBoxSuggestionChosenEventArgs args)
        {
            // Get the selected item's name and find the corresponding NavigationViewItem
            string? chosenItemName = args.SelectedItem?.ToString();
            if (chosenItemName is not null && menuItems.TryGetValue(chosenItemName, out NavigationViewItem? selectedItem))
            {
                // Select the item in the NavigationView
                MainNavigation.SelectedItem = selectedItem;

                if (selectedItem is not null)
                {
                    // Directly call NavigateToMenuItem with the selected item's tag
                    string? selectedTag = selectedItem.Tag?.ToString();

                    if (selectedTag is not null)
                    {
                        Navigate_ToPage(MainNavigation, selectedTag, null);
                    }
                }
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
                Navigate_ToPage(sender, args.InvokedItemContainer.Tag.ToString()!, args?.RecommendedNavigationTransitionInfo);
            }
        }


        /// <summary>
        /// Used by the main navigation's event, AutoSuggestBox and through the current class's singleton instance by other pages
        /// to navigate to sub-pages that aren't included in the main navigation menu
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="tag"></param>
        /// <param name="transitionInfo"></param>
        internal void Navigate_ToPage(NavigationView? sender, string tag, NavigationTransitionInfo? transitionInfo, string? Header = null)
        {

            // Find the page type based on the tag and send it to another method for final navigation action
            switch (tag)
            {
                case "CreatePolicy":
                    NavView_Navigate(typeof(Pages.CreatePolicy), transitionInfo);
                    break;
                case "GetCIHashes":
                    NavView_Navigate(typeof(Pages.GetCIHashes), transitionInfo);
                    break;
                case "GitHubDocumentation":
                    NavView_Navigate(typeof(Pages.GitHubDocumentation), transitionInfo);
                    break;
                case "MicrosoftDocumentation":
                    NavView_Navigate(typeof(Pages.MicrosoftDocumentation), transitionInfo);
                    break;
                case "GetSecurePolicySettings":
                    NavView_Navigate(typeof(Pages.GetSecurePolicySettings), transitionInfo);
                    break;
                // Doesn't need XAML nav item because it's included by default in the navigation view
                case "Settings":
                    NavView_Navigate(typeof(Pages.Settings), transitionInfo);
                    break;
                case "SystemInformation":
                    NavView_Navigate(typeof(Pages.SystemInformation), transitionInfo);
                    break;
                case "ConfigurePolicyRuleOptions":
                    NavView_Navigate(typeof(Pages.ConfigurePolicyRuleOptions), transitionInfo);
                    break;
                case "Logs":
                    NavView_Navigate(typeof(Pages.Logs), transitionInfo);
                    break;
                case "Simulation":
                    NavView_Navigate(typeof(Pages.Simulation), transitionInfo);
                    break;
                case "Update":
                    NavView_Navigate(typeof(Pages.Update), transitionInfo);
                    break;
                case "Deployment":
                    NavView_Navigate(typeof(Pages.Deployment), transitionInfo);
                    break;
                case "EventLogsPolicyCreation":
                    NavView_Navigate(typeof(Pages.EventLogsPolicyCreation), transitionInfo);
                    break;
                case "MDEAHPolicyCreation":
                    NavView_Navigate(typeof(Pages.MDEAHPolicyCreation), transitionInfo);
                    break;
                case "AllowNewApps":
                    NavView_Navigate(typeof(Pages.AllowNewApps), transitionInfo);
                    break;
                case "BuildNewCertificate":
                    NavView_Navigate(typeof(Pages.BuildNewCertificate), transitionInfo);
                    break;
                case "UpdatePageCustomMSIXPath":
                    NavView_Navigate(typeof(Pages.UpdatePageCustomMSIXPath), transitionInfo); // Sub-Page
                    break;
                case "CreateSupplementalPolicy":
                    NavView_Navigate(typeof(Pages.CreateSupplementalPolicy), transitionInfo);
                    break;
                case "CreateSupplementalPolicyFilesAndFoldersScanResults":
                    NavView_Navigate(typeof(Pages.CreateSupplementalPolicyFilesAndFoldersScanResults), transitionInfo); // Sub-Page
                    break;
                case "MergePolicies":
                    NavView_Navigate(typeof(Pages.MergePolicies), transitionInfo);
                    break;
                default:
                    break;
            }

            // Set the NavigationView's header to the Navigation view item's content
            if (MainNavigation.SelectedItem is NavigationViewItem item)
            {
                if (sender is not null)
                {
                    // Must be nullable because when NavigationViewPaneDisplayMode is top, this is null.
                    sender.Header = item.Content?.ToString();
                }
                else if (Header is not null)
                {
                    MainNavigation.Header = Header;
                }
            }
        }



        private void NavView_Navigate(Type navPageType, NavigationTransitionInfo? transitionInfo)
        {
            // Get the page's type before navigation so we can prevent duplicate
            // entries in the BackStack
            // This will prevent reloading the same page if we're already on it and works with sub-pages to navigate back to the main page
            Type preNavPageType = ContentFrame.CurrentSourcePageType;

            // Only navigate if the selected page isn't currently loaded.
            if (navPageType is not null && !Equals(preNavPageType, navPageType))
            {

                // Play sound
                ElementSoundPlayer.Play(ElementSoundKind.MoveNext);

                _ = ContentFrame.Navigate(navPageType, null, transitionInfo);
            }
        }




        /// <summary>
        /// Event handlers for the back button in the NavigationView
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        private void NavView_BackRequested(NavigationView sender, NavigationViewBackRequestedEventArgs args)
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
                Type preNavPageType = ContentFrame.CurrentSourcePageType;

                // Extract the navigation item content from the dictionary
                _ = NavigationPageToItemContentMap.TryGetValue(preNavPageType, out string? item);

                // Set the correct header after back navigation has been completed
                MainNavigation.Header = item;

            }
        }

    }
}
