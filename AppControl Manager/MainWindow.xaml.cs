using AnimatedVisuals;
using Microsoft.UI;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using static WDACConfig.AppSettings;

namespace WDACConfig
{
    public sealed partial class MainWindow : Window
    {

        public MainWindowViewModel ViewModel { get; }

        // Dictionary to store the display names and associated NavigationViewItems
        private readonly Dictionary<string, NavigationViewItem> menuItems = [];


        public MainWindow()
        {
            this.InitializeComponent();

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
            OnNavigationBackgroundChanged(AppSettings.GetSetting<bool>(SettingKeys.NavViewBackground));

            // Set the initial BackDrop setting based on the user's settings
            OnBackgroundChanged(AppSettings.GetSetting<string>(SettingKeys.BackDropBackground));

            // Set the initial App Theme based on the user's settings
            OnAppThemeChanged(AppSettings.GetSetting<string>(SettingKeys.AppTheme));


            OnIconsStylesChanged(AppSettings.GetSetting<string>(SettingKeys.IconsStyle));

        }



        private void OnIconsStylesChanged(string? newIconsStyle)
        {

            // Get the current theme
            ElementTheme currentTheme = RootGrid.ActualTheme;


            // Set the NavigationView's location based on the event
            switch (newIconsStyle)
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

                        // Create Policy from MDE Advanced Hunting
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
                            Source = new Timeline()
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

                        // Create Policy from MDE Advanced Hunting
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

                        break;
                    }
                case "Monochromatic":
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

                        // Create Policy from MDE Advanced Hunting
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

                        break;
                    }
                default:
                    {
                        // Default behavior
                        break;
                    }
            };
        }





        /// <summary>
        /// Event handler for the global NavigationView location change event
        /// </summary>
        /// <param name="newLocation"></param>
        private void OnNavigationViewLocationChanged(string newLocation)
        {
            // Set the NavigationView's location based on the event
            switch (newLocation)
            {
                case "Left":
                    {
                        // MainNavigation has no margins by default
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
        /// <param name="isBackgroundOn"></param>
        private void OnNavigationBackgroundChanged(bool isBackgroundOn)
        {
            // Get the current theme
            ElementTheme currentTheme = RootGrid.ActualTheme;

            // Calculate the opposite theme
            ElementTheme oppositeTheme = currentTheme == ElementTheme.Dark ? ElementTheme.Light : ElementTheme.Dark;

            // Switch to opposite theme
            RootGrid.RequestedTheme = oppositeTheme;

            // Perform NavigationView background changes based on the settings' page's button
            if (isBackgroundOn)
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
        /// <param name="selectedBackdrop"></param>
        private void OnBackgroundChanged(string? selectedBackdrop)
        {
            // Update the SystemBackdrop based on the selected background
            // The Default is set in the XAML
            switch (selectedBackdrop)
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
        /// <param name="newTheme"></param>
        private void OnAppThemeChanged(string? newTheme)
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
            switch (newTheme)
            {
                case "Light":
                    {
                        RootGrid.RequestedTheme = ElementTheme.Light;

                        if (string.Equals(AppSettings.GetSetting<string>(SettingKeys.IconsStyle), "Animated", System.StringComparison.OrdinalIgnoreCase))
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

                        if (string.Equals(AppSettings.GetSetting<string>(SettingKeys.IconsStyle), "Animated", System.StringComparison.OrdinalIgnoreCase))
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
                            if (string.Equals(AppSettings.GetSetting<string>(SettingKeys.IconsStyle), "Animated", System.StringComparison.OrdinalIgnoreCase))
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
                            if (string.Equals(AppSettings.GetSetting<string>(SettingKeys.IconsStyle), "Animated", System.StringComparison.OrdinalIgnoreCase))
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
                string query = sender.Text.ToLower();

                // Filter menu items based on the search query
                List<string> suggestions = menuItems.Keys
                    .Where(name => name.Contains(query, System.StringComparison.OrdinalIgnoreCase))
                    .ToList();


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
                        NavigateToMenuItem(selectedTag);
                    }
                }
            }
        }


        /// <summary>
        /// Event handler for main navigation menu selection change
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        private void NavigationView_SelectionChanged(NavigationView sender, NavigationViewSelectionChangedEventArgs args)
        {
            if (args.SelectedItem is NavigationViewItem selectedItem)
            {
                // Play sound for selection change
                ElementSoundPlayer.Play(ElementSoundKind.MoveNext);

                string selectedTag = selectedItem.Tag?.ToString()!;
                NavigateToMenuItem(selectedTag);
            }
        }


        /// <summary>
        /// Separate method to handle navigation based on the selected tag
        /// </summary>
        /// <param name="selectedTag"></param>
        private void NavigateToMenuItem(string selectedTag)
        {
            switch (selectedTag)
            {
                case "CreatePolicy":
                    _ = ContentFrame.Navigate(typeof(Pages.CreatePolicy));
                    break;
                case "GetCIHashes":
                    _ = ContentFrame.Navigate(typeof(Pages.GetCIHashes));
                    break;
                // Doesn't need XAML nav item because it's included by default in the navigation view
                case "Settings":
                    _ = ContentFrame.Navigate(typeof(Pages.Settings));
                    break;
                case "GitHubDocumentation":
                    _ = ContentFrame.Navigate(typeof(Pages.GitHubDocumentation));
                    break;
                case "MicrosoftDocumentation":
                    _ = ContentFrame.Navigate(typeof(Pages.MicrosoftDocumentation));
                    break;
                case "GetSecurePolicySettings":
                    _ = ContentFrame.Navigate(typeof(Pages.GetSecurePolicySettings));
                    break;
                case "SystemInformation":
                    _ = ContentFrame.Navigate(typeof(Pages.SystemInformation));
                    break;
                case "ConfigurePolicyRuleOptions":
                    _ = ContentFrame.Navigate(typeof(Pages.ConfigurePolicyRuleOptions));
                    break;
                case "Logs":
                    _ = ContentFrame.Navigate(typeof(Pages.Logs));
                    break;
                case "Simulation":
                    _ = ContentFrame.Navigate(typeof(Pages.Simulation));
                    break;
                case "Update":
                    _ = ContentFrame.Navigate(typeof(Pages.Update));
                    break;
                case "Deployment":
                    _ = ContentFrame.Navigate(typeof(Pages.Deployment));
                    break;
                case "EventLogsPolicyCreation":
                    _ = ContentFrame.Navigate(typeof(Pages.EventLogsPolicyCreation));
                    break;
                case "MDEAHPolicyCreation":
                    _ = ContentFrame.Navigate(typeof(Pages.MDEAHPolicyCreation));
                    break;
                case "AllowNewApps":
                    _ = ContentFrame.Navigate(typeof(Pages.AllowNewApps));
                    break;
                default:
                    break;
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

                ContentFrame.GoBack();
            }
        }


        /// <summary>
        /// Set the NavigationView's header to the Navigation view item's content
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="args"></param>
        private void NavigationView_ItemInvoked(NavigationView sender, NavigationViewItemInvokedEventArgs args)
        {
            if (MainNavigation.SelectedItem is NavigationViewItem item)
            {

                // Must be nullable because when NavigationViewPaneDisplayMode is top, this is null.
                sender.Header = item.Content?.ToString();
            }
        }


    }
}
