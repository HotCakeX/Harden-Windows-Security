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
using System.Diagnostics;
using System.Numerics;
using AnimatedVisuals;
using AppControlManager.Others;
using AppControlManager.WindowComponents;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace AppControlManager.ViewModels;

/// <summary>
/// ViewModel for the MainWindow
/// </summary>
internal sealed partial class MainWindowVM : ViewModelBase
{

	internal object? NavViewSelectedItem { get; set => SP(ref field, value); }
	internal Thickness NavViewMargin { get; } = new Thickness(0);

	/// <summary>
	/// The text in the SidebarPolicyPathTextBox
	/// </summary>
	internal string? SidebarBasePolicyPathTextBoxText
	{
		get;
		set
		{
			if (SP(ref field, value))
			{
				SidebarBasePolicyPathTextBoxTextStatic = field;
			}
		}
	}
	internal static string? SidebarBasePolicyPathTextBoxTextStatic { get; private set; }

	// a list of all the NavigationViewItem in the Main NavigationViewItem
	// It is populated in the class initializer
	// Since the app uses it multiple times, we only populate this list once to reuse it in subsequent calls
	internal IEnumerable<NavigationViewItem> allNavigationItems = [];

	/// <summary>
	/// Pages that are allowed to run when running without Administrator privileges
	/// </summary>
	internal List<Type> UnelevatedPages = [
		typeof(Pages.ValidatePolicy),
		typeof(Pages.GitHubDocumentation),
		typeof(Pages.MicrosoftDocumentation),
		typeof(Pages.Logs),
		typeof(Pages.GetCIHashes),
		typeof(Pages.PolicyEditor),
		typeof(Pages.MergePolicies),
		typeof(Pages.Settings),
		typeof(Pages.ConfigurePolicyRuleOptions),
		typeof(Pages.ViewFileCertificates)
		];


	/// <summary>
	/// Every page in the application must be defined in this dictionary.
	/// It is used by the BreadCrumbBar.
	/// Sub-pages must use the same value as their main page in the dictionary.
	/// </summary>
	internal readonly Dictionary<Type, PageTitleMap> breadCrumbMappingsV2 = [];

	internal void RebuildBreadcrumbMappings()
	{
		breadCrumbMappingsV2.Clear();

		breadCrumbMappingsV2[typeof(Pages.CreatePolicy)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("CreatePolicyNavItem/Content")],
			Pages = [typeof(Pages.CreatePolicy)]
		};

		breadCrumbMappingsV2[typeof(Pages.GetCIHashes)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("GetCodeIntegrityHashesNavItem/Content")],
			Pages = [typeof(Pages.GetCIHashes)]
		};

		breadCrumbMappingsV2[typeof(Pages.GitHubDocumentation)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("GitHubDocsNavItem/Content")],
			Pages = [typeof(Pages.GitHubDocumentation)]
		};

		breadCrumbMappingsV2[typeof(Pages.MicrosoftDocumentation)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("MSFTDocsNavItem/Content")],
			Pages = [typeof(Pages.MicrosoftDocumentation)]
		};

		breadCrumbMappingsV2[typeof(Pages.GetSecurePolicySettings)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("GetSecurePolicySettingsNavItem/Content")],
			Pages = [typeof(Pages.GetSecurePolicySettings)]
		};

		breadCrumbMappingsV2[typeof(Pages.Settings)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("SettingsNavItem/Content")],
			Pages = [typeof(Pages.Settings)]
		};

		breadCrumbMappingsV2[typeof(Pages.SystemInformation)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("SystemInformationNavItem/Content")],
			Pages = [typeof(Pages.SystemInformation)]
		};

		breadCrumbMappingsV2[typeof(Pages.ConfigurePolicyRuleOptions)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("ConfigurePolicyRuleOptionsNavItem/Content")],
			Pages = [typeof(Pages.ConfigurePolicyRuleOptions)]
		};

		breadCrumbMappingsV2[typeof(Pages.Logs)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("LogsNavItem/Content")],
			Pages = [typeof(Pages.Logs)]
		};

		breadCrumbMappingsV2[typeof(Pages.Simulation)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("SimulationNavItem/Content")],
			Pages = [typeof(Pages.Simulation)]
		};

		breadCrumbMappingsV2[typeof(Pages.UpdatePage)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("UpdateNavItem/Content"), "Custom MSIXBundle Path"],
			Pages = [typeof(Pages.UpdatePage), typeof(Pages.UpdatePageCustomMSIXPath)]
		};

		breadCrumbMappingsV2[typeof(Pages.UpdatePageCustomMSIXPath)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("UpdateNavItem/Content"), "Custom MSIXBundle Path"],
			Pages = [typeof(Pages.UpdatePage), typeof(Pages.UpdatePageCustomMSIXPath)]
		};

		breadCrumbMappingsV2[typeof(Pages.DeploymentPage)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("DeploymentNavItem/Content")],
			Pages = [typeof(Pages.DeploymentPage)]
		};

		breadCrumbMappingsV2[typeof(Pages.EventLogsPolicyCreation)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("CreatePolicyFromEventLogsNavItem/Content")],
			Pages = [typeof(Pages.EventLogsPolicyCreation)]
		};

		breadCrumbMappingsV2[typeof(Pages.MDEAHPolicyCreation)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("CreatePolicyFromMDEAHNavItem/Content")],
			Pages = [typeof(Pages.MDEAHPolicyCreation)]
		};

		breadCrumbMappingsV2[typeof(Pages.AllowNewApps)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("AllowNewAppsNavItem/Content")],
			Pages = [typeof(Pages.AllowNewApps)]
		};

		breadCrumbMappingsV2[typeof(Pages.BuildNewCertificate)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("BuildNewCertificateNavItem/Content")],
			Pages = [typeof(Pages.BuildNewCertificate)]
		};

		breadCrumbMappingsV2[typeof(Pages.MergePolicies)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("MergePoliciesNavItem/Content")],
			Pages = [typeof(Pages.MergePolicies)]
		};

		breadCrumbMappingsV2[typeof(Pages.CreateSupplementalPolicy)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("CreateSupplementalPolicyNavItem/Content"), GlobalVars.Rizz.GetString("ScanResults")],
			Pages = [typeof(Pages.CreateSupplementalPolicy), typeof(Pages.CreateSupplementalPolicyFilesAndFoldersScanResults)]
		};

		breadCrumbMappingsV2[typeof(Pages.CreateSupplementalPolicyFilesAndFoldersScanResults)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("CreateSupplementalPolicyNavItem/Content"), GlobalVars.Rizz.GetString("ScanResults")],
			Pages = [typeof(Pages.CreateSupplementalPolicy), typeof(Pages.CreateSupplementalPolicyFilesAndFoldersScanResults)]
		};

		breadCrumbMappingsV2[typeof(Pages.StrictKernelPolicyScanResults)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("CreateSupplementalPolicyNavItem/Content"), GlobalVars.Rizz.GetString("ScanResults")],
			Pages = [typeof(Pages.CreateSupplementalPolicy), typeof(Pages.StrictKernelPolicyScanResults)]
		};

		breadCrumbMappingsV2[typeof(Pages.CreateDenyPolicy)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("CreateDenyPolicyNavItem/Content"), GlobalVars.Rizz.GetString("ScanResults")],
			Pages = [typeof(Pages.CreateDenyPolicy), typeof(Pages.CreateDenyPolicyFilesAndFoldersScanResults)]
		};

		breadCrumbMappingsV2[typeof(Pages.CreateDenyPolicyFilesAndFoldersScanResults)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("CreateDenyPolicyNavItem/Content"), GlobalVars.Rizz.GetString("ScanResults")],
			Pages = [typeof(Pages.CreateDenyPolicy), typeof(Pages.CreateDenyPolicyFilesAndFoldersScanResults)]
		};

		breadCrumbMappingsV2[typeof(Pages.ValidatePolicy)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("ValidatePoliciesNavItem/Content")],
			Pages = [typeof(Pages.ValidatePolicy)]
		};

		breadCrumbMappingsV2[typeof(Pages.ViewFileCertificates)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("ViewFileCertificatesNavItem/Content")],
			Pages = [typeof(Pages.ViewFileCertificates)]
		};

		breadCrumbMappingsV2[typeof(Pages.PolicyEditor)] = new PageTitleMap
		{
			Titles = [GlobalVars.Rizz.GetString("PolicyEditorNavItem/Content")],
			Pages = [typeof(Pages.PolicyEditor)]
		};
	}

	// This collection is bound to the BreadCrumbBar's ItemsSource in the XAML
	// initially adding the default page that loads when the app is loaded to the collection
	internal readonly ObservableCollection<Crumb> Breadcrumbs = App.IsElevated ? [new Crumb(GlobalVars.Rizz.GetString("CreatePolicyNavItem/Content"), typeof(Pages.CreatePolicy))] :
		[new Crumb(GlobalVars.Rizz.GetString("PolicyEditorNavItem/Content"), typeof(Pages.PolicyEditor))];

	/// <summary>
	/// Dictionary of all the main pages in the app, used for the main navigation.
	/// Keys are the Navigation Item tags (non-localized) and values are the page types.
	/// Sub-pages should only be added if they don't rely on/access the the instance of any page that might not be initialized.
	/// </summary>
	internal readonly Dictionary<string, Type> NavigationPageToItemContentMap = new()
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
	internal readonly Dictionary<string, Type> NavigationPageToItemContentMapForSearch = [];

	internal void RebuildNavigationPageToItemContentMapForSearch()
	{
		NavigationPageToItemContentMapForSearch.Clear();

		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("CreatePolicyNavItem/Content")] = typeof(Pages.CreatePolicy);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("GetCodeIntegrityHashesNavItem/Content")] = typeof(Pages.GetCIHashes);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("GitHubDocsNavItem/Content")] = typeof(Pages.GitHubDocumentation);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("MSFTDocsNavItem/Content")] = typeof(Pages.MicrosoftDocumentation);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("GetSecurePolicySettingsNavItem/Content")] = typeof(Pages.GetSecurePolicySettings);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("SettingsNavItem/Content")] = typeof(Pages.Settings);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("SystemInformationNavItem/Content")] = typeof(Pages.SystemInformation);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("ConfigurePolicyRuleOptionsNavItem/Content")] = typeof(Pages.ConfigurePolicyRuleOptions);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("LogsNavItem/Content")] = typeof(Pages.Logs);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("SimulationNavItem/Content")] = typeof(Pages.Simulation);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("DeploymentNavItem/Content")] = typeof(Pages.DeploymentPage);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("CreatePolicyFromEventLogsNavItem/Content")] = typeof(Pages.EventLogsPolicyCreation);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("CreatePolicyFromMDEAHNavItem/Content")] = typeof(Pages.MDEAHPolicyCreation);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("AllowNewAppsNavItem/Content")] = typeof(Pages.AllowNewApps);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("BuildNewCertificateNavItem/Content")] = typeof(Pages.BuildNewCertificate);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("CreateSupplementalPolicyNavItem/Content")] = typeof(Pages.CreateSupplementalPolicy);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("MergePoliciesNavItem/Content")] = typeof(Pages.MergePolicies);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("CreateDenyPolicyNavItem/Content")] = typeof(Pages.CreateDenyPolicy);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("ValidatePoliciesNavItem/Content")] = typeof(Pages.ValidatePolicy);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("ViewFileCertificatesNavItem/Content")] = typeof(Pages.ViewFileCertificates);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("PolicyEditorNavItem/Content")] = typeof(Pages.PolicyEditor);
		NavigationPageToItemContentMapForSearch[GlobalVars.Rizz.GetString("UpdateNavItem/Content")] = typeof(Pages.UpdatePage);
	}

	/// <summary>
	/// Values for back drop combo box in the settings page
	/// </summary>
	private enum BackDropComboBoxItems
	{
		MicaAlt = 0,
		Mica = 1,
		Acrylic = 2
	};

	/// <summary>
	/// ItemsSource of the ComboBox in the Settings page
	/// </summary>
	internal IEnumerable<string> BackDropOptions => Enum.GetNames<BackDropComboBoxItems>();

	/// <summary>
	/// Constructor initializes the ViewModel and subscribes to various events, sets initial values of some variables.
	/// </summary>
	internal MainWindowVM()
	{

		RebuildBreadcrumbMappings();
		RebuildNavigationPageToItemContentMapForSearch();

		// Subscribe to the UpdateAvailable event to handle updates to the InfoBadge visibility
		AppUpdate.UpdateAvailable += OnUpdateAvailable!;

		// Set the status of the sidebar toggle switch for auto assignment by getting it from saved app settings
		AutomaticAssignmentSidebarToggleSwitchToggledState = App.Settings.AutomaticAssignmentSidebar;

		// Apply the BackDrop when the ViewModel is instantiated
		UpdateSystemBackDrop();

		// If the App is installed from the Microsoft Store source
		// Then make the update page available for non-elevated usage.
		if (App.PackageSource is 1)
			UnelevatedPages.Add(typeof(Pages.UpdatePage));
	}

	#region UI-Bound Properties

	/// <summary>
	/// Sets the initial value of the back drop. if it's null, Mica Alt will be used.
	/// </summary>
	internal int BackDropComboBoxSelectedIndex
	{
		get;
		set
		{
			// Update the value and the system backdrop
			if (SP(ref field, value))
			{
				UpdateSystemBackDrop();
			}
		}
	} = (int)Enum.Parse<BackDropComboBoxItems>(App.Settings.BackDropBackground);

	/// <summary>
	/// Defines a private property for the system backdrop style, initialized with a MicaBackdrop of kind BaseAlt.
	/// </summary>
	internal SystemBackdrop SystemBackDropStyle
	{
		get; set => SP(ref field, value);
	} = new MicaBackdrop { Kind = MicaKind.BaseAlt };

	/// <summary>
	/// Backing field for InfoBadgeOpacity, which controls the visibility of the InfoBadge in the UI.
	/// https://learn.microsoft.com/windows/apps/design/controls/info-badge
	/// Opacity level of the InfoBadge icon in the UI. When set to 1, the badge is visible.
	/// When set to 0, the badge is hidden.
	/// </summary>
	internal double InfoBadgeOpacity { get; set => SP(ref field, value); }

	/// <summary>
	/// The state of the OpenConfigDirectoryButton button which is on the Sidebar
	/// </summary>
	internal bool OpenConfigDirectoryButtonState
	{
		get; set => SP(ref field, value);
	} = App.IsElevated;

	/// <summary>
	/// Whether the sidebar pane is open or closed
	/// </summary>
	internal bool SidebarPaneIsOpen { get; set => SP(ref field, value); }

	/// <summary>
	/// Indicates whether the automatic assignment sidebar toggle switch is in a toggled state. It stores a boolean value.
	/// </summary>
	internal bool AutomaticAssignmentSidebarToggleSwitchToggledState { get; set => SP(ref field, value); }

	/// <summary>
	///  Adjust the elevation of the border to achieve the shadow effect
	/// </summary>
	internal Vector3 BorderTranslation
	{
		get; set => SP(ref field, value);
	} = new(0, 0, 500);

	/// <summary>
	/// Whether the main NavigationView's pane is open or closed
	/// </summary>
	internal bool MainNavigationIsPaneOpen
	{
		get; set => SP(ref field, value);
	} = true;

	/// <summary>
	/// The width of the TitleColumn in the main window's custom title bar
	/// </summary>
	internal GridLength TitleColumnWidth
	{
		get; set => SP(ref field, value);
	} = GridLength.Auto;


	// Navigation Icon Properties

	/// <summary>
	/// Icon for the Create Policy navigation item.
	/// </summary>
	internal IconElement? CreatePolicyIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Create Supplemental Policy navigation item.
	/// </summary>
	internal IconElement? CreateSupplementalPolicyIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Create Deny Policy navigation item.
	/// </summary>
	internal IconElement? CreateDenyPolicyIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Build New Certificate navigation item.
	/// </summary>
	internal IconElement? BuildNewCertificateIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the View File Certificates navigation item.
	/// </summary>
	internal IconElement? ViewFileCertificatesIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Create Policy from Event Logs navigation item.
	/// </summary>
	internal IconElement? CreatePolicyFromEventLogsIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the MDE Advanced Hunting navigation item.
	/// </summary>
	internal IconElement? CreatePolicyFromMDEAHIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Allow New Apps navigation item.
	/// </summary>
	internal IconElement? AllowNewAppsIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Policy Editor navigation item.
	/// </summary>
	internal IconElement? PolicyEditorIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Simulation navigation item.
	/// </summary>
	internal IconElement? SimulationIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the System Information navigation item.
	/// </summary>
	internal IconElement? SystemInformationIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Get Code Integrity Hashes navigation item.
	/// </summary>
	internal IconElement? GetCodeIntegrityHashesIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Get Secure Policy Settings navigation item.
	/// </summary>
	internal IconElement? GetSecurePolicySettingsIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Configure Policy Rule Options navigation item.
	/// </summary>
	internal IconElement? ConfigurePolicyRuleOptionsIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Merge Policies navigation item.
	/// </summary>
	internal IconElement? MergePoliciesIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Deployment navigation item.
	/// </summary>
	internal IconElement? DeploymentIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Validate Policies navigation item.
	/// </summary>
	internal IconElement? ValidatePoliciesIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the GitHub Documentation navigation item.
	/// </summary>
	internal IconElement? GitHubDocsIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Microsoft Documentation navigation item.
	/// </summary>
	internal IconElement? MSFTDocsIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Logs navigation item.
	/// </summary>
	internal IconElement? LogsIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Update navigation item in the footer.
	/// </summary>
	internal IconElement? UpdateIcon { get; set => SP(ref field, value); }

	#endregion


	/// <summary>
	/// Event handler for the main Sidebar button click
	/// </summary>
	internal void SidebarButton_Click()
	{
		SidebarPaneIsOpen = !SidebarPaneIsOpen;
	}


	/// <summary>
	/// Event handler triggered when the UpdateAvailable event is raised, indicating an update is available.
	/// Updates InfoBadgeOpacity to show the InfoBadge in the UI if an update is available.
	/// </summary>
	/// <param name="sender">Sender of the event, in this case, AppUpdate class.</param>
	/// <param name="e">Boolean indicating whether an update is available.</param>
	private void OnUpdateAvailable(object sender, UpdateAvailableEventArgs e)
	{
		// Marshal back to the UI thread using the dispatcher to safely update UI-bound properties
		_ = Dispatcher.TryEnqueue(() =>
		{
			// Set InfoBadgeOpacity based on update availability: 1 to show, 0 to hide
			InfoBadgeOpacity = e.IsUpdateAvailable ? 1 : 0;
		});
	}


	/// <summary>
	/// Event handler for the Sidebar button to open the user config directory
	/// </summary>
	internal void OpenConfigDirectoryButton_Click()
	{
		_ = Process.Start(new ProcessStartInfo
		{
			FileName = GlobalVars.UserConfigDir,
			UseShellExecute = true
		});
	}


	/// <summary>
	/// Event handler for the sidebar toggle button for auto assignment
	/// </summary>
	internal void AutomaticAssignmentSidebarToggleSwitch_Toggled()
	{
		// Save the status in app settings
		App.Settings.AutomaticAssignmentSidebar = AutomaticAssignmentSidebarToggleSwitchToggledState;
	}


	/// <summary>
	/// Event handler for sidebar settings cards for auto assignment
	/// </summary>
	internal void AutomaticAssignmentSidebarSettingsCard_Click()
	{
		AutomaticAssignmentSidebarToggleSwitchToggledState = !AutomaticAssignmentSidebarToggleSwitchToggledState;

		// Save the status in app settings
		App.Settings.AutomaticAssignmentSidebar = AutomaticAssignmentSidebarToggleSwitchToggledState;
	}


	/// <summary>
	/// Method used by other methods that create base policies so they can assign the path to the sidebar after creation
	/// If the toggle switch for automatic assignment is on
	/// </summary>
	/// <param name="unsignedPolicyPath"></param>
	internal void AssignToSidebar(string unsignedPolicyPath)
	{
		_ = Dispatcher.TryEnqueue(() =>
		{
			if (AutomaticAssignmentSidebarToggleSwitchToggledState)
			{
				SidebarBasePolicyPathTextBoxText = unsignedPolicyPath;
			}
		});
	}

	/// <summary>
	/// Event handler for the hamburger/main menu button click
	/// </summary>
	internal void HamburgerMenuButton_Click()
	{
		MainNavigationIsPaneOpen = !MainNavigationIsPaneOpen;
	}

	/// <summary>
	/// Event handler for the global Icons Style change event
	/// </summary>
	/// <param name="style"></param>
	internal void OnIconsStylesChanged(string? style)
	{
		if (MainWindow.RootGridPub is null) throw new InvalidOperationException("RootGrid is null");

		// Get the current theme from the RootGrid or another element.
		ElementTheme currentTheme = MainWindow.RootGridPub.ActualTheme;

		switch (style)
		{
			case "Animated":
				{
					CreatePolicyIcon = new AnimatedIcon
					{
						Margin = new Thickness(-10, -35, -35, -35),
						Source = new Blueprint()
					};

					SystemInformationIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -6, -6, -6),
						Source = new View()
					};

					ConfigurePolicyRuleOptionsIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Configure()
					};

					SimulationIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Simulation()
					};

					if (currentTheme == ElementTheme.Dark)
					{
						AllowNewAppsIcon = new AnimatedIcon
						{
							Margin = new Thickness(0, -6, -6, -6),
							Source = new StarYellow()
						};
					}
					else
					{
						AllowNewAppsIcon = new AnimatedIcon
						{
							Margin = new Thickness(0, -6, -6, -6),
							Source = new StarBlack()
						};
					}

					CreatePolicyFromEventLogsIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Scan()
					};

					CreatePolicyFromMDEAHIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new MDE()
					};

					GetCodeIntegrityHashesIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Hash()
					};

					GetSecurePolicySettingsIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -6, -6, -6),
						Source = new Shield()
					};

					LogsIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Timeline()
					};

					GitHubDocsIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -11, -11, -11),
						Source = new GitHub()
					};

					MSFTDocsIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -9, -9, -9),
						Source = new Document()
					};

					if (currentTheme == ElementTheme.Dark)
					{
						UpdateIcon = new AnimatedIcon
						{
							Margin = new Thickness(0, -5, -5, -5),
							Source = new Heart()
						};
					}
					else
					{
						UpdateIcon = new AnimatedIcon
						{
							Margin = new Thickness(0, -25, -25, -25),
							Source = new HeartPulse()
						};
					}

					BuildNewCertificateIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Certificate()
					};

					DeploymentIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Deployment()
					};

					CreateSupplementalPolicyIcon = new AnimatedIcon
					{
						Margin = new Thickness(-5, -28, -28, -28),
						Source = new SupplementalPolicy()
					};

					MergePoliciesIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -9, -9, -9),
						Source = new Merge()
					};

					CreateDenyPolicyIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -9, -9, -9),
						Source = new Deny()
					};

					ValidatePoliciesIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -9, -9, -9),
						Source = new Validate()
					};

					ViewFileCertificatesIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -9, -9, -9),
						Source = new ViewAllCertificates()
					};

					PolicyEditorIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -11, -11, -11),
						Source = new Honeymoon()
					};

					break;
				}
			case "Windows Accent":
				{
					// Retrieve the accent brush from the current resources.
					Brush accentBrush = (Brush)Application.Current.Resources["SystemControlHighlightAccentBrush"];

					CreatePolicyIcon = new FontIcon
					{
						Glyph = "\uE83D",
						Foreground = accentBrush
					};

					SystemInformationIcon = new FontIcon
					{
						Glyph = "\uE7C1",
						Foreground = accentBrush
					};

					ConfigurePolicyRuleOptionsIcon = new FontIcon
					{
						Glyph = "\uEEA3",
						Foreground = accentBrush
					};

					SimulationIcon = new FontIcon
					{
						Glyph = "\uE835",
						Foreground = accentBrush
					};

					AllowNewAppsIcon = new FontIcon
					{
						Glyph = "\uED35",
						Foreground = accentBrush
					};

					CreatePolicyFromEventLogsIcon = new FontIcon
					{
						Glyph = "\uEA18",
						Foreground = accentBrush
					};

					CreatePolicyFromMDEAHIcon = new FontIcon
					{
						Glyph = "\uEB44",
						Foreground = accentBrush
					};

					GetCodeIntegrityHashesIcon = new FontIcon
					{
						Glyph = "\uE950",
						Foreground = accentBrush
					};

					GetSecurePolicySettingsIcon = new FontIcon
					{
						Glyph = "\uEEA3",
						Foreground = accentBrush
					};

					LogsIcon = new FontIcon
					{
						Glyph = "\uF5A0",
						Foreground = accentBrush
					};

					GitHubDocsIcon = new FontIcon
					{
						Glyph = "\uE8A5",
						Foreground = accentBrush
					};

					MSFTDocsIcon = new FontIcon
					{
						Glyph = "\uE8A5",
						Foreground = accentBrush
					};

					UpdateIcon = new FontIcon
					{
						Glyph = "\uEB52",
						Foreground = accentBrush
					};

					BuildNewCertificateIcon = new FontIcon
					{
						Glyph = "\uEB95",
						Foreground = accentBrush
					};

					DeploymentIcon = new FontIcon
					{
						Glyph = "\uF32A",
						Foreground = accentBrush
					};

					CreateSupplementalPolicyIcon = new FontIcon
					{
						Glyph = "\uE8F9",
						Foreground = accentBrush
					};

					MergePoliciesIcon = new FontIcon
					{
						Glyph = "\uEE49",
						Foreground = accentBrush
					};

					CreateDenyPolicyIcon = new FontIcon
					{
						Glyph = "\uE8D0",
						Foreground = accentBrush
					};

					ValidatePoliciesIcon = new FontIcon
					{
						Glyph = "\uED5E",
						Foreground = accentBrush
					};

					ViewFileCertificatesIcon = new FontIcon
					{
						Glyph = "\uEBD2",
						Foreground = accentBrush
					};

					PolicyEditorIcon = new FontIcon
					{
						Glyph = "\uE70F",
						Foreground = accentBrush
					};

					break;
				}
			case "Monochromatic":
			default:
				{
					CreatePolicyIcon = new FontIcon { Glyph = "\uE83D" };
					SystemInformationIcon = new FontIcon { Glyph = "\uE7C1" };
					ConfigurePolicyRuleOptionsIcon = new FontIcon { Glyph = "\uEEA3" };
					SimulationIcon = new FontIcon { Glyph = "\uE835" };
					AllowNewAppsIcon = new FontIcon { Glyph = "\uED35" };
					CreatePolicyFromEventLogsIcon = new FontIcon { Glyph = "\uEA18" };
					CreatePolicyFromMDEAHIcon = new FontIcon { Glyph = "\uEB44" };
					GetCodeIntegrityHashesIcon = new FontIcon { Glyph = "\uE950" };
					GetSecurePolicySettingsIcon = new FontIcon { Glyph = "\uEEA3" };
					LogsIcon = new FontIcon { Glyph = "\uF5A0" };
					GitHubDocsIcon = new FontIcon { Glyph = "\uE8A5" };
					MSFTDocsIcon = new FontIcon { Glyph = "\uE8A5" };
					UpdateIcon = new FontIcon { Glyph = "\uEB52" };
					BuildNewCertificateIcon = new FontIcon { Glyph = "\uEB95" };
					DeploymentIcon = new FontIcon { Glyph = "\uF32A" };
					CreateSupplementalPolicyIcon = new FontIcon { Glyph = "\uE8F9" };
					MergePoliciesIcon = new FontIcon { Glyph = "\uEE49" };
					CreateDenyPolicyIcon = new FontIcon { Glyph = "\uE8D0" };
					ValidatePoliciesIcon = new FontIcon { Glyph = "\uED5E" };
					ViewFileCertificatesIcon = new FontIcon { Glyph = "\uEBD2" };
					PolicyEditorIcon = new FontIcon { Glyph = "\uE70F" };
					break;
				}
		}
	}

	/// <summary>
	/// Event handler for the Background ComboBox selection change event in the Settings page.
	/// </summary>
	private void UpdateSystemBackDrop()
	{
		// Cast the index to the enum
		BackDropComboBoxItems selection = (BackDropComboBoxItems)BackDropComboBoxSelectedIndex;
		switch (selection)
		{
			case BackDropComboBoxItems.MicaAlt:
				SystemBackDropStyle = new MicaBackdrop { Kind = MicaKind.BaseAlt };
				break;
			case BackDropComboBoxItems.Mica:
				SystemBackDropStyle = new MicaBackdrop { Kind = MicaKind.Base };
				break;
			case BackDropComboBoxItems.Acrylic:
				SystemBackDropStyle = new DesktopAcrylicBackdrop();
				break;
			default:
				break;
		}

		// Save the selected option (using the enum's name)
		App.Settings.BackDropBackground = selection.ToString();
	}
}
