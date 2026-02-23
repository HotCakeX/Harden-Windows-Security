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

using System.Collections.Frozen;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Threading.Tasks;
using AnimatedVisuals;
using AppControlManager.ViewModels;
using AppControlManager.WindowComponents;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace HardenSystemSecurity.ViewModels;

/// <summary>
/// ViewModel for the MainWindow
/// </summary>
internal sealed partial class MainWindowVM : ViewModelBase
{
	/// <summary>
	/// Pages that are allowed to run when running without Administrator privileges
	/// </summary>
	internal List<Type> UnelevatedPages = [
		typeof(Pages.Logs),
		typeof(Pages.Settings),
		typeof(Pages.UpdatePage),
		typeof(Pages.GitHubDocumentation),
		typeof(Pages.GroupPolicyEditor),
		typeof(Pages.Protects.NonAdmin),
		typeof(Pages.FileReputation),
		typeof(AppControlManager.Pages.Home),
		typeof(Pages.Intune),
		typeof(AppControlManager.Pages.IntuneDeploymentDetails),
		typeof(Pages.Extras.DuplicatePhotoFinder),
		typeof(Pages.Extras.EXIFManager)
		];


	internal void RebuildBreadcrumbMappings()
	{
		breadCrumbMappingsV2.Clear();

		breadCrumbMappingsV2[typeof(Pages.Protect)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("ProtectNavigationViewItem/Content")],
			pages: [typeof(Pages.Protect)]
		);

		breadCrumbMappingsV2[typeof(Pages.Logs)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("LogsNavItem/Content")],
			pages: [typeof(Pages.Logs)]
		);

		breadCrumbMappingsV2[typeof(Pages.UpdatePage)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("UpdateNavItem/Content"), GlobalVars.GetStr("UpdatePageCustomMSIXPath")],
			pages: [typeof(Pages.UpdatePage), typeof(Pages.UpdatePageCustomMSIXPath)]
		);

		breadCrumbMappingsV2[typeof(Pages.UpdatePageCustomMSIXPath)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("UpdateNavItem/Content"), GlobalVars.GetStr("UpdatePageCustomMSIXPath")],
			pages: [typeof(Pages.UpdatePage), typeof(Pages.UpdatePageCustomMSIXPath)]
		);

		breadCrumbMappingsV2[typeof(Pages.GitHubDocumentation)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("GitHubDocsNavItem/Content")],
			pages: [typeof(Pages.GitHubDocumentation)]
		);

		breadCrumbMappingsV2[typeof(Pages.Settings)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("SettingsNavItem/Content")],
			pages: [typeof(Pages.Settings)]
		);

		breadCrumbMappingsV2[typeof(Pages.GroupPolicyEditor)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("GroupPolicyEditorNavItem/Content")],
			pages: [typeof(Pages.GroupPolicyEditor)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.MicrosoftDefender)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("MicrosoftDefenderNavItem/Content")],
			pages: [typeof(Pages.Protects.MicrosoftDefender)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.ASR)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("ASRNavItem/Content")],
			pages: [typeof(Pages.Protects.ASR)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.BitLocker)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("BitLockerNavItem/Content")],
			pages: [typeof(Pages.Protects.BitLocker)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.TLS)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("TLSSecurityNavItem/Content")],
			pages: [typeof(Pages.Protects.TLS)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.LockScreen)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("LockScreenNavItem/Content")],
			pages: [typeof(Pages.Protects.LockScreen)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.UAC)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("UACNavItem/Content")],
			pages: [typeof(Pages.Protects.UAC)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.DeviceGuard)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("DeviceGuardNavItem/Content")],
			pages: [typeof(Pages.Protects.DeviceGuard)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.WindowsFirewall)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("WindowsFirewallNavItem/Content")],
			pages: [typeof(Pages.Protects.WindowsFirewall)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.OptionalWindowsFeatures)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("OptionalWindowsFeaturesNavItem/Content")],
			pages: [typeof(Pages.Protects.OptionalWindowsFeatures)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.WindowsNetworking)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("WindowsNetworkingNavItem/Content")],
			pages: [typeof(Pages.Protects.WindowsNetworking)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.MiscellaneousConfigs)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("MiscellaneousNavItem/Content")],
			pages: [typeof(Pages.Protects.MiscellaneousConfigs)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.WindowsUpdate)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("WindowsUpdateNavItem/Content")],
			pages: [typeof(Pages.Protects.WindowsUpdate)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.Edge)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("EdgeBrowserNavItem/Content")],
			pages: [typeof(Pages.Protects.Edge)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.CertificateChecking)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("CertificatesNavItem/Content")],
			pages: [typeof(Pages.Protects.CertificateChecking)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.NonAdmin)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("NonAdminCommandsNavItem/Content")],
			pages: [typeof(Pages.Protects.NonAdmin)]
		);

		breadCrumbMappingsV2[typeof(Pages.FileReputation)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("FileReputationNavItem/Content")],
			pages: [typeof(Pages.FileReputation)]
		);

		breadCrumbMappingsV2[typeof(Pages.InstalledAppsManagement)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("InstalledAppsManagementNavItem/Content")],
			pages: [typeof(Pages.InstalledAppsManagement)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.MicrosoftSecurityBaseline)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("MicrosoftSecurityBaselineNavItem/Content")],
			pages: [typeof(Pages.Protects.MicrosoftSecurityBaseline)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.Microsoft365AppsSecurityBaseline)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("Microsoft365AppsSecurityBaselineNavItem/Content")],
			pages: [typeof(Pages.Protects.Microsoft365AppsSecurityBaseline)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.MicrosoftBaseLinesOverrides)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("MicrosoftBaseLinesOverridesNavItem/Content")],
			pages: [typeof(Pages.Protects.MicrosoftBaseLinesOverrides)]
		);

		breadCrumbMappingsV2[typeof(Pages.Protects.CountryIPBlocking)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("CountryIPBlockingNavItem/Content")],
			pages: [typeof(Pages.Protects.CountryIPBlocking)]
		);

		breadCrumbMappingsV2[typeof(Pages.AuditPolicies)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("AuditPoliciesNavItem/Content")],
			pages: [typeof(Pages.AuditPolicies)]
		);

		breadCrumbMappingsV2[typeof(AppControlManager.Pages.Home)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("HomeNavItem/Content")],
			pages: [typeof(AppControlManager.Pages.Home)]
		);

		breadCrumbMappingsV2[typeof(HardenSystemSecurity.Pages.CryptographicBillOfMaterials)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("CBOMNavItem/Content")],
			pages: [typeof(HardenSystemSecurity.Pages.CryptographicBillOfMaterials)]
		);

		breadCrumbMappingsV2[typeof(HardenSystemSecurity.Pages.Intune)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("IntuneNavItem/Content"), GlobalVars.GetStr("IntuneDeploymentDetailsNavItem/Content")],
			pages: [typeof(HardenSystemSecurity.Pages.Intune), typeof(AppControlManager.Pages.IntuneDeploymentDetails)]
		);

		breadCrumbMappingsV2[typeof(AppControlManager.Pages.IntuneDeploymentDetails)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("IntuneNavItem/Content"), GlobalVars.GetStr("IntuneDeploymentDetailsNavItem/Content")],
			pages: [typeof(HardenSystemSecurity.Pages.Intune), typeof(AppControlManager.Pages.IntuneDeploymentDetails)]
		);

		breadCrumbMappingsV2[typeof(HardenSystemSecurity.Pages.CSP)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("CSPNavItem/Content")],
			pages: [typeof(HardenSystemSecurity.Pages.CSP)]
		);

		breadCrumbMappingsV2[typeof(HardenSystemSecurity.Pages.Extras.DuplicatePhotoFinder)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("DuplicatePhotosFinderNavigationViewItem/Content")],
			pages: [typeof(HardenSystemSecurity.Pages.Extras.DuplicatePhotoFinder)]
		);

		breadCrumbMappingsV2[typeof(HardenSystemSecurity.Pages.Extras.EXIFManager)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("EXIFManagerNavigationViewItem/Content")],
			pages: [typeof(HardenSystemSecurity.Pages.Extras.EXIFManager)]
		);

		breadCrumbMappingsV2[typeof(HardenSystemSecurity.Pages.ServiceManager)] = new PageTitleMap
		(
			titles: [GlobalVars.GetStr("ServiceManagerNavItem/Content")],
			pages: [typeof(HardenSystemSecurity.Pages.ServiceManager)]
		);
	}

	// This collection is bound to the BreadCrumbBar's ItemsSource in the XAML
	// initially adding the default page that loads when the app is loaded to the collection
	internal readonly ObservableCollection<Crumb> Breadcrumbs = [new Crumb(GlobalVars.GetStr("HomeNavItem/Content"), typeof(AppControlManager.Pages.Home))];

	/// <summary>
	/// Dictionary of all the main pages in the app, used for the main navigation.
	/// Keys are the Navigation Item tags (non-localized) and values are the page types.
	/// </summary>
	internal readonly FrozenDictionary<string, Type> NavigationPageToItemContentMap = new Dictionary<string, Type>(StringComparer.OrdinalIgnoreCase)
	{
		{ "Protect", typeof(Pages.Protect) },
		{ "Logs", typeof(Pages.Logs) },
		{ "GitHubDocs", typeof(Pages.GitHubDocumentation) },
		{ "Settings", typeof(Pages.Settings) },
		{ "Update", typeof(Pages.UpdatePage) },
		{ "GroupPolicyEditor", typeof(Pages.GroupPolicyEditor) },
		{ "MicrosoftDefender", typeof(Pages.Protects.MicrosoftDefender) },
		{ "ASR", typeof(Pages.Protects.ASR) },
		{ "BitLocker", typeof(Pages.Protects.BitLocker) },
		{ "TLS", typeof(Pages.Protects.TLS) },
		{ "LockScreen", typeof(Pages.Protects.LockScreen) },
		{ "UAC", typeof(Pages.Protects.UAC) },
		{ "DeviceGuard", typeof(Pages.Protects.DeviceGuard) },
		{ "Firewall", typeof(Pages.Protects.WindowsFirewall) },
		{ "OptionalWindowsFeatures", typeof(Pages.Protects.OptionalWindowsFeatures) },
		{ "WinNetworking", typeof(Pages.Protects.WindowsNetworking) },
		{ "Miscellaneous", typeof(Pages.Protects.MiscellaneousConfigs) },
		{ "WinUpdate", typeof(Pages.Protects.WindowsUpdate) },
		{ "Edge", typeof(Pages.Protects.Edge) },
		{ "Certificates", typeof(Pages.Protects.CertificateChecking) },
		{ "CountryIPBlocking", typeof(Pages.Protects.CountryIPBlocking) },
		{ "NonAdmin", typeof(Pages.Protects.NonAdmin) },
		{ "FileReputation", typeof(Pages.FileReputation) },
		{ "InstalledAppsManagement", typeof(Pages.InstalledAppsManagement) },
		{ "MicrosoftSecurityBaseline", typeof(Pages.Protects.MicrosoftSecurityBaseline) },
		{ "Microsoft365AppsSecurityBaseline", typeof(Pages.Protects.Microsoft365AppsSecurityBaseline) },
		{ "MicrosoftBaseLinesOverrides", typeof(Pages.Protects.MicrosoftBaseLinesOverrides) },
		{ "AuditPolicies", typeof(Pages.AuditPolicies) },
		{ "Home", typeof(AppControlManager.Pages.Home) },
		{ "CBOM", typeof(Pages.CryptographicBillOfMaterials) },
		{ "Intune", typeof(Pages.Intune) },
		{ "CSP", typeof(Pages.CSP) },
		{ "DuplicatePhotosFinder", typeof(Pages.Extras.DuplicatePhotoFinder) },
		{ "EXIFManager", typeof(Pages.Extras.EXIFManager) },
		{ "ServiceManager", typeof(Pages.ServiceManager) }
	}.ToFrozenDictionary(StringComparer.OrdinalIgnoreCase);

	/// <summary>
	/// Dictionary of all the pages in the app, used for the search bar.
	/// Keys are page header contents which are localized and values are page types.
	/// </summary>
	internal static readonly Dictionary<Type, string> NavigationPageToItemContentMapForSearch = [];

	internal void RebuildNavigationPageToItemContentMapForSearch()
	{
		NavigationPageToItemContentMapForSearch.Clear();

		NavigationPageToItemContentMapForSearch[typeof(Pages.Protect)] = GlobalVars.GetStr("ProtectNavigationViewItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Logs)] = GlobalVars.GetStr("LogsNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.UpdatePage)] = GlobalVars.GetStr("UpdateNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.GitHubDocumentation)] = GlobalVars.GetStr("GitHubDocsNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Settings)] = GlobalVars.GetStr("SettingsNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.GroupPolicyEditor)] = GlobalVars.GetStr("GroupPolicyEditorNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.MicrosoftDefender)] = GlobalVars.GetStr("MicrosoftDefenderNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.ASR)] = GlobalVars.GetStr("ASRNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.BitLocker)] = GlobalVars.GetStr("BitLockerNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.TLS)] = GlobalVars.GetStr("TLSSecurityNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.LockScreen)] = GlobalVars.GetStr("LockScreenNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.UAC)] = GlobalVars.GetStr("UACNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.DeviceGuard)] = GlobalVars.GetStr("DeviceGuardNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.WindowsFirewall)] = GlobalVars.GetStr("WindowsFirewallNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.OptionalWindowsFeatures)] = GlobalVars.GetStr("OptionalWindowsFeaturesNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.WindowsNetworking)] = GlobalVars.GetStr("WindowsNetworkingNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.MiscellaneousConfigs)] = GlobalVars.GetStr("MiscellaneousNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.WindowsUpdate)] = GlobalVars.GetStr("WindowsUpdateNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.Edge)] = GlobalVars.GetStr("EdgeBrowserNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.CertificateChecking)] = GlobalVars.GetStr("CertificatesNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.CountryIPBlocking)] = GlobalVars.GetStr("CountryIPBlockingNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.NonAdmin)] = GlobalVars.GetStr("NonAdminCommandsNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.FileReputation)] = GlobalVars.GetStr("FileReputationNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.InstalledAppsManagement)] = GlobalVars.GetStr("InstalledAppsManagementNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.MicrosoftSecurityBaseline)] = GlobalVars.GetStr("MicrosoftSecurityBaselineNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.Microsoft365AppsSecurityBaseline)] = GlobalVars.GetStr("Microsoft365AppsSecurityBaselineNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Protects.MicrosoftBaseLinesOverrides)] = GlobalVars.GetStr("MicrosoftBaseLinesOverridesNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.AuditPolicies)] = GlobalVars.GetStr("AuditPoliciesNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(AppControlManager.Pages.Home)] = GlobalVars.GetStr("HomeNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.CryptographicBillOfMaterials)] = GlobalVars.GetStr("CBOMNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Intune)] = GlobalVars.GetStr("IntuneNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.CSP)] = GlobalVars.GetStr("CSPNavItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.UpdatePageCustomMSIXPath)] = GlobalVars.GetStr("UpdatePageCustomMSIXPath");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Extras.DuplicatePhotoFinder)] = GlobalVars.GetStr("DuplicatePhotosFinderNavigationViewItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.Extras.EXIFManager)] = GlobalVars.GetStr("EXIFManagerNavigationViewItem/Content");
		NavigationPageToItemContentMapForSearch[typeof(Pages.ServiceManager)] = GlobalVars.GetStr("ServiceManagerNavItem/Content");
	}

	/// <summary>
	/// Constructor initializes the ViewModel and subscribes to various events, sets initial values of some variables.
	/// </summary>
	internal MainWindowVM()
	{
		RebuildBreadcrumbMappings();
		RebuildNavigationPageToItemContentMapForSearch();

		// Build mappings for pages, MUnit-based or not, so their titles can participate in the unified search experience
		foreach (KeyValuePair<Type, string> kvp in NavigationPageToItemContentMapForSearch)
		{
			Traverse.MUnitCatalog.RegisterExtraPage(kvp.Key, kvp.Value);
		}

		// Subscribe to the UpdateAvailable event to handle updates to the InfoBadge visibility
		Others.AppUpdate.UpdateAvailable += OnUpdateAvailable!;

		// Apply the BackDrop when the ViewModel is instantiated
		UpdateSystemBackDrop();

		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);
	}

	#region UI-Bound Properties

	// Navigation Icon Properties

	/// <summary>
	/// Icon for the Create Policy navigation item.
	/// </summary>
	internal IconElement? ProtectIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the GitHub Documentation navigation item.
	/// </summary>
	internal IconElement? GitHubDocsIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Logs navigation item.
	/// </summary>
	internal IconElement? LogsIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Update navigation item in the footer.
	/// </summary>
	internal IconElement? UpdateIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Group Policy Editor navigation item.
	/// </summary>
	internal IconElement? GroupPolicyEditorIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the File Reputation navigation item.
	/// </summary>
	internal IconElement? FileReputationIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the File Installed Apps Management item.
	/// </summary>
	internal IconElement? InstalledAppsManagementIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Audit Policies item.
	/// </summary>
	internal IconElement? AuditPoliciesIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Home navigation item.
	/// </summary>
	internal IconElement? HomeIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the CBOM navigation item.
	/// </summary>
	internal IconElement? CBOMIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Intune navigation item.
	/// </summary>
	internal IconElement? IntuneIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Duplicate Photos Finder navigation item.
	/// </summary>
	internal IconElement? DuplicatePhotosFinderIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Extras section.
	/// </summary>
	internal IconElement? ExtrasIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the EXIF Manager navigation item.
	/// </summary>
	internal IconElement? EXIFManagerIcon { get; set => SP(ref field, value); }

	/// <summary>
	/// Icon for the Service Manager navigation item.
	/// </summary>
	internal IconElement? ServiceManagerIcon { get; set => SP(ref field, value); }

	#endregion

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
					ProtectIcon = new AnimatedIcon
					{
						Margin = new Thickness(-10, -10, -10, -10),
						Source = new Safety()
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

					UpdateIcon = currentTheme == ElementTheme.Dark
						? new AnimatedIcon
						{
							Margin = new Thickness(0, -5, -5, -5),
							Source = new Heart()
						}
						: new AnimatedIcon
						{
							Margin = new Thickness(0, -25, -25, -25),
							Source = new HeartPulse()
						};

					GroupPolicyEditorIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -35, -35, -35),
						Source = new Star()
					};

					FileReputationIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -11, -11, -11),
						Source = new Kawaii()
					};

					InstalledAppsManagementIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new Toolbox()
					};

					AuditPoliciesIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -8, -8, -8),
						Source = new ChocolateBar()
					};

					HomeIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -7, -7, -7),
						Source = new Home()
					};

					CBOMIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, 20, -20, -20),
						Source = new CBOM()
					};

					IntuneIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -25, -25, -25),
						Source = new Intune()
					};

					DuplicatePhotosFinderIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -6, -6, -6),
						Source = new Picture()
					};

					ExtrasIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -6, -6, -6),
						Source = new Gift()
					};

					EXIFManagerIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -6, -6, -6),
						Source = new Paint_roller()
					};

					ServiceManagerIcon = new AnimatedIcon
					{
						Margin = new Thickness(0, -6, -6, -6),
						Source = new Service()
					};

					break;
				}
			case "Windows Accent":
				{
					// Retrieve the accent brush from the current resources.
					Brush accentBrush = (Brush)Application.Current.Resources["SystemControlHighlightAccentBrush"];

					ProtectIcon = new FontIcon
					{
						Glyph = "\uE83D",
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

					UpdateIcon = new FontIcon
					{
						Glyph = "\uEB52",
						Foreground = accentBrush
					};

					GroupPolicyEditorIcon = new FontIcon
					{
						Glyph = "\uE70F",
						Foreground = accentBrush
					};

					FileReputationIcon = new FontIcon
					{
						Glyph = "\uEA91",
						Foreground = accentBrush
					};

					InstalledAppsManagementIcon = new FontIcon
					{
						Glyph = "\uE71D",
						Foreground = accentBrush
					};

					AuditPoliciesIcon = new FontIcon
					{
						Glyph = "\uE9D5",
						Foreground = accentBrush
					};

					HomeIcon = new FontIcon
					{
						Glyph = "\uE80F",
						Foreground = accentBrush
					};

					CBOMIcon = new FontIcon
					{
						Glyph = "\uE705",
						Foreground = accentBrush
					};

					IntuneIcon = new FontIcon
					{
						Glyph = "\uE753",
						Foreground = accentBrush
					};

					DuplicatePhotosFinderIcon = new FontIcon
					{
						Glyph = "\uF584",
						Foreground = accentBrush
					};

					ExtrasIcon = new FontIcon
					{
						Glyph = "\uF6BA",
						Foreground = accentBrush
					};

					EXIFManagerIcon = new FontIcon
					{
						Glyph = "\uEC5A",
						Foreground = accentBrush
					};

					ServiceManagerIcon = new FontIcon
					{
						Glyph = "\uEC7A",
						Foreground = accentBrush
					};

					break;
				}
			case "Monochromatic":
			default:
				{
					ProtectIcon = new FontIcon { Glyph = "\uE83D" };
					LogsIcon = new FontIcon { Glyph = "\uF5A0" };
					GitHubDocsIcon = new FontIcon { Glyph = "\uE8A5" };
					UpdateIcon = new FontIcon { Glyph = "\uEB52" };
					GroupPolicyEditorIcon = new FontIcon { Glyph = "\uE70F" };
					FileReputationIcon = new FontIcon { Glyph = "\uEA91" };
					InstalledAppsManagementIcon = new FontIcon { Glyph = "\uE71D" };
					AuditPoliciesIcon = new FontIcon { Glyph = "\uE9D5" };
					HomeIcon = new FontIcon { Glyph = "\uE80F" };
					CBOMIcon = new FontIcon { Glyph = "\uE705" };
					IntuneIcon = new FontIcon { Glyph = "\uE753" };
					DuplicatePhotosFinderIcon = new FontIcon { Glyph = "\uF584" };
					ExtrasIcon = new FontIcon { Glyph = "\uF6BA" };
					EXIFManagerIcon = new FontIcon { Glyph = "\uEC5A" };
					ServiceManagerIcon = new FontIcon { Glyph = "\uEC7A" };
					break;
				}
		}
	}

	/// <summary>
	/// The main InfoBar for the Sidebar.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;
	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	/// <summary>
	/// Whether the button for configuring nested virtualizations on Sidebar is enabled.
	/// </summary>
	internal bool IsHyperVNestedVirtualizationButtonEnabled { get; set => SP(ref field, value); } = GlobalVars.IsElevated;

	internal async void EnableNestedVirtualizationForVMs() => await SetNestedVirtualizationForVMs(true);
	internal async void DisableNestedVirtualizationForVMs() => await SetNestedVirtualizationForVMs(false);

	/// <summary>
	/// Configures nested virtualization for all Hyper-V VMs on the system.
	/// </summary>
	internal async Task SetNestedVirtualizationForVMs(bool enable)
	{
		try
		{
			IsHyperVNestedVirtualizationButtonEnabled = false;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("ConfiguringNestedVirtualizationForAllHyperVVMs"));

			await Task.Run(() =>
			{
				string command = enable
					? "Virtualization ExposeVirtualizationExtensions --all --enable true"
					: "Virtualization ExposeVirtualizationExtensions --all --enable false";

				Logger.Write(QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, command));
			});

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("NestedVirtSuccessFormat"), enable ? GlobalVars.GetStr("EnabledLowercase") : GlobalVars.GetStr("DisabledLowercase")));
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			MainInfoBar.WriteWarning(GlobalVars.GetStr("ErrorConfiguringNestedVirtualizationForAllHyperVVMsSeeLogs"));
		}
		finally
		{
			IsHyperVNestedVirtualizationButtonEnabled = true;
		}
	}

	/// <summary>
	/// Whether the button for configuring Power Plan on Sidebar is enabled.
	/// </summary>
	internal bool IsPowerPlanConfigButtonEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Enables and activates the Ultimate Performance power plan on the system.
	/// </summary>
	internal async void EnableUltimatePerformancePowerPlan()
	{
		try
		{
			IsPowerPlanConfigButtonEnabled = false;

			await Task.Run(CommonCore.Power.PowerPlan.EnableUltimateScheme);

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("UltimatePerfPlanEnabledAndActive"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			IsPowerPlanConfigButtonEnabled = true;
		}
	}

	/// <summary>
	/// Disables and removes the Ultimate Performance power plan from the system.
	/// </summary>
	internal async void DisableUltimatePerformancePowerPlan()
	{
		try
		{
			IsPowerPlanConfigButtonEnabled = false;

			await Task.Run(CommonCore.Power.PowerPlan.DeleteUltimateSchemes);

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("UltimatePerfPlanDisabledAndRemoved"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			IsPowerPlanConfigButtonEnabled = true;
		}
	}

	internal bool IsCheckForAllAppUpdatesButtonEnabled { get; set => SP(ref field, value); } = GlobalVars.IsElevated;

	/// <summary>
	/// Event handler for the UI button.
	/// </summary>
	internal async void CheckForAllAppUpdates() => await CheckForAllAppUpdates_Internal();

	/// <summary>
	/// Called by the UI's event handler and when the app is started via CLI/ScheduledTask
	/// </summary>
	/// <returns></returns>
	internal async Task CheckForAllAppUpdates_Internal()
	{
		try
		{
			IsCheckForAllAppUpdatesButtonEnabled = false;

			MainInfoBar.WriteInfo(GlobalVars.GetStr("CheckingForMicrosoftStoreAppUpdates"));

			await Task.Run(() =>
			{
				MainInfoBar.WriteInfo(QuantumRelayHSS.Client.RunCommand(GlobalVars.ComManagerProcessPath, "do root\\cimv2\\mdm\\dmmap MDM_EnterpriseModernAppManagement_AppManagement01 UpdateScanMethod"));
			});

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessfullyCheckedForMicrosoftStoreAppUpdates"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			IsCheckForAllAppUpdatesButtonEnabled = true;
		}
	}

	/// <summary>
	/// Whether the button for generating a battery report is enabled.
	/// Generating a battery report doesn't require administrator privileges.
	/// </summary>
	internal bool IsGenerateBatteryReportButtonEnabled { get; set => SP(ref field, value); } = true;

	/// <summary>
	/// Generates a battery report and saves it to a user-selected location.
	/// </summary>
	internal async void GenerateBatteryReport()
	{
		try
		{
			IsGenerateBatteryReportButtonEnabled = false;

			string? savePath = FileDialogHelper.ShowSaveFileDialog("HTML Files|*.html", "Battery Life Report.html");

			if (savePath is null)
			{
				MainInfoBar.WriteWarning("Battery report generation cancelled.");
				return;
			}

			// Ensure the file path ends with .html
			if (!savePath.EndsWith(".html", StringComparison.OrdinalIgnoreCase))
			{
				savePath += ".html";
			}

			MainInfoBar.WriteInfo("Generating battery report...");

			await Task.Run(() =>
			{
				_ = ProcessStarter.RunCommand("powercfg.exe", $"/batteryreport /output \"{savePath}\"");
			});

			MainInfoBar.WriteSuccess($"Battery report successfully generated at {savePath}");
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			IsGenerateBatteryReportButtonEnabled = true;
		}
	}

}
