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
using AnimatedVisuals;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using AppControlManager.WindowComponents;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace HardenWindowsSecurity.ViewModels;

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
		typeof(Pages.FileReputation)
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
			titles: [GlobalVars.GetStr("UpdateNavItem/Content")],
			pages: [typeof(Pages.UpdatePage)]
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
	}

	// This collection is bound to the BreadCrumbBar's ItemsSource in the XAML
	// initially adding the default page that loads when the app is loaded to the collection
	internal readonly ObservableCollection<Crumb> Breadcrumbs = App.IsElevated ? [new Crumb(GlobalVars.GetStr("ProtectNavigationViewItem/Content"), typeof(Pages.Protect))] :
		[new Crumb(GlobalVars.GetStr("NonAdminCommandsNavItem/Content"), typeof(Pages.Protects.NonAdmin))];

	/// <summary>
	/// Dictionary of all the main pages in the app, used for the main navigation.
	/// Keys are the Navigation Item tags (non-localized) and values are the page types.
	/// </summary>
	internal readonly Dictionary<string, Type> NavigationPageToItemContentMap = new()
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
		// { "Certificates", typeof(Pages.Protects.CertificateChecking) },
		// { "CountryIPBlocking", typeof(Pages.Protects.CountryIPBlocking) },
		{ "NonAdmin", typeof(Pages.Protects.NonAdmin) },
		{ "FileReputation", typeof(Pages.FileReputation) },
		{ "InstalledAppsManagement", typeof(Pages.InstalledAppsManagement) }
	};


	/// <summary>
	/// Dictionary of all the pages in the app, used for the search bar.
	/// Keys are page header contents which are localized and values are page types.
	/// </summary>
	internal readonly Dictionary<string, Type> NavigationPageToItemContentMapForSearch = [];

	internal void RebuildNavigationPageToItemContentMapForSearch()
	{
		NavigationPageToItemContentMapForSearch.Clear();

		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("ProtectNavigationViewItem/Content")] = typeof(Pages.Protect);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("LogsNavItem/Content")] = typeof(Pages.Logs);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("UpdateNavItem/Content")] = typeof(Pages.UpdatePage);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("GitHubDocsNavItem/Content")] = typeof(Pages.GitHubDocumentation);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("SettingsNavItem/Content")] = typeof(Pages.Settings);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("GroupPolicyEditorNavItem/Content")] = typeof(Pages.GroupPolicyEditor);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("MicrosoftDefenderNavItem/Content")] = typeof(Pages.Protects.MicrosoftDefender);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("ASRNavItem/Content")] = typeof(Pages.Protects.ASR);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("BitLockerNavItem/Content")] = typeof(Pages.Protects.BitLocker);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("TLSSecurityNavItem/Content")] = typeof(Pages.Protects.TLS);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("LockScreenNavItem/Content")] = typeof(Pages.Protects.LockScreen);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("UACNavItem/Content")] = typeof(Pages.Protects.UAC);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("DeviceGuardNavItem/Content")] = typeof(Pages.Protects.DeviceGuard);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("WindowsFirewallNavItem/Content")] = typeof(Pages.Protects.WindowsFirewall);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("OptionalWindowsFeaturesNavItem/Content")] = typeof(Pages.Protects.OptionalWindowsFeatures);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("WindowsNetworkingNavItem/Content")] = typeof(Pages.Protects.WindowsNetworking);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("MiscellaneousNavItem/Content")] = typeof(Pages.Protects.MiscellaneousConfigs);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("WindowsUpdateNavItem/Content")] = typeof(Pages.Protects.WindowsUpdate);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("EdgeBrowserNavItem/Content")] = typeof(Pages.Protects.Edge);
		// NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("CertificatesNavItem/Content")] = typeof(Pages.Protects.CertificateChecking);
		//NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("CountryIPBlockingNavItem/Content")] = typeof(Pages.Protects.CountryIPBlocking);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("NonAdminCommandsNavItem/Content")] = typeof(Pages.Protects.NonAdmin);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("FileReputationNavItem/Content")] = typeof(Pages.FileReputation);
		NavigationPageToItemContentMapForSearch[GlobalVars.GetStr("InstalledAppsManagementNavItem/Content")] = typeof(Pages.InstalledAppsManagement);
	}

	/// <summary>
	/// Constructor initializes the ViewModel and subscribes to various events, sets initial values of some variables.
	/// </summary>
	internal MainWindowVM()
	{
		RebuildBreadcrumbMappings();
		RebuildNavigationPageToItemContentMapForSearch();

		// Apply the BackDrop when the ViewModel is instantiated
		UpdateSystemBackDrop();
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
					break;
				}
		}
	}
}
