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
using System.ComponentModel;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.CompilerServices;
using AnimatedVisuals;
using AppControlManager.AppSettings;
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1822

#pragma warning disable CA1812 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.

/// <summary>
/// ViewModel for the MainWindow
/// </summary>
internal sealed partial class MainWindowVM : INotifyPropertyChanged
{
	// DispatcherQueue provides access to the UI thread dispatcher, allowing for UI updates from background threads.
	private readonly DispatcherQueue Dispatch;

	// Event triggered when a bound property value changes, allowing the UI to reactively update.
	public event PropertyChangedEventHandler? PropertyChanged;

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
	public MainWindowVM()
	{
		Dispatch = DispatcherQueue.GetForCurrentThread();

		// Subscribe to the UpdateAvailable event to handle updates to the InfoBadge visibility
		AppUpdate.UpdateAvailable += OnUpdateAvailable!;

		// Set the status of the sidebar toggle switch for auto assignment by getting it from saved app settings
		AutomaticAssignmentSidebarToggleSwitchToggledState = AppSettingsCls.TryGetSetting<bool?>(AppSettingsCls.SettingKeys.AutomaticAssignmentSidebar) ?? true;

		if (App.IsElevated)
			// Get the user configuration for unsigned policy path and fill in the text box for sidebar
			SidebarBasePolicyPathTextBoxText = UserConfiguration.Get().UnsignedPolicyPath;

		// Enables Security catalogs caching by default. If the value doesn't exist in the settings then it will be null and assigned to true. If it's false it will remain false.
		bool? CacheSecurityCatalogResultsStatus = AppSettingsCls.TryGetSetting<bool?>(AppSettingsCls.SettingKeys.CacheSecurityCatalogsScanResults);
		AppSettingsCls.SaveSetting(AppSettingsCls.SettingKeys.CacheSecurityCatalogsScanResults, CacheSecurityCatalogResultsStatus ?? true);

		// Apply the BackDrop when the ViewModel is instantiated
		UpdateSystemBackDrop();
	}



	#region UI-Bound Properties

	/// <summary>
	/// Sets the initial value of the back drop. if it's null, Mica Alt will be used.
	/// </summary>
	private int _BackDropComboBoxSelectedIndex = (int)Enum.Parse<BackDropComboBoxItems>((AppSettingsCls.GetSetting<string>(AppSettingsCls.SettingKeys.BackDropBackground) ?? "MicaAlt"));
	internal int BackDropComboBoxSelectedIndex
	{
		get => _BackDropComboBoxSelectedIndex;
		set
		{
			// Update the value and the system backdrop
			if (SetProperty(_BackDropComboBoxSelectedIndex, value, newValue => _BackDropComboBoxSelectedIndex = newValue))
			{
				UpdateSystemBackDrop();
			}
		}
	}

	/// <summary>
	/// Defines a private property for the system backdrop style, initialized with a MicaBackdrop of kind BaseAlt.
	/// </summary>
	private SystemBackdrop _SystemBackDropStyle = new MicaBackdrop { Kind = MicaKind.BaseAlt };
	internal SystemBackdrop SystemBackDropStyle
	{
		get => _SystemBackDropStyle;
		set => SetProperty(_SystemBackDropStyle, value, newValue => _SystemBackDropStyle = newValue);
	}

	/// <summary>
	/// Backing field for InfoBadgeOpacity, which controls the visibility of the InfoBadge in the UI.
	/// https://learn.microsoft.com/en-us/windows/apps/design/controls/info-badge
	/// Opacity level of the InfoBadge icon in the UI. When set to 1, the badge is visible.
	/// When set to 0, the badge is hidden.
	/// </summary>
	private double _infoBadgeOpacity;
	internal double InfoBadgeOpacity
	{
		get => _infoBadgeOpacity;
		set => SetProperty(_infoBadgeOpacity, value, newValue => _infoBadgeOpacity = newValue);
	}

	/// <summary>
	/// The state of the OpenConfigDirectoryButton button which is on the Sidebar
	/// </summary>
	private bool _OpenConfigDirectoryButtonState = App.IsElevated;
	internal bool OpenConfigDirectoryButtonState
	{
		get => _OpenConfigDirectoryButtonState;
		set => SetProperty(_OpenConfigDirectoryButtonState, value, newValue => _OpenConfigDirectoryButtonState = newValue);
	}

	/// <summary>
	/// Whether the sidebar pane is open or closed
	/// </summary>
	private bool _SidebarPaneIsOpen;
	internal bool SidebarPaneIsOpen
	{
		get => _SidebarPaneIsOpen;
		set => SetProperty(_SidebarPaneIsOpen, value, newValue => _SidebarPaneIsOpen = newValue);
	}

	/// <summary>
	/// Indicates whether the automatic assignment sidebar toggle switch is in a toggled state. It stores a boolean value.
	/// </summary>
	private bool _AutomaticAssignmentSidebarToggleSwitchToggledState = true;
	internal bool AutomaticAssignmentSidebarToggleSwitchToggledState
	{
		get => _AutomaticAssignmentSidebarToggleSwitchToggledState;
		set => SetProperty(_AutomaticAssignmentSidebarToggleSwitchToggledState, value, newValue => _AutomaticAssignmentSidebarToggleSwitchToggledState = newValue);
	}

	/// <summary>
	/// The text in the SidebarBasePolicyPathTextBox
	/// </summary>
	private string? _SidebarBasePolicyPathTextBoxText;
	internal string? SidebarBasePolicyPathTextBoxText
	{
		get => _SidebarBasePolicyPathTextBoxText;
		set => SetProperty(_SidebarBasePolicyPathTextBoxText, value, newValue => _SidebarBasePolicyPathTextBoxText = newValue);
	}

	/// <summary>
	///  Adjust the elevation of the border to achieve the shadow effect
	/// </summary>
	private Vector3 _BorderTranslation = new(0, 0, 500);
	internal Vector3 BorderTranslation
	{
		get => _BorderTranslation;
		set => SetProperty(_BorderTranslation, value, newValue => _BorderTranslation = newValue);
	}

	/// <summary>
	/// Whether the main NavigationView's pane is open or closed
	/// </summary>
	private bool _MainNavigationIsPaneOpen = true;
	internal bool MainNavigationIsPaneOpen
	{
		get => _MainNavigationIsPaneOpen;
		set => SetProperty(_MainNavigationIsPaneOpen, value, newValue => _MainNavigationIsPaneOpen = newValue);
	}

	/// <summary>
	/// The width of the TitleColumn in the main window's custom title bar
	/// </summary>
	private GridLength _TitleColumnWidth = GridLength.Auto;
	internal GridLength TitleColumnWidth
	{
		get => _TitleColumnWidth;
		set => SetProperty(_TitleColumnWidth, value, newValue => _TitleColumnWidth = newValue);
	}




	// Navigation Icon Properties

	private IconElement? _CreatePolicyIcon;
	/// <summary>
	/// Icon for the Create Policy navigation item.
	/// </summary>
	internal IconElement? CreatePolicyIcon
	{
		get => _CreatePolicyIcon;
		set => SetProperty(_CreatePolicyIcon, value, newValue => _CreatePolicyIcon = newValue);
	}

	private IconElement? _CreateSupplementalPolicyIcon;
	/// <summary>
	/// Icon for the Create Supplemental Policy navigation item.
	/// </summary>
	internal IconElement? CreateSupplementalPolicyIcon
	{
		get => _CreateSupplementalPolicyIcon;
		set => SetProperty(_CreateSupplementalPolicyIcon, value, newValue => _CreateSupplementalPolicyIcon = newValue);
	}

	private IconElement? _CreateDenyPolicyIcon;
	/// <summary>
	/// Icon for the Create Deny Policy navigation item.
	/// </summary>
	internal IconElement? CreateDenyPolicyIcon
	{
		get => _CreateDenyPolicyIcon;
		set => SetProperty(_CreateDenyPolicyIcon, value, newValue => _CreateDenyPolicyIcon = newValue);
	}

	private IconElement? _BuildNewCertificateIcon;
	/// <summary>
	/// Icon for the Build New Certificate navigation item.
	/// </summary>
	internal IconElement? BuildNewCertificateIcon
	{
		get => _BuildNewCertificateIcon;
		set => SetProperty(_BuildNewCertificateIcon, value, newValue => _BuildNewCertificateIcon = newValue);
	}

	private IconElement? _ViewFileCertificatesIcon;
	/// <summary>
	/// Icon for the View File Certificates navigation item.
	/// </summary>
	internal IconElement? ViewFileCertificatesIcon
	{
		get => _ViewFileCertificatesIcon;
		set => SetProperty(_ViewFileCertificatesIcon, value, newValue => _ViewFileCertificatesIcon = newValue);
	}

	private IconElement? _CreatePolicyFromEventLogsIcon;
	/// <summary>
	/// Icon for the Create Policy from Event Logs navigation item.
	/// </summary>
	internal IconElement? CreatePolicyFromEventLogsIcon
	{
		get => _CreatePolicyFromEventLogsIcon;
		set => SetProperty(_CreatePolicyFromEventLogsIcon, value, newValue => _CreatePolicyFromEventLogsIcon = newValue);
	}

	private IconElement? _CreatePolicyFromMDEAHIcon;
	/// <summary>
	/// Icon for the MDE Advanced Hunting navigation item.
	/// </summary>
	internal IconElement? CreatePolicyFromMDEAHIcon
	{
		get => _CreatePolicyFromMDEAHIcon;
		set => SetProperty(_CreatePolicyFromMDEAHIcon, value, newValue => _CreatePolicyFromMDEAHIcon = newValue);
	}

	private IconElement? _AllowNewAppsIcon;
	/// <summary>
	/// Icon for the Allow New Apps navigation item.
	/// </summary>
	internal IconElement? AllowNewAppsIcon
	{
		get => _AllowNewAppsIcon;
		set => SetProperty(_AllowNewAppsIcon, value, newValue => _AllowNewAppsIcon = newValue);
	}

	private IconElement? _PolicyEditorIcon;
	/// <summary>
	/// Icon for the Policy Editor navigation item.
	/// </summary>
	internal IconElement? PolicyEditorIcon
	{
		get => _PolicyEditorIcon;
		set => SetProperty(_PolicyEditorIcon, value, newValue => _PolicyEditorIcon = newValue);
	}

	private IconElement? _SimulationIcon;
	/// <summary>
	/// Icon for the Simulation navigation item.
	/// </summary>
	internal IconElement? SimulationIcon
	{
		get => _SimulationIcon;
		set => SetProperty(_SimulationIcon, value, newValue => _SimulationIcon = newValue);
	}

	private IconElement? _SystemInformationIcon;
	/// <summary>
	/// Icon for the System Information navigation item.
	/// </summary>
	internal IconElement? SystemInformationIcon
	{
		get => _SystemInformationIcon;
		set => SetProperty(_SystemInformationIcon, value, newValue => _SystemInformationIcon = newValue);
	}

	private IconElement? _GetCodeIntegrityHashesIcon;
	/// <summary>
	/// Icon for the Get Code Integrity Hashes navigation item.
	/// </summary>
	internal IconElement? GetCodeIntegrityHashesIcon
	{
		get => _GetCodeIntegrityHashesIcon;
		set => SetProperty(_GetCodeIntegrityHashesIcon, value, newValue => _GetCodeIntegrityHashesIcon = newValue);
	}

	private IconElement? _GetSecurePolicySettingsIcon;
	/// <summary>
	/// Icon for the Get Secure Policy Settings navigation item.
	/// </summary>
	internal IconElement? GetSecurePolicySettingsIcon
	{
		get => _GetSecurePolicySettingsIcon;
		set => SetProperty(_GetSecurePolicySettingsIcon, value, newValue => _GetSecurePolicySettingsIcon = newValue);
	}

	private IconElement? _ConfigurePolicyRuleOptionsIcon;
	/// <summary>
	/// Icon for the Configure Policy Rule Options navigation item.
	/// </summary>
	internal IconElement? ConfigurePolicyRuleOptionsIcon
	{
		get => _ConfigurePolicyRuleOptionsIcon;
		set => SetProperty(_ConfigurePolicyRuleOptionsIcon, value, newValue => _ConfigurePolicyRuleOptionsIcon = newValue);
	}

	private IconElement? _MergePoliciesIcon;
	/// <summary>
	/// Icon for the Merge Policies navigation item.
	/// </summary>
	internal IconElement? MergePoliciesIcon
	{
		get => _MergePoliciesIcon;
		set => SetProperty(_MergePoliciesIcon, value, newValue => _MergePoliciesIcon = newValue);
	}

	private IconElement? _DeploymentIcon;
	/// <summary>
	/// Icon for the Deployment navigation item.
	/// </summary>
	internal IconElement? DeploymentIcon
	{
		get => _DeploymentIcon;
		set => SetProperty(_DeploymentIcon, value, newValue => _DeploymentIcon = newValue);
	}

	private IconElement? _ValidatePoliciesIcon;
	/// <summary>
	/// Icon for the Validate Policies navigation item.
	/// </summary>
	internal IconElement? ValidatePoliciesIcon
	{
		get => _ValidatePoliciesIcon;
		set => SetProperty(_ValidatePoliciesIcon, value, newValue => _ValidatePoliciesIcon = newValue);
	}

	private IconElement? _GitHubDocsIcon;
	/// <summary>
	/// Icon for the GitHub Documentation navigation item.
	/// </summary>
	internal IconElement? GitHubDocsIcon
	{
		get => _GitHubDocsIcon;
		set => SetProperty(_GitHubDocsIcon, value, newValue => _GitHubDocsIcon = newValue);
	}

	private IconElement? _MSFTDocsIcon;
	/// <summary>
	/// Icon for the Microsoft Documentation navigation item.
	/// </summary>
	internal IconElement? MSFTDocsIcon
	{
		get => _MSFTDocsIcon;
		set => SetProperty(_MSFTDocsIcon, value, newValue => _MSFTDocsIcon = newValue);
	}

	private IconElement? _LogsIcon;
	/// <summary>
	/// Icon for the Logs navigation item.
	/// </summary>
	internal IconElement? LogsIcon
	{
		get => _LogsIcon;
		set => SetProperty(_LogsIcon, value, newValue => _LogsIcon = newValue);
	}

	private IconElement? _UpdateIcon;
	/// <summary>
	/// Icon for the Update navigation item in the footer.
	/// </summary>
	internal IconElement? UpdateIcon
	{
		get => _UpdateIcon;
		set => SetProperty(_UpdateIcon, value, newValue => _UpdateIcon = newValue);
	}

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
		_ = Dispatch.TryEnqueue(() =>
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
		AppSettingsCls.SaveSetting(AppSettingsCls.SettingKeys.AutomaticAssignmentSidebar, AutomaticAssignmentSidebarToggleSwitchToggledState);
	}


	/// <summary>
	/// Event handler for sidebar settings cards for auto assignment
	/// </summary>
	internal void AutomaticAssignmentSidebarSettingsCard_Click()
	{
		AutomaticAssignmentSidebarToggleSwitchToggledState = !AutomaticAssignmentSidebarToggleSwitchToggledState;

		// Save the status in app settings
		AppSettingsCls.SaveSetting(AppSettingsCls.SettingKeys.AutomaticAssignmentSidebar, AutomaticAssignmentSidebarToggleSwitchToggledState);
	}


	/// <summary>
	/// Method used by other methods that create base policies so they can assign the path to the sidebar after creation
	/// If the toggle switch for automatic assignment is on
	/// </summary>
	/// <param name="unsignedPolicyPath"></param>
	internal void AssignToSidebar(string unsignedPolicyPath)
	{
		_ = Dispatch.TryEnqueue(() =>
		{
			if (AutomaticAssignmentSidebarToggleSwitchToggledState)
			{
				SidebarBasePolicyPathTextBoxText = unsignedPolicyPath;
			}
		});
	}


	/// <summary>
	/// Event handler for the sidebar base policy browse button
	/// </summary>
	internal void SidebarBasePolicyBrowseButton_Click()
	{

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			SidebarBasePolicyPathTextBoxText = selectedFile;

			// Show the animated icons on the currently visible page
			MainWindow.Instance.AffectPagesAnimatedIconsVisibilities(true);
		}
	}


	/// <summary>
	/// Event handler for the clear button in the sidebar for unsigned policy path
	/// </summary>
	internal void SidebarBasePolicyClearButton_Click()
	{
		// Clear the Sidebar text box
		SidebarBasePolicyPathTextBoxText = null;

		// Hide the animated icons on the currently visible page
		MainWindow.Instance.AffectPagesAnimatedIconsVisibilities(false);
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
		// Get the current theme from your RootGrid or another element.
		ElementTheme currentTheme = MainWindow.Instance.RootGridPub.ActualTheme;

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
		AppSettingsCls.SaveSetting(AppSettingsCls.SettingKeys.BackDropBackground, selection.ToString());
	}


	/// <summary>
	/// Sets the property and raises the PropertyChanged event if the value has changed.
	/// This also prevents infinite loops where a property raises OnPropertyChanged which could trigger an update in the UI, and the UI might call set again, leading to an infinite loop.
	/// </summary>
	/// <typeparam name="T"></typeparam>
	/// <param name="currentValue"></param>
	/// <param name="newValue"></param>
	/// <param name="setter"></param>
	/// <param name="propertyName"></param>
	/// <returns></returns>
	private bool SetProperty<T>(T currentValue, T newValue, Action<T> setter, [CallerMemberName] string? propertyName = null)
	{
		if (EqualityComparer<T>.Default.Equals(currentValue, newValue))
			return false;
		setter(newValue);
		OnPropertyChanged(propertyName);
		return true;
	}

	private void OnPropertyChanged(string? propertyName)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}
}
