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
using System.Diagnostics;
using System.Numerics;
using AnimatedVisuals;
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.UI.Composition.SystemBackdrops;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace AppControlManager.ViewModels;

#pragma warning disable CA1812, CA1822 // an internal class that is apparently never instantiated
// It's handled by Dependency Injection so this warning is a false-positive.

/// <summary>
/// ViewModel for the MainWindow
/// </summary>
internal sealed partial class MainWindowVM : ViewModelBase
{

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
		// Subscribe to the UpdateAvailable event to handle updates to the InfoBadge visibility
		AppUpdate.UpdateAvailable += OnUpdateAvailable!;

		// Set the status of the sidebar toggle switch for auto assignment by getting it from saved app settings
		AutomaticAssignmentSidebarToggleSwitchToggledState = App.Settings.AutomaticAssignmentSidebar;

		if (App.IsElevated)
			// Get the user configuration for unsigned policy path and fill in the text box for sidebar
			SidebarBasePolicyPathTextBoxText = UserConfiguration.Get().UnsignedPolicyPath;

		// Apply the BackDrop when the ViewModel is instantiated
		UpdateSystemBackDrop();
	}


	#region UI-Bound Properties

	/// <summary>
	/// The visibility of the Update page in the main NavigationView.
	/// Only make it visible if the app is installed from the GitHub source.
	/// </summary>	
	internal Visibility UpdatePageNavItemVisibility = App.PackageSource is 0 ? Visibility.Visible : Visibility.Collapsed;

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
	/// The text in the SidebarBasePolicyPathTextBox
	/// </summary>
	internal string? SidebarBasePolicyPathTextBoxText { get; set => SP(ref field, value); }

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
		App.Settings.BackDropBackground = selection.ToString();
	}
}
