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

using System.Collections.Generic;
using AppControlManager.AppSettings;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.Globalization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Dispatching;

#if HARDEN_SYSTEM_SECURITY
using AppControlManager.ViewModels;
using HardenSystemSecurity.WindowComponents;
namespace HardenSystemSecurity.ViewModels;
#endif

#if APP_CONTROL_MANAGER
using System.Collections.ObjectModel;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.WindowComponents;
using System.Threading.Tasks;
using System.Linq;
namespace AppControlManager.ViewModels;
#endif

internal sealed partial class SettingsVM : ViewModelBase
{

	private NavigationService Nav { get; } = ViewModelProvider.NavigationService;

	internal SettingsVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		// Populate the ComboBoxes' ItemsSource collections
		LoadLanguages();

#if APP_CONTROL_MANAGER
		FontFamilies = Microsoft.Graphics.Canvas.Text.CanvasTextFormat.GetSystemFontFamilies().ToList();
		FontFamilies.Sort(); // Sort alphabetically
#endif

	}

	private void LoadLanguages()
	{
		LanguageOptions.Add(new LanguageOption("English", "ms-appx:///Assets/CountryFlags/usa-240.png"));
		LanguageOptions.Add(new LanguageOption("עברית", "ms-appx:///Assets/CountryFlags/israel-240.png"));
		LanguageOptions.Add(new LanguageOption("Ελληνικά", "ms-appx:///Assets/CountryFlags/greece-240.png"));
		LanguageOptions.Add(new LanguageOption("हिंदी", "ms-appx:///Assets/CountryFlags/india-240.png"));
		LanguageOptions.Add(new LanguageOption("Polski", "ms-appx:///Assets/CountryFlags/poland-240.png"));
		LanguageOptions.Add(new LanguageOption("العربية", "ms-appx:///Assets/CountryFlags/saudi-arabia-240.png"));
		LanguageOptions.Add(new LanguageOption("Español", "ms-appx:///Assets/CountryFlags/mexico-240.png"));
		LanguageOptions.Add(new LanguageOption("മലയാളം", "ms-appx:///Assets/CountryFlags/india-240.png"));
		LanguageOptions.Add(new LanguageOption("Deutsch", "ms-appx:///Assets/CountryFlags/germany-240.png"));
	}

	/// <summary>
	/// The main InfoBar for this VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	private MainWindowVM ViewModelMainWindow { get; } = ViewModelProvider.MainWindowVM;

	internal bool UIFlowDirectionToggleSwitch
	{
		get; set
		{
			if (SP(ref field, value))
			{
				App.Settings.ApplicationGlobalFlowDirection = field ? "LeftToRight" : "RightToLeft";
			}
		}
	} = string.Equals(App.Settings.ApplicationGlobalFlowDirection, "LeftToRight", StringComparison.OrdinalIgnoreCase);

	private enum NavViewLocation
	{
		Left = 0,
		Top = 1
	}

	internal int NavigationMenuLocationComboBoxSelectedIndex
	{
		get; set
		{
			if (SP(ref field, value))
			{
				string x = ((NavViewLocation)field).ToString();

				// Raise the global OnNavigationViewLocationChanged event
				NavigationViewLocationManager.OnNavigationViewLocationChanged(x);

				App.Settings.NavViewPaneDisplayMode = x;
			}
		}
	}

	private static readonly Dictionary<string, int> SupportedLanguages = new(StringComparer.OrdinalIgnoreCase)
	{
		{ "en-US", 0 },
		{ "he", 1 },
		{ "el", 2 },
		{ "hi", 3 },
		{ "pl", 4 },
		{ "ar", 5 },
		{ "es", 6 },
		{ "ml", 7 },
		{ "de", 8 }
	};

	private static readonly string[] SupportedLanguagesReverse = [
		 "en-US",
		 "he",
		 "el",
		 "hi",
		 "pl",
		 "ar",
		 "es",
		 "ml",
		 "de"
	];

	internal int LanguageComboBoxSelectedIndex
	{
		get; set
		{
			if (SP(ref field, value))
			{
				string x = SupportedLanguagesReverse[field];

				ApplicationLanguages.PrimaryLanguageOverride = x;
				App.Settings.ApplicationGlobalLanguage = x;

				// Get reference to the MainWindow and refresh the localized content
				if (App.MainWindow is MainWindow mainWindow)
				{
					mainWindow.RefreshLocalizedContent();
				}

				// Refresh this page.
				Nav.RefreshSettingsPage();
			}
		}
	} = SupportedLanguages.TryGetValue(App.Settings.ApplicationGlobalLanguage, out int x) ? x : 0;

	/// <summary>
	/// Language Selection ComboBox ItemsSource
	/// </summary>
	internal readonly List<LanguageOption> LanguageOptions = [];

	private static readonly Dictionary<string, int> AppThemes = new(StringComparer.OrdinalIgnoreCase)
	{
		{"Use System Setting", 0 },
		{"Dark", 1 },
		{"Light", 2 }
	};
	private static readonly string[] AppThemesReverse = [
		"Use System Setting",
		"Dark" ,
		"Light"
	];

	internal int AppThemeComboBoxSelectedIndex
	{
		get; set
		{
			if (SP(ref field, value))
			{
				// Raise the global BackgroundChanged event
				AppThemeManager.OnAppThemeChanged(AppThemesReverse[field]);

				App.Settings.AppTheme = AppThemesReverse[field];
			}
		}
	} = AppThemes.TryGetValue(App.Settings.AppTheme, out int x) ? x : 0;

	private static readonly Dictionary<string, int> IconsStyles = new(StringComparer.OrdinalIgnoreCase)
	{
		{"Animated", 0 },
		{"Windows Accent", 1 },
		{"Monochromatic" , 2 }
	};
	private static readonly Dictionary<int, string> IconsStylesReverse = new()
	{
		{ 0, "Animated" },
		{ 1, "Windows Accent"},
		{ 2, "Monochromatic" }
	};

	internal int IconsStylesComboBoxSelectedIndex
	{
		get; set
		{
			if (SP(ref field, value))
			{
				if (IconsStylesReverse.TryGetValue(field, out string? x))
				{
					ViewModelMainWindow.OnIconsStylesChanged(x);

					App.Settings.IconsStyle = x;
				}
				else
				{
					Logger.Write($"Unknown Icons Style Index: {field}");
				}
			}
		}
	} = IconsStyles.TryGetValue(App.Settings.IconsStyle, out int x) ? x : 2;

	/// <summary>
	/// Set the version in the settings card to the current app version
	/// </summary>
	internal readonly string VersionTextBlockText = $"Version {App.currentAppVersion}";

	/// <summary>
	/// Set the year for the copyright section
	/// </summary>
	internal readonly string CopyRightSettingsExpanderDescription = $"© {DateTime.Now.Year}. All rights reserved.";

	/// <summary>
	/// Executed when flow direction toggle is changed.
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	internal void FlowDirectionToggleSwitch_Toggled(object sender, RoutedEventArgs e)
	{
		MainWindowVM.SetCaptionButtonsFlowDirection(((ToggleSwitch)sender).IsOn ? FlowDirection.LeftToRight : FlowDirection.RightToLeft);

		// Needs to run via Dispatcher, otherwise the 1st double-click on the UI elements register as pass-through, meaning they will resize the window as if we clicked on an empty area on the TitleBar.
		_ = Dispatcher.TryEnqueue(DispatcherQueuePriority.Normal, () =>
		{
			// Get reference to the MainWindow and refresh the localized content
			if (App.MainWindow is MainWindow mainWindow)
			{
				mainWindow.SetRegionsForCustomTitleBar();
			}
		});
	}

#if APP_CONTROL_MANAGER

	/// <summary>
	/// The list of all Font Families for the ComboBox ItemsSource.
	/// </summary>
	internal readonly List<string> FontFamilies = [];

	/// <summary>
	/// Opens a file picker for Code Integrity Schema path.
	/// </summary>
	internal void BrowseForCISchemaPath()
	{
		string? path = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XSDFilePickerFilter);

		if (path is not null)
			App.Settings.CiPolicySchemaPath = path;
	}

	internal string? SignedPolicyPathTextBox { get; set => SP(ref field, value); }
	internal string? UnsignedPolicyPathTextBox { get; set => SP(ref field, value); }
	internal string? CertificatePathTextBox { get; set => SP(ref field, value); }

	internal bool MainUserConfigurationsSettingsExpanderIsExpanded { get; set => SP(ref field, value); }

	// When the button to get the user configurations on the settings card is pressed
	internal void GetConfigurationButton()
	{
		UserConfiguration userConfig = UserConfiguration.Get();

		SignedPolicyPathTextBox = userConfig.SignedPolicyPath ?? string.Empty;
		UnsignedPolicyPathTextBox = userConfig.UnsignedPolicyPath ?? string.Empty;
		CertCNsAutoSuggestBoxText = userConfig.CertificateCommonName ?? string.Empty;
		CertificatePathTextBox = userConfig.CertificatePath ?? string.Empty;

		// Expand the settings expander to make the configurations visible
		MainUserConfigurationsSettingsExpanderIsExpanded = true;
	}

	#region Signed Policy Path

	internal void EditButton_SignedPolicyPath_Click()
	{
		_ = UserConfiguration.Set(SignedPolicyPath: SignedPolicyPathTextBox);
	}

	internal void ClearButton_SignedPolicyPath_Click()
	{
		UserConfiguration.Remove(SignedPolicyPath: true);
		SignedPolicyPathTextBox = null;
	}

	internal void BrowseButton_SignedPolicyPath_Click()
	{
		SignedPolicyPathTextBox = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);
	}

	#endregion

	#region Unsigned Policy Path

	internal void EditButton_UnsignedPolicyPath_Click()
	{
		_ = UserConfiguration.Set(UnsignedPolicyPath: UnsignedPolicyPathTextBox);
	}

	internal void ClearButton_UnsignedPolicyPath_Click()
	{
		UserConfiguration.Remove(UnsignedPolicyPath: true);
		UnsignedPolicyPathTextBox = null;
	}

	internal void BrowseButton_UnsignedPolicyPath_Click()
	{
		UnsignedPolicyPathTextBox = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);
	}

	#endregion

	#region Certificate Common Name

	// To store the selectable Certificate common names
	internal readonly ObservableCollection<string> CertCommonNames = [];
	internal readonly List<string> CertCommonNamesList = [];

	internal string? CertCNsAutoSuggestBoxText { get; set => SPT(ref field, value); }

	internal bool CertCNAutoSuggestBoxIsSuggestionListOpen { get; set => SP(ref field, value); }

	// If user never clicked on the Refresh button and directly clicks inside of the AutoSuggestBox instead,
	// The certs must be retrieved and displayed. If Refresh button is first used, it won't be retrieved again when clicked inside of the AutoSuggestBox.
	private bool _InitialFetchComplete;

	/// <summary>
	/// Get all of the common names of the certificates in the user/my certificate stores
	/// And add them to the observable collection that is the source of the AutoSuggestBox
	/// </summary>
	private async Task FetchLatestCertificateCNsPrivate()
	{
		try
		{
			_InitialFetchComplete = true;

			IEnumerable<string> certCNs = await Task.Run(CertCNFetcher.GetCertCNs);

			CertCommonNames.Clear();
			CertCommonNamesList.Clear();

			foreach (string item in certCNs)
			{
				CertCommonNames.Add(item);
				CertCommonNamesList.Add(item);
			}

			CertCNAutoSuggestBoxIsSuggestionListOpen = true;
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// For the Refresh button that retrieves the latest certificate CNs
	/// </summary>
	internal async void FetchLatestCertificateCNs()
	{
		try
		{
			await FetchLatestCertificateCNsPrivate();
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Handles the GotFocus event for the Certificate Common Name auto-suggest box. It opens the suggestion list when the
	/// box gains focus. Without this, the suggestion list would not open when the box is clicked, user would have to type something first.
	/// </summary>
	internal async void CertificateCommonNameAutoSuggestBox_GotFocus()
	{
		try
		{
			if (!_InitialFetchComplete)
			{
				_InitialFetchComplete = true;

				await FetchLatestCertificateCNsPrivate();
			}

			CertCNAutoSuggestBoxIsSuggestionListOpen = true;
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
	}

	/// <summary>
	/// Event handler for AutoSuggestBox
	/// </summary>
	internal void CertificateCNAutoSuggestBox_TextChanged()
	{
		if (CertCNsAutoSuggestBoxText is null)
			return;

		// Filter menu items based on the search query
		List<string> suggestions = [.. CertCommonNamesList.Where(name => name.Contains(CertCNsAutoSuggestBoxText, StringComparison.OrdinalIgnoreCase))];

		CertCommonNames.Clear();

		foreach (string item in suggestions)
		{
			CertCommonNames.Add(item);
		}
	}

	internal void EditButton_CertificateCommonName_Click()
	{
		_ = UserConfiguration.Set(CertificateCommonName: CertCNsAutoSuggestBoxText);
	}

	internal void ClearButton_CertificateCommonName_Click()
	{
		UserConfiguration.Remove(CertificateCommonName: true);
		CertCNsAutoSuggestBoxText = null;
	}

	#endregion

	#region Certificate Path

	internal void EditButton_CertificatePath_Click()
	{
		_ = UserConfiguration.Set(CertificatePath: CertificatePathTextBox);
	}

	internal void ClearButton_CertificatePath_Click()
	{
		UserConfiguration.Remove(CertificatePath: true);
		CertificatePathTextBox = null;
	}

	internal void BrowseButton_CertificatePath_Click()
	{
		CertificatePathTextBox = FileDialogHelper.ShowFilePickerDialog(GlobalVars.CertificatePickerFilter);
	}

	#endregion

#endif

	#region App Border Color Customization
	internal void StartRainbowAnimation() => CustomUIElements.AppWindowBorderCustomization.StartAnimatedFrame();
	internal void StopRainbowAnimation() => CustomUIElements.AppWindowBorderCustomization.StopAnimatedFrame();
	internal void ColorPicker_ColorChanged(ColorPicker sender, ColorChangedEventArgs args)
	{
		R = args.NewColor.R;
		G = args.NewColor.G;
		B = args.NewColor.B;
	}
	private byte R;
	private byte G;
	private byte B;

	internal void StartCustomColorAnimation() => CustomUIElements.AppWindowBorderCustomization.SetBorderColor(R, G, B);
	internal void StopCustomColorAnimation() => CustomUIElements.AppWindowBorderCustomization.ResetBorderColor();

	#endregion

}
