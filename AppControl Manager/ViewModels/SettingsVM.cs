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
using System.Threading.Tasks;
using Windows.ApplicationModel;
using Windows.Foundation;
using Windows.UI.Shell;
using Windows.UI.StartScreen;
using Microsoft.UI.Xaml.Controls;
using Microsoft.Windows.Globalization;
using Microsoft.UI.Xaml;
using Microsoft.UI.Dispatching;
using CommonCore.AppSettings;
using Microsoft.Windows.AppNotifications;
using Microsoft.UI.Xaml.Controls.Primitives;
using System.Linq;
using Windows.ApplicationModel.Core;

#if HARDEN_SYSTEM_SECURITY
using HardenSystemSecurity.WindowComponents;
namespace HardenSystemSecurity.ViewModels;
#endif

#if APP_CONTROL_MANAGER
using System.Collections.ObjectModel;
using CommonCore.IntelGathering;
using AppControlManager.Main;
using AppControlManager.WindowComponents;
using System.Runtime.InteropServices;
using CommonCore.IncrementalCollection;
namespace AppControlManager.ViewModels;
#endif

internal sealed partial class SettingsVM : ViewModelBase
{
	private const string UkrainianLanguageToken = "uk";
	private const string UkrainianLanguageResourceId = "uk-UA";
	private const string PersianLanguageToken = "fa";
	private const string PersianLanguageResourceId = "fa-IR";
	private const string ItalianLanguageToken = "it";
	private const string ItalianLanguageResourceId = "it-IT";
	private const string MandarinChineseLanguageToken = "zh";
	private const string MandarinChineseLanguageResourceId = "zh-CN";
	private const string IndonesianLanguageToken = "id";
	private const string IndonesianLanguageResourceId = "id-ID";
	private const string ThaiLanguageToken = "th";
	private const string ThaiLanguageResourceId = "th-TH";
	private const string LanguageAddonsResourceId = "ExtraLanguagesPack1";
	private static readonly bool ExtraLanguagesPack1Installed = GetLanguageAddonsPackage() is not null;
	private bool _suppressExtraLanguagesPack1ToggleSwitchToggled;

	private void SetExtraLanguagesPack1ToggleSwitchIsOn(ToggleSwitch toggleSwitch, bool isOn)
	{
		_suppressExtraLanguagesPack1ToggleSwitchToggled = true;

		try
		{
			toggleSwitch.IsOn = isOn;
		}
		finally
		{
			_suppressExtraLanguagesPack1ToggleSwitchToggled = false;
		}
	}

	internal void ExtraLanguagesPack1ToggleSwitch_Loaded(object sender, Microsoft.UI.Xaml.RoutedEventArgs e)
	{
		if (sender is ToggleSwitch toggleSwitch)
		{
			// Synchronize the startup UI state without invoking the add/remove workflow.
			SetExtraLanguagesPack1ToggleSwitchIsOn(toggleSwitch, ExtraLanguagesPack1Installed);
		}
	}

	internal SettingsVM()
	{
		// Populate the ComboBoxes' ItemsSource collections
		LoadLanguages();

		FontFamilies = Microsoft.Graphics.Canvas.Text.CanvasTextFormat.GetSystemFontFamilies().ToList();
		FontFamilies.Sort(); // Sort alphabetically
	}

	private void LoadLanguages()
	{
		LanguageOptions.Add(new("English", "ms-appx:///Assets/CountryFlags/usa-240.png"));
		LanguageOptions.Add(new("עברית", "ms-appx:///Assets/CountryFlags/israel-240.png"));
		LanguageOptions.Add(new("Ελληνικά", "ms-appx:///Assets/CountryFlags/greece-240.png"));
		LanguageOptions.Add(new("हिंदी", "ms-appx:///Assets/CountryFlags/india-240.png"));
		LanguageOptions.Add(new("Polski", "ms-appx:///Assets/CountryFlags/poland-240.png"));
		LanguageOptions.Add(new("العربية", "ms-appx:///Assets/CountryFlags/saudi-arabia-240.png"));
		LanguageOptions.Add(new("Español", "ms-appx:///Assets/CountryFlags/mexico-240.png"));
		LanguageOptions.Add(new("മലയാളം", "ms-appx:///Assets/CountryFlags/india-240.png"));
		LanguageOptions.Add(new("Deutsch", "ms-appx:///Assets/CountryFlags/germany-240.png"));
		LanguageOptions.Add(new("Français", "ms-appx:///Assets/CountryFlags/france-240.png"));
		LanguageOptions.Add(new("日本語", "ms-appx:///Assets/CountryFlags/japan-96.png"));
		if (ExtraLanguagesPack1Installed)
		{
			LanguageOptions.Add(new("Українська", "ms-appx:///Assets/CountryFlags/ukraine-240.png"));
			LanguageOptions.Add(new("فارسی", "ms-appx:///Assets/CountryFlags/iran-240.png"));
			LanguageOptions.Add(new("Italiano", "ms-appx:///Assets/CountryFlags/italy-240.png"));
			LanguageOptions.Add(new("中文（普通话）", "ms-appx:///Assets/CountryFlags/china-240.png"));
			LanguageOptions.Add(new("Bahasa Indonesia", "ms-appx:///Assets/CountryFlags/indonesia-240.png"));
			LanguageOptions.Add(new("ไทย", "ms-appx:///Assets/CountryFlags/thailand-240.png"));
		}
	}

	/// <summary>
	/// The main InfoBar for this VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar = new();

	internal bool UIFlowDirectionToggleSwitch
	{
		get; set
		{
			if (SP(ref field, value))
			{
				Atlas.Settings.ApplicationGlobalFlowDirection = field ? "LeftToRight" : "RightToLeft";
			}
		}
	} = string.Equals(Atlas.Settings.ApplicationGlobalFlowDirection, "LeftToRight", StringComparison.OrdinalIgnoreCase);

	internal enum NavViewLocation
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

				Atlas.Settings.NavViewPaneDisplayMode = x;
			}
		}
	}

	internal static readonly Dictionary<string, int> SupportedLanguages = CreateSupportedLanguages();

	private static Dictionary<string, int> CreateSupportedLanguages()
	{
		Dictionary<string, int> languages = new(StringComparer.OrdinalIgnoreCase)
		{
			{ "en-US", 0 },
			{ "he", 1 },
			{ "el", 2 },
			{ "hi", 3 },
			{ "pl", 4 },
			{ "ar", 5 },
			{ "es", 6 },
			{ "ml", 7 },
			{ "de", 8 },
			{ "fr", 9 },
			{ "ja", 10 }
		};
		if (ExtraLanguagesPack1Installed)
		{
			languages.Add(UkrainianLanguageToken, 11);
			languages.Add(PersianLanguageToken, 12);
			languages.Add(ItalianLanguageToken, 13);
			languages.Add(MandarinChineseLanguageToken, 14);
			languages.Add(IndonesianLanguageToken, 15);
			languages.Add(ThaiLanguageToken, 16);
		}
		return languages;
	}

	internal static readonly string[] SupportedLanguagesReverse = CreateSupportedLanguagesReverse();

	private static string[] CreateSupportedLanguagesReverse()
	{
		List<string> languages =
		[
			"en-US",
			"he",
			"el",
			"hi",
			"pl",
			"ar",
			"es",
			"ml",
			"de",
			"fr",
			"ja"
		];
		if (ExtraLanguagesPack1Installed)
		{
			languages.Add(UkrainianLanguageToken);
			languages.Add(PersianLanguageToken);
			languages.Add(ItalianLanguageToken);
			languages.Add(MandarinChineseLanguageToken);
			languages.Add(IndonesianLanguageToken);
			languages.Add(ThaiLanguageToken);
		}
		return [.. languages];
	}

	private static bool IsLanguageAddonResource(string language) =>
		string.Equals(language, UkrainianLanguageToken, StringComparison.OrdinalIgnoreCase) ||
		string.Equals(language, UkrainianLanguageResourceId, StringComparison.OrdinalIgnoreCase) ||
		string.Equals(language, PersianLanguageToken, StringComparison.OrdinalIgnoreCase) ||
		string.Equals(language, PersianLanguageResourceId, StringComparison.OrdinalIgnoreCase) ||
		string.Equals(language, ItalianLanguageToken, StringComparison.OrdinalIgnoreCase) ||
		string.Equals(language, ItalianLanguageResourceId, StringComparison.OrdinalIgnoreCase) ||
		string.Equals(language, MandarinChineseLanguageToken, StringComparison.OrdinalIgnoreCase) ||
		string.Equals(language, MandarinChineseLanguageResourceId, StringComparison.OrdinalIgnoreCase) ||
		string.Equals(language, IndonesianLanguageToken, StringComparison.OrdinalIgnoreCase) ||
		string.Equals(language, IndonesianLanguageResourceId, StringComparison.OrdinalIgnoreCase) ||
		string.Equals(language, ThaiLanguageToken, StringComparison.OrdinalIgnoreCase) ||
		string.Equals(language, ThaiLanguageResourceId, StringComparison.OrdinalIgnoreCase);

	private static bool IsUnavailableLanguageAddonResource(string language) => IsLanguageAddonResource(language) && !ExtraLanguagesPack1Installed;

	private static Package? GetLanguageAddonsPackage() => Package.Current.Dependencies.FirstOrDefault(package => string.Equals(package.Id.ResourceId, LanguageAddonsResourceId, StringComparison.OrdinalIgnoreCase));

	/// <summary>
	/// Runs very early at app startup to detect and set the app's language.
	/// </summary>
	internal static void SetLanguageOnStartup()
	{
		try
		{
			// If a language has already been assigned then use it.
			if (!string.IsNullOrEmpty(Atlas.Settings.ApplicationGlobalLanguage))
			{
				// If the language saved in the settings belongs to one of those included in Resource Package, and that resource package is not currently installed, then fall back to en-US
				if (IsUnavailableLanguageAddonResource(Atlas.Settings.ApplicationGlobalLanguage))
				{
					ApplicationLanguages.PrimaryLanguageOverride = "en-US";
					Atlas.Settings.ApplicationGlobalLanguage = "en-US";
					return;
				}

				// Set the language of the application to the user's preferred language
				ApplicationLanguages.PrimaryLanguageOverride = Atlas.Settings.ApplicationGlobalLanguage;

				return;
			}

			// Get the language(s) that user has added to the system.
			IReadOnlyList<string> systemLanguages = ApplicationLanguages.Languages;

			Logger.Write($"Detected system languages: {string.Join(", ", systemLanguages)}");

			// The first item in the list is the user's primary language or the first language added to the system.
			foreach (string language in systemLanguages)
			{
				// See if the same exact language is supported by the app.
				if (SupportedLanguages.ContainsKey(language))
				{
					// Skip if the language was supported but it is in a resource package that is currently not installed.
					if (IsUnavailableLanguageAddonResource(language))
					{
						continue;
					}

					// Set the app's language
					ApplicationLanguages.PrimaryLanguageOverride = language;

					// Save the configuration to the app's settings.
					Atlas.Settings.ApplicationGlobalLanguage = language;

					return;
				}

				int separatorIndex = language.IndexOf('-', StringComparison.OrdinalIgnoreCase);
				if (separatorIndex > 0)
				{
					string neutralLanguage = language[..separatorIndex];

					if (SupportedLanguages.ContainsKey(neutralLanguage))
					{
						// If the current system language partially matches one of the languages that exists in the Resource package that is currently not installed then skip it.
						if (IsUnavailableLanguageAddonResource(neutralLanguage))
						{
							continue;
						}
						// Set the app's language
						ApplicationLanguages.PrimaryLanguageOverride = neutralLanguage;

						// Save the configuration to the app's settings.
						Atlas.Settings.ApplicationGlobalLanguage = neutralLanguage;

						return;
					}
				}
			}

			// Set the app's language to en-US if we couldn't determine the language from the system.
			ApplicationLanguages.PrimaryLanguageOverride = "en-US";

			// Save the configuration to the app's settings.
			Atlas.Settings.ApplicationGlobalLanguage = "en-US";

			return;
		}
		catch (Exception ex)
		{
			Logger.Write(ex);

			// Set the language to en-US if there was an error.
			ApplicationLanguages.PrimaryLanguageOverride = "en-US";

			// Save the configuration to the app's settings.
			Atlas.Settings.ApplicationGlobalLanguage = "en-US";
		}
	}

	// It doesn't successfully add/remove the resource package when elevated.
	internal bool ExtraLanguagesPack1ToggleIsEnabled => !LanguageAddonsOperationInProgress;

	internal Visibility LanguageAddonsOperationProgressVisibility => LanguageAddonsOperationInProgress ? Visibility.Visible : Visibility.Collapsed;

	internal double LanguageAddonsOperationProgressValue { get; set => SP(ref field, value); }

	private bool LanguageAddonsOperationInProgress
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(ExtraLanguagesPack1ToggleIsEnabled));
				OnPropertyChanged(nameof(LanguageAddonsOperationProgressVisibility));
			}
		}
	}

	internal async void ManageExtraLanguagesPack1(object sender, RoutedEventArgs e)
	{
		if (_suppressExtraLanguagesPack1ToggleSwitchToggled)
		{
			return;
		}

		if (sender is ToggleSwitch ts)
		{
			try
			{
				bool isInstalled = GetLanguageAddonsPackage() is not null;

				if (ts.IsOn == isInstalled)
				{
					return;
				}

				if (ts.IsOn)
				{
					await AddLanguageAddonsAsync();
				}
				else
				{
					await RemoveLanguageAddonsAsync();
				}

				// Keep the toggle synchronized if the user cancels the dialog or Windows does not change the package state.
				SetExtraLanguagesPack1ToggleSwitchIsOn(ts, GetLanguageAddonsPackage() is not null);
			}
			catch (Exception ex)
			{
				// Set it back to what it was if the operation was not successful.
				SetExtraLanguagesPack1ToggleSwitchIsOn(ts, !ts.IsOn);
				MainInfoBar.WriteError(ex);
			}
			finally
			{
				LanguageAddonsOperationInProgress = false;
				LanguageAddonsOperationProgressValue = 0;
			}
		}
	}

	private async Task AddLanguageAddonsAsync()
	{
		using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
		{
			Title = "Add Extra Languages Pack 1 Add-on",
			Content = "Windows will download the language add-on for this app. If the package is added successfully, the app will be restarted so the new resources can be loaded.",
			PrimaryButtonText = "Add",
			CloseButtonText = Atlas.GetStr("Cancel"),
			DefaultButton = ContentDialogButton.Primary
		};

		ContentDialogResult dialogResult = await dialog.ShowAsync();
		if (dialogResult is not ContentDialogResult.Primary)
		{
			return;
		}

		LanguageAddonsOperationInProgress = true;

		PackageCatalog packageCatalog = PackageCatalog.OpenForCurrentPackage();
		IAsyncOperationWithProgress<PackageCatalogAddResourcePackageResult, PackageInstallProgress> operation =
			packageCatalog.AddResourcePackageAsync(
				resourcePackageFamilyName: Package.Current.Id.FamilyName,
				resourceID: LanguageAddonsResourceId,
				options: AddResourcePackageOptions.ApplyUpdateIfAvailable | AddResourcePackageOptions.ForceTargetAppShutdown);

		operation.Progress = (asyncOperation, progress) => _ = Atlas.AppDispatcher.TryEnqueue(() => LanguageAddonsOperationProgressValue = progress.PercentComplete);

		PackageCatalogAddResourcePackageResult result = await operation;
		if (result.ExtendedError is not null)
		{
			throw result.ExtendedError;
		}

		MainInfoBar.WriteSuccess("The language add-ons package was added. Restart Harden System Security if it did not restart automatically.");
	}

	private async Task RemoveLanguageAddonsAsync()
	{
		Package? languageAddonsPackage = GetLanguageAddonsPackage();
		if (languageAddonsPackage is null)
		{
			MainInfoBar.WriteWarning("The language add-ons package is already removed.");
			return;
		}

		using AppControlManager.CustomUIElements.ContentDialogV2 dialog = new()
		{
			Title = "Remove Extra Languages Pack 1 Add-on",
			Content = "Windows will remove the language add-on if it is not required for the current user or device. Restart Harden System Security after removal so the available languages list is refreshed.",
			PrimaryButtonText = "Remove",
			CloseButtonText = Atlas.GetStr("Cancel"),
			DefaultButton = ContentDialogButton.Primary
		};

		ContentDialogResult dialogResult = await dialog.ShowAsync();
		if (dialogResult is not ContentDialogResult.Primary)
		{
			return;
		}

		LanguageAddonsOperationInProgress = true;

		PackageCatalog packageCatalog = PackageCatalog.OpenForCurrentPackage();
		Package[] languageAddonsPackages = [languageAddonsPackage];
		PackageCatalogRemoveResourcePackagesResult result = await packageCatalog.RemoveResourcePackagesAsync(languageAddonsPackages);
		if (result.ExtendedError is not null)
		{
			throw result.ExtendedError;
		}

		MainInfoBar.WriteSuccess("The language add-on was removed. Restart Harden System Security to refresh the available languages.");
	}

	internal int LanguageComboBoxSelectedIndex
	{
		get; set
		{
			if (SP(ref field, value))
			{
				string x = SupportedLanguagesReverse[field];

				ApplicationLanguages.PrimaryLanguageOverride = x;
				Atlas.Settings.ApplicationGlobalLanguage = x;

				// Get reference to the MainWindow and refresh the localized content
				App.MainWindow?.RefreshLocalizedContent();

				// Refresh this page.
				ViewModelProvider.NavigationService.RefreshSettingsPage();
			}
		}
	} = SupportedLanguages.TryGetValue(Atlas.Settings.ApplicationGlobalLanguage, out int x) ? x : 0;

	/// <summary>
	/// Language Selection ComboBox ItemsSource
	/// </summary>
	internal readonly List<LanguageOption> LanguageOptions = [];

	internal static readonly Dictionary<string, int> AppThemes = new(StringComparer.OrdinalIgnoreCase)
	{
		{"Use System Setting", 0 },
		{"Dark", 1 },
		{"Light", 2 }
	};
	internal static readonly string[] AppThemesReverse = [
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

				Atlas.Settings.AppTheme = AppThemesReverse[field];
			}
		}
	} = AppThemes.TryGetValue(Atlas.Settings.AppTheme, out int x) ? x : 0;

	internal static readonly Dictionary<string, int> IconsStyles = new(StringComparer.OrdinalIgnoreCase)
	{
		{"Animated", 0 },
		{"Windows Accent", 1 },
		{"Monochromatic" , 2 }
	};

	internal static readonly string[] IconsStylesReverse = [
		"Animated",
		"Windows Accent",
		"Monochromatic"
	];

	internal int IconsStylesComboBoxSelectedIndex
	{
		get; set
		{
			if (SP(ref field, value))
			{
				string x = IconsStylesReverse[field];

				ViewModelProvider.MainWindowVM.OnIconsStylesChanged(x);

				Atlas.Settings.IconsStyle = x;
			}
		}
	} = IconsStyles.TryGetValue(Atlas.Settings.IconsStyle, out int x) ? x : 2;

	/// <summary>
	/// Set the version in the settings card to the current app version
	/// </summary>
	internal readonly string VersionTextBlockText = $"Version {Atlas.currentAppVersion}";

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
		_ = Atlas.AppDispatcher.TryEnqueue(DispatcherQueuePriority.Normal, () =>
		{
			// Get reference to the MainWindow and refresh the localized content
			App.MainWindow?.SetRegionsForCustomTitleBar();
		});
	}

	// Only Dark theme looks good when Acrylic Thin or custom backdrop brushes are used.
	internal void AppThemeSetting_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		int x = ((ComboBox)sender).SelectedIndex;
		AppThemeSettingsCardVisibility = x is 3 or 4 or 5 ? Visibility.Collapsed : Visibility.Visible;
		AcrylicThinConfigurationsSettingsCardVisibility = x == 3 ? Visibility.Visible : Visibility.Collapsed;
		BackdropMicaBrushConfigurationsSettingsCardVisibility = x == 4 ? Visibility.Visible : Visibility.Collapsed;
		BackdropBlurBrushConfigurationsSettingsCardVisibility = x == 5 ? Visibility.Visible : Visibility.Collapsed;
		BackdropCustomBrushPictureSelectionSettingsCardVisibility = x is 4 or 5 ? Visibility.Visible : Visibility.Collapsed; // Both custom backdrops use the same image and browse button.

		// Change app theme to dark because only Dark theme looks good when Acrylic Thin or custom backdrop brushes are used.
		if (AppThemeSettingsCardVisibility is Visibility.Collapsed)
		{
			AppThemeComboBoxSelectedIndex = 1;
		}
	}

	// Only Dark theme looks good when Acrylic Thin or custom backdrop brushes are used, so we control the App Theme settings card's visibility here.
	internal Visibility AppThemeSettingsCardVisibility { get; set => SP(ref field, value); } = ViewModelProvider.MainWindowVM.BackDropComboBoxSelectedIndex is 3 or 4 or 5 ? Visibility.Collapsed : Visibility.Visible;

	#region Acrylic Thin Options

	// Controls whether the configurations for Acrylic Thin Backdrop are visible or not.
	internal Visibility AcrylicThinConfigurationsSettingsCardVisibility { get; set => SP(ref field, value); } = ViewModelProvider.MainWindowVM.BackDropComboBoxSelectedIndex == 3 ? Visibility.Visible : Visibility.Collapsed;

	internal void TintColorPicker_ColorChanged(ColorPicker sender, ColorChangedEventArgs args)
	{
		byte R = args.NewColor.R;
		byte G = args.NewColor.G;
		byte B = args.NewColor.B;
		byte A = args.NewColor.A;

		_ = (ViewModelProvider.MainWindowVM.AcrylicController?.TintColor = Windows.UI.Color.FromArgb(A, R, G, B));

		// Save the color as hex in the App settings.
		Atlas.Settings.AcrylicThinTintColor = RGBHEX.ToHex(R, G, B);
	}

	// To set the Color Picker's color to the one currently in use in App Settings.
	internal void AcrylicThinTintColorPicker_Loaded(object sender, RoutedEventArgs e)
	{
		if (RGBHEX.ToRGB(Atlas.Settings.AcrylicThinTintColor, out byte R, out byte G, out byte B))
		{
			((ColorPicker)sender).Color = Windows.UI.Color.FromArgb(255, R, G, B);
		}
	}

	internal void AcrylicThinLuminosityOpacitySlider_ValueChanged(object sender, RangeBaseValueChangedEventArgs e)
	{
		_ = (ViewModelProvider.MainWindowVM.AcrylicController?.LuminosityOpacity = (float)e.NewValue);
	}

	#endregion

	// Controls the visibility of the settings card used by the custom brush backdrops.
	internal Visibility BackdropCustomBrushPictureSelectionSettingsCardVisibility { get; set => SP(ref field, value); } = ViewModelProvider.MainWindowVM.BackDropComboBoxSelectedIndex is 4 or 5 ? Visibility.Visible : Visibility.Collapsed;

	#region Backdrop Mica Brush Options

	// Controls whether the configurations for Mica Brush Backdrop are visible or not.
	internal Visibility BackdropMicaBrushConfigurationsSettingsCardVisibility { get; set => SP(ref field, value); } = ViewModelProvider.MainWindowVM.BackDropComboBoxSelectedIndex == 4 ? Visibility.Visible : Visibility.Collapsed;

	internal void BackdropMicaBrushTintColorPicker_ColorChanged(ColorPicker sender, ColorChangedEventArgs args)
	{
		byte R = args.NewColor.R;
		byte G = args.NewColor.G;
		byte B = args.NewColor.B;
		byte A = args.NewColor.A;

		if (MainWindow.CustomAcrylicWithPictureBackdropHostPub?.Fill is CommonCore.UI.Brush.BackdropMicaBrush brush)
		{
			brush.TintColor = Windows.UI.Color.FromArgb(A, R, G, B);
		}

		// Save the color as hex in the App settings.
		Atlas.Settings.BackdropMicaBrushTintColor = RGBHEX.ToHex(R, G, B);
	}

	// To set the Color Picker's color to the one currently in use in App Settings.
	internal void BackdropMicaBrushTintColorPicker_Loaded(object sender, RoutedEventArgs e)
	{
		if (RGBHEX.ToRGB(Atlas.Settings.BackdropMicaBrushTintColor, out byte R, out byte G, out byte B))
		{
			((ColorPicker)sender).Color = Windows.UI.Color.FromArgb(255, R, G, B);
		}
	}

	internal void BackdropMicaBrushLuminosityOpacitySlider_ValueChanged(object sender, RangeBaseValueChangedEventArgs e)
	{
		if (MainWindow.CustomAcrylicWithPictureBackdropHostPub?.Fill is CommonCore.UI.Brush.BackdropMicaBrush brush)
		{
			brush.LuminosityOpacity = e.NewValue;
		}
	}

	internal void BackdropMicaBrushTintOpacity_ValueChanged(object sender, RangeBaseValueChangedEventArgs e)
	{
		if (MainWindow.CustomAcrylicWithPictureBackdropHostPub?.Fill is CommonCore.UI.Brush.BackdropMicaBrush brush)
		{
			brush.TintOpacity = e.NewValue;
		}
	}

	internal void BackdropMicaBrushBlurAmount_ValueChanged(object sender, RangeBaseValueChangedEventArgs e)
	{
		if (MainWindow.CustomAcrylicWithPictureBackdropHostPub?.Fill is CommonCore.UI.Brush.BackdropMicaBrush brush)
		{
			brush.Amount = e.NewValue;
		}
	}

	#endregion

	#region Backdrop Blur Brush Options

	// Controls whether the configurations for Blur Brush Backdrop are visible or not.
	internal Visibility BackdropBlurBrushConfigurationsSettingsCardVisibility { get; set => SP(ref field, value); } = ViewModelProvider.MainWindowVM.BackDropComboBoxSelectedIndex == 5 ? Visibility.Visible : Visibility.Collapsed;

	internal void BackdropBlurBrushTintColorPicker_ColorChanged(ColorPicker sender, ColorChangedEventArgs args)
	{
		byte R = args.NewColor.R;
		byte G = args.NewColor.G;
		byte B = args.NewColor.B;
		byte A = args.NewColor.A;

		if (MainWindow.CustomAcrylicWithPictureBackdropHostPub?.Fill is CommonCore.UI.Brush.BackdropBlurBrush brush)
		{
			brush.TintColor = Windows.UI.Color.FromArgb(A, R, G, B);
		}

		// Save the color as hex in the App settings.
		Atlas.Settings.BackdropBlurBrushTintColor = RGBHEX.ToHex(R, G, B);
	}

	// To set the Color Picker's color to the one currently in use in App Settings.
	internal void BackdropBlurBrushTintColorPicker_Loaded(object sender, RoutedEventArgs e)
	{
		if (RGBHEX.ToRGB(Atlas.Settings.BackdropBlurBrushTintColor, out byte R, out byte G, out byte B))
		{
			((ColorPicker)sender).Color = Windows.UI.Color.FromArgb(255, R, G, B);
		}
	}

	internal void BackdropBlurBrushTintOpacity_ValueChanged(object sender, RangeBaseValueChangedEventArgs e)
	{
		if (MainWindow.CustomAcrylicWithPictureBackdropHostPub?.Fill is CommonCore.UI.Brush.BackdropBlurBrush brush)
		{
			brush.TintOpacity = e.NewValue;
		}
	}

	internal void BackdropBlurBrushBlurAmount_ValueChanged(object sender, RangeBaseValueChangedEventArgs e)
	{
		if (MainWindow.CustomAcrylicWithPictureBackdropHostPub?.Fill is CommonCore.UI.Brush.BackdropBlurBrush brush)
		{
			brush.Amount = e.NewValue;
		}
	}

	internal void BackdropBlurBrushBrowseForPicButton_Click()
	{
		string? selectedFile = FileDialogHelper.ShowFilePickerDialog("Pictures|*.JPG;*.JPEG;*.PNG;*.HEIC;*.WEBP;*.GIF;*.ICO;*.BMP");

		if (selectedFile is not null && ValidateBackdropImage(selectedFile))
		{
			Atlas.Settings.BackdropCustomBrushPictureSelection = selectedFile;
		}
	}

	internal static bool ValidateBackdropImage(string filePath)
	{
		UriCreationOptions options = new()
		{
			DangerousDisablePathAndQueryCanonicalization = false
		};

		return System.IO.Path.IsPathRooted(filePath) && Uri.TryCreate(filePath, options, out Uri? _);
	}

	internal void ClearBackdropCustomBrushPictureSelection() => Atlas.Settings.BackdropCustomBrushPictureSelection = string.Empty;

	#endregion

	internal async void RemoveAllToastNotifications() => await AppNotificationManager.Default.RemoveAllAsync();

	/// <summary>
	/// The list of all Font Families for the ComboBox ItemsSource.
	/// </summary>
	internal readonly List<string> FontFamilies = [];

#if APP_CONTROL_MANAGER

	internal string? CertificatePathTextBox { get; set => SP(ref field, value); }

	internal bool MainUserConfigurationsSettingsExpanderIsExpanded { get; set => SP(ref field, value); }

	// When the button to get the user configurations on the settings card is pressed
	internal void GetConfigurationButton()
	{
		UserConfiguration userConfig = UserConfiguration.Get();

		CertCNsAutoSuggestBoxText = userConfig.CertificateCommonName ?? string.Empty;
		CertificatePathTextBox = userConfig.CertificatePath ?? string.Empty;

		// Expand the settings expander to make the configurations visible
		MainUserConfigurationsSettingsExpanderIsExpanded = true;
	}

	#region Certificate Common Name

	// To store the selectable Certificate common names
	internal readonly RangedObservableCollection<string> CertCommonNames = [];
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

			CertCommonNames.AddRange(certCNs);
			CertCommonNamesList.AddRange(certCNs);

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
		IEnumerable<string> suggestions = CertCommonNamesList.Where(name => name.Contains(CertCNsAutoSuggestBoxText, StringComparison.OrdinalIgnoreCase));

		CertCommonNames.Clear();
		CertCommonNames.AddRange(suggestions);
	}

	internal void EditButton_CertificateCommonName_Click() => _ = UserConfiguration.Set(CertificateCommonName: CertCNsAutoSuggestBoxText);

	internal void ClearButton_CertificateCommonName_Click()
	{
		UserConfiguration.Remove(CertificateCommonName: true);
		CertCNsAutoSuggestBoxText = null;
	}

	#endregion

	#region Certificate Path

	internal void EditButton_CertificatePath_Click() => _ = UserConfiguration.Set(CertificatePath: CertificatePathTextBox);

	internal void ClearButton_CertificatePath_Click()
	{
		UserConfiguration.Remove(CertificatePath: true);
		CertificatePathTextBox = null;
	}

	internal void BrowseButton_CertificatePath_Click() => CertificatePathTextBox = FileDialogHelper.ShowFilePickerDialog(Atlas.CertificatePickerFilter);

	#endregion

#endif

	#region App Border Color Customization
	internal void StartRainbowAnimation() => CustomUIElements.AppWindowBorderCustomization.StartAnimatedFrame();
	internal void StopRainbowAnimation() => CustomUIElements.AppWindowBorderCustomization.StopAnimatedFrame();
	internal void ColorPicker_ColorChanged(ColorPicker sender, ColorChangedEventArgs args)
	{
		_R = args.NewColor.R;
		_G = args.NewColor.G;
		_B = args.NewColor.B;
	}
	private byte _R;
	private byte _G;
	private byte _B;

	internal void StartCustomColorAnimation() => CustomUIElements.AppWindowBorderCustomization.SetBorderColor(_R, _G, _B);
	internal void StopCustomColorAnimation() => CustomUIElements.AppWindowBorderCustomization.ResetBorderColor();

	#endregion

	#region App Shortcuts

	/// <summary>
	/// Gets the app list entry for the current package.
	/// </summary>
	private static async Task<AppListEntry?> GetCurrentAppListEntry()
	{
		IReadOnlyList<AppListEntry> entries = await Package.Current.GetAppListEntriesAsync();
		return entries.Count > 0 ? entries[0] : null;
	}

	/// <summary>
	/// Asks Windows to pin the current app to the taskbar after the user confirms the system prompt.
	/// </summary>
	internal async void PinToTaskbar()
	{
		try
		{
			TaskbarManager taskbarManager = TaskbarManager.GetDefault();
			if (!taskbarManager.IsSupported)
			{
				MainInfoBar.WriteWarning("Taskbar pinning is not supported on this device.");
				return;
			}

			if (!taskbarManager.IsPinningAllowed)
			{
				MainInfoBar.WriteWarning("Taskbar pinning is disabled by the current Windows configuration or policy.");
				return;
			}

			bool isPinned = await taskbarManager.IsCurrentAppPinnedAsync();
			if (isPinned)
			{
				MainInfoBar.WriteInfo("The app is already pinned to the taskbar.");
				return;
			}

			bool pinned = await taskbarManager.RequestPinCurrentAppAsync();
			if (pinned)
			{
				MainInfoBar.WriteSuccess("The app was pinned to the taskbar.");
			}
			else
			{
				MainInfoBar.WriteInfo("The taskbar pin request was not approved.");
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			MainInfoBar.IsClosable = true;
		}
	}

	/// <summary>
	/// Asks Windows to pin the app to Start after the user confirms the system prompt.
	/// </summary>
	internal async void PinToStartMenu()
	{
		try
		{
			AppListEntry? entry = await GetCurrentAppListEntry();
			if (entry is null)
			{
				MainInfoBar.WriteWarning("The app list entry could not be found, so the app was not pinned to Start.");
				return;
			}

			StartScreenManager startScreenManager = StartScreenManager.GetDefault();
			if (!startScreenManager.SupportsAppListEntry(entry))
			{
				MainInfoBar.WriteWarning("Start menu pinning is not supported for this app entry on this device.");
				return;
			}

			bool isPinned = await startScreenManager.ContainsAppListEntryAsync(entry);
			if (isPinned)
			{
				MainInfoBar.WriteInfo("The app is already pinned to Start.");
				return;
			}

			bool pinned = await startScreenManager.RequestAddAppListEntryAsync(entry);
			if (pinned)
			{
				MainInfoBar.WriteSuccess("The app was pinned to Start.");
			}
			else
			{
				MainInfoBar.WriteInfo("The Start pin request was not approved.");
			}
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			MainInfoBar.IsClosable = true;
		}
	}

	#endregion

	internal async void OpenWindowsSettings() => await OpenFileInDefaultFileHandler("ms-settings:personalization-colors");

	internal async void OpenSettingsBackupRestorePage() => await ViewModelProvider.NavigationService.Navigate(typeof(AppControlManager.Pages.SettingsBackupRestore), null);
}
