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
using System.Collections.ObjectModel;
using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using CommonCore.MicrosoftGraph;
using Microsoft.UI.Xaml;

#if HARDEN_SYSTEM_SECURITY
using HardenSystemSecurity;
using HardenSystemSecurity.CustomUIElements;
using HardenSystemSecurity.ViewModels;
#else
using AppControlManager;
using AppControlManager.ViewModels;
using AppControlManager.CustomUIElements;
#endif

namespace CommonCore.AppSettings;

internal sealed class AppSettingDisplayItem(string name, string currentValue, string acceptedFormat)
{
	internal string Name => name;
	internal string CurrentValue => currentValue;
	internal string AcceptedFormat => acceptedFormat;
}

internal sealed partial class SettingsBackupRestoreVM : ViewModelBase
{
	internal readonly InfoBarSettings MainInfoBar = new();
	internal readonly ObservableCollection<AppSettingDisplayItem> SettingsItems = [];

	internal SettingsBackupRestoreVM() => RefreshDisplayedSettings();

	internal void RefreshDisplayedSettings()
	{
		SettingsItems.Clear();

		foreach (AppSettingDescriptor descriptor in SettingsBackupRestoreSerializer.Descriptors)
		{
			SettingsItems.Add(new AppSettingDisplayItem(descriptor.Name, descriptor.GetDisplayValue(Atlas.Settings), descriptor.AcceptedFormat));
		}
	}

	internal async void ExportAsync()
	{
		try
		{
			string? savePath = FileDialogHelper.ShowSaveFileDialog(Atlas.JSONPickerFilter, $"AppSettingsBackup-{DateTimeOffset.UtcNow:yyyyMMdd-HHmmss}.json");
			if (savePath is null)
			{
				return;
			}

			MainInfoBar.WriteInfo(Atlas.GetStr("ExportingSettingsToJsonMessage"));

			byte[] jsonPayload = SettingsBackupRestoreSerializer.Export(Atlas.Settings);
			await File.WriteAllBytesAsync(savePath, jsonPayload);

			RefreshDisplayedSettings();
			MainInfoBar.WriteSuccess(string.Format(CultureInfo.CurrentCulture, Atlas.GetStr("SuccessfullyExportedSettingsToJsonMessage"), SettingsItems.Count, savePath));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, Atlas.GetStr("CouldNotExportSettingsToJsonMessage"));
		}
	}

	internal async void ImportAsync()
	{
		try
		{
			string? selectedFile = FileDialogHelper.ShowFilePickerDialog(Atlas.JSONPickerFilter);
			if (selectedFile is null)
			{
				return;
			}

			MainInfoBar.WriteInfo(Atlas.GetStr("ImportingSettingsFromJsonMessage"));

			byte[] jsonPayload = await File.ReadAllBytesAsync(selectedFile);
			SettingsBackupRestoreSerializer.Import(jsonPayload, Atlas.Settings);
			await ApplyImportedSettingsAsync();
			RefreshDisplayedSettings();

			MainInfoBar.WriteSuccess(string.Format(CultureInfo.CurrentCulture, Atlas.GetStr("SuccessfullyImportedSettingsFromJsonMessage"), SettingsItems.Count, selectedFile));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, Atlas.GetStr("CouldNotImportSettingsFromJsonMessage"));
		}
	}

	internal async void ResetToDefaultsAsync()
	{
		try
		{
			MainInfoBar.WriteInfo(Atlas.GetStr("ResettingSettingsToDefaultsMessage"));

			Main defaultSettings = Main.CreateDefaultSettingsSnapshot();
			byte[] jsonPayload = SettingsBackupRestoreSerializer.Export(defaultSettings);
			SettingsBackupRestoreSerializer.Import(jsonPayload, Atlas.Settings);
			await ApplyImportedSettingsAsync();
			RefreshDisplayedSettings();

			MainInfoBar.WriteSuccess(string.Format(CultureInfo.CurrentCulture, Atlas.GetStr("SuccessfullyResetSettingsToDefaultsMessage"), SettingsItems.Count));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex, Atlas.GetStr("CouldNotResetSettingsToDefaultsMessage"));
		}
	}

	private static async Task ApplyImportedSettingsAsync()
	{
		ElementSoundPlayer.State = Atlas.Settings.SoundSetting ? ElementSoundPlayerState.On : ElementSoundPlayerState.Off;
		ElementSoundPlayer.SpatialAudioMode = Atlas.Settings.SoundSetting ? ElementSpatialAudioMode.On : ElementSpatialAudioMode.Off;
		NavigationBackgroundManager.OnNavigationBackgroundChanged(Atlas.Settings.NavViewBackground);
		NavigationViewLocationManager.OnNavigationViewLocationChanged(Atlas.Settings.NavViewPaneDisplayMode);
		AppThemeManager.OnAppThemeChanged(Atlas.Settings.AppTheme);
		ListViewHelper.UpdateFontFamily(Atlas.Settings.ListViewFontFamily);
		SettingsVM.SetLanguageOnStartup(); // Automatically detects and sets the language of the app after it's been assigned to the "Atlas.Settings.ApplicationGlobalLanguage" below.
		MainWindowVM.SetCaptionButtonsFlowDirection(string.Equals(Atlas.Settings.ApplicationGlobalFlowDirection, "LeftToRight", StringComparison.OrdinalIgnoreCase)
		? FlowDirection.LeftToRight
		: FlowDirection.RightToLeft);

		if (Atlas.Settings.IsAnimatedRainbowEnabled)
		{
			AppWindowBorderCustomization.StartAnimatedFrame();
		}
		else if (!string.IsNullOrEmpty(Atlas.Settings.CustomAppWindowsBorder) && RGBHEX.ToRGB(Atlas.Settings.CustomAppWindowsBorder, out byte red, out byte green, out byte blue))
		{
			AppWindowBorderCustomization.SetBorderColor(red, green, blue);
		}
		else
		{
			AppWindowBorderCustomization.ResetBorderColor();
		}

		ViewModelProvider.MainWindowVM.OnIconsStylesChanged(Atlas.Settings.IconsStyle);
		ViewModelProvider.MainWindowVM.BackDropComboBoxSelectedIndex = (int)Enum.Parse<MainWindowVM.BackDropComboBoxItems>(Atlas.Settings.BackDropBackground);
		App.MainWindow?.RefreshLocalizedContent();
		App.MainWindow?.SetRegionsForCustomTitleBar();
	}
}

internal static class SettingsBackupRestoreSerializer
{
	private const string ExportedAtUtcPropertyName = "exportedAtUtc";
	private const string FormatVersionPropertyName = "formatVersion";
	private const string SettingsPropertyName = "settings";
	private const int CurrentFormatVersion = 1;
	internal static readonly AppSettingDescriptor[] Descriptors =
	[
		CreateBoolean(nameof(Main.SoundSetting), settings => settings.SoundSetting, (settings, value) => settings.SoundSetting = value),

		CreateBoolean(nameof(Main.NavViewBackground), settings => settings.NavViewBackground, (settings, value) => settings.NavViewBackground = value),

		CreateEnumStringSetting<SettingsVM.NavViewLocation>(nameof(Main.NavViewPaneDisplayMode), settings => settings.NavViewPaneDisplayMode, (settings, value) => settings.NavViewPaneDisplayMode = value),

		CreateStringFromKnownValues(nameof(Main.AppTheme), SettingsVM.AppThemesReverse, static value => SettingsVM.AppThemes.ContainsKey(value), settings => settings.AppTheme, (settings, value) => settings.AppTheme = value),

		CreateEnumStringSetting<MainWindowVM.BackDropComboBoxItems>(nameof(Main.BackDropBackground), settings => settings.BackDropBackground, (settings, value) => settings.BackDropBackground = value),

		CreateStringFromKnownValues(nameof(Main.IconsStyle), SettingsVM.IconsStylesReverse, static value => SettingsVM.IconsStyles.ContainsKey(value), settings => settings.IconsStyle, (settings, value) => settings.IconsStyle = value),

		CreateInt(nameof(Main.MainWindowWidth), "Integer in range 700-Max Screen Width", 700, 10000, settings => settings.MainWindowWidth, (settings, value) => settings.MainWindowWidth = value),

		CreateInt(nameof(Main.MainWindowHeight), "Integer in range 700-Max Screen Height", 700, 10000, settings => settings.MainWindowHeight, (settings, value) => settings.MainWindowHeight = value),

		CreateBoolean(nameof(Main.MainWindowIsMaximized), settings => settings.MainWindowIsMaximized, (settings, value) => settings.MainWindowIsMaximized = value),

		CreateBoolean(nameof(Main.ListViewsVerticalCentering), settings => settings.ListViewsVerticalCentering, (settings, value) => settings.ListViewsVerticalCentering = value),

		CreateBoolean(nameof(Main.StickyHeadersForListViews), settings => settings.StickyHeadersForListViews, (settings, value) => settings.StickyHeadersForListViews = value),

		CreateBoolean(nameof(Main.CacheSecurityCatalogsScanResults), settings => settings.CacheSecurityCatalogsScanResults, (settings, value) => settings.CacheSecurityCatalogsScanResults = value),

		CreateBoolean(nameof(Main.PromptForElevationOnStartup), settings => settings.PromptForElevationOnStartup, (settings, value) => settings.PromptForElevationOnStartup = value),

		CreateBoolean(nameof(Main.AutoCheckForUpdateAtStartup), settings => settings.AutoCheckForUpdateAtStartup, (settings, value) => settings.AutoCheckForUpdateAtStartup = value),

		CreateStringWithCustomValidation(nameof(Main.ApplicationGlobalLanguage), $"Empty string or one of: {string.Join(", ",  SettingsVM.SupportedLanguagesReverse)}", settings => settings.ApplicationGlobalLanguage, (settings, value) => settings.ApplicationGlobalLanguage = value,
			static value => SettingsVM.SupportedLanguages.ContainsKey(value) || value.Length == 0,
			$"'{nameof(Main.ApplicationGlobalLanguage)}' must be empty or a supported language token."),

		CreateEnumStringSetting<FlowDirection>(nameof(Main.ApplicationGlobalFlowDirection), settings => settings.ApplicationGlobalFlowDirection, (settings, value) => settings.ApplicationGlobalFlowDirection = value),

		CreateStringWithCustomValidation(nameof(Main.CiPolicySchemaPath), "Absolute path or empty string", settings => settings.CiPolicySchemaPath, (settings, value) => settings.CiPolicySchemaPath = value,
			static value => string.IsNullOrEmpty(value) || Path.IsPathRooted(value),
			$"'{nameof(Main.CiPolicySchemaPath)}' must be empty or an absolute path."),

		CreateBoolean(nameof(Main.ScreenShield), settings => settings.ScreenShield, (settings, value) => settings.ScreenShield = value),

		CreateBoolean(nameof(Main.PublishUserActivityInTheOS), settings => settings.PublishUserActivityInTheOS, (settings, value) => settings.PublishUserActivityInTheOS = value),

		CreateBoolean(nameof(Main.LinkPreviewsForSecurityMeasure), settings => settings.LinkPreviewsForSecurityMeasure, (settings, value) => settings.LinkPreviewsForSecurityMeasure = value),

		CreateBoolean(nameof(Main.AutoResizeListViewColumns), settings => settings.AutoResizeListViewColumns, (settings, value) => settings.AutoResizeListViewColumns = value),

		CreateStringWithCustomValidation(nameof(Main.ListViewFontFamily), "Non-empty string", settings => settings.ListViewFontFamily, (settings, value) => settings.ListViewFontFamily = value,
			static value => !string.IsNullOrWhiteSpace(value),
			$"'{nameof(Main.ListViewFontFamily)}' must be a non-empty string."),

		CreateInt(nameof(Main.SelectedSignInMethodForMSGraph), "Integer in range 0-1", (int)SignInMethods.WebAccountManager, (int)SignInMethods.WebBrowser, settings => settings.SelectedSignInMethodForMSGraph, (settings, value) => settings.SelectedSignInMethodForMSGraph = value),

		CreateBoolean(nameof(Main.IsAnimatedRainbowEnabled), settings => settings.IsAnimatedRainbowEnabled, (settings, value) => settings.IsAnimatedRainbowEnabled = value),

		CreateStringWithCustomValidation(nameof(Main.CustomAppWindowsBorder), "Empty string or hex color (#RRGGBB or RRGGBB)", settings => settings.CustomAppWindowsBorder, (settings, value) => settings.CustomAppWindowsBorder = value,
			static value => string.IsNullOrEmpty(value) || RGBHEX.ToRGB(value, out _, out _, out _),
			$"'{nameof(Main.CustomAppWindowsBorder)}' must be empty or a valid RGB hex color."),

		CreateBoolean(nameof(Main.UseV2CIManagement), settings => settings.UseV2CIManagement, (settings, value) => settings.UseV2CIManagement = value),

		CreateInt(nameof(Main.AppCloseConfirmationBehavior), "Integer in range 0-2", 0, 2, settings => settings.AppCloseConfirmationBehavior, (settings, value) => settings.AppCloseConfirmationBehavior = value),

		CreateBoolean(nameof(Main.PersistentPoliciesLibrary), settings => settings.PersistentPoliciesLibrary, (settings, value) => settings.PersistentPoliciesLibrary = value),

		CreateBoolean(nameof(Main.EncryptPoliciesLibrary), settings => settings.EncryptPoliciesLibrary, (settings, value) => settings.EncryptPoliciesLibrary = value),

		CreateBoolean(nameof(Main.EncryptionScopePoliciesLibrary), settings => settings.EncryptionScopePoliciesLibrary, (settings, value) => settings.EncryptionScopePoliciesLibrary = value),

		CreateString(nameof(Main.FirewallSentinelPinnedPolicyID), "String", settings => settings.FirewallSentinelPinnedPolicyID, (settings, value) => settings.FirewallSentinelPinnedPolicyID = value),

		CreateBoolean(nameof(Main.CacheAuthenticationTokensLocally), settings => settings.CacheAuthenticationTokensLocally, (settings, value) => settings.CacheAuthenticationTokensLocally = value),

		CreateStringWithCustomValidation(nameof(Main.CustomSidebarPoliciesLibraryCacheLocation), "Absolute path or empty string", settings => settings.CustomSidebarPoliciesLibraryCacheLocation, (settings, value) => settings.CustomSidebarPoliciesLibraryCacheLocation = value,
			static value => string.IsNullOrEmpty(value) || Path.IsPathRooted(value),
			$"'{nameof(Main.CustomSidebarPoliciesLibraryCacheLocation)}' must be empty or an absolute path."),

		CreateStringWithCustomValidation(nameof(Main.DownloadManagerDirectory), "Absolute path or empty string", settings => settings.DownloadManagerDirectory, (settings, value) => settings.DownloadManagerDirectory = value,
			static value => string.IsNullOrEmpty(value) || Path.IsPathRooted(value),
			$"'{nameof(Main.DownloadManagerDirectory)}' must be empty or an absolute path."),

		CreateInt(nameof(Main.DownloadManagerMaximumSimultaneousDownloads), "Integer in range 1-16", 1, 16, settings => settings.DownloadManagerMaximumSimultaneousDownloads, (settings, value) => settings.DownloadManagerMaximumSimultaneousDownloads = value),

		CreateInt(nameof(Main.DownloadManagerParallelConnectionsPerDownload), "Integer in range 1-32", 1, 32, settings => settings.DownloadManagerParallelConnectionsPerDownload, (settings, value) => settings.DownloadManagerParallelConnectionsPerDownload = value),

		CreateInt(nameof(Main.DownloadManagerSlowPresetKilobytesPerSecond), "Integer in range 1-1048576", 1, 1_048_576, settings => settings.DownloadManagerSlowPresetKilobytesPerSecond, (settings, value) => settings.DownloadManagerSlowPresetKilobytesPerSecond = value),

		CreateInt(nameof(Main.DownloadManagerMediumPresetKilobytesPerSecond), "Integer in range 1-1048576", 1, 1_048_576, settings => settings.DownloadManagerMediumPresetKilobytesPerSecond, (settings, value) => settings.DownloadManagerMediumPresetKilobytesPerSecond = value),

		CreateInt(nameof(Main.DownloadManagerFullPresetKilobytesPerSecond), "Integer in range 1-1048576", 1, 1_048_576, settings => settings.DownloadManagerFullPresetKilobytesPerSecond, (settings, value) => settings.DownloadManagerFullPresetKilobytesPerSecond = value),

		CreateInt(nameof(Main.DownloadManagerSelectedSpeedPreset), "Integer in range 0-2", 0, 2, settings => settings.DownloadManagerSelectedSpeedPreset, (settings, value) => settings.DownloadManagerSelectedSpeedPreset = value),

		CreateBoolean(nameof(Main.DownloadManagerIsFullPresetUnlimited), settings => settings.DownloadManagerIsFullPresetUnlimited, (settings, value) => settings.DownloadManagerIsFullPresetUnlimited = value),

		CreateInt(nameof(Main.DownloadManagerCompletionAction), "Integer in range 0-3", 0, 3, settings => settings.DownloadManagerCompletionAction, (settings, value) => settings.DownloadManagerCompletionAction = value),

		CreateInt(nameof(Main.DownloadManagerExistingDownloadConflictBehavior), "Integer in range 0-2", 0, 2, settings => settings.DownloadManagerExistingDownloadConflictBehavior, (settings, value) => settings.DownloadManagerExistingDownloadConflictBehavior = value),

		CreateBoolean(nameof(Main.DownloadManagerRemoveCompletedItemsFromList), settings => settings.DownloadManagerRemoveCompletedItemsFromList, (settings, value) => settings.DownloadManagerRemoveCompletedItemsFromList = value),

		CreateFloat(nameof(Main.AcrylicThinLuminosityOpacity), "Number in range 0-1", 0F, 1F, settings => settings.AcrylicThinLuminosityOpacity, (settings, value) => settings.AcrylicThinLuminosityOpacity = value),

		CreateFloat(nameof(Main.AcrylicThinTintOpacity), "Number in range 0-1", 0F, 1F, settings => settings.AcrylicThinTintOpacity, (settings, value) => settings.AcrylicThinTintOpacity = value),

		CreateStringWithCustomValidation(nameof(Main.AcrylicThinTintColor), "Hex color (#RRGGBB or RRGGBB)", settings => settings.AcrylicThinTintColor, (settings, value) => settings.AcrylicThinTintColor = value,
			static value => RGBHEX.ToRGB(value, out _, out _, out _),
			$"'{nameof(Main.AcrylicThinTintColor)}' must be a valid RGB hex color."),

		CreateBoolean(nameof(Main.ToastNotificationsAreEnabled), settings => settings.ToastNotificationsAreEnabled, (settings, value) => settings.ToastNotificationsAreEnabled = value),

		CreateInt(nameof(Main.SidebarPaneDisplayMode), "Integer in range 0-1", 0, 1, settings => settings.SidebarPaneDisplayMode, (settings, value) => settings.SidebarPaneDisplayMode = value),

		CreateBoolean(nameof(Main.AutoSwitchToAnalysisPageAfterDataRetrieval), settings => settings.AutoSwitchToAnalysisPageAfterDataRetrieval, (settings, value) => settings.AutoSwitchToAnalysisPageAfterDataRetrieval = value),

		CreateBoolean(nameof(Main.RememberMSSecurityBaselineFilePath), settings => settings.RememberMSSecurityBaselineFilePath, (settings, value) => settings.RememberMSSecurityBaselineFilePath = value),

		CreateStringWithCustomValidation(nameof(Main.MSSecurityBaselineFilePath), "Absolute path or empty string", settings => settings.MSSecurityBaselineFilePath, (settings, value) => settings.MSSecurityBaselineFilePath = value,
			static value => string.IsNullOrEmpty(value) || Path.IsPathRooted(value),
			$"'{nameof(Main.MSSecurityBaselineFilePath)}' must be empty or an absolute path."),

		CreateBoolean(nameof(Main.RememberMS365AppsSecurityBaselineFilePath), settings => settings.RememberMS365AppsSecurityBaselineFilePath, (settings, value) => settings.RememberMS365AppsSecurityBaselineFilePath = value),

		CreateStringWithCustomValidation(nameof(Main.MS365AppsSecurityBaselineFilePath), "Absolute path or empty string", settings => settings.MS365AppsSecurityBaselineFilePath, (settings, value) => settings.MS365AppsSecurityBaselineFilePath = value,
			static value => string.IsNullOrEmpty(value) || Path.IsPathRooted(value),
			$"'{nameof(Main.MS365AppsSecurityBaselineFilePath)}' must be empty or an absolute path."),

		CreateStringWithCustomValidation(nameof(Main.BackdropCustomBrushPictureSelection), $"'{Main.DefaultCustomBrushAppPackageBackgroundPicture}' or absolute path", settings => settings.BackdropCustomBrushPictureSelection, (settings, value) => settings.BackdropCustomBrushPictureSelection = value,
			static value => IsValidUriOrAbsolutePath(value),
			$"'{nameof(Main.BackdropCustomBrushPictureSelection)}' must be '{Main.DefaultCustomBrushAppPackageBackgroundPicture}' or an absolute path."),

		CreateDouble(nameof(Main.BackdropMicaBrushLuminosityOpacity), "Number in range 0-1", 0D, 1D, settings => settings.BackdropMicaBrushLuminosityOpacity, (settings, value) => settings.BackdropMicaBrushLuminosityOpacity = value),

		CreateDouble(nameof(Main.BackdropMicaBrushTintOpacity), "Number in range 0-1", 0D, 1D, settings => settings.BackdropMicaBrushTintOpacity, (settings, value) => settings.BackdropMicaBrushTintOpacity = value),

		CreateStringWithCustomValidation(nameof(Main.BackdropMicaBrushTintColor), "Hex color (#RRGGBB or RRGGBB)", settings => settings.BackdropMicaBrushTintColor, (settings, value) => settings.BackdropMicaBrushTintColor = value,
			static value => RGBHEX.ToRGB(value, out _, out _, out _),
			$"'{nameof(Main.BackdropMicaBrushTintColor)}' must be a valid RGB hex color."),

		CreateDouble(nameof(Main.BackdropMicaBrushBlurAmount), "Number in range 1-100", 1D, 100D, settings => settings.BackdropMicaBrushBlurAmount, (settings, value) => settings.BackdropMicaBrushBlurAmount = value),

		CreateDouble(nameof(Main.BackdropBlurBrushTintOpacity), "Number in range 0-1", 0D, 1D, settings => settings.BackdropBlurBrushTintOpacity, (settings, value) => settings.BackdropBlurBrushTintOpacity = value),

		CreateStringWithCustomValidation(nameof(Main.BackdropBlurBrushTintColor), "Hex color (#RRGGBB or RRGGBB)", settings => settings.BackdropBlurBrushTintColor, (settings, value) => settings.BackdropBlurBrushTintColor = value,
			static value => RGBHEX.ToRGB(value, out _, out _, out _),
			$"'{nameof(Main.BackdropBlurBrushTintColor)}' must be a valid RGB hex color."),

		CreateDouble(nameof(Main.BackdropBlurBrushBlurAmount), "Number in range 1-100", 1D, 100D, settings => settings.BackdropBlurBrushBlurAmount, (settings, value) => settings.BackdropBlurBrushBlurAmount = value)
	];

	internal static byte[] Export(Main settings)
	{
		using MemoryStream memoryStream = new();
		using Utf8JsonWriter writer = new(memoryStream, new JsonWriterOptions { Indented = true });

		writer.WriteStartObject();
		writer.WriteNumber(FormatVersionPropertyName, CurrentFormatVersion);
		writer.WriteString(ExportedAtUtcPropertyName, DateTimeOffset.UtcNow.ToString("O", CultureInfo.InvariantCulture));
		writer.WriteStartObject(SettingsPropertyName);

		foreach (AppSettingDescriptor descriptor in Descriptors)
		{
			descriptor.WriteJsonValue(writer, settings);
		}

		writer.WriteEndObject();
		writer.WriteEndObject();
		writer.Flush();

		return memoryStream.ToArray();
	}

	internal static void Import(byte[] jsonPayload, Main settings)
	{
		using JsonDocument document = JsonDocument.Parse(jsonPayload, new JsonDocumentOptions
		{
			AllowTrailingCommas = false,
			CommentHandling = JsonCommentHandling.Disallow,
			MaxDepth = 8
		});

		JsonElement rootElement = document.RootElement;
		if (rootElement.ValueKind is not JsonValueKind.Object)
		{
			throw new InvalidDataException("The backup file must contain a JSON object at the root level.");
		}

		ValidateRootObject(rootElement, out JsonElement settingsElement);

		if (settingsElement.ValueKind is not JsonValueKind.Object)
		{
			throw new InvalidDataException($"'{SettingsPropertyName}' must be a JSON object.");
		}

		Dictionary<string, Action<Main>> assignments = new(StringComparer.OrdinalIgnoreCase);
		HashSet<string> seenProperties = new(StringComparer.OrdinalIgnoreCase);

		foreach (JsonProperty property in settingsElement.EnumerateObject())
		{
			if (!seenProperties.Add(property.Name))
			{
				throw new InvalidDataException($"Duplicate setting '{property.Name}' was found in the JSON file.");
			}

			AppSettingDescriptor? descriptor = GetDescriptor(property.Name) ?? throw new InvalidDataException($"Unexpected setting '{property.Name}' was found in the JSON file.");
			DescriptorValidationResult validationResult = descriptor.ValidateAndCreateAssignment(property.Value);
			if (!validationResult.IsValid || validationResult.Assignment is null)
			{
				throw new InvalidDataException(validationResult.ErrorMessage ?? $"The setting '{property.Name}' is invalid.");
			}

			assignments[property.Name] = validationResult.Assignment;
		}

		if (seenProperties.Count != Descriptors.Length)
		{
			List<string> missingProperties = [];

			foreach (AppSettingDescriptor descriptor in Descriptors)
			{
				if (!seenProperties.Contains(descriptor.Name))
				{
					missingProperties.Add(descriptor.Name);
				}
			}

			throw new InvalidDataException($"The JSON file is missing the following required settings: {string.Join(", ", missingProperties)}.");
		}

		foreach (AppSettingDescriptor descriptor in Descriptors)
		{
			assignments[descriptor.Name](settings);
		}
	}

	private static void ValidateRootObject(JsonElement rootElement, out JsonElement settingsElement)
	{
		settingsElement = default;
		bool hasFormatVersion = false;
		bool hasExportedAtUtc = false;
		bool hasSettings = false;
		HashSet<string> rootProperties = new(StringComparer.OrdinalIgnoreCase);

		foreach (JsonProperty property in rootElement.EnumerateObject())
		{
			if (!rootProperties.Add(property.Name))
			{
				throw new InvalidDataException($"Duplicate root property '{property.Name}' was found in the JSON file.");
			}

			switch (property.Name)
			{
				case FormatVersionPropertyName:
					if (!property.Value.TryGetInt32(out int formatVersion) || formatVersion != CurrentFormatVersion)
					{
						throw new InvalidDataException($"'{FormatVersionPropertyName}' must be the integer value {CurrentFormatVersion}.");
					}

					hasFormatVersion = true;
					break;
				case ExportedAtUtcPropertyName:
					if (property.Value.ValueKind is not JsonValueKind.String
					|| !DateTimeOffset.TryParse(property.Value.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out _))
					{
						throw new InvalidDataException($"'{ExportedAtUtcPropertyName}' must be a valid round-trip UTC timestamp string.");
					}

					hasExportedAtUtc = true;
					break;
				case SettingsPropertyName:
					settingsElement = property.Value;
					hasSettings = true;
					break;
				default:
					throw new InvalidDataException($"Unexpected root property '{property.Name}' was found in the JSON file.");
			}
		}

		if (!hasFormatVersion || !hasExportedAtUtc || !hasSettings || rootProperties.Count != 3)
		{
			throw new InvalidDataException($"The JSON file must contain exactly '{FormatVersionPropertyName}', '{ExportedAtUtcPropertyName}', and '{SettingsPropertyName}' at the root level.");
		}
	}

	private static bool IsValidUriOrAbsolutePath(string value)
	{
		if (string.Equals(value, Main.DefaultCustomBrushAppPackageBackgroundPicture, StringComparison.OrdinalIgnoreCase))
		{
			return true;
		}

		return SettingsVM.ValidateBackdropImage(value);
	}

	private static AppSettingDescriptor? GetDescriptor(string name)
	{
		foreach (AppSettingDescriptor descriptor in Descriptors)
		{
			if (string.Equals(descriptor.Name, name, StringComparison.OrdinalIgnoreCase))
			{
				return descriptor;
			}
		}

		return null;
	}

	private static AppSettingDescriptor CreateBoolean(string name, Func<Main, bool> getter, Action<Main, bool> setter) =>
	new(name,
		"Boolean",
		settings => getter(settings).ToString(CultureInfo.InvariantCulture),
		(writer, settings) => writer.WriteBoolean(name, getter(settings)),
		element =>
		{
			if (element.ValueKind is JsonValueKind.True or JsonValueKind.False)
			{
				bool parsedValue = element.GetBoolean();
				return DescriptorValidationResult.Success(settings => setter(settings, parsedValue));
			}

			return DescriptorValidationResult.Failure($"'{name}' must be a JSON boolean.");
		});

	private static AppSettingDescriptor CreateEnumStringSetting<TEnum>(string name, Func<Main, string> getter, Action<Main, string> setter) where TEnum : struct, Enum =>
		 CreateStringFromKnownValues(name, Enum.GetNames<TEnum>(), static value => Enum.TryParse<TEnum>(value, true, out _), getter, setter);

	private static AppSettingDescriptor CreateDouble(string name, string acceptedFormat, double minimum, double maximum, Func<Main, double> getter, Action<Main, double> setter) =>
	new(name,
		acceptedFormat,
		settings => getter(settings).ToString(CultureInfo.InvariantCulture),
		(writer, settings) => writer.WriteNumber(name, getter(settings)),
		element =>
		{
			if (element.ValueKind is not JsonValueKind.Number || !element.TryGetDouble(out double parsedValue) || parsedValue < minimum || parsedValue > maximum)
			{
				return DescriptorValidationResult.Failure($"'{name}' must be {acceptedFormat}.");
			}

			return DescriptorValidationResult.Success(settings => setter(settings, parsedValue));
		});

	private static AppSettingDescriptor CreateFloat(string name, string acceptedFormat, float minimum, float maximum, Func<Main, float> getter, Action<Main, float> setter) =>
	new(name,
		acceptedFormat,
		settings => getter(settings).ToString(CultureInfo.InvariantCulture),
		(writer, settings) => writer.WriteNumber(name, getter(settings)),
		element =>
		{
			if (element.ValueKind is not JsonValueKind.Number || !element.TryGetSingle(out float parsedValue) || parsedValue < minimum || parsedValue > maximum)
			{
				return DescriptorValidationResult.Failure($"'{name}' must be {acceptedFormat}.");
			}

			return DescriptorValidationResult.Success(settings => setter(settings, parsedValue));
		});

	private static AppSettingDescriptor CreateInt(string name, string acceptedFormat, int minimum, int maximum, Func<Main, int> getter, Action<Main, int> setter) =>
	new(name,
		acceptedFormat,
		settings => getter(settings).ToString(CultureInfo.InvariantCulture),
		(writer, settings) => writer.WriteNumber(name, getter(settings)),
		element =>
		{
			if (element.ValueKind is not JsonValueKind.Number || !element.TryGetInt32(out int parsedValue) || parsedValue < minimum || parsedValue > maximum)
			{
				return DescriptorValidationResult.Failure($"'{name}' must be {acceptedFormat}.");
			}

			return DescriptorValidationResult.Success(settings => setter(settings, parsedValue));
		});

	private static AppSettingDescriptor CreateString(string name, string acceptedFormat, Func<Main, string> getter, Action<Main, string> setter) =>
	new(name,
		acceptedFormat,
		getter,
		(writer, settings) => writer.WriteString(name, getter(settings)),
		element =>
		{
			if (element.ValueKind is not JsonValueKind.String)
			{
				return DescriptorValidationResult.Failure($"'{name}' must be a JSON string.");
			}

			string? parsedValue = element.GetString();
			if (parsedValue is null)
			{
				return DescriptorValidationResult.Failure($"'{name}' cannot be null.");
			}

			return DescriptorValidationResult.Success(settings => setter(settings, parsedValue));
		});

	private static AppSettingDescriptor CreateStringFromKnownValues(string name, string[] values, Func<string, bool> validator, Func<Main, string> getter, Action<Main, string> setter) =>
		CreateStringWithCustomValidation(name, $"One of: {string.Join(", ", values)}", getter, setter, validator, $"'{name}' must be one of: {string.Join(", ", values)}.");

	private static AppSettingDescriptor CreateStringWithCustomValidation(string name, string acceptedFormat, Func<Main, string> getter, Action<Main, string> setter, Func<string, bool> validator, string errorMessage) =>
	new(name,
		acceptedFormat,
		getter,
		(writer, settings) => writer.WriteString(name, getter(settings)),
		element =>
		{
			if (element.ValueKind is not JsonValueKind.String)
			{
				return DescriptorValidationResult.Failure($"'{name}' must be a JSON string.");
			}

			string? parsedValue = element.GetString();
			if (parsedValue is null || !validator(parsedValue))
			{
				return DescriptorValidationResult.Failure(errorMessage);
			}

			return DescriptorValidationResult.Success(settings => setter(settings, parsedValue));
		});
}

internal sealed class AppSettingDescriptor(string name, string acceptedFormat, Func<Main, string> getDisplayValue, Action<Utf8JsonWriter, Main> writeJsonValue, Func<JsonElement, DescriptorValidationResult> validateAndCreateAssignment)
{
	internal string Name => name;
	internal string AcceptedFormat => acceptedFormat;
	internal string GetDisplayValue(Main settings) => getDisplayValue(settings);
	internal void WriteJsonValue(Utf8JsonWriter writer, Main settings) => writeJsonValue(writer, settings);
	internal DescriptorValidationResult ValidateAndCreateAssignment(JsonElement value) => validateAndCreateAssignment(value);
}

internal readonly struct DescriptorValidationResult(Action<Main>? assignment, string? errorMessage)
{
	internal Action<Main>? Assignment => assignment;
	internal string? ErrorMessage => errorMessage;
	internal bool IsValid => assignment is not null && string.IsNullOrEmpty(errorMessage);
	internal static DescriptorValidationResult Failure(string errorMessage) => new(null, errorMessage);
	internal static DescriptorValidationResult Success(Action<Main> assignment) => new(assignment, null);
}
