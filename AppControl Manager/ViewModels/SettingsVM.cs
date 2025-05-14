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
using System.Linq;
using System.Threading.Tasks;
using AppControlManager.AppSettings;
using AppControlManager.IntelGathering;
using AppControlManager.Main;
using AppControlManager.Others;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Windows.Globalization;

namespace AppControlManager.ViewModels;

internal sealed partial class SettingsVM : ViewModelBase
{
	private MainWindowVM ViewModelMainWindow { get; } = App.AppHost.Services.GetRequiredService<MainWindowVM>();

	internal bool IsElevated => App.IsElevated;

	/// <summary>
	/// Opens a file picker for Code Integrity Schema path.
	/// </summary>
	internal void BrowseForCISchemaPath()
	{
		string? path = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XSDFilePickerFilter);

		if (path is not null)
			App.Settings.CiPolicySchemaPath = path;
	}

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
		{ "ml", 7 }

	};
	private static readonly Dictionary<int, string> SupportedLanguagesReverse = new()
	{
		{ 0, "en-US" },
		{ 1, "he" },
		{ 2, "el" },
		{ 3, "hi" },
		{ 4, "pl" },
		{ 5, "ar" },
		{ 6, "es" },
		{ 7, "ml" }
	};

	internal bool LanguageSectionSettingsExpanderInfoBarIsOpen { get; set => SP(ref field, value); }

	internal int LanguageComboBoxSelectedIndex
	{
		get; set
		{
			if (SP(ref field, value))
			{
				if (SupportedLanguagesReverse.TryGetValue(field, out string? x))
				{
					ApplicationLanguages.PrimaryLanguageOverride = x;
					App.Settings.ApplicationGlobalLanguage = x;
					LanguageSectionSettingsExpanderInfoBarIsOpen = true;
				}
				else
				{
					Logger.Write($"Unknown language Index: {field}");
				}
			}
		}
	} = SupportedLanguages.TryGetValue(App.Settings.ApplicationGlobalLanguage, out int x) ? x : 0;

	private static readonly Dictionary<string, int> AppThemes = new(StringComparer.OrdinalIgnoreCase)
	{
		{"Use System Setting", 0 },
		{"Dark", 1 },
		{"Light", 2 }
	};
	private static readonly Dictionary<int, string> AppThemesReverse = new()
	{
		{ 0, "Use System Setting" },
		{ 1, "Dark" },
		{ 2, "Light" }
	};

	internal int AppThemeComboBoxSelectedIndex
	{
		get; set
		{
			if (SP(ref field, value))
			{
				if (AppThemesReverse.TryGetValue(field, out string? x))
				{
					// Raise the global BackgroundChanged event
					AppThemeManager.OnAppThemeChanged(x);

					App.Settings.AppTheme = x;
				}
				else
				{
					Logger.Write($"Unknown theme Index: {field}");
				}
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

	internal string? SignedPolicyPathTextBox { get; set => SP(ref field, value); }
	internal string? UnsignedPolicyPathTextBox { get; set => SP(ref field, value); }
	internal string? SignToolCustomPathTextBox { get; set => SP(ref field, value); }
	internal string? CertificatePathTextBox { get; set => SP(ref field, value); }

	internal bool MainUserConfigurationsSettingsExpanderIsExpanded { get; set => SP(ref field, value); }

	// When the button to get the user configurations on the settings card is pressed
	internal void GetConfigurationButton()
	{
		UserConfiguration userConfig = UserConfiguration.Get();

		SignedPolicyPathTextBox = userConfig.SignedPolicyPath ?? string.Empty;
		UnsignedPolicyPathTextBox = userConfig.UnsignedPolicyPath ?? string.Empty;
		SignToolCustomPathTextBox = userConfig.SignToolCustomPath ?? string.Empty;
		CertCNsAutoSuggestBoxText = userConfig.CertificateCommonName ?? string.Empty;
		CertificatePathTextBox = userConfig.CertificatePath ?? string.Empty;

		// Expand the settings expander to make the configurations visible
		MainUserConfigurationsSettingsExpanderIsExpanded = true;
	}

	#region Signed Policy Path

	internal void EditButton_SignedPolicyPath_Click()
	{
		_ = UserConfiguration.Set(SignedPolicyPath: SignedPolicyPathTextBox);
		Logger.Write($"Edited SignedPolicyPathTextBox to {SignedPolicyPathTextBox}");
	}

	internal void ClearButton_SignedPolicyPath_Click()
	{
		UserConfiguration.Remove(SignedPolicyPath: true);
		Logger.Write("Cleared SignedPolicyPath");
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
		Logger.Write($"Edited UnsignedPolicyPath to {UnsignedPolicyPathTextBox}");
	}

	internal void ClearButton_UnsignedPolicyPath_Click()
	{
		UserConfiguration.Remove(UnsignedPolicyPath: true);
		Logger.Write("Cleared UnsignedPolicyPath");
		UnsignedPolicyPathTextBox = null;
	}

	internal void BrowseButton_UnsignedPolicyPath_Click()
	{
		UnsignedPolicyPathTextBox = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);
	}

	#endregion

	#region Custom Sign Tool Path

	internal void EditButton_SignToolCustomPath_Click()
	{
		_ = UserConfiguration.Set(SignToolCustomPath: SignToolCustomPathTextBox);
		Logger.Write($"Edited SignToolCustomPath to {SignToolCustomPathTextBox}");
	}

	internal void ClearButton_SignToolCustomPath_Click()
	{
		UserConfiguration.Remove(SignToolCustomPath: true);
		Logger.Write("Cleared SignToolCustomPath");
		SignToolCustomPathTextBox = null;
	}

	internal void BrowseButton_SignToolCustomPath_Click()
	{
		SignToolCustomPathTextBox = FileDialogHelper.ShowFilePickerDialog(GlobalVars.ExecutablesPickerFilter);
	}

	#endregion

	#region Certificate Common Name

	// To store the selectable Certificate common names
	internal readonly ObservableCollection<string> CertCommonNames = [];
	internal readonly List<string> CertCommonNamesList = [];

	internal string? CertCNsAutoSuggestBoxText { get; set => SP(ref field, value); }

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

	/// <summary>
	/// For the Refresh button that retrieves the latest certificate CNs
	/// </summary>
	internal async void FetchLatestCertificateCNs()
	{
		await FetchLatestCertificateCNsPrivate();
	}

	/// <summary>
	/// Handles the GotFocus event for the Certificate Common Name auto-suggest box. It opens the suggestion list when the
	/// box gains focus. Without this, the suggestion list would not open when the box is clicked, user would have to type something first.
	/// </summary>
	internal async void CertificateCommonNameAutoSuggestBox_GotFocus()
	{
		if (!_InitialFetchComplete)
		{
			_InitialFetchComplete = true;

			await FetchLatestCertificateCNsPrivate();
		}

		CertCNAutoSuggestBoxIsSuggestionListOpen = true;
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
		Logger.Write($"Edited CertificateCommonName to {CertCNsAutoSuggestBoxText}");
	}

	internal void ClearButton_CertificateCommonName_Click()
	{
		UserConfiguration.Remove(CertificateCommonName: true);
		Logger.Write("Cleared CertificateCommonName");
		CertCNsAutoSuggestBoxText = null;
	}

	#endregion

	#region Certificate Path

	internal void EditButton_CertificatePath_Click()
	{
		_ = UserConfiguration.Set(CertificatePath: CertificatePathTextBox);
		Logger.Write($"Edited CertificatePath to {CertificatePathTextBox}");
	}

	internal void ClearButton_CertificatePath_Click()
	{
		UserConfiguration.Remove(CertificatePath: true);
		Logger.Write("Cleared CertificatePath");
		CertificatePathTextBox = null;
	}

	internal void BrowseButton_CertificatePath_Click()
	{
		CertificatePathTextBox = FileDialogHelper.ShowFilePickerDialog(GlobalVars.CertificatePickerFilter);
	}

	#endregion

}
