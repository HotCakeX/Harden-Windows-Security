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
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using AppControlManager.ViewModels;
using HardenSystemSecurity.GroupPolicy;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.ViewModels;

/// <summary>
/// Data model for targeted lists ComboBox items.
/// </summary>
/// <param name="title"></param>
/// <param name="learnMoreUrl"></param>
internal sealed class ComboBoxItemModelForCountryIPBlocking(string title, string learnMoreUrl)
{
	internal string Title => title;
	internal string LearnMoreUrl => learnMoreUrl;
}

/// <summary>
/// Model representing country data from the JSON file.
/// </summary>
internal sealed class CountryData(
	string alpha2Code,
	string alpha3Code,
	string ipv4Link,
	string ipv6Link,
	string friendlyName
	)
{
	[JsonPropertyName("Alpha2Code")]
	[JsonInclude]
	internal string Alpha2Code => alpha2Code;

	[JsonPropertyName("Alpha3Code")]
	[JsonInclude]
	internal string Alpha3Code => alpha3Code;

	[JsonPropertyName("IPv4Link")]
	[JsonInclude]
	internal string IPv4Link => ipv4Link;

	[JsonPropertyName("IPv6Link")]
	[JsonInclude]
	internal string IPv6Link => ipv6Link;

	[JsonPropertyName("FriendlyName")]
	[JsonInclude]
	internal string FriendlyName => friendlyName;
}

/// <summary>
/// JSON source generation context for <see cref="CountryData"/>
/// </summary>
[JsonSourceGenerationOptions(WriteIndented = false, PropertyNamingPolicy = JsonKnownNamingPolicy.CamelCase)]
[JsonSerializable(typeof(CountryData[]))]
internal sealed partial class CountryDataJsonContext : JsonSerializerContext
{
}

internal sealed partial class CountryIPBlockingVM : ViewModelBase
{
	internal CountryIPBlockingVM()
	{
		MainInfoBar = new InfoBarSettings(
			() => MainInfoBarIsOpen, value => MainInfoBarIsOpen = value,
			() => MainInfoBarMessage, value => MainInfoBarMessage = value,
			() => MainInfoBarSeverity, value => MainInfoBarSeverity = value,
			() => MainInfoBarIsClosable, value => MainInfoBarIsClosable = value,
			Dispatcher, null, null);

		// Load countries data
		_ = LoadCountriesDataAsync();
	}

	/// <summary>
	/// The main InfoBar for this VM.
	/// </summary>
	internal readonly InfoBarSettings MainInfoBar;

	internal bool MainInfoBarIsOpen { get; set => SP(ref field, value); }
	internal string? MainInfoBarMessage { get; set => SP(ref field, value); }
	internal InfoBarSeverity MainInfoBarSeverity { get; set => SP(ref field, value); } = InfoBarSeverity.Informational;
	internal bool MainInfoBarIsClosable { get; set => SP(ref field, value); }

	internal Visibility ProgressBarVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;

	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressBarVisibility = field ? Visibility.Collapsed : Visibility.Visible;
			}
		}
	} = true;

	internal int TargetedListSelectedIndex { get; set => SP(ref field, value); }
	internal int CountrySelectedIndex { get; set => SP(ref field, value); }

	/// <summary>
	/// Search text for filtering countries
	/// </summary>
	internal string? CountrySearchText
	{
		get; set
		{
			if (SP(ref field, value))
			{
				FilterCountries();
			}
		}
	}

	private const string RuleNameForSSOT = "State Sponsors of Terrorism IP range blocking";

	internal List<ComboBoxItemModelForCountryIPBlocking> TargetedLists =
	[
		new ComboBoxItemModelForCountryIPBlocking
		(
			title: "State Sponsors of Terrorism",
			learnMoreUrl: "https://www.state.gov/state-sponsors-of-terrorism/"
		),
		new ComboBoxItemModelForCountryIPBlocking
		(
			title: "Office of Foreign Assets Control",
			learnMoreUrl: "https://ofac.treasury.gov/sanctions-programs-and-country-information"
		)
	];

	/// <summary>
	/// ComboBox's ItemsSource.
	/// </summary>
	internal ObservableCollection<CountryData> CountryLists { get; } = [];

	/// <summary>
	/// All countries loaded from JSON (unfiltered)
	/// </summary>
	private List<CountryData> _allCountries = [];

	/// <summary>
	/// The path to the JSON file containing the country data.
	/// </summary>
	private static readonly string jsonPath = Path.Combine(AppContext.BaseDirectory, "Resources", "CountryIPsData", "CountriesData.json");

	/// <summary>
	/// Filters countries based on search text
	/// </summary>
	private void FilterCountries()
	{
		if (_allCountries.Count == 0)
			return;

		List<CountryData> filteredCountries;

		if (string.IsNullOrWhiteSpace(CountrySearchText))
		{
			// Show all countries if search is empty
			filteredCountries = _allCountries;
		}
		else
		{
			// Filter countries by friendly name or alpha codes
			filteredCountries = _allCountries
				.Where(country =>
					country.FriendlyName.Contains(CountrySearchText, StringComparison.OrdinalIgnoreCase) ||
					country.Alpha2Code.Contains(CountrySearchText, StringComparison.OrdinalIgnoreCase) ||
					country.Alpha3Code.Contains(CountrySearchText, StringComparison.OrdinalIgnoreCase))
				.ToList();
		}

		// Update UI on the dispatcher thread
		_ = Dispatcher.TryEnqueue(() =>
		{
			// Update the observable collection
			CountryLists.Clear();
			foreach (CountryData country in filteredCountries)
			{
				CountryLists.Add(country);
			}

			// Set selected index to 0 if search yields results, otherwise clear selection
			CountrySelectedIndex = CountryLists.Count > 0 ? 0 : -1;
		});
	}

	/// <summary>
	/// Loads country data from the JSON file.
	/// </summary>
	private async Task LoadCountriesDataAsync()
	{
		try
		{
			ElementsAreEnabled = false;
			Logger.Write(GlobalVars.GetStr("LoadingCountriesDataMessage"));

			await Task.Run(() =>
			{
				// Read and deserialize the JSON file
				byte[] jsonContent = File.ReadAllBytes(jsonPath);
				CountryData[]? countries = JsonSerializer.Deserialize(jsonContent, CountryDataJsonContext.Default.CountryDataArray) ?? throw new InvalidOperationException("Failed to deserialize countries data");

				// Sort by friendly name
				List<CountryData> countryItems = countries
					.OrderBy(item => item.FriendlyName, StringComparer.OrdinalIgnoreCase)
					.ToList();

				_allCountries = countryItems;

				FilterCountries(); // Initial population
			});

			Logger.Write(string.Format(GlobalVars.GetStr("CountriesLoadedSuccessMessage"), _allCountries.Count));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Event handler for the UI.
	/// </summary>
	internal async void TargetedListAdd() => await TargetedListAddInternal();

	/// <summary>
	/// Method for adding rules for targeted lists.
	/// </summary>
	internal async Task TargetedListAddInternal()
	{
		try
		{
			ElementsAreEnabled = false;

			await Task.Run(() =>
			{
				switch (TargetedListSelectedIndex)
				{
					case 0:
						{
							MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("CreatingRulesForMessage"), RuleNameForSSOT));

							Logger.Write(ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"firewall \"{RuleNameForSSOT}\" https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/StateSponsorsOfTerrorism.txt true"));
							break;
						}
					case 1:
						{
							const string ruleName = "OFAC Sanctioned Countries IP range blocking";

							MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("CreatingRulesForMessage"), ruleName));

							Logger.Write(ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"firewall \"{ruleName}\" https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/OFACSanctioned.txt true"));
							break;
						}
					default: break;
				}

				// Update policies to take effect immediately
				CSEMgr.RegisterCSEGuids();
			});

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessfullyAddedIPRangeMessage"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Event handler for the UI.
	/// </summary>
	internal async void TargetedListRemove() => await TargetedListRemoveInternal();

	/// <summary>
	/// Method for removing rules for targeted lists.
	/// </summary>
	internal async Task TargetedListRemoveInternal()
	{
		try
		{
			ElementsAreEnabled = false;

			await Task.Run(() =>
			{
				switch (TargetedListSelectedIndex)
				{
					case 0:
						{
							MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("RemovingRulesForMessage"), RuleNameForSSOT));

							Logger.Write(ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"firewall \"{RuleNameForSSOT}\" https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/StateSponsorsOfTerrorism.txt false"));
							break;
						}
					case 1:
						{
							const string ruleName = "OFAC Sanctioned Countries IP range blocking";

							MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("RemovingRulesForMessage"), ruleName));

							Logger.Write(ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"firewall \"{ruleName}\" https://raw.githubusercontent.com/HotCakeX/Official-IANA-IP-blocks/main/Curated-Lists/OFACSanctioned.txt false"));
							break;
						}
					default: break;
				}

				// Update policies to take effect immediately
				CSEMgr.RegisterCSEGuids();
			});

			MainInfoBar.WriteSuccess(GlobalVars.GetStr("SuccessfullyRemovedIPRangeMessage"));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Method for adding IP blocking rules for the selected country.
	/// </summary>
	internal async void CountryAdd()
	{
		try
		{
			if (CountrySelectedIndex < 0 || CountrySelectedIndex >= CountryLists.Count)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("PleaseSelectCountryWarning"));
				return;
			}

			ElementsAreEnabled = false;

			CountryData selectedCountry = CountryLists[CountrySelectedIndex];

			await Task.Run(() =>
			{
				string ruleNameIPv4 = $"{selectedCountry.FriendlyName} IPv4 IP range blocking";
				string ruleNameIPv6 = $"{selectedCountry.FriendlyName} IPv6 IP range blocking";

				MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("CreatingIPv4RulesMessage"), selectedCountry.FriendlyName));

				// Add IPv4 rules
				Logger.Write(ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"firewall \"{ruleNameIPv4}\" {selectedCountry.IPv4Link} true"));

				MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("CreatingIPv6RulesMessage"), selectedCountry.FriendlyName));

				// Add IPv6 rules
				Logger.Write(ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"firewall \"{ruleNameIPv6}\" {selectedCountry.IPv6Link} true"));

				// Update policies to take effect immediately
				CSEMgr.RegisterCSEGuids();
			});

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyAddedIPBlockingRulesMessage"), selectedCountry.FriendlyName));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	/// <summary>
	/// Method for removing IP blocking rules for the selected country
	/// </summary>
	internal async void CountryRemove()
	{
		try
		{
			if (CountrySelectedIndex < 0 || CountrySelectedIndex >= CountryLists.Count)
			{
				MainInfoBar.WriteWarning(GlobalVars.GetStr("PleaseSelectCountryWarning"));
				return;
			}

			ElementsAreEnabled = false;

			CountryData selectedCountry = CountryLists[CountrySelectedIndex];

			await Task.Run(() =>
			{
				string ruleNameIPv4 = $"{selectedCountry.FriendlyName} IPv4 IP range blocking";
				string ruleNameIPv6 = $"{selectedCountry.FriendlyName} IPv6 IP range blocking";

				MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("RemovingIPv4RulesMessage"), selectedCountry.FriendlyName));

				// Remove IPv4 rules
				Logger.Write(ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"firewall \"{ruleNameIPv4}\" {selectedCountry.IPv4Link} false"));

				MainInfoBar.WriteInfo(string.Format(GlobalVars.GetStr("RemovingIPv6RulesMessage"), selectedCountry.FriendlyName));

				// Remove IPv6 rules
				Logger.Write(ProcessStarter.RunCommand(GlobalVars.ComManagerProcessPath, $"firewall \"{ruleNameIPv6}\" {selectedCountry.IPv6Link} false"));

				// Update policies to take effect immediately
				CSEMgr.RegisterCSEGuids();
			});

			MainInfoBar.WriteSuccess(string.Format(GlobalVars.GetStr("SuccessfullyRemovedIPBlockingRulesMessage"), selectedCountry.FriendlyName));
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
		}
	}

	internal async Task AddSSOT()
	{
		TargetedListSelectedIndex = 0;
		await TargetedListAddInternal();
	}

	internal async Task RemoveSSOT()
	{
		TargetedListSelectedIndex = 0;
		await TargetedListRemoveInternal();
	}

}
