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
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using AppControlManager.SiPolicy;
using CommonCore.ToolKits;
using Microsoft.UI.Xaml;

namespace AppControlManager.ViewModels;

/// <summary>
/// A selectable inventory row. Selecting the row enables both policies. The first and second count chips can then be toggled independently.
/// </summary>
internal sealed partial class PolicyElementCountItem(
	string key,
	string section,
	int firstCount,
	int secondCount,
	string note,
	Action<PolicyElementCountItem> changed) : ViewModelBase
{
	internal string Key => key;
	internal string Section => section;
	internal int FirstCount => firstCount;
	internal int SecondCount => secondCount;
	internal string Note => note;
	internal string DeltaText => firstCount == secondCount ? "Same" : firstCount > secondCount ? $"First +{firstCount - secondCount}" : $"Second +{secondCount - firstCount}";

	internal bool? IsFirstEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				changed(this);
			}
		}
	} = true;

	internal bool? IsSecondEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				changed(this);
			}
		}
	} = true;

	internal void EnableBoth()
	{
		IsFirstEnabled = true;
		IsSecondEnabled = true;
	}
}

/// <summary>
/// A single item displayed in the right side preview pane.
/// </summary>
internal sealed class PolicyPreviewItem(
	string title,
	string details,
	bool inFirstPolicy,
	bool inSecondPolicy,
	string sharedDetails,
	string differentDetails)
{
	internal string Title => title;
	internal string Details => details;
	internal string SharedDetails => sharedDetails;
	internal string DifferentDetails => differentDetails;
	internal Visibility FirstPolicyLabelVisibility => inFirstPolicy ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility SecondPolicyLabelVisibility => inSecondPolicy ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility SharedDetailsVisibility => string.IsNullOrWhiteSpace(sharedDetails) ? Visibility.Collapsed : Visibility.Visible;
	internal Visibility DifferentDetailsVisibility => string.IsNullOrWhiteSpace(differentDetails) ? Visibility.Collapsed : Visibility.Visible;
	internal Visibility RawDetailsVisibility => string.IsNullOrWhiteSpace(sharedDetails) && string.IsNullOrWhiteSpace(differentDetails) ? Visibility.Visible : Visibility.Collapsed;
}

/// <summary>
/// View model for the Compare Policies page. All comparison, inventory, preview, and JSON export logic etc. lives here.
/// </summary>
internal sealed partial class ComparePoliciesVM : ViewModelBase
{

	private const string PreviewSortBoth = "Both";
	private const string PreviewSortFirstPolicy = "First Policy";
	private const string PreviewSortSecondPolicy = "Second Policy";

	private static readonly PolicyComparisonJsonContext JsonExportContext = new(new JsonSerializerOptions
	{
		Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
		WriteIndented = true
	});

	internal readonly InfoBarSettings MainInfoBar = new();
	internal readonly ObservableCollection<PolicyElementCountItem> ElementCounts = [];
	internal readonly ObservableCollection<PolicyPreviewItem> PreviewItems = [];
	internal readonly List<string> PreviewSortOptions = [PreviewSortBoth, PreviewSortFirstPolicy, PreviewSortSecondPolicy];
	internal string SelectedPreviewSortOption { get; set => SP(ref field, value); } = PreviewSortBoth;

	internal PolicyFileRepresent? FirstPolicy { get; set => SP(ref field, value); }
	internal PolicyFileRepresent? SecondPolicy { get; set => SP(ref field, value); }
	private PolicyCatalog? FirstCatalog;
	private PolicyCatalog? SecondCatalog;

	internal ComparePoliciesVM()
	{
		ElementCounts.CollectionChanged += (sender, args) => OnPropertyChanged(nameof(InventoryEmptyStateVisibility));
		PreviewItems.CollectionChanged += (sender, args) => OnPropertyChanged(nameof(PreviewEmptyStateVisibility));
	}

	internal bool ElementsAreEnabled
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ProgressRingVisibility = field ? Visibility.Collapsed : Visibility.Visible;
				MainInfoBar.IsClosable = field;
			}
		}
	} = true;

	internal Visibility ProgressRingVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility FirstPolicyLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility SecondPolicyLightAnimatedIconVisibility { get; set => SP(ref field, value); } = Visibility.Collapsed;
	internal string? PreviewTitle { get; set => SP(ref field, value); }
	internal string? PreviewSubtitle { get; set => SP(ref field, value); }

	internal object? SelectedElementCountItem
	{
		get; set
		{
			if (SP(ref field, value) && field is PolicyElementCountItem item)
			{
				item.EnableBoth();
				RefreshPreviewForItem(item);
			}
		}
	}

	internal Visibility InventoryEmptyStateVisibility => ElementCounts.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility PreviewEmptyStateVisibility => PreviewItems.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

	internal async void BrowseForFirstPolicy()
	{
		try
		{
			ElementsAreEnabled = false;

			string? selectedFile = FileDialogHelper.ShowFilePickerDialog(Atlas.MultiAppControlPolicyPickerFilter);
			if (string.IsNullOrEmpty(selectedFile))
			{
				return;
			}

			FirstPolicy = await Task.Run(() => PolicyEditorVM.ParseFilePathAsPolicyRepresent(selectedFile));
			ClearComparisonOutput();
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

	internal async void BrowseForSecondPolicy()
	{
		try
		{
			ElementsAreEnabled = false;

			string? selectedFile = FileDialogHelper.ShowFilePickerDialog(Atlas.MultiAppControlPolicyPickerFilter);
			if (string.IsNullOrEmpty(selectedFile))
			{
				return;
			}

			SecondPolicy = await Task.Run(() => PolicyEditorVM.ParseFilePathAsPolicyRepresent(selectedFile));
			ClearComparisonOutput();
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

	internal void ClearFirstPolicy()
	{
		FirstPolicy = null;
		ClearComparisonOutput();
	}

	internal void ClearSecondPolicy()
	{
		SecondPolicy = null;
		ClearComparisonOutput();
	}

	private void ClearComparisonOutput()
	{
		ElementCounts.Clear();
		PreviewItems.Clear();
		FirstCatalog = null;
		SecondCatalog = null;
		SelectedElementCountItem = null;
		PreviewTitle = null;
		PreviewSubtitle = null;
	}

	internal async void CompareLogic()
	{
		try
		{
			ElementsAreEnabled = false;

			if (FirstPolicy is null || SecondPolicy is null)
			{
				MainInfoBar.WriteWarning(Atlas.GetStr("ComparePolicies_SelectBothMessage"));
				return;
			}

			MainInfoBar.WriteInfo(Atlas.GetStr("ComparePolicies_ComparingMessage"));
			await Atlas.AppDispatcher.EnqueueAsync(ClearComparisonOutput);

			PolicyCatalog firstCatalog = await Task.Run(() => PolicyCatalog.Create(FirstPolicy.PolicyObj));
			PolicyCatalog secondCatalog = await Task.Run(() => PolicyCatalog.Create(SecondPolicy.PolicyObj));

			await Atlas.AppDispatcher.EnqueueAsync(() =>
			{
				FirstCatalog = firstCatalog;
				SecondCatalog = secondCatalog;
				PopulateInventory(firstCatalog, secondCatalog);

				if (ElementCounts.Count > 0)
				{
					SelectedElementCountItem = ElementCounts[0];
				}
			});

			MainInfoBar.WriteSuccess("Policy inventory comparison completed. Select a section on the left to preview its items.");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	internal async void ExportResultsToJsonLogic()
	{
		try
		{
			if (FirstCatalog is null || SecondCatalog is null)
			{
				MainInfoBar.WriteWarning("Run a comparison before exporting JSON.");
				return;
			}

			ElementsAreEnabled = false;

			string? filePathToSaveTo = FileDialogHelper.ShowSaveFileDialog(Atlas.JSONPickerFilter, "Policy comparison export results.json");
			if (filePathToSaveTo is null)
			{
				MainInfoBar.WriteWarning("You need to select a location to save the exported file to.");
				return;
			}

			string json = await Task.Run(() =>
			{
				PolicyComparisonExportModel exportModel = BuildExportModel(FirstCatalog, SecondCatalog);
				return JsonSerializer.Serialize(exportModel, JsonExportContext.PolicyComparisonExportModel);
			});

			await File.WriteAllTextAsync(filePathToSaveTo, json, Encoding.UTF8);
			MainInfoBar.WriteSuccess($"Exported the comparison result to {filePathToSaveTo}");
		}
		catch (Exception ex)
		{
			MainInfoBar.WriteError(ex);
		}
		finally
		{
			ElementsAreEnabled = true;
			MainInfoBar.IsClosable = true;
		}
	}

	private PolicyComparisonExportModel BuildExportModel(PolicyCatalog firstCatalog, PolicyCatalog secondCatalog)
	{
		List<PolicyInventoryExportModel> inventory = new(ElementCounts.Count);
		List<PolicySectionExportModel> sections = new(ElementCounts.Count);

		foreach (PolicyElementCountItem item in ElementCounts)
		{
			PolicySection firstSection = firstCatalog.GetSection(item.Key);
			PolicySection secondSection = secondCatalog.GetSection(item.Key);
			List<PolicyPreviewExportModel> previewItems = BuildSectionExportItems(firstSection, secondSection);

			inventory.Add(new PolicyInventoryExportModel
			{
				Section = item.Section,
				Note = item.Note,
				FirstCount = item.FirstCount,
				SecondCount = item.SecondCount,
				Delta = item.DeltaText
			});

			sections.Add(new PolicySectionExportModel
			{
				Section = item.Section,
				Note = item.Note,
				FirstCount = item.FirstCount,
				SecondCount = item.SecondCount,
				Items = previewItems
			});
		}

		return new PolicyComparisonExportModel
		{
			SchemaVersion = 1,
			ExportedAtUtc = DateTimeOffset.UtcNow,
			FirstPolicyName = FirstPolicy?.PolicyIdentifier ?? string.Empty,
			SecondPolicyName = SecondPolicy?.PolicyIdentifier ?? string.Empty,
			FirstPolicyPath = FirstPolicy?.FilePath ?? string.Empty,
			SecondPolicyPath = SecondPolicy?.FilePath ?? string.Empty,
			Inventory = inventory,
			Sections = sections
		};
	}

	private static List<PolicyPreviewExportModel> BuildSectionExportItems(PolicySection firstSection, PolicySection secondSection)
	{
		HashSet<string> keys = [.. firstSection.Items.Keys, .. secondSection.Items.Keys];
		List<PolicyPreviewExportModel> items = [];

		foreach (string key in keys.OrderBy(static x => x, StringComparer.OrdinalIgnoreCase))
		{
			bool inFirstPolicy = firstSection.Items.TryGetValue(key, out PolicyPreviewSource? firstSource);
			bool inSecondPolicy = secondSection.Items.TryGetValue(key, out PolicyPreviewSource? secondSource);
			ComparisonSummary summary = BuildComparisonSummary(firstSource, secondSource);

			items.Add(new PolicyPreviewExportModel
			{
				Title = firstSource?.Title ?? secondSource?.Title ?? key,
				InFirstPolicy = inFirstPolicy,
				InSecondPolicy = inSecondPolicy,
				FirstDetails = firstSource?.Details ?? string.Empty,
				SecondDetails = secondSource?.Details ?? string.Empty,
				SharedDetails = summary.SharedDetails,
				DifferentDetails = summary.DifferentDetails
			});
		}

		return items;
	}

	private void PopulateInventory(PolicyCatalog first, PolicyCatalog second)
	{
		ElementCounts.Clear();
		ElementCounts.Add(new("EKUs", "EKUs", first.Ekus.Count, second.Ekus.Count, "Unique EKU definitions available for signer constraints.", RefreshPreviewForItem));
		ElementCounts.Add(new("AllFileRules", "All file rules", first.AllFileRules.Count, second.AllFileRules.Count, "All Allow, Deny, FileAttrib, and generic FileRule elements.", RefreshPreviewForItem));
		ElementCounts.Add(new("AllowRules", "Allow rules", first.AllowRules.Count, second.AllowRules.Count, "Direct allow file rules in the FileRules section.", RefreshPreviewForItem));
		ElementCounts.Add(new("DenyRules", "Deny rules", first.DenyRules.Count, second.DenyRules.Count, "Direct deny file rules in the FileRules section.", RefreshPreviewForItem));
		ElementCounts.Add(new("FileAttributes", "File attributes", first.FileAttributes.Count, second.FileAttributes.Count, "File publisher attributes referenced by signers.", RefreshPreviewForItem));
		ElementCounts.Add(new("GenericFileRules", "Generic FileRule elements", first.GenericFileRules.Count, second.GenericFileRules.Count, "Schema FileRule elements with Match, Exclude, or Attribute type.", RefreshPreviewForItem));
		ElementCounts.Add(new("Signers", "Signers", first.Signers.Count, second.Signers.Count, "Signer definitions in the Signers section.", RefreshPreviewForItem));
		ElementCounts.Add(new("CiSigners", "CI signers", first.CiSigners.Count, second.CiSigners.Count, "Signers trusted for CI policy signing semantics.", RefreshPreviewForItem));
		ElementCounts.Add(new("UpdatePolicySigners", "Update policy signers", first.UpdatePolicySigners.Count, second.UpdatePolicySigners.Count, "Signers authorized to update the policy.", RefreshPreviewForItem));
		ElementCounts.Add(new("SupplementalPolicySigners", "Supplemental policy signers", first.SupplementalPolicySigners.Count, second.SupplementalPolicySigners.Count, "Signers authorized for supplemental policies.", RefreshPreviewForItem));
		ElementCounts.Add(new("SigningScenarios", "Signing scenarios", first.SigningScenarios.Count, second.SigningScenarios.Count, "Total signing scenarios in the policy.", RefreshPreviewForItem));
		ElementCounts.Add(new("UserModeAllowedSigners", "User mode allowed signers", first.UserModeAllowedSigners.Count, second.UserModeAllowedSigners.Count, "Allowed signer references in signing scenario value 12.", RefreshPreviewForItem));
		ElementCounts.Add(new("UserModeDeniedSigners", "User mode denied signers", first.UserModeDeniedSigners.Count, second.UserModeDeniedSigners.Count, "Denied signer references in signing scenario value 12.", RefreshPreviewForItem));
		ElementCounts.Add(new("UserModeFileRuleRefs", "User mode file rule refs", first.UserModeFileRuleRefs.Count, second.UserModeFileRuleRefs.Count, "File rule references in signing scenario value 12.", RefreshPreviewForItem));
		ElementCounts.Add(new("KernelModeAllowedSigners", "Kernel mode allowed signers", first.KernelModeAllowedSigners.Count, second.KernelModeAllowedSigners.Count, "Allowed signer references in signing scenario value 131.", RefreshPreviewForItem));
		ElementCounts.Add(new("KernelModeDeniedSigners", "Kernel mode denied signers", first.KernelModeDeniedSigners.Count, second.KernelModeDeniedSigners.Count, "Denied signer references in signing scenario value 131.", RefreshPreviewForItem));
		ElementCounts.Add(new("KernelModeFileRuleRefs", "Kernel mode file rule refs", first.KernelModeFileRuleRefs.Count, second.KernelModeFileRuleRefs.Count, "File rule references in signing scenario value 131.", RefreshPreviewForItem));
		ElementCounts.Add(new("Settings", "Settings", first.Settings.Count, second.Settings.Count, "All settings in the Settings section, including PolicyInfo metadata.", RefreshPreviewForItem));
		ElementCounts.Add(new("Macros", "Macros", first.Macros.Count, second.Macros.Count, "Macro definitions used by file rules and settings.", RefreshPreviewForItem));
		ElementCounts.Add(new("AppSettings", "App settings", first.AppSettings.Count, second.AppSettings.Count, "Application settings under AppSettings.", RefreshPreviewForItem));
		ElementCounts.Add(new("AppIDTags", "AppID tags", first.AppIdTags.Count, second.AppIdTags.Count, "AppID tags across signing scenarios.", RefreshPreviewForItem));
	}

	internal void ApplyPreviewSortLogic()
	{
		if (SelectedElementCountItem is PolicyElementCountItem item)
		{
			RefreshPreviewForItem(item);
		}
	}

	private void RefreshPreviewForItem(PolicyElementCountItem item)
	{
		if (FirstCatalog is null || SecondCatalog is null)
		{
			return;
		}

		PolicySection firstSection = FirstCatalog.GetSection(item.Key);
		PolicySection secondSection = SecondCatalog.GetSection(item.Key);
		HashSet<string> keys = [];

		if (item.IsFirstEnabled is true)
		{
			keys.UnionWith(firstSection.Items.Keys);
		}

		if (item.IsSecondEnabled is true)
		{
			keys.UnionWith(secondSection.Items.Keys);
		}

		List<(int SortRank, string Title, PolicyPreviewItem Item)> sortedItems = new(keys.Count);

		foreach (string key in keys)
		{
			PolicyPreviewSource? firstSource = null;
			PolicyPreviewSource? secondSource = null;
			bool inFirstPolicy = item.IsFirstEnabled is true && firstSection.Items.TryGetValue(key, out firstSource);
			bool inSecondPolicy = item.IsSecondEnabled is true && secondSection.Items.TryGetValue(key, out secondSource);
			ComparisonSummary summary = BuildComparisonSummary(firstSource, secondSource);
			string title = firstSource?.Title ?? secondSource?.Title ?? key;
			string details = summary.HasDetails ? string.Empty : BuildPreviewDetails(firstSource?.Details, secondSource?.Details, inFirstPolicy, inSecondPolicy);
			PolicyPreviewItem previewItem = new(title, details, inFirstPolicy, inSecondPolicy, summary.SharedDetails, summary.DifferentDetails);
			sortedItems.Add((GetPreviewSortRank(inFirstPolicy, inSecondPolicy), title, previewItem));
		}

		PreviewItems.Clear();

		foreach ((int SortRank, string Title, PolicyPreviewItem Item) in sortedItems.OrderBy(static x => x.SortRank).ThenBy(static x => x.Title, StringComparer.OrdinalIgnoreCase))
		{
			PreviewItems.Add(Item);
		}

		PreviewTitle = item.Section;
		PreviewSubtitle = BuildPreviewSubtitle(item.IsFirstEnabled is true, item.IsSecondEnabled is true);
	}

	private int GetPreviewSortRank(bool inFirstPolicy, bool inSecondPolicy)
	{
		if (string.Equals(SelectedPreviewSortOption, PreviewSortFirstPolicy, StringComparison.OrdinalIgnoreCase))
		{
			return inFirstPolicy && !inSecondPolicy ? 0 : inFirstPolicy ? 1 : 2;
		}

		if (string.Equals(SelectedPreviewSortOption, PreviewSortSecondPolicy, StringComparison.OrdinalIgnoreCase))
		{
			return inSecondPolicy && !inFirstPolicy ? 0 : inSecondPolicy ? 1 : 2;
		}

		return inFirstPolicy && inSecondPolicy ? 0 : inFirstPolicy ? 1 : 2;
	}

	private static ComparisonSummary BuildComparisonSummary(PolicyPreviewSource? firstSource, PolicyPreviewSource? secondSource) =>
		firstSource is not null && secondSource is not null
			? CompareSources(firstSource, secondSource)
			: ComparisonSummary.Empty;

	private static ComparisonSummary CompareSources(PolicyPreviewSource firstSource, PolicyPreviewSource secondSource)
	{
		PropertyComparison comparison = CompareProperties(firstSource.Properties, secondSource.Properties);
		return new(BuildPropertyListText(comparison.Shared), BuildPropertyListText(comparison.Different));
	}

	private static PropertyComparison CompareProperties(IReadOnlyList<PropertyFact> firstProperties, IReadOnlyList<PropertyFact> secondProperties)
	{
		Dictionary<string, PropertyFact> secondPropertiesByName = new(secondProperties.Count, StringComparer.OrdinalIgnoreCase);

		foreach (PropertyFact secondProperty in secondProperties)
		{
			secondPropertiesByName[secondProperty.Name] = secondProperty;
		}

		List<string> shared = new(firstProperties.Count);
		List<string> different = new(firstProperties.Count);

		foreach (PropertyFact firstProperty in firstProperties)
		{
			if (!secondPropertiesByName.TryGetValue(firstProperty.Name, out PropertyFact? secondProperty))
			{
				continue;
			}

			if (string.IsNullOrWhiteSpace(firstProperty.Value) && string.IsNullOrWhiteSpace(secondProperty.Value))
			{
				continue;
			}

			if (string.Equals(firstProperty.Value, secondProperty.Value, StringComparison.OrdinalIgnoreCase))
			{
				shared.Add(string.IsNullOrWhiteSpace(firstProperty.Name) ? firstProperty.Value : $"{firstProperty.Name}: {firstProperty.Value}");
			}
			else
			{
				StringBuilder builder = new();

				if (!string.IsNullOrWhiteSpace(firstProperty.Name))
				{
					_ = builder.Append(firstProperty.Name);
				}

				if (!string.IsNullOrWhiteSpace(firstProperty.Value))
				{
					if (builder.Length > 0)
					{
						_ = builder.Append('\n');
					}

					_ = builder.Append("First policy: ").Append(firstProperty.Value);
				}

				if (!string.IsNullOrWhiteSpace(secondProperty.Value))
				{
					if (builder.Length > 0)
					{
						_ = builder.Append('\n');
					}

					_ = builder.Append("Second policy: ").Append(secondProperty.Value);
				}

				different.Add(builder.ToString());
			}
		}

		return new(shared, different);
	}

	private static string BuildPropertyListText(IReadOnlyList<string> values)
	{
		StringBuilder builder = new();

		foreach (string value in values)
		{
			if (string.IsNullOrWhiteSpace(value))
			{
				continue;
			}

			if (builder.Length > 0)
			{
				_ = builder.Append('\n').Append('\n');
			}

			_ = builder.Append('•').Append(' ').Append(value);
		}

		return builder.ToString();
	}

	private static string BuildDetails(params (string Label, string? Value)[] lines)
	{
		StringBuilder builder = new();

		foreach ((string Label, string? Value) in lines)
		{
			if (string.IsNullOrWhiteSpace(Value))
			{
				continue;
			}

			if (builder.Length > 0)
			{
				_ = builder.Append('\n');
			}

			_ = Label.Length == 0
				? builder.Append(Value)
				: Value.Contains('\n', StringComparison.Ordinal)
					? builder.Append(Label).Append(':').Append('\n').Append(Value)
					: builder.Append(Label).Append(": ").Append(Value);
		}

		return builder.ToString();
	}

	private static List<PropertyFact> BuildPropertyFacts(params (string Name, string? Value)[] facts)
	{
		List<PropertyFact> result = new(facts.Length);

		foreach ((string Name, string? Value) in facts)
		{
			if (!string.IsNullOrWhiteSpace(Value))
			{
				result.Add(new(Name, Value));
			}
		}

		return result;
	}

	private static string BuildPreviewSubtitle(bool includeFirstPolicy, bool includeSecondPolicy)
	{
		if (includeFirstPolicy && includeSecondPolicy)
		{
			return "Showing first policy and second policy items. Items present in both selected policies show both color labels.";
		}

		if (includeFirstPolicy)
		{
			return "Showing first policy items only.";
		}

		return includeSecondPolicy ? "Showing second policy items only." : "No policy source is enabled for this section.";
	}

	private static string BuildPreviewDetails(string? firstDetails, string? secondDetails, bool inFirstPolicy, bool inSecondPolicy)
	{
		if (inFirstPolicy && inSecondPolicy && string.Equals(firstDetails, secondDetails, StringComparison.OrdinalIgnoreCase))
		{
			return firstDetails ?? string.Empty;
		}

		if (inFirstPolicy && inSecondPolicy)
		{
			return $"First: {firstDetails}\nSecond: {secondDetails}";
		}

		return inFirstPolicy ? firstDetails ?? string.Empty : secondDetails ?? string.Empty;
	}

	private static string Hex(ReadOnlyMemory<byte> value) => value.IsEmpty ? string.Empty : Convert.ToHexString(value.Span);

	private static string SettingValueToString(SettingValueType? settingValue)
	{
		if (settingValue?.Item is null)
		{
			return string.Empty;
		}

		return settingValue.Item switch
		{
			byte[] bytes => Convert.ToHexString(bytes),
			ReadOnlyMemory<byte> bytes => Hex(bytes),
			bool boolean => boolean.ToString(),
			uint number => number.ToString(),
			string text => text,
			_ => settingValue.Item.ToString() ?? string.Empty
		};
	}

	private sealed class PolicyCatalog
	{
		internal PolicySection Ekus { get; } = new();
		internal PolicySection AllFileRules { get; } = new();
		internal PolicySection AllowRules { get; } = new();
		internal PolicySection DenyRules { get; } = new();
		internal PolicySection FileAttributes { get; } = new();
		internal PolicySection GenericFileRules { get; } = new();
		internal PolicySection Signers { get; } = new();
		internal PolicySection CiSigners { get; } = new();
		internal PolicySection UpdatePolicySigners { get; } = new();
		internal PolicySection SupplementalPolicySigners { get; } = new();
		internal PolicySection SigningScenarios { get; } = new();
		internal PolicySection UserModeAllowedSigners { get; } = new();
		internal PolicySection UserModeDeniedSigners { get; } = new();
		internal PolicySection UserModeFileRuleRefs { get; } = new();
		internal PolicySection KernelModeAllowedSigners { get; } = new();
		internal PolicySection KernelModeDeniedSigners { get; } = new();
		internal PolicySection KernelModeFileRuleRefs { get; } = new();
		internal PolicySection Settings { get; } = new();
		internal PolicySection Macros { get; } = new();
		internal PolicySection AppSettings { get; } = new();
		internal PolicySection AppIdTags { get; } = new();

		private readonly Dictionary<string, EkuFact> _ekuById = new(StringComparer.OrdinalIgnoreCase);
		private readonly Dictionary<string, PolicyPreviewSource> _fileRuleById = new(StringComparer.OrdinalIgnoreCase);
		private readonly Dictionary<string, PolicyPreviewSource> _signerById = new(StringComparer.OrdinalIgnoreCase);

		internal static PolicyCatalog Create(SiPolicy.SiPolicy policy)
		{
			PolicyCatalog catalog = new();
			catalog.IndexEkus(policy);
			catalog.IndexFileRules(policy);
			catalog.IndexSigners(policy);
			catalog.IndexSignerReferenceLists(policy);
			catalog.IndexSigningScenarios(policy);
			catalog.IndexSettings(policy);
			catalog.IndexMacros(policy);
			catalog.IndexAppSettings(policy);
			return catalog;
		}

		internal PolicySection GetSection(string key) => key switch
		{
			"EKUs" => Ekus,
			"AllFileRules" => AllFileRules,
			"AllowRules" => AllowRules,
			"DenyRules" => DenyRules,
			"FileAttributes" => FileAttributes,
			"GenericFileRules" => GenericFileRules,
			"Signers" => Signers,
			"CiSigners" => CiSigners,
			"UpdatePolicySigners" => UpdatePolicySigners,
			"SupplementalPolicySigners" => SupplementalPolicySigners,
			"SigningScenarios" => SigningScenarios,
			"UserModeAllowedSigners" => UserModeAllowedSigners,
			"UserModeDeniedSigners" => UserModeDeniedSigners,
			"UserModeFileRuleRefs" => UserModeFileRuleRefs,
			"KernelModeAllowedSigners" => KernelModeAllowedSigners,
			"KernelModeDeniedSigners" => KernelModeDeniedSigners,
			"KernelModeFileRuleRefs" => KernelModeFileRuleRefs,
			"Settings" => Settings,
			"Macros" => Macros,
			"AppSettings" => AppSettings,
			"AppIDTags" => AppIdTags,
			_ => new PolicySection()
		};

		private void IndexEkus(SiPolicy.SiPolicy policy)
		{
			foreach (EKU eku in CollectionsMarshal.AsSpan(policy.EKUs))
			{
				string value = Hex(eku.Value);
				string oid = string.IsNullOrWhiteSpace(eku.OID) ? string.Empty : eku.OID.Trim();
				string key = Canonical("EKU", value, oid);
				string title = !string.IsNullOrWhiteSpace(eku.FriendlyName) ? eku.FriendlyName : !string.IsNullOrWhiteSpace(oid) ? oid : value;
				string comparisonText = !string.IsNullOrWhiteSpace(oid) ? oid : value;
				string details = BuildDetails(("Value", value), ("OID", oid), ("Friendly name", eku.FriendlyName));
				List<PropertyFact> properties = BuildPropertyFacts(("Value", value), ("OID", oid));
				EkuFact fact = new(key, comparisonText);
				_ekuById[eku.ID] = fact;
				Ekus.Items[key] = new(title, details, key, properties);
			}
		}

		private void IndexFileRules(SiPolicy.SiPolicy policy)
		{
			foreach (object item in CollectionsMarshal.AsSpan(policy.FileRules))
			{
				switch (item)
				{
					case Allow allow:
						AddFileRule(allow.ID, "Allow", allow.FriendlyName, allow.FileName, allow.InternalName, allow.FileDescription, allow.ProductName, allow.PackageFamilyName, allow.FilePath, Hex(allow.Hash), AllowRules);
						break;
					case Deny deny:
						AddFileRule(deny.ID, "Deny", deny.FriendlyName, deny.FileName, deny.InternalName, deny.FileDescription, deny.ProductName, deny.PackageFamilyName, deny.FilePath, Hex(deny.Hash), DenyRules);
						break;
					case FileAttrib fileAttrib:
						AddFileRule(fileAttrib.ID, "File attribute", fileAttrib.FriendlyName, fileAttrib.FileName, fileAttrib.InternalName, fileAttrib.FileDescription, fileAttrib.ProductName, fileAttrib.PackageFamilyName, fileAttrib.FilePath, Hex(fileAttrib.Hash), FileAttributes);
						break;
					case FileRule fileRule:
						AddFileRule(fileRule.ID, $"FileRule {fileRule.Type}", fileRule.FriendlyName, fileRule.FileName, fileRule.InternalName, fileRule.FileDescription, fileRule.ProductName, fileRule.PackageFamilyName, fileRule.FilePath, Hex(fileRule.Hash), GenericFileRules);
						break;
					default:
						break;
				}
			}
		}

		private void AddFileRule(string id, string kind, string? friendlyName, string? fileName, string? internalName, string? fileDescription, string? productName, string? packageFamilyName, string? filePath, string hash, PolicySection section)
		{
			string key = Canonical(kind, fileName, internalName, fileDescription, productName, packageFamilyName, filePath, hash);
			string title = ReadableFileRule(kind, friendlyName, fileName, internalName, fileDescription, productName, packageFamilyName, filePath, hash);
			string details = BuildDetails(("Kind", kind), ("Friendly name", friendlyName), ("File name", fileName), ("Internal name", internalName), ("Description", fileDescription), ("Product", productName), ("Package family", packageFamilyName), ("Path", filePath), ("Hash", hash));
			List<PropertyFact> properties = BuildPropertyFacts(("Kind", kind), ("File name", fileName), ("Internal name", internalName), ("Description", fileDescription), ("Product", productName), ("Package family", packageFamilyName), ("Path", filePath), ("Hash", hash));
			PolicyPreviewSource source = new(title, details, key, properties);
			_fileRuleById[id] = source;
			section.Items[key] = source;
			AllFileRules.Items[key] = source;
		}

		private void IndexSigners(SiPolicy.SiPolicy policy)
		{
			foreach (Signer signer in CollectionsMarshal.AsSpan(policy.Signers))
			{
				PolicyPreviewSource source = BuildSignerSource(signer);
				_signerById[signer.ID] = source;
				Signers.Items[source.Key] = source;
			}
		}

		private PolicyPreviewSource BuildSignerSource(Signer signer)
		{
			List<string> constraintKeys = [];
			List<string> constraintDisplay = [];

			foreach (CertEKU certEku in CollectionsMarshal.AsSpan(signer.CertEKU))
			{
				EkuFact ekuFact = _ekuById.TryGetValue(certEku.ID, out EkuFact? resolved) ? resolved : new EkuFact(Canonical("UnresolvedEKU", certEku.ID), certEku.ID);
				string condition = certEku.Condition?.ToString() ?? string.Empty;
				constraintKeys.Add(Canonical("EKU", ekuFact.Key, condition));
				constraintDisplay.Add($"EKU: {ekuFact.ComparisonText} {condition}".Trim());
			}

			foreach (FileAttribRef fileAttribRef in CollectionsMarshal.AsSpan(signer.FileAttribRef))
			{
				if (_fileRuleById.TryGetValue(fileAttribRef.RuleID, out PolicyPreviewSource? source))
				{
					constraintKeys.Add(Canonical("FileAttribute", source.Key));
					constraintDisplay.Add($"File attribute: {source.Title}");
				}
			}

			string root = Hex(signer.CertRoot.Value);
			string constraintIdentity = Canonical([.. constraintKeys.OrderBy(static x => x, StringComparer.OrdinalIgnoreCase)]);
			string? constraintsText = constraintDisplay.Count > 0 ? string.Join("\n", constraintDisplay.OrderBy(static x => x, StringComparer.OrdinalIgnoreCase)) : null;
			string key = Canonical("Signer", signer.Name, signer.CertRoot.Type.ToString(), root, signer.CertPublisher?.Value, signer.CertIssuer?.Value, signer.CertOemID?.Value, constraintIdentity);
			string details = BuildDetails(("Name", signer.Name), ("Root", $"{signer.CertRoot.Type}:{root}"), ("Publisher", signer.CertPublisher?.Value), ("Issuer", signer.CertIssuer?.Value), ("OEM", signer.CertOemID?.Value), (string.Empty, constraintsText));
			List<PropertyFact> properties = BuildPropertyFacts(("Root type", signer.CertRoot.Type.ToString()), ("Root value", root), ("Publisher", signer.CertPublisher?.Value), ("Issuer", signer.CertIssuer?.Value), ("OEM", signer.CertOemID?.Value), (string.Empty, constraintsText));

			return new PolicyPreviewSource(ReadableSigner(signer), details, key, properties);
		}

		private void IndexSignerReferenceLists(SiPolicy.SiPolicy policy)
		{
			foreach (CiSigner signer in CollectionsMarshal.AsSpan(policy.CiSigners)) AddSignerReference(CiSigners, signer.SignerId);
			foreach (UpdatePolicySigner signer in CollectionsMarshal.AsSpan(policy.UpdatePolicySigners)) AddSignerReference(UpdatePolicySigners, signer.SignerId);
			foreach (SupplementalPolicySigner signer in CollectionsMarshal.AsSpan(policy.SupplementalPolicySigners)) AddSignerReference(SupplementalPolicySigners, signer.SignerId);
		}

		private void IndexSigningScenarios(SiPolicy.SiPolicy policy)
		{
			foreach (SigningScenario scenario in CollectionsMarshal.AsSpan(policy.SigningScenarios))
			{
				string minimumHashAlgorithm = scenario.MinimumHashAlgorithm?.ToString() ?? string.Empty;
				string key = Canonical("Scenario", scenario.Value.ToString(), minimumHashAlgorithm);
				string details = BuildDetails(("Value", scenario.Value.ToString()), ("Minimum hash algorithm", minimumHashAlgorithm));
				SigningScenarios.Items[key] = new(ScenarioLabel(scenario.Value), details, key, BuildPropertyFacts(("Scenario value", scenario.Value.ToString()), ("Minimum hash algorithm", minimumHashAlgorithm)));
				PolicySection allowedSection = scenario.Value == 12 ? UserModeAllowedSigners : scenario.Value == 131 ? KernelModeAllowedSigners : new PolicySection();
				PolicySection deniedSection = scenario.Value == 12 ? UserModeDeniedSigners : scenario.Value == 131 ? KernelModeDeniedSigners : new PolicySection();
				PolicySection fileRuleSection = scenario.Value == 12 ? UserModeFileRuleRefs : scenario.Value == 131 ? KernelModeFileRuleRefs : new PolicySection();
				AddAllowedSignerRefs(allowedSection, scenario.ProductSigners.AllowedSigners);
				AddDeniedSignerRefs(deniedSection, scenario.ProductSigners.DeniedSigners);
				AddFileRuleRefs(fileRuleSection, scenario.ProductSigners.FileRulesRef);
				AddAppIdTags(scenario.Value, scenario.AppIDTags);
			}
		}

		private void AddSignerReference(PolicySection section, string signerId)
		{
			if (_signerById.TryGetValue(signerId, out PolicyPreviewSource? source))
			{
				section.Items[source.Key] = source;
			}
		}

		private void AddAllowedSignerRefs(PolicySection section, AllowedSigners? signers)
		{
			if (signers is null)
			{
				return;
			}

			foreach (AllowedSigner signer in CollectionsMarshal.AsSpan(signers.AllowedSigner)) AddSignerReference(section, signer.SignerId);
		}

		private void AddDeniedSignerRefs(PolicySection section, DeniedSigners? signers)
		{
			if (signers is null)
			{
				return;
			}

			foreach (DeniedSigner signer in CollectionsMarshal.AsSpan(signers.DeniedSigner)) AddSignerReference(section, signer.SignerId);
		}

		private void AddFileRuleRefs(PolicySection section, FileRulesRef? refs)
		{
			if (refs is null)
			{
				return;
			}

			foreach (FileRuleRef fileRuleRef in CollectionsMarshal.AsSpan(refs.FileRuleRef))
			{
				if (_fileRuleById.TryGetValue(fileRuleRef.RuleID, out PolicyPreviewSource? source))
				{
					section.Items[source.Key] = source;
				}
			}
		}

		private void AddAppIdTags(byte scenarioValue, AppIDTags? tags)
		{
			if (tags is null)
			{
				return;
			}

			if (tags.EnforceDLL is not null)
			{
				string enforceValue = tags.EnforceDLL.Value.ToString();
				string enforceKey = Canonical("AppIDTag", scenarioValue.ToString(), "EnforceDLL", enforceValue);
				string details = BuildDetails(("Scenario", ScenarioLabel(scenarioValue)), ("Key", "EnforceDLL"), ("Value", enforceValue));
				AppIdTags.Items[enforceKey] = new("EnforceDLL", details, enforceKey, BuildPropertyFacts(("Scenario", ScenarioLabel(scenarioValue)), ("Key", "EnforceDLL"), ("Value", enforceValue)));
			}

			foreach (AppIDTag tag in CollectionsMarshal.AsSpan(tags.AppIDTag))
			{
				string key = Canonical("AppIDTag", scenarioValue.ToString(), tag.Key, tag.Value);
				string details = BuildDetails(("Scenario", ScenarioLabel(scenarioValue)), ("Key", tag.Key), ("Value", tag.Value));
				AppIdTags.Items[key] = new($"{tag.Key} = {tag.Value}", details, key, BuildPropertyFacts(("Scenario", ScenarioLabel(scenarioValue)), ("Key", tag.Key), ("Value", tag.Value)));
			}
		}

		private void IndexSettings(SiPolicy.SiPolicy policy)
		{
			foreach (Setting setting in CollectionsMarshal.AsSpan(policy.Settings))
			{
				string value = SettingValueToString(setting.Value);
				string key = Canonical("Setting", setting.Provider, setting.Key, setting.ValueName, value);
				string details = BuildDetails(("Provider", setting.Provider), ("Key", setting.Key), ("Value name", setting.ValueName), ("Value", value));
				Settings.Items[key] = new($"{setting.Provider} / {setting.Key} / {setting.ValueName}", details, key, BuildPropertyFacts(("Provider", setting.Provider), ("Key", setting.Key), ("Value name", setting.ValueName), ("Value", value)));
			}
		}

		private void IndexMacros(SiPolicy.SiPolicy policy)
		{
			foreach (MacrosMacro macro in CollectionsMarshal.AsSpan(policy.Macros))
			{
				string key = Canonical("Macro", macro.Value);
				string details = BuildDetails(("Value", macro.Value));
				Macros.Items[key] = new(macro.Value, details, key, BuildPropertyFacts(("Value", macro.Value)));
			}
		}

		private void IndexAppSettings(SiPolicy.SiPolicy policy)
		{
			if (policy.AppSettings?.App is null)
			{
				return;
			}

			foreach (AppRoot app in CollectionsMarshal.AsSpan(policy.AppSettings.App))
			{
				if (app.Setting is null)
				{
					continue;
				}

				foreach (AppSetting setting in app.Setting.OrderBy(static x => x.Name ?? string.Empty, StringComparer.OrdinalIgnoreCase))
				{
					List<string> values = setting.Value is null ? [] : [.. setting.Value.OrderBy(static x => x, StringComparer.OrdinalIgnoreCase)];
					string valueText = string.Join(", ", values);
					string key = Canonical("AppSetting", app.Manifest, setting.Name, valueText);
					string details = BuildDetails(("Manifest", app.Manifest), ("Name", setting.Name), ("Values", valueText));
					AppSettings.Items[key] = new($"{app.Manifest} / {setting.Name}", details, key, BuildPropertyFacts(("Manifest", app.Manifest), ("Name", setting.Name), ("Values", valueText)));
				}
			}
		}
	}

	private sealed class PolicySection
	{
		internal Dictionary<string, PolicyPreviewSource> Items { get; } = new(StringComparer.OrdinalIgnoreCase);
		internal int Count => Items.Count;
	}

	private sealed class EkuFact(string key, string comparisonText)
	{
		internal string Key => key;
		internal string ComparisonText => comparisonText;
	}

	private sealed class PolicyPreviewSource(string title, string details, string key, IReadOnlyList<PropertyFact> properties)
	{
		internal string Title => title;
		internal string Details => details;
		internal string Key => key;
		internal IReadOnlyList<PropertyFact> Properties => properties;
	}

	private sealed class PropertyFact(string name, string? value)
	{
		internal string Name => name;
		internal string Value => value ?? string.Empty;
	}

	private sealed class PropertyComparison(IReadOnlyList<string> shared, IReadOnlyList<string> different)
	{
		internal IReadOnlyList<string> Shared => shared;
		internal IReadOnlyList<string> Different => different;
	}

	private sealed class ComparisonSummary(string sharedDetails, string differentDetails)
	{
		internal static ComparisonSummary Empty { get; } = new(string.Empty, string.Empty);
		internal string SharedDetails => sharedDetails;
		internal string DifferentDetails => differentDetails;
		internal bool HasDetails => !string.IsNullOrWhiteSpace(sharedDetails) || !string.IsNullOrWhiteSpace(differentDetails);
	}

	private static string Canonical(params string?[] values)
	{
		StringBuilder builder = new();

		for (int i = 0; i < values.Length; i++)
		{
			string value = values[i]?.Trim() ?? string.Empty;
			_ = builder.Append(i).Append('=').Append(value.Length).Append(':').Append(value);
		}

		return builder.ToString();
	}

	private static string ScenarioLabel(byte value) => value switch
	{
		12 => "User mode signing scenario",
		131 => "Kernel mode signing scenario",
		_ => $"Signing scenario {value}"
	};

	private static string ReadableFileRule(string kind, string? friendlyName, string? fileName, string? internalName, string? fileDescription, string? productName, string? packageFamilyName, string? filePath, string hash)
	{
		if (!string.IsNullOrEmpty(friendlyName)) return $"{kind}: {friendlyName}";
		if (!string.IsNullOrEmpty(fileName)) return $"{kind}: {fileName}";
		if (!string.IsNullOrEmpty(internalName)) return $"{kind}: {internalName}";
		if (!string.IsNullOrEmpty(fileDescription)) return $"{kind}: {fileDescription}";
		if (!string.IsNullOrEmpty(productName)) return $"{kind}: {productName}";
		if (!string.IsNullOrEmpty(packageFamilyName)) return $"{kind}: PFN {packageFamilyName}";
		if (!string.IsNullOrEmpty(filePath)) return $"{kind}: {filePath}";
		if (!string.IsNullOrEmpty(hash)) return $"{kind}: Hash {hash}";
		return $"{kind}: (none)";
	}

	private static string ReadableSigner(Signer signer)
	{
		List<string> parts = new(5);
		if (!string.IsNullOrEmpty(signer.Name)) parts.Add(signer.Name);
		if (signer.CertPublisher is not null && !string.IsNullOrEmpty(signer.CertPublisher.Value)) parts.Add($"Publisher {signer.CertPublisher.Value}");
		if (signer.CertIssuer is not null && !string.IsNullOrEmpty(signer.CertIssuer.Value)) parts.Add($"Issuer {signer.CertIssuer.Value}");
		if (signer.CertOemID is not null && !string.IsNullOrEmpty(signer.CertOemID.Value)) parts.Add($"OEM {signer.CertOemID.Value}");
		string root = Hex(signer.CertRoot.Value);
		if (!string.IsNullOrEmpty(root)) parts.Add($"Root {signer.CertRoot.Type}:{root}");
		return parts.Count == 0 ? "(none)" : string.Join(" | ", parts);
	}
}

internal sealed class PolicyComparisonExportModel
{
	public int SchemaVersion { get; init; }
	public DateTimeOffset ExportedAtUtc { get; init; }
	public string FirstPolicyName { get; init; } = string.Empty;
	public string SecondPolicyName { get; init; } = string.Empty;
	public string FirstPolicyPath { get; init; } = string.Empty;
	public string SecondPolicyPath { get; init; } = string.Empty;
	public List<PolicyInventoryExportModel> Inventory { get; init; } = [];
	public List<PolicySectionExportModel> Sections { get; init; } = [];
}

internal sealed class PolicyInventoryExportModel
{
	public string Section { get; init; } = string.Empty;
	public string Note { get; init; } = string.Empty;
	public int FirstCount { get; init; }
	public int SecondCount { get; init; }
	public string Delta { get; init; } = string.Empty;
}

internal sealed class PolicySectionExportModel
{
	public string Section { get; init; } = string.Empty;
	public string Note { get; init; } = string.Empty;
	public int FirstCount { get; init; }
	public int SecondCount { get; init; }
	public List<PolicyPreviewExportModel> Items { get; init; } = [];
}

internal sealed class PolicyPreviewExportModel
{
	public string Title { get; init; } = string.Empty;
	public bool InFirstPolicy { get; init; }
	public bool InSecondPolicy { get; init; }
	public string FirstDetails { get; init; } = string.Empty;
	public string SecondDetails { get; init; } = string.Empty;
	public string SharedDetails { get; init; } = string.Empty;
	public string DifferentDetails { get; init; } = string.Empty;
}

[JsonSourceGenerationOptions(WriteIndented = true)]
[JsonSerializable(typeof(PolicyComparisonExportModel))]
internal sealed partial class PolicyComparisonJsonContext : JsonSerializerContext
{
}
