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

using System.Collections;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using System.Linq;
using System.Text.Json.Nodes;
using AppControlManager.CustomUIElements;
using CommonCore.GroupPolicy;
using HardenSystemSecurity.Protect;
using HardenSystemSecurity.Traverse;
using HardenSystemSecurity.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using WinRT;

namespace HardenSystemSecurity.CustomUIElements;

/// <summary>
/// Displays the contents of a system state backup file and allows modifying them.
/// The modifications can be saved back to the file and/or applied to the system.
/// A <see cref="ContentDialogResult.Primary"/> result means the (modified) <see cref="MContainer"/> must be applied to the system.
/// When the restoration mode is not provided (Fine Tune), the dialog only allows saving and has no Apply button.
/// </summary>
internal sealed partial class SystemStateRestoreDialog : ContentDialogV2
{
	private readonly string _filePath;
	private readonly JsonObject _root;
	private readonly MContainer _container;

	/// <param name="filePath">Path to the backup file.</param>
	/// <param name="root">The document returned by <see cref="MContainerJsonContext.LoadEditable"/>.</param>
	/// <param name="container">The container returned by <see cref="MContainerJsonContext.LoadEditable"/>. Modified in place by the dialog.</param>
	/// <param name="synchronizeExact">The restoration mode that will be used when applying. Null when the changes can only be saved to the file.</param>
	internal SystemStateRestoreDialog(string filePath, JsonObject root, MContainer container, bool? synchronizeExact)
	{
		InitializeComponent();

		_filePath = filePath;
		_root = root;
		_container = container;

		Title = "Review System State Backup";
		SecondaryButtonText = Atlas.GetStr("SaveSandboxProfileButton/Content");
		CloseButtonText = Atlas.GetStr("LoopbackDialogCloseButtonText");

		// The metadata are read from the document because the MContainer properties for them return the current values instead.
		string? time = root["Time"]?.ToString();
		Created = DateTime.TryParse(time, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTime created) ? created.ToString(CultureInfo.CurrentCulture) : time;
		MachineName = root[nameof(MachineName)]?.ToString();
		UserName = root[nameof(UserName)]?.ToString();
		AppVersion = root[nameof(AppVersion)]?.ToString();

		// Applying is only offered when the restoration mode is provided, an empty PrimaryButtonText hides the Apply button.
		if (synchronizeExact is bool exact)
		{
			CanApply = true;
			PrimaryButtonText = Atlas.GetStr("ApplyText/Text");
			RestorationMode = string.Concat(Atlas.GetStr("RestoreModeMenuFlyoutItem/Text"), ": ", Atlas.GetStr(exact ? "FullRestoreModeMenuFlyoutItem/Text" : "PartialRestoreModeMenuFlyoutItem/Text"));
			RestorationModeDescription = Atlas.GetStr(exact ? "FullRestoreModeMenuFlyoutItem/ToolTipService/ToolTip" : "PartialRestoreModeMenuFlyoutItem/ToolTipService/ToolTip");
		}

		// Same order as the categories in the file.
		AddSection(Categories.MicrosoftSecurityBaseline, container.MicrosoftSecurityBaseline?.Items);
		AddSection(Categories.Microsoft365AppsSecurityBaseline, container.Microsoft365AppsSecurityBaseline?.Items);
		AddSection(Categories.MicrosoftDefender, container.MicrosoftDefender?.Items);
		AddSection(Categories.AttackSurfaceReductionRules, container.AttackSurfaceReductionRules?.Items);
		AddSection(Categories.BitLockerSettings, container.BitLockerSettings?.Items);
		AddSection(Categories.TLSSecurity, container.TLSSecurity?.Items);
		AddSection(Categories.LockScreen, container.LockScreen?.Items);
		AddSection(Categories.UserAccountControl, container.UserAccountControl?.Items);
		AddSection(Categories.DeviceGuard, container.DeviceGuard?.Items);
		AddSection(Categories.WindowsFirewall, container.WindowsFirewall?.Items);
		AddSection(Categories.WindowsNetworking, container.WindowsNetworking?.Items);
		AddSection(Categories.MiscellaneousConfigurations, container.MiscellaneousConfigurations?.Items);
		AddSection(Categories.WindowsUpdateConfigurations, container.WindowsUpdateConfigurations?.Items);
		AddSection(Categories.EdgeBrowserConfigurations, container.EdgeBrowserConfigurations?.Items);
		AddSection(Categories.NonAdminCommands, container.NonAdminCommands?.Items);
		AddSection(Categories.MSFTSecBaselines_OptionalOverrides, container.MSFTSecBaselines_OptionalOverrides?.Items);
	}

	internal string? Created { get; }
	internal string? MachineName { get; }
	internal string? UserName { get; }
	internal string? AppVersion { get; }

	// Read from the document on every binding update because saving the modifications changes them.
	internal string? Total => _root[nameof(Total)]?.ToString();
	internal string? Compliant => _root[nameof(Compliant)]?.ToString();
	internal string? NonCompliant => _root[nameof(NonCompliant)]?.ToString();
	internal bool CanApply { get; }
	internal string? RestorationMode { get; }
	internal string? RestorationModeDescription { get; }
	internal string Hint => CanApply
		? "Checked items are marked as applied or compliant. You can modify them, save the changes back to the file, or apply them to the system."
		: "Checked items are marked as applied or compliant. You can modify them and save the changes back to the file.";
	internal List<SystemStateRestoreSection> Sections { get; } = new(16);
	internal InfoBarSettings DialogInfoBar { get; } = new();

	private void AddSection(Categories category, IList? items)
	{
		if (items is { Count: > 0 })
		{
			Sections.Add(new(ViewModelProvider.ProtectVM.CreateCategory(category), items));
		}
	}

	/// <summary>
	/// Displays only the items that match the search term in every category.
	/// </summary>
	[DynamicWindowsRuntimeCast(typeof(TextBox))]
	private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
	{
		string term = ((TextBox)sender).Text.Trim();

		foreach (SystemStateRestoreSection section in Sections)
		{
			section.Filter(term);
		}
	}

	/// <summary>
	/// Saves the modifications back to the file while keeping the dialog open.
	/// </summary>
	private void OnSecondaryButtonClick(ContentDialog sender, ContentDialogButtonClickEventArgs args)
	{
		args.Cancel = true;

		try
		{
			int total = 0;
			int compliant = 0;

			foreach (SystemStateRestoreSection section in Sections)
			{
				total += section.Count;
				compliant += section.CompliantCount;
			}

			MContainerJsonContext.SaveEdited(_root, _container, total, compliant, _filePath);

			// Displays the new counts that were saved to the file.
			Bindings.Update();

			DialogInfoBar.WriteSuccess("Successfully saved the changes to the backup file.");
		}
		catch (Exception ex)
		{
			DialogInfoBar.WriteError(ex);
		}
	}
}

/// <summary>
/// A category of the backup file displayed in the <see cref="SystemStateRestoreDialog"/>.
/// Only the items list that matches the type of the category's items is non-null.
/// </summary>
/// <param name="header">Provides the title, subtitle and logo of the category.</param>
/// <param name="items">Items of the category in the backup file.</param>
internal sealed partial class SystemStateRestoreSection(ProtectionCategoryListViewItem header, IList items) : ViewModelBase
{
	internal ProtectionCategoryListViewItem Header => header;
	internal int Count => items.Count;

	[AllowNull]
	private IList DisplayedItems { get => field ?? items; set; }

	internal List<VerificationResult>? BaselineItems => DisplayedItems as List<VerificationResult>;
	internal List<ASRRuleEntry>? ASRItems => DisplayedItems as List<ASRRuleEntry>;
	internal List<MUnit>? MUnitItems => DisplayedItems as List<MUnit>;

	/// <summary>
	/// Whether any of the items match the search term. The category is hidden when none of them do.
	/// </summary>
	internal bool HasDisplayedItems => DisplayedItems.Count > 0;

	internal bool IsExpanded { get; set => SP(ref field, value); }

	/// <summary>
	/// Expansion state of the category before the search began, null when there is no search term.
	/// Restored when the search term is cleared so the search does not leave the categories expanded.
	/// </summary>
	private bool? _expandedBeforeSearch;

	internal Visibility BaselineItemsVisibility => items is List<VerificationResult> ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility ASRItemsVisibility => items is List<ASRRuleEntry> ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility MUnitItemsVisibility => items is List<MUnit> ? Visibility.Visible : Visibility.Collapsed;

	/// <summary>
	/// Number of the items that are marked as applied or compliant, calculated the same way as the category scores are calculated when the backup file is generated.
	/// </summary>
	internal int CompliantCount => items switch
	{
		List<VerificationResult> baselineItems => baselineItems.Count(static item => item.IsCompliant),
		List<ASRRuleEntry> asrItems => asrItems.Count(static item => item.State is ASRRuleState.Block),
		List<MUnit> mUnitItems => mUnitItems.Count(static item => item.IsApplied == true),
		_ => 0
	};

	/// <summary>
	/// Displays only the items that match the search term and expands the category so they are visible.
	/// An empty search term displays all of the items and restores the expansion state from before the search.
	/// </summary>
	internal void Filter(string term)
	{
		if (term.Length == 0)
		{
			if (_expandedBeforeSearch is bool expandedBeforeSearch)
			{
				IsExpanded = expandedBeforeSearch;
				_expandedBeforeSearch = null;
			}
		}
		else
		{
			_expandedBeforeSearch ??= IsExpanded;
			IsExpanded = true;
		}

		DisplayedItems = term.Length == 0 ? null : items switch
		{
			List<VerificationResult> baselineItems => baselineItems.FindAll(item => Matches(item.FriendlyName, term) || Matches(item.SourceDisplay, term)),
			List<ASRRuleEntry> asrItems => asrItems.FindAll(item => Matches(item.Name, term)),
			List<MUnit> mUnitItems => mUnitItems.FindAll(item => Matches(item.Name, term) || Matches(item.SubCategoryName, term)),
			_ => null
		};

		// An empty property name refreshes all of the bindings: the displayed items and the visibility of the category.
		// Rebinding is cheap because the items are displayed by virtualized ItemsRepeaters that only create the visible elements and recycle them.
		OnPropertyChanged(string.Empty);
	}

	private static bool Matches(string? value, string term) => value is not null && value.Contains(term, StringComparison.OrdinalIgnoreCase);
}
