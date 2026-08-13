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
using System.ComponentModel;
using Microsoft.UI.Xaml;

namespace CommonCore.IntelGathering;

internal enum ScanLevels
{
	WHQLFilePublisher,
	FilePublisher,
	Publisher,
	Hash,
	FilePath,
	WildCardFolderPath,
	PFN,
	CustomFileRulePattern,
	FileName
}

internal sealed class FallbackItem(string name, Visibility chevronVisibility, ScanLevelsComboBoxType? owner = null, ScanLevelFallbackOption? option = null)
{
	internal string Name => name;
	internal Visibility ChevronVisibility => chevronVisibility;
	internal ScanLevelsComboBoxType? Owner => owner;
	internal ScanLevelFallbackOption? Option => option;
	internal bool CanEdit => owner is not null && option is not null;
}

internal sealed class FallbackRow
{
	internal ObservableCollection<FallbackItem> Items { get; } = [];
}

internal sealed partial class ScanLevelFallbackOption(
	string friendlyName,
	ScanLevels level,
	bool isSelected,
	Action changed) : INotifyPropertyChanged
{
	public event PropertyChangedEventHandler? PropertyChanged;

	internal string FriendlyName => friendlyName;
	internal ScanLevels Level => level;

	internal bool IsSelected
	{
		get; set
		{
			if (field == value)
				return;

			field = value;
			PropertyChanged?.Invoke(this, new(nameof(IsSelected)));
			changed();
		}
	} = isSelected;
}

internal sealed partial class ScanLevelsComboBoxType : INotifyPropertyChanged
{
	public event PropertyChangedEventHandler? PropertyChanged;

	internal ScanLevelsComboBoxType(
		string friendlyName,
		ScanLevels level,
		int rating,
		IReadOnlyList<(string Name, ScanLevels Level)> availableFallbacks,
		IReadOnlySet<ScanLevels> defaultFallbacks)
	{
		FriendlyName = friendlyName;
		Level = level;
		Rating = rating;

		foreach ((string name, ScanLevels fallbackLevel) in availableFallbacks)
		{
			AvailableFallbacks.Add(new(
				name,
				fallbackLevel,
				defaultFallbacks.Contains(fallbackLevel),
				RebuildFallbackChains));
		}

		RebuildFallbackChains();
	}

	internal string FriendlyName { get; }
	internal ScanLevels Level { get; }
	internal int Rating { get; }
	internal bool IsSelected
	{
		get; set
		{
			if (field == value)
				return;

			field = value;
			PropertyChanged?.Invoke(this, new(nameof(IsSelected)));
			PropertyChanged?.Invoke(this, new(nameof(SelectionIndicatorOpacity)));
		}
	}
	internal double SelectionIndicatorOpacity => IsSelected ? 1.0 : 0.0;
	internal readonly ObservableCollection<FallbackRow> EditableFallbackRows = [];
	internal readonly ObservableCollection<ScanLevelFallbackOption> AvailableFallbacks = [];

	internal List<ScanLevels> SelectedFallbackLevels
	{
		get
		{
			List<ScanLevels> result = new(AvailableFallbacks.Count);
			foreach (ScanLevelFallbackOption option in AvailableFallbacks)
			{
				if (option.IsSelected)
					result.Add(option.Level);
			}
			return result;
		}
	}

	internal void MoveFallback(int oldIndex, int requestedIndex)
	{
		int availableCount = AvailableFallbacks.Count;
		if (oldIndex < 0 || oldIndex >= availableCount)
			return;

		ScanLevelFallbackOption movingOption = AvailableFallbacks[oldIndex];
		if (!movingOption.IsSelected)
			return;

		List<ScanLevelFallbackOption> selectedOptions = new(availableCount);
		foreach (ScanLevelFallbackOption option in AvailableFallbacks)
		{
			if (option.IsSelected)
				selectedOptions.Add(option);
		}

		int selectedCount = selectedOptions.Count;
		if (selectedCount < 2)
			return;

		int selectedIndex = selectedOptions.IndexOf(movingOption);

		// The UI supplies oldIndex + direction. Apply that direction to the selected
		// fallback sequence, not the full available-options collection. Unselected
		// options must never consume an arrow click.
		int direction = requestedIndex > oldIndex ? 1 : requestedIndex < oldIndex ? -1 : 0;
		if (direction is 0)
			return;

		int targetSelectedIndex = direction > 0
			? selectedIndex == selectedCount - 1 ? 0 : selectedIndex + 1
			: selectedIndex == 0 ? selectedCount - 1 : selectedIndex - 1;

		int targetAvailableIndex = AvailableFallbacks.IndexOf(selectedOptions[targetSelectedIndex]);
		if (targetAvailableIndex == oldIndex)
			return;

		AvailableFallbacks.Move(oldIndex, targetAvailableIndex);
		RebuildFallbackChains();
	}

	private void RebuildFallbackChains()
	{
		EditableFallbackRows.Clear();

		List<ScanLevelFallbackOption> selected = new(AvailableFallbacks.Count);
		foreach (ScanLevelFallbackOption option in AvailableFallbacks)
		{
			if (option.IsSelected)
				selected.Add(option);
		}

		if (selected.Count is 0)
		{
			FallbackRow row = new();
			row.Items.Add(new("No Fallback", Visibility.Collapsed));
			EditableFallbackRows.Add(row);
			return;
		}

		FallbackRow? currentRow = null;
		for (int i = 0; i < selected.Count; i++)
		{
			FallbackItem item = new(
				selected[i].FriendlyName,
				i < selected.Count - 1 ? Visibility.Visible : Visibility.Collapsed,
				this,
				selected[i]);


			if (i % 2 is 0)
			{
				currentRow = new();
				EditableFallbackRows.Add(currentRow);
			}

			currentRow!.Items.Add(item);
		}
	}
}

internal static class ScanLevelFallbackCatalog
{
	private static readonly (string, ScanLevels)[] WHQL =
	[
		("File Publisher", ScanLevels.FilePublisher),
		("Publisher", ScanLevels.Publisher),
		("Hash", ScanLevels.Hash),
		("File Name", ScanLevels.FileName),
		("File Path", ScanLevels.FilePath)
	];

	private static readonly (string, ScanLevels)[] FilePublisher =
	[
		("Publisher", ScanLevels.Publisher),
		("Hash", ScanLevels.Hash),
		("File Name", ScanLevels.FileName),
		("File Path", ScanLevels.FilePath)
	];

	private static readonly (string, ScanLevels)[] Publisher =
	[
		("Hash", ScanLevels.Hash),
		("File Name", ScanLevels.FileName),
		("File Path", ScanLevels.FilePath)
	];

	private static readonly (string, ScanLevels)[] FileName =
	[
		("Hash", ScanLevels.Hash),
		("File Path", ScanLevels.FilePath)
	];

	internal static List<ScanLevels> GetDefaultLevels(ScanLevels level) => level switch
	{
		ScanLevels.WHQLFilePublisher => [ScanLevels.FilePublisher, ScanLevels.Publisher, ScanLevels.Hash],
		ScanLevels.FilePublisher => [ScanLevels.Publisher, ScanLevels.Hash],
		ScanLevels.Publisher => [ScanLevels.Hash],
		ScanLevels.FileName => [ScanLevels.Hash],
		_ => []
	};

	internal static List<ScanLevelsComboBoxType> CreateSource(bool folders)
	{
		List<ScanLevelsComboBoxType> result = new(folders ? 7 : 6)
		{
			Create(ScanLevels.WHQLFilePublisher),
			Create(ScanLevels.FilePublisher),
			Create(ScanLevels.Publisher),
			Create(ScanLevels.Hash),
			Create(ScanLevels.FilePath),
			Create(ScanLevels.FileName)
		};

		if (folders)
			result.Add(Create(ScanLevels.WildCardFolderPath));

		return result;
	}

	private static ScanLevelsComboBoxType Create(ScanLevels level) => level switch
	{
		ScanLevels.WHQLFilePublisher => new("WHQL File Publisher", level, 5, WHQL, new HashSet<ScanLevels>(GetDefaultLevels(level))),
		ScanLevels.FilePublisher => new("File Publisher", level, 4, FilePublisher, new HashSet<ScanLevels>(GetDefaultLevels(level))),
		ScanLevels.Publisher => new("Publisher", level, 3, Publisher, new HashSet<ScanLevels>(GetDefaultLevels(level))),
		ScanLevels.Hash => new("Hash", level, 5, [], new HashSet<ScanLevels>()),
		ScanLevels.FilePath => new("File Path", level, 2, [], new HashSet<ScanLevels>()),
		ScanLevels.WildCardFolderPath => new("Wildcard Folder Path", level, 1, [], new HashSet<ScanLevels>()),
		ScanLevels.FileName => new("File Name", level, 2, FileName, new HashSet<ScanLevels>(GetDefaultLevels(level))),
		_ => throw new ArgumentOutOfRangeException(nameof(level))
	};
}
