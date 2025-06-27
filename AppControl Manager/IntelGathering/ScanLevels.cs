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

namespace AppControlManager.IntelGathering;

/// <summary>
/// The levels based on which the files are scanned by the app. They have fallback orders.
/// </summary>
internal enum ScanLevels
{
	WHQLFilePublisher, // WHQLFilePublisher => FilePublisher => Publisher => Hash
	FilePublisher, // FilePublisher => Publisher => Hash
	Publisher, // Publisher => Hash
	Hash,
	FilePath,
	WildCardFolderPath, // Only for folders
	PFN,
	CustomFileRulePattern
}

/// <summary>
/// Bound to the ComboBox ItemsSource.
/// </summary>
/// <param name="friendlyName">The display name of the level for UI.</param>
/// <param name="level">The actual Enum value used in code.</param>
/// <param name="rating">The rating displayed on the UI.</param>
internal sealed class ScanLevelsComboBoxType(string friendlyName, ScanLevels level, int rating)
{
	internal string FriendlyName => friendlyName;
	internal ScanLevels Level => level;
	internal int Rating => rating;
}
