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
using System.ComponentModel;
using System.Runtime.CompilerServices;
using AppControlManager.IntelGathering;
using Microsoft.UI.Dispatching;

namespace AppControlManager.ViewModels;

/// <summary>
/// All of the ViewModel classes must inherit from this class
/// </summary>
internal abstract class ViewModelBase : INotifyPropertyChanged
{
	public event PropertyChangedEventHandler? PropertyChanged;

	// Expose the dispatcher queue so that derived classes can marshal
	// calls to the UI thread when needed.
	protected readonly DispatcherQueue Dispatcher = DispatcherQueue.GetForCurrentThread();

	/// <summary>
	/// Sets the field to <paramref name="newValue"/> if it differs from its current contents,
	/// raises PropertyChanged, and returns true if a change occurred.
	/// This also prevents infinite loops where a property raises OnPropertyChanged which could trigger an update in the UI,
	/// and the UI might call set again, leading to an infinite loop.
	/// </summary>
	/// <param name="field">The existing value.</param>
	/// <param name="newValue">The new value.</param>
	/// <param name="propertyName"></param>
	protected bool SP<T>(ref T field, T newValue, [CallerMemberName] string? propertyName = null)
	{
		if (EqualityComparer<T>.Default.Equals(field, newValue))
			return false;

		field = newValue;
		OnPropertyChanged(propertyName);
		return true;
	}

	/// <summary>
	/// Raises the PropertyChanged event.
	/// </summary>
	/// <param name="propertyName">The name of the property that changed.</param>
	protected void OnPropertyChanged(string? propertyName)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}

	// Dictionaries used for quick conversion and parsing of ScanLevels.
	internal static readonly Dictionary<string, ScanLevels> StringToScanLevel = new(StringComparer.OrdinalIgnoreCase)
	{
		{ "File Publisher", ScanLevels.FilePublisher },
		{ "Publisher", ScanLevels.Publisher },
		{ "Hash", ScanLevels.Hash },
		{ "File Path", ScanLevels.FilePath },
		{ "WildCard Folder Path", ScanLevels.WildCardFolderPath },
		{ "PFN", ScanLevels.PFN },
		{ "Custom File Rule Pattern", ScanLevels.CustomFileRulePattern }
	};

	internal static readonly Dictionary<ScanLevels, string> ScanLevelToString = new()
	{
		{ ScanLevels.FilePublisher, "File Publisher" },
		{ ScanLevels.Publisher, "Publisher" },
		{ ScanLevels.Hash, "Hash" },
		{ ScanLevels.FilePath, "File Path" },
		{ ScanLevels.WildCardFolderPath, "WildCard Folder Path" },
		{ ScanLevels.PFN, "PFN" },
		{ ScanLevels.CustomFileRulePattern, "Custom File Rule Pattern" }
	 };
}
