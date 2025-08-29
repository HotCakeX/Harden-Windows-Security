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
using System.ComponentModel;
using System.Runtime.CompilerServices;
using AppControlManager.CustomUIElements;

namespace HardenSystemSecurity.CustomUIElements;

internal sealed partial class AddKeyProtectorDialog : ContentDialogV2, INotifyPropertyChanged
{
	private AppSettings.Main AppSettings => App.Settings;

	internal readonly BitLocker.BitLockerVolume Volume;

	internal AddKeyProtectorDialog(BitLocker.BitLockerVolume volume)
	{
		InitializeComponent();

		Volume = volume;
	}

	/// <summary>
	/// The selected key protector type in the Segmented element.
	/// </summary>
	internal int SelectedKeyProtectorType { get; set => SP(ref field, value); }


	#region INotifyPropertyChanged Implementation

	/// <summary>
	/// INotifyPropertyChanged event for the interface.
	/// </summary>
	public event PropertyChangedEventHandler? PropertyChanged;

	/// <summary>
	/// Raises the PropertyChanged event.
	/// </summary>
	/// <param name="propertyName">The name of the property that changed.</param>
	private void OnPropertyChanged(string? propertyName)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}

	/// <summary>
	/// Sets the field to <paramref name="newValue"/> if it differs from its current contents,
	/// raises PropertyChanged, and returns true if a change occurred.
	/// This also prevents infinite loops where a property raises OnPropertyChanged which could trigger an update in the UI,
	/// and the UI might call set again, leading to an infinite loop.
	/// </summary>
	/// <param name="field">The existing value.</param>
	/// <param name="newValue">The new value.</param>
	/// <param name="propertyName"></param>
	private bool SP<T>(ref T field, T newValue, [CallerMemberName] string? propertyName = null)
	{
		if (EqualityComparer<T>.Default.Equals(field, newValue))
			return false;

		field = newValue;

		if (App.AppDispatcher.HasThreadAccess)
		{
			OnPropertyChanged(propertyName);
		}
		else
		{
			_ = App.AppDispatcher.TryEnqueue(() => OnPropertyChanged(propertyName));
		}

		return true;
	}

	#endregion

}
