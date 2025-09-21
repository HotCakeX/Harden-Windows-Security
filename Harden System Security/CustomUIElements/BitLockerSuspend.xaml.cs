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

using System.ComponentModel;
using AppControlManager.CustomUIElements;
using AppControlManager.ViewModels;

namespace HardenSystemSecurity.CustomUIElements;

internal sealed partial class BitLockerSuspend : ContentDialogV2, INPCImplant
{
	private AppSettings.Main AppSettings => App.Settings;

	internal BitLockerSuspend()
	{
		InitializeComponent();
	}

	internal double RestartCount { get; private set => this.SP(ref field, value); } = 1;

	#region IPropertyChangeHost Implementation
	public event PropertyChangedEventHandler? PropertyChanged;
	public void RaisePropertyChanged(string? propertyName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	#endregion

}
