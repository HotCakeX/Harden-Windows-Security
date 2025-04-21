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
using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;

namespace AppControlManager.CustomUIElements;

internal partial class ContentDialogV2 : ContentDialog
{
	internal ContentDialogV2()
	{
		BorderBrush = Application.Current.Resources["AccentFillColorDefaultBrush"] as Brush ?? new SolidColorBrush(Colors.Transparent);
		BorderThickness = new Thickness(1);
		XamlRoot = App.MainWindow?.Content.XamlRoot;
		RequestedTheme = string.Equals(App.Settings.AppTheme, "Light", StringComparison.OrdinalIgnoreCase) ? ElementTheme.Light : (string.Equals(App.Settings.AppTheme, "Dark", StringComparison.OrdinalIgnoreCase) ? ElementTheme.Dark : ElementTheme.Default);
		CornerRadius = new CornerRadius(8);
	}

	internal new IAsyncOperation<ContentDialogResult> ShowAsync()
	{
		App.CurrentlyOpenContentDialog = this;
		return base.ShowAsync();
	}

}
