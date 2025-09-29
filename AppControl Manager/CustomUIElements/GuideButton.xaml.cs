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
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements;

internal sealed partial class GuideButton : UserControl
{
	internal GuideButton()
	{
		InitializeComponent();
	}

	public Uri? NavigateUri
	{
		get => (Uri?)GetValue(NavigateUriProperty);
		set => SetValue(NavigateUriProperty, value);
	}

	public static readonly DependencyProperty NavigateUriProperty =
		DependencyProperty.Register(
			nameof(NavigateUri),
			typeof(Uri),
			typeof(GuideButton),
			new PropertyMetadata(null)
		);
}
