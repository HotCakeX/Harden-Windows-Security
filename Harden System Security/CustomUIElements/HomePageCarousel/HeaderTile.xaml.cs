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

// The following code is based on the Microsoft AI Dev Gallery, MIT licensed code.
// It has modifications made by Violet Hansen.
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
// Repository: https://github.com/microsoft/ai-dev-gallery
// License file: https://github.com/microsoft/ai-dev-gallery/blob/main/LICENSE
//    MIT License
//
//    Copyright (c) Microsoft Corporation.
//
//    Permission is hereby granted, free of charge, to any person obtaining a copy
//    of this software and associated documentation files (the "Software"), to deal
//    in the Software without restriction, including without limitation the rights
//    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//    copies of the Software, and to permit persons to whom the Software is
//    furnished to do so, subject to the following conditions:
//
//    The above copyright notice and this permission notice shall be included in all
//    copies or substantial portions of the Software.
//
//    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//    SOFTWARE
//

using CommunityToolkit.WinUI.Animations;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;

namespace HardenSystemSecurity.CustomUIElements.HomePageCarousel;

internal sealed partial class HeaderTile : Button
{
	public static readonly DependencyProperty ImageUrlProperty = DependencyProperty.Register(
	nameof(ImageUrl),
	typeof(ImageSource),
	typeof(HeaderTile),
	new PropertyMetadata(null));

	public ImageSource ImageUrl
	{
		get => (ImageSource)GetValue(ImageUrlProperty);
		set => SetValue(ImageUrlProperty, value);
	}

	public static readonly DependencyProperty HeaderProperty = DependencyProperty.Register(nameof(Header), typeof(string), typeof(HeaderTile), new PropertyMetadata(defaultValue: null, (d, e) => ((HeaderTile)d).HeaderChanged((string)e.OldValue, (string)e.NewValue)));

	public string Header
	{
		get => (string)GetValue(HeaderProperty);
		set => SetValue(HeaderProperty, value);
	}

	public static readonly DependencyProperty DescriptionProperty = DependencyProperty.Register(nameof(Description), typeof(string), typeof(HeaderTile), new PropertyMetadata(defaultValue: null));

	public string Description
	{
		get => (string)GetValue(DescriptionProperty);
		set => SetValue(DescriptionProperty, value);
	}

	public static readonly DependencyProperty SampleIDProperty = DependencyProperty.Register(nameof(SampleID), typeof(string), typeof(HeaderTile), new PropertyMetadata(defaultValue: string.Empty));

	public string SampleID
	{
		get => (string)GetValue(SampleIDProperty);
		set => SetValue(SampleIDProperty, value);
	}

	public static readonly DependencyProperty IsSelectedProperty = DependencyProperty.Register(nameof(IsSelected), typeof(bool), typeof(HeaderTile), new PropertyMetadata(defaultValue: false, (d, e) => ((HeaderTile)d).IsSelectedChanged((bool)e.OldValue, (bool)e.NewValue)));

	public bool IsSelected
	{
		get => (bool)GetValue(IsSelectedProperty);
		set => SetValue(IsSelectedProperty, value);
	}

	internal HeaderTile()
	{
		DefaultStyleKey = typeof(HeaderTile);
	}

	private void IsSelectedChanged(object oldValue, object newValue)
	{
		if (IsSelected)
		{
			Canvas.SetZIndex(this, 10);
			_ = VisualStateManager.GoToState(this, "Selected", true);
			AnimationSet selectAnimation = [new ScaleAnimation() { To = "1.0", Duration = TimeSpan.FromMilliseconds(600) }, new OpacityDropShadowAnimation() { To = 0.4 }, new BlurRadiusDropShadowAnimation() { To = 24 }];
			selectAnimation.Start(this);
		}
		else
		{
			_ = VisualStateManager.GoToState(this, "NotSelected", true);
			AnimationSet deselectAnimation = [new ScaleAnimation() { To = "0.8", Duration = TimeSpan.FromMilliseconds(350) }, new OpacityDropShadowAnimation() { To = 0.2 }, new BlurRadiusDropShadowAnimation() { To = 12 }];
			deselectAnimation.Completed += (s, e) =>
			{
				Canvas.SetZIndex(this, 0);
			};
			deselectAnimation.Start(this);
		}
	}

	private void HeaderChanged(string oldValue, string newValue)
	{
		if (!string.IsNullOrEmpty(Header))
		{
			AutomationProperties.SetName(this, Header);
		}
	}
}
