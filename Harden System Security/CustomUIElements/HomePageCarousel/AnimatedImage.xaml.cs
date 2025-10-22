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
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Imaging;

namespace HardenSystemSecurity.CustomUIElements.HomePageCarousel;

internal sealed partial class AnimatedImage : UserControl
{
	private AnimationSet? selectAnimation;

	public static readonly DependencyProperty ImageUrlProperty = DependencyProperty.Register(
		nameof(ImageUrl),
		typeof(Uri),
		typeof(AnimatedImage),
		new PropertyMetadata(defaultValue: null, (d, e) => ((AnimatedImage)d).IsImageChanged((Uri)e.OldValue, (Uri)e.NewValue)));

	public Uri ImageUrl
	{
		get => (Uri)GetValue(ImageUrlProperty);
		set => SetValue(ImageUrlProperty, value);
	}

	public AnimatedImage()
	{
		this.InitializeComponent();
	}

	private void AnimatedImage_Unloaded(object sender, RoutedEventArgs e)
	{
		if (selectAnimation != null)
		{
			selectAnimation.Completed -= SelectAnimation_Completed;
			selectAnimation = null;
		}
	}

	private void IsImageChanged(Uri oldValue, Uri newValue)
	{
		BottomImage.Source = new BitmapImage(this.ImageUrl);
		BottomImage.Opacity = 1;

		if (selectAnimation != null)
		{
			selectAnimation.Completed -= SelectAnimation_Completed;
		}

		selectAnimation = [new OpacityAnimation() { From = 1, To = 0, Duration = TimeSpan.FromMilliseconds(800) }];
		selectAnimation.Completed += SelectAnimation_Completed;
		selectAnimation.Start(TopImage);
	}

	private void SelectAnimation_Completed(object? sender, EventArgs e)
	{
		try
		{
			TopImage.Source = new BitmapImage(this.ImageUrl);
			TopImage.Opacity = 1;
		}
		catch
		{
		}
	}
}
