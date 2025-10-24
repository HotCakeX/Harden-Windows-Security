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

using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace HardenSystemSecurity.CustomUIElements.HomePageCarousel;

internal sealed partial class TileGallery : UserControl
{
	internal TileGallery()
	{
		InitializeComponent();
	}

	public object Source
	{
		get => GetValue(SourceProperty);
		set => SetValue(SourceProperty, value);
	}

	public static readonly DependencyProperty SourceProperty =
		DependencyProperty.Register("Source", typeof(object), typeof(TileGallery), new PropertyMetadata(null));

	private void Scroller_ViewChanging(object sender, ScrollViewerViewChangingEventArgs e)
	{
		if (e.FinalView.HorizontalOffset < 1)
		{
			ScrollBackBtn.Visibility = Visibility.Collapsed;
		}
		else if (e.FinalView.HorizontalOffset > 1)
		{
			ScrollBackBtn.Visibility = Visibility.Visible;
		}

		if (e.FinalView.HorizontalOffset > scroller.ScrollableWidth - 1)
		{
			ScrollForwardBtn.Visibility = Visibility.Collapsed;
		}
		else if (e.FinalView.HorizontalOffset < scroller.ScrollableWidth - 1)
		{
			ScrollForwardBtn.Visibility = Visibility.Visible;
		}
	}

	private void ScrollBackBtn_Click(object sender, RoutedEventArgs e)
	{
		_ = scroller.ChangeView(scroller.HorizontalOffset - scroller.ViewportWidth, null, null);

		// Manually focus to ScrollForwardBtn since this button disappears after scrolling to the end.
		_ = ScrollForwardBtn.Focus(FocusState.Programmatic);
	}

	private void ScrollForwardBtn_Click(object sender, RoutedEventArgs e)
	{
		_ = scroller.ChangeView(scroller.HorizontalOffset + scroller.ViewportWidth, null, null);

		// Manually focus to ScrollBackBtn since this button disappears after scrolling to the end.
		_ = ScrollBackBtn.Focus(FocusState.Programmatic);
	}

	private void Scroller_SizeChanged(object sender, SizeChangedEventArgs e)
	{
		ScrollForwardBtn.Visibility = scroller.ScrollableWidth > 0 ? Visibility.Visible : Visibility.Collapsed;
	}
}
