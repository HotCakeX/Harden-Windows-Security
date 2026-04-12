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

using System.Numerics;
using CommonCore.ToolKits;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Media;

namespace AppControlManager.CustomUIElements.HomePageCarousel;

internal sealed partial class HeaderTile : Button
{
	private static readonly DependencyProperty ImageUrlProperty = DependencyProperty.Register(
	nameof(ImageUrl),
	typeof(ImageSource),
	typeof(HeaderTile),
	new PropertyMetadata(null));

	public ImageSource ImageUrl
	{
		get => (ImageSource)GetValue(ImageUrlProperty);
		set => SetValue(ImageUrlProperty, value);
	}

	private static readonly DependencyProperty HeaderProperty = DependencyProperty.Register(nameof(Header), typeof(string), typeof(HeaderTile), new PropertyMetadata(defaultValue: null, (d, e) => ((HeaderTile)d).HeaderChanged()));

	public string Header
	{
		get => (string)GetValue(HeaderProperty);
		set => SetValue(HeaderProperty, value);
	}

	private static readonly DependencyProperty DescriptionProperty = DependencyProperty.Register(nameof(Description), typeof(string), typeof(HeaderTile), new PropertyMetadata(defaultValue: null));

	public string Description
	{
		get => (string)GetValue(DescriptionProperty);
		set => SetValue(DescriptionProperty, value);
	}

	private static readonly DependencyProperty SampleIDProperty = DependencyProperty.Register(nameof(SampleID), typeof(string), typeof(HeaderTile), new PropertyMetadata(defaultValue: string.Empty));

	public string SampleID
	{
		get => (string)GetValue(SampleIDProperty);
		set => SetValue(SampleIDProperty, value);
	}

	private static readonly DependencyProperty IsSelectedProperty = DependencyProperty.Register(nameof(IsSelected), typeof(bool), typeof(HeaderTile), new PropertyMetadata(defaultValue: false, (d, e) => ((HeaderTile)d).IsSelectedChanged((bool)e.OldValue, (bool)e.NewValue)));

	public bool IsSelected
	{
		get => (bool)GetValue(IsSelectedProperty);
		set => SetValue(IsSelectedProperty, value);
	}

	private StackPanel? _textPanel;

	internal HeaderTile()
	{
		Visual visual = ElementCompositionPreview.GetElementVisual(this);
		visual.Scale = new Vector3(0.8f);

		Vector2 center = new(0.5f, 0.5f);
		const string expression = "Vector2(this.Target.Size.X * X, this.Target.Size.Y * Y)";
		ExpressionAnimation animation = visual.Compositor.CreateExpressionAnimation(expression);

		animation.SetScalarParameter("X", center.X);
		animation.SetScalarParameter("Y", center.Y);

		visual.StopAnimation("CenterPoint.XY");
		visual.StartAnimation("CenterPoint.XY", animation);

		DefaultStyleKey = typeof(HeaderTile);
	}

	protected override void OnApplyTemplate()
	{
		base.OnApplyTemplate();
		_textPanel = GetTemplateChild("TextPanel") as StackPanel;

		if (_textPanel != null)
		{
			// Explicitly enable the Translation property
			ElementCompositionPreview.SetIsTranslationEnabled(_textPanel, true);

			// Initialize default visual state position
			Visual textVisual = ElementCompositionPreview.GetElementVisual(_textPanel);
			textVisual.Properties.InsertVector3("Translation", new Vector3(0f, 200f, 0f));
			textVisual.Opacity = 0.0f;
		}
	}

	private void IsSelectedChanged(bool oldValue, bool newValue)
	{
		if (_textPanel == null)
		{
			return;
		}

		Visual tileVisual = ElementCompositionPreview.GetElementVisual(this);
		Visual textVisual = ElementCompositionPreview.GetElementVisual(_textPanel);
		Compositor compositor = tileVisual.Compositor;

		AttachedShadowBase? shadowBase = Effects.GetShadow(this);
		DropShadow? dropShadow = shadowBase?.GetElementContext(this)?.Shadow;

		if (IsSelected)
		{
			Canvas.SetZIndex(this, 10);
			_textPanel.Visibility = Visibility.Visible;

			// We only provide the final destination (1.0f keyframe). 
			// Composition will perfectly interpolate from wherever it currently is.

			Vector3KeyFrameAnimation scaleAnimation = compositor.CreateVector3KeyFrameAnimation();
			scaleAnimation.InsertKeyFrame(1.0f, new Vector3(1.0f, 1.0f, 1.0f));
			scaleAnimation.Duration = TimeSpan.FromMilliseconds(600);
			tileVisual.StartAnimation("Scale", scaleAnimation);

			if (dropShadow != null)
			{
				ScalarKeyFrameAnimation shadowOpacity = compositor.CreateScalarKeyFrameAnimation();
				shadowOpacity.InsertKeyFrame(1.0f, 0.4f);
				shadowOpacity.Duration = TimeSpan.FromMilliseconds(600);
				dropShadow.StartAnimation("Opacity", shadowOpacity);

				ScalarKeyFrameAnimation shadowBlur = compositor.CreateScalarKeyFrameAnimation();
				shadowBlur.InsertKeyFrame(1.0f, 24.0f);
				shadowBlur.Duration = TimeSpan.FromMilliseconds(600);
				dropShadow.StartAnimation("BlurRadius", shadowBlur);
			}

			ScalarKeyFrameAnimation textOpacity = compositor.CreateScalarKeyFrameAnimation();
			textOpacity.InsertKeyFrame(1.0f, 1.0f);
			textOpacity.Duration = TimeSpan.FromMilliseconds(400);
			textVisual.StartAnimation("Opacity", textOpacity);

			Vector3KeyFrameAnimation textTranslation = compositor.CreateVector3KeyFrameAnimation();
			textTranslation.InsertKeyFrame(1.0f, new Vector3(0f, 0f, 0f));
			textTranslation.Duration = TimeSpan.FromMilliseconds(600);
			textVisual.StartAnimation("Translation", textTranslation);
		}
		else
		{
			CompositionScopedBatch batch = compositor.CreateScopedBatch(CompositionBatchTypes.Animation);

			Vector3KeyFrameAnimation scaleAnimation = compositor.CreateVector3KeyFrameAnimation();
			scaleAnimation.InsertKeyFrame(1.0f, new Vector3(0.8f, 0.8f, 1.0f));
			scaleAnimation.Duration = TimeSpan.FromMilliseconds(350);
			tileVisual.StartAnimation("Scale", scaleAnimation);

			if (dropShadow != null)
			{
				ScalarKeyFrameAnimation shadowOpacity = compositor.CreateScalarKeyFrameAnimation();
				shadowOpacity.InsertKeyFrame(1.0f, 0.2f);
				shadowOpacity.Duration = TimeSpan.FromMilliseconds(350);
				dropShadow.StartAnimation("Opacity", shadowOpacity);

				ScalarKeyFrameAnimation shadowBlur = compositor.CreateScalarKeyFrameAnimation();
				shadowBlur.InsertKeyFrame(1.0f, 12.0f);
				shadowBlur.Duration = TimeSpan.FromMilliseconds(350);
				dropShadow.StartAnimation("BlurRadius", shadowBlur);
			}

			ScalarKeyFrameAnimation textOpacity = compositor.CreateScalarKeyFrameAnimation();
			textOpacity.InsertKeyFrame(1.0f, 0.0f);
			textOpacity.Duration = TimeSpan.FromMilliseconds(350);
			textVisual.StartAnimation("Opacity", textOpacity);

			Vector3KeyFrameAnimation textTranslation = compositor.CreateVector3KeyFrameAnimation();
			textTranslation.InsertKeyFrame(1.0f, new Vector3(0f, 200f, 0f));
			textTranslation.Duration = TimeSpan.FromMilliseconds(600);
			textVisual.StartAnimation("Translation", textTranslation);

			batch.End();

			// Wait for animation to finish completely before hiding to prevent chopping
			batch.Completed += (s, e) =>
			{
				if (!IsSelected)
				{
					_textPanel.Visibility = Visibility.Collapsed;
					Canvas.SetZIndex(this, 0);
				}
			};
		}
	}

	private void HeaderChanged() => AutomationProperties.SetName(this, Header);
}
