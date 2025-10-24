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
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Media;

namespace AppControlManager.CustomUIElements.HomePageCarousel;

/// <summary>
/// A control that applies an opacity mask to its content.
/// </summary>
[TemplatePart(Name = RootGridTemplateName, Type = typeof(Grid))]
[TemplatePart(Name = MaskContainerTemplateName, Type = typeof(Border))]
[TemplatePart(Name = ContentPresenterTemplateName, Type = typeof(ContentPresenter))]
internal sealed partial class OpacityMaskView : ContentControl
{
	// This is from Windows Community Toolkit Labs: https://github.com/CommunityToolkit/Labs-Windows/pull/491

	/// <summary>
	/// Identifies the <see cref="OpacityMask"/> property.
	/// </summary>
	public static readonly DependencyProperty OpacityMaskProperty =
		DependencyProperty.Register(nameof(OpacityMask), typeof(UIElement), typeof(OpacityMaskView), new PropertyMetadata(null, OnOpacityMaskChanged));

	private const string ContentPresenterTemplateName = "PART_ContentPresenter";
	private const string MaskContainerTemplateName = "PART_MaskContainer";
	private const string RootGridTemplateName = "PART_RootGrid";

	private readonly Compositor _compositor = CompositionTarget.GetCompositorForCurrentThread();

	// Composition resources we create and need to tear down explicitly to avoid retaining composition references longer than necessary
	private CompositionBrush? _mask;
	private CompositionMaskBrush? _maskBrush;
	private CompositionSurfaceBrush? _sourceBrush;
	private Grid? _rootGrid;
	private SpriteVisual? _redirectVisual;

	/// <summary>
	/// Initializes a new instance of the <see cref="OpacityMaskView"/> class.
	/// Creates a new instance of the <see cref="OpacityMaskView"/> class.
	/// </summary>
	internal OpacityMaskView()
	{
		DefaultStyleKey = typeof(OpacityMaskView);

		// Ensure composition resources are cleaned up when control unloads
		Unloaded += OpacityMaskView_Unloaded;
	}

	/// <summary>
	/// Gets or sets a <see cref="UIElement"/> as the opacity mask that is applied to alpha-channel masking for the rendered content of the content.
	/// </summary>
	public UIElement? OpacityMask
	{
		get => (UIElement?)GetValue(OpacityMaskProperty);
		set => SetValue(OpacityMaskProperty, value);
	}

	/// <inheritdoc />
	protected override void OnApplyTemplate()
	{
		base.OnApplyTemplate();

		// Clean up any prior composition resources (e.g., when the template is re-applied)
		CleanupComposition();

		Grid rootGrid = (Grid)GetTemplateChild(RootGridTemplateName);
		ContentPresenter contentPresenter = (ContentPresenter)GetTemplateChild(ContentPresenterTemplateName);
		Border maskContainer = (Border)GetTemplateChild(MaskContainerTemplateName);

		_rootGrid = rootGrid;

		// Create mask brush and its sources
		_maskBrush = _compositor.CreateMaskBrush();
		// Source is the content we want to render through the mask
		_sourceBrush = GetVisualBrush(contentPresenter);
		_maskBrush.Source = _sourceBrush;
		// Mask is the opacity mask visual brush
		_mask = GetVisualBrush(maskContainer);
		_maskBrush.Mask = OpacityMask is null ? null : _mask;

		// Create a sprite visual that draws with the mask brush, and redirect the control visual to it
		SpriteVisual redirectVisual = _compositor.CreateSpriteVisual();
		redirectVisual.RelativeSizeAdjustment = Vector2.One;
		redirectVisual.Brush = _maskBrush;
		ElementCompositionPreview.SetElementChildVisual(rootGrid, redirectVisual);
		_redirectVisual = redirectVisual;
	}

	private static CompositionSurfaceBrush GetVisualBrush(UIElement element)
	{
		Visual visual = ElementCompositionPreview.GetElementVisual(element);

		Compositor compositor = visual.Compositor;

		CompositionVisualSurface visualSurface = compositor.CreateVisualSurface();
		visualSurface.SourceVisual = visual;
		ExpressionAnimation sourceSizeAnimation = compositor.CreateExpressionAnimation($"{nameof(visual)}.Size");
		sourceSizeAnimation.SetReferenceParameter(nameof(visual), visual);
		visualSurface.StartAnimation(nameof(visualSurface.SourceSize), sourceSizeAnimation);

		CompositionSurfaceBrush brush = compositor.CreateSurfaceBrush(visualSurface);

		visual.Opacity = 0;

		return brush;
	}

	private static void OnOpacityMaskChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		OpacityMaskView self = (OpacityMaskView)d;
		if (self._maskBrush is not { } maskBrush)
		{
			return;
		}

		UIElement? opacityMask = (UIElement?)e.NewValue;
		// Switch to the mask brush if an opacity mask is set; otherwise remove the mask
		maskBrush.Mask = opacityMask is null ? null : self._mask;
	}

	// On control unload, ensure we tear down composition resources and clear the child visual
	private void OpacityMaskView_Unloaded(object sender, RoutedEventArgs e) => CleanupComposition();

	/// <summary>
	/// Clears the ElementCompositionPreview child visual and disposes all composition resources created by this control.
	/// This prevents composition resource retention across template reapplications or when the control is unloaded.
	/// </summary>
	private void CleanupComposition()
	{
		// Detach the child visual from the root grid if present
		if (_rootGrid != null)
		{
			ElementCompositionPreview.SetElementChildVisual(_rootGrid, null);
		}

		// Dispose the redirect visual
		if (_redirectVisual != null)
		{
			_redirectVisual.Brush = null;
			_redirectVisual.Dispose();
			_redirectVisual = null;
		}

		// Dispose mask brush and its sources
		if (_maskBrush != null)
		{
			_maskBrush.Source = null;
			_maskBrush.Mask = null;
			_maskBrush.Dispose();
			_maskBrush = null;
		}

		// Dispose the source content brush explicitly
		_sourceBrush?.Dispose();
		_sourceBrush = null;

		// Dispose the mask brush instance if we created one
		_mask?.Dispose();
		_mask = null;

		_rootGrid = null;
	}
}
