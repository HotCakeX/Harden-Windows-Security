// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// Source: https://github.com/CommunityToolkit/Labs-Windows/tree/main/components/Shimmer
// License: https://github.com/CommunityToolkit/Labs-Windows/blob/main/License.md
// It's been modified to meet the Harden Windows Security repository's requirements.

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

using System.Numerics;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace CommonCore.ToolKits;

/// <summary>
/// A generic shimmer control that can be used to construct a beautiful loading effect.
/// </summary>
internal sealed partial class Shimmer : UserControl
{
	private const float InitialStartPointX = -7.92f;

	/// <summary>
	/// Identifies the <see cref="Duration"/> dependency property.
	/// </summary>
	public static readonly DependencyProperty DurationProperty = DependencyProperty.Register(
	   nameof(Duration),
	   typeof(object),
	   typeof(Shimmer),
	   new PropertyMetadata(defaultValue: TimeSpan.FromMilliseconds(1600), PropertyChanged));

	/// <summary>
	/// Identifies the <see cref="IsActive"/> dependency property.
	/// </summary>
	public static readonly DependencyProperty IsActiveProperty = DependencyProperty.Register(
	  nameof(IsActive),
	  typeof(bool),
	  typeof(Shimmer),
	  new PropertyMetadata(defaultValue: true, PropertyChanged));

	private ExpressionAnimation? _sizeAnimation;
	private Vector2KeyFrameAnimation? _gradientStartPointAnimation;
	private Vector2KeyFrameAnimation? _gradientEndPointAnimation;
	private CompositionColorGradientStop? _gradientStop1;
	private CompositionColorGradientStop? _gradientStop2;
	private CompositionColorGradientStop? _gradientStop3;
	private CompositionColorGradientStop? _gradientStop4;
	private CompositionRoundedRectangleGeometry? _rectangleGeometry;
	private CompositionSpriteShape? _spriteShape;
	private ShapeVisual? _shapeVisual;
	private CompositionLinearGradientBrush? _shimmerMaskGradient;

	// The visual container for the effect
	private readonly Border _shape;

	private bool _initialized;
	private bool _animationStarted;

	internal Shimmer()
	{
		// Initialize the content visuals
		_shape = new();
		Content = _shape;

		// Apply default style values
		MinWidth = 40;
		MinHeight = 8;
		CornerRadius = new(4);

		// Bind the inner Border's properties to the UserControl's properties
		// so that setting <CCToolKit:Shimmer Background="..." /> works as expected.
		Binding backgroundBinding = new()
		{
			Source = this,
			Path = new PropertyPath(nameof(Background)),
			Mode = BindingMode.OneWay
		};
		_shape.SetBinding(Border.BackgroundProperty, backgroundBinding);

		Binding cornerRadiusBinding = new()
		{
			Source = this,
			Path = new PropertyPath(nameof(CornerRadius)),
			Mode = BindingMode.OneWay
		};
		_shape.SetBinding(Border.CornerRadiusProperty, cornerRadiusBinding);

		// Attempt to set the default background resource if available
		if (Application.Current.Resources.TryGetValue("ControlAltFillColorTertiaryBrush", out object? brushObj)
			&& brushObj is Brush defaultBrush)
		{
			Background = defaultBrush;
		}

		Loaded += OnLoaded;
		Unloaded += OnUnloaded;
	}

	/// <summary>
	/// Gets or sets the animation duration
	/// </summary>
	public TimeSpan Duration
	{
		get => (TimeSpan)GetValue(DurationProperty);
		set => SetValue(DurationProperty, value);
	}

	/// <summary>
	/// Gets or sets if the animation is playing
	/// </summary>
	public bool IsActive
	{
		get => (bool)GetValue(IsActiveProperty);
		set => SetValue(IsActiveProperty, value);
	}

	private static void PropertyChanged(DependencyObject s, DependencyPropertyChangedEventArgs e)
	{
		if (s is Shimmer self)
		{
			if (self.IsActive)
			{
				self.StopAnimation();
				self.TryStartAnimation();
			}
			else
			{
				self.StopAnimation();
			}
		}
	}

	private void OnLoaded(object sender, RoutedEventArgs e)
	{
		if (!_initialized && TryInitializationResource() && IsActive)
		{
			TryStartAnimation();
		}

		ActualThemeChanged += OnActualThemeChanged;
	}

	private void OnUnloaded(object sender, RoutedEventArgs e)
	{
		ActualThemeChanged -= OnActualThemeChanged;
		StopAnimation();

		if (_initialized)
		{
			ElementCompositionPreview.SetElementChildVisual(_shape, null);

			_spriteShape?.Dispose();
			_rectangleGeometry?.Dispose();
			_shapeVisual?.Dispose();
			_shimmerMaskGradient?.Dispose();
			_gradientStop1?.Dispose();
			_gradientStop2?.Dispose();
			_gradientStop3?.Dispose();
			_gradientStop4?.Dispose();

			_initialized = false;
		}
	}

	private void OnActualThemeChanged(FrameworkElement sender, object args)
	{
		if (!_initialized)
		{
			return;
		}

		SetGradientStopColorsByTheme();
	}

	private bool TryInitializationResource()
	{
		if (_initialized)
		{
			return true;
		}

		if (!IsLoaded)
		{
			return false;
		}

		Visual rootVisual = ElementCompositionPreview.GetElementVisual(_shape);
		Compositor compositor = rootVisual.Compositor;

		_rectangleGeometry = compositor.CreateRoundedRectangleGeometry();
		_shapeVisual = compositor.CreateShapeVisual();
		_shimmerMaskGradient = compositor.CreateLinearGradientBrush();
		_gradientStop1 = compositor.CreateColorGradientStop();
		_gradientStop2 = compositor.CreateColorGradientStop();
		_gradientStop3 = compositor.CreateColorGradientStop();
		_gradientStop4 = compositor.CreateColorGradientStop();

		SetGradientAndStops();
		SetGradientStopColorsByTheme();

		// Ensure geometry is valid before usage
		if (_rectangleGeometry is { } geometry)
		{
			geometry.CornerRadius = new Vector2((float)CornerRadius.TopLeft);
			_spriteShape = compositor.CreateSpriteShape(geometry);
			_spriteShape.FillBrush = _shimmerMaskGradient;

			if (_shapeVisual is { } visual)
			{
				visual.Shapes.Add(_spriteShape);
				ElementCompositionPreview.SetElementChildVisual(_shape, visual);
				_initialized = true;
				return true;
			}
		}

		return false;
	}

	private void SetGradientAndStops()
	{
		if (_shimmerMaskGradient is { } gradient)
		{
			gradient.StartPoint = new Vector2(InitialStartPointX, 0.0f);
			gradient.EndPoint = new Vector2(0.0f, 1.0f); //Vector2.One

			if (_gradientStop1 is { } s1)
			{
				s1.Offset = 0.273f;
				gradient.ColorStops.Add(s1);
			}
			if (_gradientStop2 is { } s2)
			{
				s2.Offset = 0.436f;
				gradient.ColorStops.Add(s2);
			}
			if (_gradientStop3 is { } s3)
			{
				s3.Offset = 0.482f;
				gradient.ColorStops.Add(s3);
			}
			if (_gradientStop4 is { } s4)
			{
				s4.Offset = 0.643f;
				gradient.ColorStops.Add(s4);
			}
		}
	}

	private void SetGradientStopColorsByTheme()
	{
		// Safe access to gradient stops
		if (_gradientStop1 is null || _gradientStop2 is null || _gradientStop3 is null || _gradientStop4 is null)
		{
			return;
		}

		switch (ActualTheme)
		{
			case ElementTheme.Default:
			case ElementTheme.Dark:
				_gradientStop1.Color = Color.FromArgb((byte)(255 * 6.05 / 100), 255, 255, 255);
				_gradientStop2.Color = Color.FromArgb((byte)(255 * 3.26 / 100), 255, 255, 255);
				_gradientStop3.Color = Color.FromArgb((byte)(255 * 3.26 / 100), 255, 255, 255);
				_gradientStop4.Color = Color.FromArgb((byte)(255 * 6.05 / 100), 255, 255, 255);
				break;
			case ElementTheme.Light:
				_gradientStop1.Color = Color.FromArgb((byte)(255 * 5.37 / 100), 0, 0, 0);
				_gradientStop2.Color = Color.FromArgb((byte)(255 * 2.89 / 100), 0, 0, 0);
				_gradientStop3.Color = Color.FromArgb((byte)(255 * 2.89 / 100), 0, 0, 0);
				_gradientStop4.Color = Color.FromArgb((byte)(255 * 5.37 / 100), 0, 0, 0);
				break;
			default:
				break;
		}
	}

	private void TryStartAnimation()
	{
		if (_animationStarted || !_initialized || _shapeVisual is null || _rectangleGeometry is null || _shimmerMaskGradient is null)
		{
			return;
		}

		Visual rootVisual = ElementCompositionPreview.GetElementVisual(_shape);
		Compositor compositor = rootVisual.Compositor;

		// Size Animation
		_sizeAnimation = compositor.CreateExpressionAnimation("HostVisual.Size");
		_sizeAnimation.SetReferenceParameter("HostVisual", rootVisual);

		_shapeVisual.StartAnimation("Size", _sizeAnimation);
		_rectangleGeometry.StartAnimation("Size", _sizeAnimation);

		_gradientStartPointAnimation = compositor.CreateVector2KeyFrameAnimation();
		_gradientStartPointAnimation.Duration = Duration;
		_gradientStartPointAnimation.IterationBehavior = AnimationIterationBehavior.Forever;
		_gradientStartPointAnimation.InsertKeyFrame(0.0f, new Vector2(InitialStartPointX, 0.0f));
		_gradientStartPointAnimation.InsertKeyFrame(1.0f, Vector2.Zero);
		_shimmerMaskGradient.StartAnimation(nameof(CompositionLinearGradientBrush.StartPoint), _gradientStartPointAnimation);

		_gradientEndPointAnimation = compositor.CreateVector2KeyFrameAnimation();
		_gradientEndPointAnimation.Duration = Duration;
		_gradientEndPointAnimation.IterationBehavior = AnimationIterationBehavior.Forever;
		_gradientEndPointAnimation.InsertKeyFrame(0.0f, new Vector2(1.0f, 0.0f)); //Vector2.One
		_gradientEndPointAnimation.InsertKeyFrame(1.0f, new Vector2(-InitialStartPointX, 1.0f));
		_shimmerMaskGradient.StartAnimation(nameof(CompositionLinearGradientBrush.EndPoint), _gradientEndPointAnimation);

		_animationStarted = true;
	}

	private void StopAnimation()
	{
		if (!_animationStarted)
		{
			return;
		}

		_shapeVisual?.StopAnimation(nameof(ShapeVisual.Size));
		_rectangleGeometry?.StopAnimation(nameof(CompositionRoundedRectangleGeometry.Size));
		_shimmerMaskGradient?.StopAnimation(nameof(CompositionLinearGradientBrush.StartPoint));
		_shimmerMaskGradient?.StopAnimation(nameof(CompositionLinearGradientBrush.EndPoint));

		_sizeAnimation?.Dispose();
		_gradientStartPointAnimation?.Dispose();
		_gradientEndPointAnimation?.Dispose();
		_animationStarted = false;
	}
}
