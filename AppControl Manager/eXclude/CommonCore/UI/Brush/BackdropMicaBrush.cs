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

// Parts of this code have been implemented based on the following repo's source code: https://github.com/wherewhere/Mica-For-UWP
// It's been significantly modified to meet the Harden Windows Security repo's requirements.
// MIT License
//
// Copyright(c) 2021 wherewhere
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
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#if HARDEN_SYSTEM_SECURITY
using HardenSystemSecurity;
#else
using AppControlManager;
#endif
using Microsoft.Graphics.Canvas.Effects;
using Microsoft.UI;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Media;
using Windows.UI;

namespace CommonCore.UI.Brush;

internal sealed partial class BackdropMicaBrush : XamlCompositionBrushBase
{
	private CompositionEffectBrush? brush;

	// Keeping a reference to the backdrop so we can dispose it explicitly in OnDisconnected.
	private CompositionBackdropBrush? backdrop;

	private Compositor? Compositor
	{
		get
		{
			if (field == null)
			{
				field = ElementCompositionPreview.GetElementVisual(MainWindow.RootGridPub).Compositor;
			}
			return field;
		}
	}

	#region TintColor

	private static readonly DependencyProperty TintColorProperty =
		DependencyProperty.Register(
			nameof(TintColor),
			typeof(Color),
			typeof(BackdropMicaBrush),
			new PropertyMetadata(default(Color), OnTintColorPropertyChanged));

	public Color TintColor
	{
		get => (Color)GetValue(TintColorProperty);
		set => SetValue(TintColorProperty, value);
	}

	private static void OnTintColorPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is BackdropMicaBrush brush && e.NewValue?.Equals(e.OldValue) != true && e.NewValue is not null)
		{
			Color color = (Color)e.NewValue;

			if (brush.brush is CompositionEffectBrush effect)
			{
				effect.Properties.InsertColor("TintColor.Color", color);
				effect.Properties.InsertColor("LuminosityColor.Color", color);
			}
		}
	}

	#endregion

	#region Amount

	private static readonly DependencyProperty AmountProperty =
		DependencyProperty.Register(
			nameof(Amount),
			typeof(double),
			typeof(BackdropMicaBrush),
			new PropertyMetadata(Atlas.Settings.BackdropMicaBrushBlurAmount, new PropertyChangedCallback(OnAmountChanged)));

	public double Amount
	{
		get => (double)GetValue(AmountProperty);
		set => SetValue(AmountProperty, value);
	}

	private static void OnAmountChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is BackdropMicaBrush brush && e.NewValue?.Equals(e.OldValue) != true && e.NewValue is not null)
		{
			double value = (double)e.NewValue;
			if (value > 100) value = 100;
			else if (value < 0) value = 0;

			brush.brush?.Properties.InsertScalar("Blur.BlurAmount", (float)value);
		}
	}

	#endregion

	#region LuminosityOpacity

	private static readonly DependencyProperty LuminosityOpacityProperty =
		DependencyProperty.Register(
			nameof(LuminosityOpacity),
			typeof(double),
			typeof(BackdropMicaBrush),
			new PropertyMetadata(Atlas.Settings.BackdropMicaBrushLuminosityOpacity, OnLuminosityOpacityPropertyChanged));

	public double LuminosityOpacity
	{
		get => (double)GetValue(LuminosityOpacityProperty);
		set => SetValue(LuminosityOpacityProperty, value);
	}

	private static void OnLuminosityOpacityPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is BackdropMicaBrush brush && e.NewValue?.Equals(e.OldValue) != true && e.NewValue is not null)
		{
			double value = (double)e.NewValue;
			if (value > 1) value = 1;
			else if (value < 0) value = 0;

			brush.brush?.Properties.InsertScalar("LuminosityOpacity.Opacity", (float)value);
		}
	}

	#endregion

	#region TintOpacity

	private static readonly DependencyProperty TintOpacityProperty =
		DependencyProperty.Register(
			nameof(TintOpacity),
			typeof(double),
			typeof(BackdropMicaBrush),
			new PropertyMetadata(Atlas.Settings.BackdropMicaBrushTintOpacity, OnTintOpacityPropertyChanged));

	public double TintOpacity
	{
		get => (double)GetValue(TintOpacityProperty);
		set => SetValue(TintOpacityProperty, value);
	}

	private static readonly string[] animatableProperties = ["TintColor.Color", "TintOpacity.Opacity", "LuminosityColor.Color", "LuminosityOpacity.Opacity", "Blur.BlurAmount"];

	private static void OnTintOpacityPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is BackdropMicaBrush brush && e.NewValue?.Equals(e.OldValue) != true && e.NewValue is not null)
		{
			double value = (double)e.NewValue;
			if (value > 1) value = 1;
			else if (value < 0) value = 0;

			brush.brush?.Properties.InsertScalar("TintOpacity.Opacity", (float)value);
		}
	}

	#endregion

	public BackdropMicaBrush() { }

	protected override void OnConnected()
	{
		if (CompositionBrush == null)
		{
			if (Compositor is not Compositor compositor)
			{
				return;
			}

			try
			{
				using ColorSourceEffect tintColorEffect = new()
				{
					Color = TintColor,
					Name = "TintColor"
				};

				using OpacityEffect tintOpacityEffect = new()
				{
					Name = "TintOpacity",
					Source = tintColorEffect,
					Opacity = (float)TintOpacity
				};

				using ColorSourceEffect luminosityColorEffect = new()
				{
					Color = TintColor,
					Name = "LuminosityColor"
				};

				using OpacityEffect luminosityOpacityEffect = new()
				{
					Name = "LuminosityOpacity",
					Source = luminosityColorEffect,
					Opacity = (float)LuminosityOpacity
				};

				using ColorSourceEffect colorSourceEffect = new()
				{
					Color = Colors.Black
				};

				using GaussianBlurEffect gaussianBlurEffect = new()
				{
					Name = "Blur",
					BlurAmount = (float)Amount,
					BorderMode = EffectBorderMode.Hard,
					Optimization = EffectOptimization.Quality,
					Source = new CompositionEffectSourceParameter("BlurredWallpaperBackdrop")
				};

				using CompositeEffect innerCompositeEffect = new()
				{
					Sources = { colorSourceEffect, gaussianBlurEffect }
				};

				using BlendEffect luminosityBlendEffect = new()
				{
					Mode = BlendEffectMode.Color,
					Foreground = luminosityOpacityEffect,
					Background = innerCompositeEffect
				};

				using BlendEffect colorBlendEffect = new()
				{
					Foreground = tintOpacityEffect,
					Mode = BlendEffectMode.Luminosity,
					Background = luminosityBlendEffect,
				};

				// Create and store backdrop so it can be disposed in OnDisconnected.
				backdrop = compositor.CreateBackdropBrush();

				using CompositionEffectFactory effectFactory = compositor.CreateEffectFactory(colorBlendEffect, animatableProperties);
				CompositionEffectBrush micaEffectBrush = effectFactory.CreateBrush();
				micaEffectBrush.SetSourceParameter("BlurredWallpaperBackdrop", backdrop);

				brush = micaEffectBrush;
				CompositionBrush = brush;
			}
			catch (Exception ex)
			{
				Logger.Write(ex);
			}
		}
	}

	protected override void OnDisconnected()
	{
		CompositionBrush = null;
		brush?.Dispose();
		brush = null;
		backdrop?.Dispose();
		backdrop = null;
	}
}
