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

internal sealed partial class BackdropBlurBrush : XamlCompositionBrushBase
{
	private CompositionEffectBrush? brush;

	// Keep a reference to the backdrop so we can dispose it explicitly in OnDisconnected.
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
			typeof(BackdropBlurBrush),
			new PropertyMetadata(default(Color), OnTintColorPropertyChanged));

	public Color TintColor
	{
		get => (Color)GetValue(TintColorProperty);
		set => SetValue(TintColorProperty, value);
	}

	private static void OnTintColorPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is BackdropBlurBrush brush && e.NewValue?.Equals(e.OldValue) != true && e.NewValue is not null)
		{
			Color color = (Color)e.NewValue;
			brush.brush?.Properties.InsertColor("TintColor.Color", color);
		}
	}

	#endregion

	#region Amount

	private static readonly DependencyProperty AmountProperty =
		DependencyProperty.Register(
			nameof(Amount),
			typeof(double),
			typeof(BackdropBlurBrush),
			new PropertyMetadata(Atlas.Settings.BackdropBlurBrushBlurAmount, new PropertyChangedCallback(OnAmountChanged)));

	public double Amount
	{
		get => (double)GetValue(AmountProperty);
		set => SetValue(AmountProperty, value);
	}

	private static void OnAmountChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is BackdropBlurBrush brush && e.NewValue?.Equals(e.OldValue) != true && e.NewValue is not null)
		{
			double value = (double)e.NewValue;
			if (value > 100) value = 100;
			else if (value < 0) value = 0;

			brush.brush?.Properties.InsertScalar("Blur.BlurAmount", (float)value);
		}
	}

	#endregion

	#region TintOpacity

	private static readonly DependencyProperty TintOpacityProperty =
		DependencyProperty.Register(
			nameof(TintOpacity),
			typeof(double),
			typeof(BackdropBlurBrush),
			new PropertyMetadata(Atlas.Settings.BackdropBlurBrushTintOpacity, OnTintOpacityPropertyChanged));

	public double TintOpacity
	{
		get => (double)GetValue(TintOpacityProperty);
		set => SetValue(TintOpacityProperty, value);
	}

	private static readonly string[] animatableProperties = ["Blur.BlurAmount", "Arithmetic.Source1Amount", "Arithmetic.Source2Amount", "TintColor.Color"];

	private static void OnTintOpacityPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is BackdropBlurBrush brush && e.NewValue?.Equals(e.OldValue) != true && e.NewValue is not null)
		{
			double value = (double)e.NewValue;
			if (value > 1) value = 1;
			else if (value < 0) value = 0;

			if (brush.brush is CompositionEffectBrush effect)
			{
				effect.Properties.InsertScalar("Arithmetic.Source1Amount", (float)(1 - value));
				effect.Properties.InsertScalar("Arithmetic.Source2Amount", (float)value);
			}
		}
	}

	#endregion

	public BackdropBlurBrush() { }

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
				backdrop = compositor.CreateBackdropBrush();

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
					Source = new CompositionEffectSourceParameter("backdrop")
				};

				using CompositeEffect innerCompositeEffect = new()
				{
					Sources = { colorSourceEffect, gaussianBlurEffect }
				};

				using ColorSourceEffect tintColorEffect = new()
				{
					Name = "TintColor",
					Color = TintColor
				};

				using ArithmeticCompositeEffect compositeEffect = new()
				{
					Name = "Arithmetic",
					MultiplyAmount = 0f,
					Source1Amount = (float)(1f - TintOpacity),
					Source2Amount = (float)TintOpacity,
					Source1 = innerCompositeEffect,
					Source2 = tintColorEffect
				};

				using CompositionEffectFactory effectFactory = compositor.CreateEffectFactory(compositeEffect, animatableProperties);
				CompositionEffectBrush effectBrush = effectFactory.CreateBrush();

				effectBrush.SetSourceParameter("backdrop", backdrop);

				brush = effectBrush;
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
