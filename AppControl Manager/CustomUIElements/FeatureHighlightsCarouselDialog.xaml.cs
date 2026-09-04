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

#if HARDEN_SYSTEM_SECURITY
using HardenSystemSecurity;
#endif
using System.Collections.Generic;
using System.Diagnostics;
using System.Numerics;
using Microsoft.Graphics.Canvas.Effects;
using Microsoft.UI;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Microsoft.UI.Xaml.Shapes;
using Windows.Foundation;
using Windows.System;
using WinRT;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// Displays app feature highlights in a locally templated frameless carousel dialog.
/// </summary>
internal sealed partial class FeatureHighlightsCarouselDialog : ContentDialog, IDisposable
{
	/// <summary>
	/// The carousel content.
	/// </summary>
#if HARDEN_SYSTEM_SECURITY
	private readonly FeatureHighlightSlide[] Highlights =
	[
		new(new BitmapImage(new Uri("ms-appx:///Assets/FeatureHighlightsCarousel/Windows Widgets.jpg")), "Windows Widgets", "Pin the Widgets offered by this app to the Windows Widgets Board for quick access to useful tools.", "https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security#windows-widgets-support", new SolidColorBrush(Colors.White)),
		new(new BitmapImage(new Uri("ms-appx:///Assets/FeatureHighlightsCarousel/MCP Server.png")), "Artificial Intelligence", "Install the MCP Server from the Microsoft Store to use this app's features in agentic workflows.", "https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security#mcp-server", new SolidColorBrush(Colors.Black)),
		new(new BitmapImage(new Uri("ms-appx:///Assets/FeatureHighlightsCarousel/CLI.jpg")), "Command Line", "See how you can use this app in unattended and headless scenarios.", "https://github.com/HotCakeX/Harden-Windows-Security/wiki/Harden-System-Security#commandline-interface-cli-support", new SolidColorBrush(Colors.White)),
		new(new BitmapImage(new Uri("ms-appx:///Assets/FeatureHighlightsCarousel/Support.jpg")), "Support", "Support is always available on GitHub, just ask.", "https://github.com/HotCakeX/Harden-Windows-Security/discussions", new SolidColorBrush(Colors.Black))
	];
#else
	private readonly FeatureHighlightSlide[] Highlights =
	[
		new(new BitmapImage(new Uri("ms-appx:///Assets/FeatureHighlightsCarousel/Introduction.jpg")), "Introduction", "This is an specialized application for managing all aspects of Application Control for Business policies.", "https://github.com/HotCakeX/Harden-Windows-Security/wiki/Application-Control-(WDAC)-Frequently-Asked-Questions-(FAQs)", new SolidColorBrush(Colors.White)),
		new(new BitmapImage(new Uri("ms-appx:///Assets/FeatureHighlightsCarousel/ImportantNote.jpg")), "Important Note", "If you are not familiar with Application Control policies management, you can accidentally end up blocking important applications on your system.", "https://github.com/HotCakeX/Harden-Windows-Security/wiki/Introduction", new SolidColorBrush(Colors.White)),
		new(new BitmapImage(new Uri("ms-appx:///Assets/FeatureHighlightsCarousel/StrictKernelMode.jpg")), "Kernel Protection", "Create robust kernel-mode policy that only loads drivers you select and does not disrupt everyday user-mode programs.", "https://github.com/HotCakeX/Harden-Windows-Security/wiki/How-To-Create-and-Maintain-Strict-Kernel%E2%80%90Mode-App-Control-Policy", new SolidColorBrush(Colors.White)),
		new(new BitmapImage(new Uri("ms-appx:///Assets/FeatureHighlightsCarousel/Support.jpg")), "Support", "Support is always available on GitHub, just ask.", "https://github.com/HotCakeX/Harden-Windows-Security/discussions", new SolidColorBrush(Colors.Black))
	];
#endif

	private const int SlideCount = 4;
	private const int ContentLayersPerSlide = 3;
	private const double SlideTransitionDurationMilliseconds = 500.0;

	private static readonly SlideVisualState[] SlideLayouts =
	[
		new(0, 0, 800, 400, 0),
		new(0, 0, 800, 400, 0),
		new(400, 200, 200, 250, -0.5),
		new(620, 200, 200, 250, -0.5)
	];

	private static readonly TimeSpan[] ContentAnimationDelays =
	[
		TimeSpan.Zero,
		TimeSpan.FromMilliseconds(300),
		TimeSpan.FromMilliseconds(600)
	];

	private readonly Grid[] _slides;
	private readonly StackPanel[] _contentRoots;
	private readonly Grid[] _contentHosts;
	private readonly FrameworkElement[] _contentSources;
	private readonly SlideVisualState[] _currentStates = new SlideVisualState[SlideCount];
	private readonly SlideVisualState[] _startStates = new SlideVisualState[SlideCount];
	private readonly SlideVisualState[] _targetStates = new SlideVisualState[SlideCount];
	private readonly int[] _order = [0, 1, 2, 3];
	private readonly PointerEventHandler _lightDismissPointerPressedHandler;

	private CarouselAnimatedContentLayer[]? _contentLayers;
	private UIElement? _dialogBackgroundElement;
	private Rectangle? _smokeLayer;
	private long _dialogBackgroundShadowChangedToken = -1;
	private long _transitionStartTimestamp;
	private bool _isRenderingSubscribed;
	private bool _isClosed;
	private bool _disposed;

	internal FeatureHighlightsCarouselDialog()
	{
		_lightDismissPointerPressedHandler = new PointerEventHandler(SmokeLayer_PointerPressed);
		InitializeComponent();

		XamlRoot = App.MainWindow?.Content.XamlRoot;
		RequestedTheme = Enum.TryParse<ElementTheme>(Atlas.Settings.AppTheme, true, out ElementTheme theme) ? theme : ElementTheme.Default;
		Resources["ContentDialogMaxWidth"] = 5000;
		Resources["ContentDialogMaxHeight"] = 5000;


		_slides = [Slide0, Slide1, Slide2, Slide3];
		_contentRoots = [Slide0Content, Slide1Content, Slide2Content, Slide3Content];
		_contentHosts =
		[
			Slide0NameHost,
			Slide0DescriptionHost,
			Slide0ButtonHost,
			Slide1NameHost,
			Slide1DescriptionHost,
			Slide1ButtonHost,
			Slide2NameHost,
			Slide2DescriptionHost,
			Slide2ButtonHost,
			Slide3NameHost,
			Slide3DescriptionHost,
			Slide3ButtonHost
		];
		_contentSources =
		[
			Slide0NameSource,
			Slide0DescriptionSource,
			Slide0ButtonSource,
			Slide1NameSource,
			Slide1DescriptionSource,
			Slide1ButtonSource,
			Slide2NameSource,
			Slide2DescriptionSource,
			Slide2ButtonSource,
			Slide3NameSource,
			Slide3DescriptionSource,
			Slide3ButtonSource
		];

		InitializeSlideStates();
	}

	internal new IAsyncOperation<ContentDialogResult> ShowAsync()
	{
		ContentDialogV2.RegisterContentDialog(this);
		return base.ShowAsync();
	}

	[DynamicWindowsRuntimeCast(typeof(UIElement))]
	protected override void OnApplyTemplate()
	{
		StopSuppressingDialogBackgroundShadow();
		base.OnApplyTemplate();

		_dialogBackgroundElement = GetTemplateChild("BackgroundElement") as UIElement;
		if (_dialogBackgroundElement is not null)
		{
			_dialogBackgroundShadowChangedToken = _dialogBackgroundElement.RegisterPropertyChangedCallback(
				ShadowProperty,
				OnDialogBackgroundShadowChanged);
			_dialogBackgroundElement.Shadow = null;
		}
	}

	private static void OnDialogBackgroundShadowChanged(DependencyObject sender, DependencyProperty property)
	{
		if (sender is UIElement { Shadow: not null } backgroundElement)
		{
			backgroundElement.Shadow = null;
		}
	}

	[DynamicWindowsRuntimeCast(typeof(Rectangle))]
	private void FeatureHighlightsCarouselDialog_Opened()
	{
		if (XamlRoot is null)
		{
			return;
		}

		IReadOnlyList<Popup> openPopups = VisualTreeHelper.GetOpenPopupsForXamlRoot(XamlRoot);
		foreach (Popup popup in openPopups)
		{
			if (popup.Child is Rectangle smokeLayer &&
				string.Equals(smokeLayer.Name, "SmokeLayerBackground", StringComparison.OrdinalIgnoreCase))
			{
				_smokeLayer = smokeLayer;
				_smokeLayer.AddHandler(PointerPressedEvent, _lightDismissPointerPressedHandler, true);
				return;
			}
		}
	}

	private void FeatureHighlightsCarouselDialog_Loaded()
	{
		if (_contentLayers is not null || _isClosed)
		{
			return;
		}

		_contentLayers = new CarouselAnimatedContentLayer[_contentSources.Length];
		for (int i = 0; i < _contentSources.Length; i++)
		{
			_contentLayers[i] = new CarouselAnimatedContentLayer(_contentHosts[i], _contentSources[i]);
		}

		ShowActiveContent();
	}

	private void InitializeSlideStates()
	{
		for (int position = 0; position < SlideCount; position++)
		{
			int slideIndex = _order[position];
			SlideVisualState state = SlideLayouts[position];
			_currentStates[slideIndex] = state;
			_startStates[slideIndex] = state;
			_targetStates[slideIndex] = state;
			Canvas.SetZIndex(_slides[slideIndex], position);
			ApplySlideState(_slides[slideIndex], state);
		}
	}

	private void NextButton_Click() => RotateSlides(moveForward: true);

	private void PreviousButton_Click() => RotateSlides(moveForward: false);

	private void RotateSlides(bool moveForward)
	{
		if (_isClosed || _contentLayers is null)
		{
			return;
		}

		// Finish an interrupted transition before reordering so a full-size slide always covers the viewport.
		CompleteSlideAnimation();

		int movedSlideIndex;
		if (moveForward)
		{
			int firstSlide = _order[0];
			Array.Copy(_order, 1, _order, 0, SlideCount - 1);
			_order[^1] = firstSlide;
			movedSlideIndex = firstSlide;
		}
		else
		{
			int lastSlide = _order[^1];
			Array.Copy(_order, 0, _order, 1, SlideCount - 1);
			_order[0] = lastSlide;
			movedSlideIndex = lastSlide;
		}

		for (int position = 0; position < SlideCount; position++)
		{
			int slideIndex = _order[position];
			_startStates[slideIndex] = _currentStates[slideIndex];
			_targetStates[slideIndex] = SlideLayouts[position];
			Canvas.SetZIndex(_slides[slideIndex], position);

			// appendChild/prepend moves the wrapped item directly to its new layout.
			if (slideIndex == movedSlideIndex)
			{
				_currentStates[slideIndex] = _targetStates[slideIndex];
				_startStates[slideIndex] = _targetStates[slideIndex];
				ApplySlideState(_slides[slideIndex], _targetStates[slideIndex]);
			}
		}

		ShowActiveContent();

		_transitionStartTimestamp = Stopwatch.GetTimestamp();
		if (!_isRenderingSubscribed)
		{
			CompositionTarget.Rendering += CompositionTarget_Rendering;
			_isRenderingSubscribed = true;
		}
	}

	private void ShowActiveContent()
	{
		if (_contentLayers is null)
		{
			return;
		}

		int activeSlideIndex = _order[1];

		for (int slideIndex = 0; slideIndex < SlideCount; slideIndex++)
		{
			bool isActive = slideIndex == activeSlideIndex;
			_contentRoots[slideIndex].Visibility = isActive ? Visibility.Visible : Visibility.Collapsed;
			_contentRoots[slideIndex].IsHitTestVisible = isActive;

			int firstLayerIndex = slideIndex * ContentLayersPerSlide;
			for (int layerOffset = 0; layerOffset < ContentLayersPerSlide; layerOffset++)
			{
				CarouselAnimatedContentLayer layer = _contentLayers[firstLayerIndex + layerOffset];
				if (isActive)
				{
					layer.Start(ContentAnimationDelays[layerOffset]);
				}
				else
				{
					layer.Hide();
				}
			}
		}
	}

	private void CompositionTarget_Rendering(object? sender, object e) => UpdateSlideAnimationFrame();

	private void UpdateSlideAnimationFrame()
	{
		if (!_isRenderingSubscribed)
		{
			return;
		}

		double elapsedMilliseconds = Stopwatch.GetElapsedTime(_transitionStartTimestamp).TotalMilliseconds;
		double progress = Math.Clamp(elapsedMilliseconds / SlideTransitionDurationMilliseconds, 0.0, 1.0);
		double easedProgress = Ease(progress);

		for (int slideIndex = 0; slideIndex < SlideCount; slideIndex++)
		{
			SlideVisualState state = Lerp(_startStates[slideIndex], _targetStates[slideIndex], easedProgress);
			_currentStates[slideIndex] = state;
			ApplySlideState(_slides[slideIndex], state);
		}

		if (progress >= 1.0)
		{
			StopSlideAnimation();
		}
	}

	private void CompleteSlideAnimation()
	{
		if (!_isRenderingSubscribed)
		{
			return;
		}

		for (int slideIndex = 0; slideIndex < SlideCount; slideIndex++)
		{
			SlideVisualState state = _targetStates[slideIndex];
			_currentStates[slideIndex] = state;
			ApplySlideState(_slides[slideIndex], state);
		}

		StopSlideAnimation();
	}

	private static double Ease(double progress)
	{
		double parameter = progress;

		for (int i = 0; i < 8; i++)
		{
			double difference = EvaluateBezier(parameter, 0.25, 0.25) - progress;
			if (Math.Abs(difference) < 0.000001)
			{
				break;
			}

			double derivative = EvaluateBezierDerivative(parameter, 0.25, 0.25);
			if (Math.Abs(derivative) < 0.000001)
			{
				break;
			}

			parameter = Math.Clamp(parameter - (difference / derivative), 0.0, 1.0);
		}

		return EvaluateBezier(parameter, 0.1, 1.0);
	}

	private static double EvaluateBezier(double parameter, double firstControlPoint, double secondControlPoint) =>
		(3.0 * (1.0 - parameter) * (1.0 - parameter) * parameter * firstControlPoint) +
		(3.0 * (1.0 - parameter) * parameter * parameter * secondControlPoint) +
		(parameter * parameter * parameter);

	private static double EvaluateBezierDerivative(double parameter, double firstControlPoint, double secondControlPoint) =>
		(3.0 * (1.0 - parameter) * (1.0 - parameter) * firstControlPoint) +
		(6.0 * (1.0 - parameter) * parameter * (secondControlPoint - firstControlPoint)) +
		(3.0 * parameter * parameter * (1.0 - secondControlPoint));

	private static SlideVisualState Lerp(SlideVisualState start, SlideVisualState end, double progress) =>
		new(
			start.Left + ((end.Left - start.Left) * progress),
			start.Top + ((end.Top - start.Top) * progress),
			start.Width + ((end.Width - start.Width) * progress),
			start.Height + ((end.Height - start.Height) * progress),
			start.TranslationYFactor + ((end.TranslationYFactor - start.TranslationYFactor) * progress));

	private static void ApplySlideState(Grid slide, SlideVisualState state)
	{
		Canvas.SetLeft(slide, state.Left);
		Canvas.SetTop(slide, state.Top);
		slide.Width = state.Width;
		slide.Height = state.Height;
		slide.Translation = new Vector3(0.0f, (float)(state.TranslationYFactor * state.Height), 0.0f);
	}

	private void StopSlideAnimation()
	{
		if (!_isRenderingSubscribed)
		{
			return;
		}

		CompositionTarget.Rendering -= CompositionTarget_Rendering;
		_isRenderingSubscribed = false;
	}

	private void SmokeLayer_PointerPressed(object sender, PointerRoutedEventArgs e)
	{
		e.Handled = true;
		Hide();
	}

	[DynamicWindowsRuntimeCast(typeof(Button))]
	private async void SeeMoreButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button { Tag: string destination } &&
			Uri.TryCreate(destination, UriKind.Absolute, out Uri? destinationUri))
		{
			_ = await Launcher.LaunchUriAsync(destinationUri);
		}
	}

	private void StopSuppressingDialogBackgroundShadow()
	{
		if (_dialogBackgroundElement is null)
		{
			return;
		}

		if (_dialogBackgroundShadowChangedToken >= 0)
		{
			_dialogBackgroundElement.UnregisterPropertyChangedCallback(
				ShadowProperty,
				_dialogBackgroundShadowChangedToken);
			_dialogBackgroundShadowChangedToken = -1;
		}

		_dialogBackgroundElement.Shadow = null;
		_dialogBackgroundElement = null;
	}

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		_isClosed = true;
		ContentDialogV2.UnregisterContentDialog(this);
		StopSlideAnimation();
		StopSuppressingDialogBackgroundShadow();
		_smokeLayer?.RemoveHandler(PointerPressedEvent, _lightDismissPointerPressedHandler);
		_smokeLayer = null;

		if (_contentLayers is not null)
		{
			foreach (CarouselAnimatedContentLayer layer in _contentLayers)
			{
				layer.Dispose();
			}

			_contentLayers = null;
		}

	}

	// Changed from "readonly record struct"
	// See https://github.com/microsoft/CsWinRT/issues/2546
	internal sealed record SlideVisualState(
		double Left,
		double Top,
		double Width,
		double Height,
		double TranslationYFactor);
}

/// <summary>
/// Immutable content displayed by one feature-highlight slide.
/// </summary>
internal sealed record FeatureHighlightSlide(
	BitmapImage ImageSource,
	string Title,
	string Description,
	string Destination,
	SolidColorBrush TextForeground);

/// <summary>
/// Redirects a XAML element through an animatable Win2D blur effect.
/// </summary>
internal sealed partial class CarouselAnimatedContentLayer : IDisposable
{
	private const float BlurAmount = 33.0f;
	private const float EffectPadding = 100.0f;
	private const float EntranceTranslation = 100.0f;
	private const string BlurPropertyName = "Blur.BlurAmount";

	private static readonly TimeSpan AnimationDuration = TimeSpan.FromSeconds(1);
	private static readonly string[] AnimatableEffectProperties = [BlurPropertyName];
	private static readonly Vector3 HiddenTranslation = new(0.0f, EntranceTranslation, 0.0f);

	private readonly Grid _host;
	private readonly FrameworkElement _source;
	private readonly CompositionVisualSurface _visualSurface;
	private readonly CompositionSurfaceBrush _surfaceBrush;
	private readonly CompositionEffectBrush _effectBrush;
	private readonly SpriteVisual _outputVisual;
	private readonly CubicBezierEasingFunction _easingFunction;
	private readonly Vector3 _restingOffset;

	private ScalarKeyFrameAnimation? _opacityAnimation;
	private Vector3KeyFrameAnimation? _translationAnimation;
	private ScalarKeyFrameAnimation? _blurAnimation;
	private bool _disposed;

	internal CarouselAnimatedContentLayer(Grid host, FrameworkElement source)
	{
		_host = host;
		_source = source;
		Visual sourceVisual = ElementCompositionPreview.GetElementVisual(source);
		Compositor compositor = sourceVisual.Compositor;

		_visualSurface = compositor.CreateVisualSurface();
		_visualSurface.SourceVisual = sourceVisual;
		_visualSurface.SourceOffset = new Vector2(-EffectPadding, -EffectPadding);

		_surfaceBrush = compositor.CreateSurfaceBrush(_visualSurface);
		_surfaceBrush.Stretch = CompositionStretch.None;

		using GaussianBlurEffect blurEffect = new()
		{
			Name = "Blur",
			BlurAmount = BlurAmount,
			BorderMode = EffectBorderMode.Soft,
			Optimization = EffectOptimization.Quality,
			Source = new CompositionEffectSourceParameter("source")
		};
		using CompositionEffectFactory effectFactory = compositor.CreateEffectFactory(blurEffect, AnimatableEffectProperties);
		_effectBrush = effectFactory.CreateBrush();
		_effectBrush.SetSourceParameter("source", _surfaceBrush);

		_restingOffset = new Vector3(-EffectPadding, -EffectPadding, 0.0f);

		_outputVisual = compositor.CreateSpriteVisual();
		_outputVisual.Brush = _effectBrush;
		_outputVisual.Offset = _restingOffset;
		_outputVisual.Opacity = 0.0f;

		_easingFunction = compositor.CreateCubicBezierEasingFunction(
			new Vector2(0.42f, 0.0f),
			new Vector2(0.58f, 1.0f));

		ElementCompositionPreview.SetElementChildVisual(_host, _outputVisual);
		_host.Translation = HiddenTranslation;
		sourceVisual.Opacity = 0.0f;
		_source.SizeChanged += Source_SizeChanged;
		UpdateEffectSize(new Size(_source.ActualWidth, _source.ActualHeight));
	}

	internal void Start(TimeSpan delay)
	{
		if (_disposed)
		{
			return;
		}

		StopAndDisposeAnimations();

		_outputVisual.Opacity = 0.0f;
		_host.Translation = HiddenTranslation;
		_effectBrush.Properties.InsertScalar(BlurPropertyName, BlurAmount);

		Compositor compositor = _outputVisual.Compositor;

		_opacityAnimation = compositor.CreateScalarKeyFrameAnimation();
		_opacityAnimation.InsertKeyFrame(0.0f, 0.0f);
		_opacityAnimation.InsertKeyFrame(1.0f, 1.0f, _easingFunction);
		ConfigureAnimation(_opacityAnimation, delay);

		_translationAnimation = compositor.CreateVector3KeyFrameAnimation();
		_translationAnimation.Target = nameof(UIElement.Translation);
		_translationAnimation.InsertKeyFrame(0.0f, HiddenTranslation);
		_translationAnimation.InsertKeyFrame(1.0f, Vector3.Zero, _easingFunction);
		ConfigureAnimation(_translationAnimation, delay);

		_blurAnimation = compositor.CreateScalarKeyFrameAnimation();
		_blurAnimation.InsertKeyFrame(0.0f, BlurAmount);
		_blurAnimation.InsertKeyFrame(1.0f, 0.0f, _easingFunction);
		ConfigureAnimation(_blurAnimation, delay);

		_outputVisual.StartAnimation(nameof(Visual.Opacity), _opacityAnimation);
		_host.StartAnimation(_translationAnimation);
		_effectBrush.Properties.StartAnimation(BlurPropertyName, _blurAnimation);
	}

	internal void Hide()
	{
		if (_disposed)
		{
			return;
		}

		StopAndDisposeAnimations();
		_outputVisual.Opacity = 0.0f;
		_host.Translation = HiddenTranslation;
		_effectBrush.Properties.InsertScalar(BlurPropertyName, BlurAmount);
	}

	private void Source_SizeChanged(object sender, SizeChangedEventArgs e) => UpdateEffectSize(e.NewSize);

	private void UpdateEffectSize(Size sourceSize)
	{
		Vector2 effectSize = new(
			Math.Max(1.0f, (float)sourceSize.Width) + (EffectPadding * 2.0f),
			Math.Max(1.0f, (float)sourceSize.Height) + (EffectPadding * 2.0f));

		_visualSurface.SourceSize = effectSize;
		_outputVisual.Size = effectSize;
	}

	private static void ConfigureAnimation(KeyFrameAnimation animation, TimeSpan delay)
	{
		animation.Duration = AnimationDuration;
		animation.DelayTime = delay;
		animation.DelayBehavior = AnimationDelayBehavior.SetInitialValueBeforeDelay;
		animation.StopBehavior = AnimationStopBehavior.SetToFinalValue;
	}

	private void StopAndDisposeAnimations()
	{
		_outputVisual.StopAnimation(nameof(Visual.Opacity));
		_effectBrush.Properties.StopAnimation(BlurPropertyName);

		_opacityAnimation?.Dispose();
		_opacityAnimation = null;
		if (_translationAnimation is not null)
		{
			_host.StopAnimation(_translationAnimation);
			_translationAnimation.Dispose();
			_translationAnimation = null;
		}
		_blurAnimation?.Dispose();
		_blurAnimation = null;
	}

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		StopAndDisposeAnimations();
		_source.SizeChanged -= Source_SizeChanged;
		ElementCompositionPreview.SetElementChildVisual(_host, null);
		_host.Translation = Vector3.Zero;
		_visualSurface.SourceVisual.Opacity = 1.0f;

		_outputVisual.Brush = null;
		_outputVisual.Dispose();
		_effectBrush.Dispose();
		_surfaceBrush.Dispose();
		_visualSurface.Dispose();
		_easingFunction.Dispose();
	}
}
