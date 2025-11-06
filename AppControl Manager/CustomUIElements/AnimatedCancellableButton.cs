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

using System.Threading;
using System.Threading.Tasks;
using CommunityToolkit.WinUI;
using CommunityToolkit.WinUI.Media;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.UI;

namespace AppControlManager.CustomUIElements;

internal sealed partial class AnimatedCancellableButton : Button, IDisposable, IExplicitDisposalOptIn
{
	private const string ZeroOffsetString = "0";
	private const string ButtonDefaultText = "Button";
	private const string OpacityPropertyName = "Opacity";
	private static readonly TimeSpan FiftyMsTimeSpan = TimeSpan.FromMilliseconds(50);
	private static readonly TimeSpan OneHundredFiftyMsTimeSpan = TimeSpan.FromMilliseconds(150);
	private static readonly Color TransparentColor = Color.FromArgb(0, 0, 0, 0);

	// Static cached button styles
	private static readonly Style DefaultButtonStyle = (Style)Application.Current.Resources["DefaultButtonStyle"];
	private static readonly Style AccentButtonStyle = (Style)Application.Current.Resources["AccentButtonStyle"];

	private Storyboard _fadeOutStoryboard = new();
	private Storyboard _fadeInStoryboard = new();
	private DoubleAnimation _fadeOutAnimation = new();
	private DoubleAnimation _fadeInAnimation = new();
	private Storyboard _shadowAnimationStoryboard = new();
	private AttachedCardShadow? _attachedShadow;
	private bool _isShadowAnimationRunning;
	private bool _hasShadowApplied;
	private DispatcherTimer? _shadowTimer;
	private bool _shadowIncreasing = true;
	private double _currentBlurRadius = 8.0;
	private const double MIN_BLUR_RADIUS = 8.0;
	private const double MAX_BLUR_RADIUS = 30.0;
	private const double BLUR_STEP = 1.0;
	private volatile bool _isClickInProgress;
	private readonly Lock _stateLock = new();
	private volatile bool _operationStarted;
	private bool _isLoaded;
	private DispatcherTimer? _clickDelayTimer;
	private CancellationTokenSource? _disposalCancellationTokenSource;
	private volatile bool _isDisposed;
	private volatile bool _isDisposing;

	private int _currentColorIndex;
	private int _nextColorIndex = 1;
	private int _colorTransitionCounter;
	private const int COLOR_TRANSITION_DURATION = 60;
	private const int COLOR_HOLD_DURATION = 80;
	private int _colorHoldCounter;
	private bool _inColorTransition;
	private const double SHADOW_OPACITY = 0.85;

	private static readonly Color[] _shadowColors = [
		Color.FromArgb(255, 255, 192, 203), // Pink
		Color.FromArgb(255, 255, 20, 147),  // Hot Pink
		Color.FromArgb(255, 144, 238, 144), // Light Green
		Color.FromArgb(255, 173, 216, 230), // Light Blue
		Color.FromArgb(255, 221, 160, 221)  // Light Purple
	];

	internal new event RoutedEventHandler? Click;

	internal static readonly DependencyProperty CancelMethodProperty =
		DependencyProperty.Register(
			nameof(CancelMethod),
			typeof(Func<Task>),
			typeof(AnimatedCancellableButton),
			new PropertyMetadata(null));

	internal Func<Task>? CancelMethod
	{
		get => (Func<Task>?)GetValue(CancelMethodProperty);
		set => SetValue(CancelMethodProperty, value);
	}

	internal static readonly DependencyProperty ExternalOperationInProgressProperty =
		DependencyProperty.Register(
			nameof(ExternalOperationInProgress),
			typeof(bool),
			typeof(AnimatedCancellableButton),
			new PropertyMetadata(false, OnExternalOperationInProgressChanged));

	internal bool ExternalOperationInProgress
	{
		get => (bool)GetValue(ExternalOperationInProgressProperty);
		set => SetValue(ExternalOperationInProgressProperty, value);
	}

	private static void OnExternalOperationInProgressChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is AnimatedCancellableButton button && !button._isDisposed && !button._isDisposing)
		{
			bool isInProgress = (bool)e.NewValue;

			if (!isInProgress &&
				!button.ExternalIsCancelState &&
				!button.ExternalIsCancellingState &&
				!button.ExternalIsAnimating)
			{
				button.SynchronizeWithExternalState();
			}
		}
	}

	internal static readonly DependencyProperty ExternalIsCancelStateProperty =
		DependencyProperty.Register(
			nameof(ExternalIsCancelState),
			typeof(bool),
			typeof(AnimatedCancellableButton),
			new PropertyMetadata(false, OnExternalIsCancelStateChanged));

	internal bool ExternalIsCancelState
	{
		get => (bool)GetValue(ExternalIsCancelStateProperty);
		set => SetValue(ExternalIsCancelStateProperty, value);
	}

	private static void OnExternalIsCancelStateChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is AnimatedCancellableButton button && !button._isDisposed && !button._isDisposing)
		{
			button.SynchronizeWithExternalState();
		}
	}

	internal static readonly DependencyProperty ExternalIsCancellingStateProperty =
		DependencyProperty.Register(
			nameof(ExternalIsCancellingState),
			typeof(bool),
			typeof(AnimatedCancellableButton),
			new PropertyMetadata(false, OnExternalIsCancellingStateChanged));

	internal bool ExternalIsCancellingState
	{
		get => (bool)GetValue(ExternalIsCancellingStateProperty);
		set => SetValue(ExternalIsCancellingStateProperty, value);
	}

	private static void OnExternalIsCancellingStateChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is AnimatedCancellableButton button && !button._isDisposed && !button._isDisposing)
		{
			button.SynchronizeWithExternalState();
		}
	}

	internal static readonly DependencyProperty ExternalIsAnimatingProperty =
		DependencyProperty.Register(
			nameof(ExternalIsAnimating),
			typeof(bool),
			typeof(AnimatedCancellableButton),
			new PropertyMetadata(false, OnExternalIsAnimatingChanged));

	internal bool ExternalIsAnimating
	{
		get => (bool)GetValue(ExternalIsAnimatingProperty);
		set => SetValue(ExternalIsAnimatingProperty, value);
	}

	private static void OnExternalIsAnimatingChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is AnimatedCancellableButton button && !button._isDisposed && !button._isDisposing)
		{
			button.SynchronizeWithExternalState();
		}
	}

	internal static readonly DependencyProperty ExternalButtonContentProperty =
		DependencyProperty.Register(
			nameof(ExternalButtonContent),
			typeof(string),
			typeof(AnimatedCancellableButton),
			new PropertyMetadata(string.Empty, OnExternalButtonContentChanged));

	internal string ExternalButtonContent
	{
		get => (string)GetValue(ExternalButtonContentProperty);
		set => SetValue(ExternalButtonContentProperty, value);
	}

	private static void OnExternalButtonContentChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is AnimatedCancellableButton button && !button._isDisposed && !button._isDisposing)
		{
			string newContent = (string)e.NewValue;

			if (!string.IsNullOrEmpty(newContent))
			{
				button.Content = newContent;
			}
		}
	}

	internal static readonly DependencyProperty ExternalOriginalTextProperty =
		DependencyProperty.Register(
			nameof(ExternalOriginalText),
			typeof(string),
			typeof(AnimatedCancellableButton),
			new PropertyMetadata(string.Empty, OnExternalOriginalTextChanged));

	internal string ExternalOriginalText
	{
		get => (string)GetValue(ExternalOriginalTextProperty);
		set => SetValue(ExternalOriginalTextProperty, value);
	}

	private static void OnExternalOriginalTextChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is AnimatedCancellableButton button && !button._isDisposed && !button._isDisposing)
		{
			button.SynchronizeWithExternalState();
		}
	}

	internal static readonly DependencyProperty ExternalInternalIsCancelStateProperty =
		DependencyProperty.Register(
			nameof(ExternalInternalIsCancelState),
			typeof(bool),
			typeof(AnimatedCancellableButton),
			new PropertyMetadata(false, OnExternalInternalIsCancelStateChanged));

	internal bool ExternalInternalIsCancelState
	{
		get => (bool)GetValue(ExternalInternalIsCancelStateProperty);
		set => SetValue(ExternalInternalIsCancelStateProperty, value);
	}

	private static void OnExternalInternalIsCancelStateChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is AnimatedCancellableButton button && !button._isDisposed && !button._isDisposing)
		{
			button.SynchronizeWithExternalState();
		}
	}

	internal static readonly DependencyProperty ExternalInternalIsCancellingStateProperty =
		DependencyProperty.Register(
			nameof(ExternalInternalIsCancellingState),
			typeof(bool),
			typeof(AnimatedCancellableButton),
			new PropertyMetadata(false, OnExternalInternalIsCancellingStateChanged));

	internal bool ExternalInternalIsCancellingState
	{
		get => (bool)GetValue(ExternalInternalIsCancellingStateProperty);
		set => SetValue(ExternalInternalIsCancellingStateProperty, value);
	}

	private static void OnExternalInternalIsCancellingStateChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is AnimatedCancellableButton button && !button._isDisposed && !button._isDisposing)
		{
			button.SynchronizeWithExternalState();
		}
	}

	internal static readonly DependencyProperty ExternalInternalIsAnimatingProperty =
		DependencyProperty.Register(
			nameof(ExternalInternalIsAnimating),
			typeof(bool),
			typeof(AnimatedCancellableButton),
			new PropertyMetadata(false, OnExternalInternalIsAnimatingChanged));

	internal bool ExternalInternalIsAnimating
	{
		get => (bool)GetValue(ExternalInternalIsAnimatingProperty);
		set => SetValue(ExternalInternalIsAnimatingProperty, value);
	}

	private static void OnExternalInternalIsAnimatingChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is AnimatedCancellableButton button && !button._isDisposed && !button._isDisposing)
		{
			button.SynchronizeWithExternalState();
		}
	}

	internal static readonly DependencyProperty ExternalInternalIsOperationInProgressProperty =
		DependencyProperty.Register(
			nameof(ExternalInternalIsOperationInProgress),
			typeof(bool),
			typeof(AnimatedCancellableButton),
			new PropertyMetadata(false, OnExternalInternalIsOperationInProgressChanged));

	internal bool ExternalInternalIsOperationInProgress
	{
		get => (bool)GetValue(ExternalInternalIsOperationInProgressProperty);
		set => SetValue(ExternalInternalIsOperationInProgressProperty, value);
	}

	private static void OnExternalInternalIsOperationInProgressChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is AnimatedCancellableButton button && !button._isDisposed && !button._isDisposing)
		{
			button.SynchronizeWithExternalState();
		}
	}

	internal static readonly DependencyProperty ExternalInternalSuppressExternalClickProperty =
		DependencyProperty.Register(
			nameof(ExternalInternalSuppressExternalClick),
			typeof(bool),
			typeof(AnimatedCancellableButton),
			new PropertyMetadata(false, OnExternalInternalSuppressExternalClickChanged));

	internal bool ExternalInternalSuppressExternalClick
	{
		get => (bool)GetValue(ExternalInternalSuppressExternalClickProperty);
		set => SetValue(ExternalInternalSuppressExternalClickProperty, value);
	}

	private static void OnExternalInternalSuppressExternalClickChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is AnimatedCancellableButton button && !button._isDisposed && !button._isDisposing)
		{
			button.SynchronizeWithExternalState();
		}
	}

	internal static readonly DependencyProperty ExternalShadowAnimationRunningProperty =
		DependencyProperty.Register(
			nameof(ExternalShadowAnimationRunning),
			typeof(bool),
			typeof(AnimatedCancellableButton),
			new PropertyMetadata(false, OnExternalShadowAnimationRunningChanged));

	internal bool ExternalShadowAnimationRunning
	{
		get => (bool)GetValue(ExternalShadowAnimationRunningProperty);
		set => SetValue(ExternalShadowAnimationRunningProperty, value);
	}

	private static void OnExternalShadowAnimationRunningChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is AnimatedCancellableButton button && !button._isDisposed && !button._isDisposing)
		{
			bool shouldAnimate = (bool)e.NewValue;

			if (button._isLoaded)
			{
				if (shouldAnimate && !button._isShadowAnimationRunning)
				{
					button.StartShadowAnimation();
				}
				else if (!shouldAnimate && button._isShadowAnimationRunning)
				{
					button.StopShadowAnimation();
				}
			}
		}
	}

	internal static readonly DependencyProperty ExternalOperationStartedProperty =
		DependencyProperty.Register(
			nameof(ExternalOperationStarted),
			typeof(bool),
			typeof(AnimatedCancellableButton),
			new PropertyMetadata(false, OnExternalOperationStartedChanged));

	internal bool ExternalOperationStarted
	{
		get => (bool)GetValue(ExternalOperationStartedProperty);
		set => SetValue(ExternalOperationStartedProperty, value);
	}

	private static void OnExternalOperationStartedChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is AnimatedCancellableButton button && !button._isDisposed && !button._isDisposing)
		{
			bool operationStarted = (bool)e.NewValue;
			button._operationStarted = operationStarted;
		}
	}

	// Allows opting out of automatic disposal on Unloaded (default false).
	internal static readonly DependencyProperty DisposeOnlyOnExplicitCallProperty =
		DependencyProperty.Register(
			nameof(DisposeOnlyOnExplicitCall),
			typeof(bool),
			typeof(AnimatedCancellableButton),
			new PropertyMetadata(false));

	/// <summary>
	/// When true, the control will not dispose itself on Unloaded. The host must call Dispose() explicitly (e.g. in Page.OnNavigatedFrom).
	/// Defaults to false.
	/// Currently only used for pages that implement TabView. Cycling through different tabs in the same page that has a TabView causes unload event to fire unnecessarily
	/// So we use Page's code-behind instead to manually call the dispose method.
	/// </summary>
	public bool DisposeOnlyOnExplicitCall
	{
		get => (bool)GetValue(DisposeOnlyOnExplicitCallProperty);
		set => SetValue(DisposeOnlyOnExplicitCallProperty, value);
	}

	private void InitializeClickDelayTimer()
	{
		_clickDelayTimer = new DispatcherTimer
		{
			Interval = FiftyMsTimeSpan
		};
		_clickDelayTimer.Tick += ClickDelayTimer_Tick;
	}

	private void ClickDelayTimer_Tick(object? sender, object e)
	{
		if (_isDisposed || _isDisposing) return;

		lock (_stateLock)
		{
			if (_isDisposed || _isDisposing) return;

			_clickDelayTimer?.Stop();
			_isClickInProgress = false;
		}
	}

	private void InvokeCancelMethodSafely()
	{
		CancellationTokenSource? cts = null;
		lock (_stateLock)
		{
			if (!_isDisposed && !_isDisposing && _disposalCancellationTokenSource is not null)
			{
				cts = _disposalCancellationTokenSource;
			}
		}

		if (CancelMethod is not null && cts is not null)
		{
			_ = Task.Run(async () =>
			{
				try
				{
					if (!cts.Token.IsCancellationRequested)
					{
						await CancelMethod.Invoke();
					}
				}
				catch (Exception)
				{ }
			}, cts.Token);
		}
	}

	private AttachedCardShadow? CreateShadow()
	{
		return new AttachedCardShadow
		{
			Color = GetCurrentShadowColor(),
			Offset = ZeroOffsetString,
			BlurRadius = MIN_BLUR_RADIUS,
			Opacity = SHADOW_OPACITY,
			CornerRadius = 5.0
		};
	}

	private Color GetCurrentShadowColor()
	{
		if (_isDisposed || _isDisposing) return TransparentColor;

		if (_currentColorIndex < 0 || _currentColorIndex >= _shadowColors.Length)
		{
			_currentColorIndex = 0;
		}

		if (_nextColorIndex < 0 || _nextColorIndex >= _shadowColors.Length)
		{
			_nextColorIndex = (_currentColorIndex + 1) % _shadowColors.Length;
		}

		if (!_inColorTransition)
		{
			return _shadowColors[_currentColorIndex];
		}

		double transitionProgress = (double)_colorTransitionCounter / COLOR_TRANSITION_DURATION;
		transitionProgress = Math.Clamp(transitionProgress, 0.0, 1.0);

		double easedProgress = EaseInOutCubic(transitionProgress);

		Color currentColor = _shadowColors[_currentColorIndex];
		Color nextColor = _shadowColors[_nextColorIndex];

		byte interpolatedA = (byte)(currentColor.A + (nextColor.A - currentColor.A) * easedProgress);
		byte interpolatedR = (byte)(currentColor.R + (nextColor.R - currentColor.R) * easedProgress);
		byte interpolatedG = (byte)(currentColor.G + (nextColor.G - currentColor.G) * easedProgress);
		byte interpolatedB = (byte)(currentColor.B + (nextColor.B - currentColor.B) * easedProgress);

		return Color.FromArgb(interpolatedA, interpolatedR, interpolatedG, interpolatedB);
	}

	private static double EaseInOutCubic(double t)
	{
		return t < 0.5 ? 4 * t * t * t : 1 - Math.Pow(-2 * t + 2, 3) / 2;
	}

	private void AdvanceToNextShadowColor()
	{
		_currentColorIndex = _nextColorIndex;
		_nextColorIndex = (_currentColorIndex + 1) % _shadowColors.Length;
	}

	private void StartColorTransition()
	{
		if (!_inColorTransition)
		{
			_inColorTransition = true;
			_colorTransitionCounter = 0;
		}
	}

	private void UpdateShadowColor()
	{
		if (_attachedShadow != null)
		{
			try
			{
				_attachedShadow.Color = GetCurrentShadowColor();
			}
			catch (Exception)
			{ }
		}
	}

	private void InitializeShadowAnimation()
	{
		try
		{
			_shadowAnimationStoryboard = new Storyboard();

			_shadowTimer = new DispatcherTimer
			{
				Interval = FiftyMsTimeSpan
			};
			_shadowTimer.Tick += ShadowTimer_Tick;

			_currentColorIndex = 0;
			_nextColorIndex = 1;
			_colorTransitionCounter = 0;
			_colorHoldCounter = 0;
			_inColorTransition = false;
		}
		catch (Exception)
		{
			_shadowTimer = new DispatcherTimer
			{
				Interval = FiftyMsTimeSpan
			};
			_shadowTimer.Tick += ShadowTimer_Tick;
			_currentColorIndex = 0;
			_nextColorIndex = 1;
			_colorTransitionCounter = 0;
			_colorHoldCounter = 0;
			_inColorTransition = false;
		}
	}

	private void ShadowTimer_Tick(object? sender, object e)
	{
		if (_isDisposed || _isDisposing) return;

		lock (_stateLock)
		{
			if (_isDisposed || _isDisposing) return;

			try
			{
				if (_attachedShadow != null && _isShadowAnimationRunning)
				{
					if (_shadowIncreasing)
					{
						_currentBlurRadius += BLUR_STEP;
						if (_currentBlurRadius >= MAX_BLUR_RADIUS)
						{
							_currentBlurRadius = MAX_BLUR_RADIUS;
							_shadowIncreasing = false;
						}
					}
					else
					{
						_currentBlurRadius -= BLUR_STEP;
						if (_currentBlurRadius <= MIN_BLUR_RADIUS)
						{
							_currentBlurRadius = MIN_BLUR_RADIUS;
							_shadowIncreasing = true;
						}
					}

					_attachedShadow.BlurRadius = _currentBlurRadius;

					if (_inColorTransition)
					{
						_colorTransitionCounter++;
						UpdateShadowColor();

						if (_colorTransitionCounter >= COLOR_TRANSITION_DURATION)
						{
							_inColorTransition = false;
							_colorTransitionCounter = 0;
							AdvanceToNextShadowColor();
							_colorHoldCounter = 0;
							UpdateShadowColor();
						}
					}
					else
					{
						_colorHoldCounter++;
						if (_colorHoldCounter >= COLOR_HOLD_DURATION)
						{
							StartColorTransition();
						}
					}
				}
			}
			catch (Exception)
			{ }
		}
	}

	private void StartShadowAnimation()
	{
		if (_isShadowAnimationRunning || _isDisposed || _isDisposing)
		{
			return;
		}

		try
		{
			if (_attachedShadow == null)
			{
				_attachedShadow = CreateShadow();
			}

			if (_attachedShadow != null && !_hasShadowApplied)
			{
				Effects.SetShadow(this, _attachedShadow);
				_hasShadowApplied = true;
			}

			if (_attachedShadow != null)
			{
				_currentBlurRadius = MIN_BLUR_RADIUS;
				_shadowIncreasing = true;
				_colorTransitionCounter = 0;
				_colorHoldCounter = 0;
				_inColorTransition = false;
				_attachedShadow.BlurRadius = _currentBlurRadius;
				_attachedShadow.Color = GetCurrentShadowColor();
				_attachedShadow.Opacity = SHADOW_OPACITY;

				if (_shadowTimer != null)
				{
					_shadowTimer.Start();
					_isShadowAnimationRunning = true;

					ExternalShadowAnimationRunning = true;
				}
			}
		}
		catch (Exception)
		{
			_isShadowAnimationRunning = true;
			ExternalShadowAnimationRunning = true;
		}
	}

	private void StopShadowAnimation()
	{
		try
		{
			if (_shadowTimer != null && _shadowTimer.IsEnabled)
			{
				_shadowTimer.Stop();
			}

			_isShadowAnimationRunning = false;

			ExternalShadowAnimationRunning = false;

			if (_hasShadowApplied)
			{
				ClearValue(Effects.ShadowProperty);
				_hasShadowApplied = false;
			}

			_attachedShadow = null;
		}
		catch (Exception)
		{
			_isShadowAnimationRunning = false;
			ExternalShadowAnimationRunning = false;
		}
	}

	private void UpdateButtonContentImmediately()
	{
		if (_isDisposed || _isDisposing) return;

		try
		{
			if (ExternalInternalIsCancellingState)
			{
				this.Content = GlobalVars.GetStr("Cancelling");
				UpdateButtonStyle(true);
			}
			else if (ExternalInternalIsCancelState)
			{
				this.Content = GlobalVars.GetStr("Cancel");
				UpdateButtonStyle(true);
			}
			else
			{
				if (!string.IsNullOrEmpty(ExternalButtonContent))
				{
					this.Content = ExternalButtonContent;
				}
				else if (!string.IsNullOrEmpty(ExternalOriginalText))
				{
					this.Content = ExternalOriginalText;
				}
				else
				{
					this.Content = ButtonDefaultText;
				}
				UpdateButtonStyle(false);
			}
		}
		catch (Exception)
		{ }
	}

	private void UpdateButtonStyle(bool isCancelState)
	{
		try
		{
			// Apply DefaultButtonStyle for Cancel/Cancelling, and AccentButtonStyle for ready/active states
			this.Style = isCancelState ? DefaultButtonStyle : AccentButtonStyle;
		}
		catch (Exception)
		{ }
	}

	private void ForceResetToOriginalState()
	{
		if (_isDisposed || _isDisposing) return;

		lock (_stateLock)
		{
			if (_isDisposed || _isDisposing) return;

			_operationStarted = false;
			_isClickInProgress = false;

			ExternalOperationStarted = false;
			ExternalShadowAnimationRunning = false;

			try
			{
				if (_fadeOutStoryboard.GetCurrentState() != ClockState.Stopped)
				{
					_fadeOutStoryboard.Stop();
				}
				if (_fadeInStoryboard.GetCurrentState() != ClockState.Stopped)
				{
					_fadeInStoryboard.Stop();
				}
			}
			catch (Exception)
			{ }

			StopShadowAnimation();

			UpdateButtonContentImmediately();

			this.Opacity = 1.0;
		}
	}

	private void SynchronizeWithExternalState()
	{
		if (_isDisposed || _isDisposing) return;

		lock (_stateLock)
		{
			if (_isDisposed || _isDisposing) return;

			_operationStarted = ExternalOperationStarted;

			if (!_operationStarted)
			{
				UpdateButtonContentImmediately();

				if (_isShadowAnimationRunning)
				{
					StopShadowAnimation();
				}

				try
				{
					if (_fadeOutStoryboard.GetCurrentState() != ClockState.Stopped)
					{
						_fadeOutStoryboard.Stop();
					}
					if (_fadeInStoryboard.GetCurrentState() != ClockState.Stopped)
					{
						_fadeInStoryboard.Stop();
					}

					this.Opacity = 1.0;
				}
				catch (Exception)
				{ }
				return;
			}

			UpdateButtonContentImmediately();

			bool shouldAnimateShadow = (ExternalInternalIsCancelState || ExternalInternalIsCancellingState) && ExternalShadowAnimationRunning;

			if (shouldAnimateShadow && !_isShadowAnimationRunning && _isLoaded)
			{
				StartShadowAnimation();
			}
			else if (!shouldAnimateShadow && _isShadowAnimationRunning)
			{
				StopShadowAnimation();
			}

			try
			{
				if (_fadeOutStoryboard.GetCurrentState() != ClockState.Stopped)
				{
					_fadeOutStoryboard.Stop();
				}
				if (_fadeInStoryboard.GetCurrentState() != ClockState.Stopped)
				{
					_fadeInStoryboard.Stop();
				}

				this.Opacity = 1.0;
			}
			catch (Exception)
			{ }
		}
	}

	private void RestoreShadowAnimationAfterNavigation()
	{
		if (_isDisposed || _isDisposing) return;

		if (ExternalShadowAnimationRunning && !_isShadowAnimationRunning && _isLoaded)
		{
			bool shouldAnimate = ExternalInternalIsCancelState || ExternalInternalIsCancellingState;

			if (shouldAnimate)
			{
				StartShadowAnimation();
			}
		}
	}

	internal AnimatedCancellableButton()
	{
		this.DefaultStyleKey = typeof(Button);
		base.Click += AnimatedCancellableButton_BaseClick;
		this.Loaded += AnimatedCancellableButton_Loaded;
		this.Unloaded += AnimatedCancellableButton_Unloaded;
		InitializeAnimations();
		InitializeShadowAnimation();
		InitializeClickDelayTimer();
		_disposalCancellationTokenSource = new CancellationTokenSource();
	}

	private void AnimatedCancellableButton_Loaded(object? sender, RoutedEventArgs e)
	{
		_isLoaded = true;

		SynchronizeWithExternalState();

		RestoreShadowAnimationAfterNavigation();
	}

	private void InitializeAnimations()
	{
		_fadeOutAnimation = new DoubleAnimation
		{
			From = 1.0,
			To = 0.0,
			Duration = new Duration(OneHundredFiftyMsTimeSpan),
			EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseInOut }
		};

		_fadeOutStoryboard = new Storyboard();
		_fadeOutStoryboard.Children.Add(_fadeOutAnimation);
		_fadeOutStoryboard.Completed += FadeOutStoryboard_Completed;

		_fadeInAnimation = new DoubleAnimation
		{
			From = 0.0,
			To = 1.0,
			Duration = new Duration(OneHundredFiftyMsTimeSpan),
			EasingFunction = new QuadraticEase { EasingMode = EasingMode.EaseInOut }
		};

		_fadeInStoryboard = new Storyboard();
		_fadeInStoryboard.Children.Add(_fadeInAnimation);
	}

	private void AnimatedCancellableButton_BaseClick(object? sender, RoutedEventArgs e)
	{
		if (_isClickInProgress || _isDisposed || _isDisposing)
		{
			return;
		}

		lock (_stateLock)
		{
			if (_isClickInProgress || _isDisposed || _isDisposing)
			{
				return;
			}

			_isClickInProgress = true;

			try
			{
				if (ExternalInternalIsAnimating)
				{
					return;
				}

				if (!ExternalInternalIsCancelState && !ExternalInternalIsCancellingState)
				{
					_operationStarted = true;
					ExternalOperationStarted = true;

					StartOperation();

					try
					{
						Click?.Invoke(this, e);

						_ = DispatcherQueue.TryEnqueue(DispatcherQueuePriority.High, () =>
						{
							if (!ExternalInternalIsOperationInProgress &&
								!ExternalInternalIsCancelState &&
								!ExternalInternalIsCancellingState)
							{
								ForceResetToOriginalState();
							}
						});
					}
					catch (Exception)
					{
						ForceResetToOriginalState();
						throw;
					}
				}
				else if (ExternalInternalIsCancelState && !ExternalInternalIsCancellingState)
				{
					_ = CancelOperationAsync();
				}
				else if (ExternalInternalIsCancellingState)
				{
					return;
				}
			}
			finally
			{
				if (!_isDisposed && !_isDisposing)
				{
					_clickDelayTimer?.Start();
				}
				else
				{
					_isClickInProgress = false;
				}
			}
		}
	}

	private void StartOperation()
	{
		if (_isDisposed || _isDisposing) return;

		StartShadowAnimation();

		AnimateToState(true, false);
	}

	private async Task CancelOperationAsync()
	{
		if (_isDisposed || _isDisposing) return;

		AnimateToState(false, true);

		if (CancelMethod is not null)
		{
			try
			{
				await CancelMethod.Invoke();
			}
			catch (Exception)
			{ }
		}
	}

	private void AnimateToState(bool toCancelState, bool toCancellingState)
	{
		if (_isDisposed || _isDisposing) return;

		try
		{
			if (_fadeOutStoryboard.GetCurrentState() != ClockState.Stopped)
			{
				_fadeOutStoryboard.Stop();
			}
			if (_fadeInStoryboard.GetCurrentState() != ClockState.Stopped)
			{
				_fadeInStoryboard.Stop();
			}

			bool shouldAnimateShadow = toCancelState || toCancellingState;

			if (shouldAnimateShadow && !_isShadowAnimationRunning)
			{
				StartShadowAnimation();
			}
			else if (!shouldAnimateShadow && _isShadowAnimationRunning)
			{
				StopShadowAnimation();
			}

			Storyboard.SetTarget(_fadeOutAnimation, this);
			Storyboard.SetTargetProperty(_fadeOutAnimation, OpacityPropertyName);

			_targetStateAfterFadeOut = toCancelState;
			_targetCancellingStateAfterFadeOut = toCancellingState;

			_fadeOutStoryboard.Begin();
		}
		catch (Exception)
		{ }
	}

	private bool _targetStateAfterFadeOut;
	private bool _targetCancellingStateAfterFadeOut;

	private void FadeOutStoryboard_Completed(object? sender, object? e)
	{
		if (_isDisposed || _isDisposing) return;

		try
		{
			if (_targetCancellingStateAfterFadeOut)
			{
				this.Content = GlobalVars.GetStr("Cancelling");
				UpdateButtonStyle(true);
			}
			else if (_targetStateAfterFadeOut)
			{
				this.Content = GlobalVars.GetStr("Cancel");
				UpdateButtonStyle(true);
			}
			else
			{
				if (!string.IsNullOrEmpty(ExternalButtonContent))
				{
					this.Content = ExternalButtonContent;
				}
				else if (!string.IsNullOrEmpty(ExternalOriginalText))
				{
					this.Content = ExternalOriginalText;
				}
				else
				{
					this.Content = ButtonDefaultText;
				}
				UpdateButtonStyle(false);
			}

			if (_fadeInStoryboard.GetCurrentState() != ClockState.Stopped)
			{
				_fadeInStoryboard.Stop();
			}

			Storyboard.SetTarget(_fadeInAnimation, this);
			Storyboard.SetTargetProperty(_fadeInAnimation, OpacityPropertyName);

			_fadeInStoryboard.Begin();
		}
		catch (Exception)
		{ }
	}

	internal bool IsCancelState => !_isDisposed && !_isDisposing && ExternalInternalIsCancelState;

	internal bool IsCancellingState => !_isDisposed && !_isDisposing && ExternalInternalIsCancellingState;

	internal bool IsOperationInProgress => !_isDisposed && !_isDisposing && ExternalInternalIsOperationInProgress;

	internal bool IsSuppressingExternalClick => !_isDisposed && !_isDisposing && ExternalInternalSuppressExternalClick;

	internal bool IsShadowAnimationRunning => !_isDisposed && !_isDisposing && _isShadowAnimationRunning;

	internal int CurrentShadowColorIndex => _isDisposed || _isDisposing ? 0 : _currentColorIndex;

	internal bool IsInColorTransition => !_isDisposed && !_isDisposing && _inColorTransition;

	internal double ColorTransitionProgress => (_isDisposed || _isDisposing || !_inColorTransition) ? 0.0 : (double)_colorTransitionCounter / COLOR_TRANSITION_DURATION;

	internal double AnimationDurationMilliseconds
	{
		get => _isDisposed || _isDisposing ? 150.0 : _fadeOutAnimation.Duration.TimeSpan.TotalMilliseconds;
		set
		{
			if (_isDisposed || _isDisposing) return;

			Duration duration = new(TimeSpan.FromMilliseconds(Math.Max(50, value)));
			_fadeOutAnimation.Duration = duration;
			_fadeInAnimation.Duration = duration;
		}
	}

	internal double ShadowAnimationDurationMilliseconds
	{
		get => _isDisposed || _isDisposing ? 50.0 : _shadowTimer?.Interval.TotalMilliseconds ?? 50.0;
		set
		{
			if (!_isDisposed && !_isDisposing && _shadowTimer is not null)
			{
				_shadowTimer.Interval = TimeSpan.FromMilliseconds(Math.Max(10, value));
			}
		}
	}

	protected override void OnApplyTemplate()
	{
		base.OnApplyTemplate();

		if (_isDisposed || _isDisposing) return;

		if (_fadeOutStoryboard.Children.Count == 0 || _fadeInStoryboard.Children.Count == 0)
		{
			InitializeAnimations();
		}

		if (_shadowTimer is null)
		{
			InitializeShadowAnimation();
		}

		SynchronizeWithExternalState();
	}

	private void AnimatedCancellableButton_Unloaded(object? sender, RoutedEventArgs e)
	{
		// Respect DisposeOnlyOnExplicitCall flag so that
		// in special pages (Pages with TabView) transient Unloaded does not kill the control.
		if (DisposeOnlyOnExplicitCall)
		{
			return;
		}
		if (_isDisposed) return;
		PerformCleanup();
	}

	private void PerformCleanup()
	{
		_isLoaded = false;

		lock (_stateLock)
		{
			_isDisposing = true;
			_isClickInProgress = false;

			try
			{
				if (_fadeOutStoryboard.GetCurrentState() != ClockState.Stopped)
				{
					_fadeOutStoryboard.Stop();
				}
				if (_fadeInStoryboard.GetCurrentState() != ClockState.Stopped)
				{
					_fadeInStoryboard.Stop();
				}
			}
			catch (Exception)
			{ }

			if (_shadowTimer != null && _shadowTimer.IsEnabled)
			{
				_shadowTimer.Stop();
			}
			_isShadowAnimationRunning = false;

			if (_hasShadowApplied)
			{
				ClearValue(Effects.ShadowProperty);
				_hasShadowApplied = false;
			}

			_shadowAnimationStoryboard?.Children.Clear();

			if (_shadowTimer is not null)
			{
				_shadowTimer.Stop();
				_shadowTimer.Tick -= ShadowTimer_Tick;
				_shadowTimer = null;
			}

			if (_clickDelayTimer is not null)
			{
				_clickDelayTimer.Stop();
				_clickDelayTimer.Tick -= ClickDelayTimer_Tick;
				_clickDelayTimer = null;
			}

			_fadeOutStoryboard.Completed -= FadeOutStoryboard_Completed;
			_fadeOutStoryboard.Children.Clear();

			_fadeInStoryboard.Children.Clear();

			InvokeCancelMethodSafely();

			_disposalCancellationTokenSource?.Cancel();
			_disposalCancellationTokenSource?.Dispose();
			_disposalCancellationTokenSource = null;

			_isDisposed = true;
		}

		try
		{
			base.Click -= AnimatedCancellableButton_BaseClick;
			this.Loaded -= AnimatedCancellableButton_Loaded;
			this.Unloaded -= AnimatedCancellableButton_Unloaded;
		}
		catch (Exception)
		{ }
	}

	public void Dispose()
	{
		if (_isDisposed) return;
		PerformCleanup();
	}
}
