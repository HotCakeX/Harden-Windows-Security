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

using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Threading;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.Foundation;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// Enhanced InfoBar control with custom animations for show/hide operations.
/// This control extends the standard WinUI3 InfoBar to provide smooth animated transitions
/// when opening and closing, including proper handling of close button clicks.
/// </summary>
internal sealed partial class InfoBarV2 : InfoBar, INotifyPropertyChanged
{
	// Animation storyboards - these handle the actual animation sequences
	private Storyboard? _showStoryboard;
	private Storyboard? _hideStoryboard;

	// Animation state tracking
	private bool _isAnimating;
	private bool _pendingAnimationState;
	private bool _hasPendingAnimation;

	// Transform objects for different animation types (slide, scale, etc.)
	private TranslateTransform _translateTransform = new();
	private ScaleTransform _scaleTransform = new();
	private CompositeTransform _compositeTransform = new();
	private TransformGroup _transformGroup = new();

	// Critical flags for managing property changes and preventing infinite loops
	// This flag prevents the OnIsOpenPropertyChanged from triggering animations when setting IsOpen internally
	private bool _isInternalIsOpenChange;

	// Track the last known state to detect actual changes vs redundant property sets
	private bool _lastKnownIsOpenState;

	// Flag to track when close animation was triggered by the close button vs programmatic changes
	private bool _isClosingViaButton;

	// Flag to suppress default close animations in specific scenarios
	private bool _suppressCloseAnimation;

	// Flag to indicate when handling the close button click to allow proper close after animation
	private bool _isHandlingCloseButton;

	// Flag to prevent default close behavior when wanting to show custom animation first
	private bool _preventDefaultClose;

	// Flag to track if any animation is currently in progress to prevent conflicts
	private bool _animationInProgress;

	// Enables one-time activation of text selection on the internal "Message" TextBlock
	private bool _messageTextSelectionEnabled;

	// Timer used for close button handling - needed to work around InfoBar's internal close timing
	private readonly DispatcherTimer _closeButtonTimer;

	// Additional state tracking for better animation conflict resolution
	private bool _isCurrentlyShowingAnimation;
	private bool _isCurrentlyHidingAnimation;
	private bool _shouldCancelCurrentAnimation;

	// Critical flags for handling page navigation and cleanup
	private bool _isDisposed;
	private bool _isUnloading;
	private readonly Lock _stateLock = new();

	// Track pending DispatcherQueue operations to prevent crashes during navigation
	private readonly System.Collections.Generic.List<Action> _pendingDispatcherOperations = [];

	// token for IsOpen property-changed callback
	private long _isOpenCallbackToken = -1;

	// Animation type enumeration defining all supported animation styles
	internal enum InfoBarAnimationType
	{
		Slide,
		Scale,
		Fade,
		SlideAndScale,
		SlideAndFade,
		ScaleAndFade,
		All,
		FadeAndScale
	}

	internal InfoBarV2()
	{
		// Wire up all necessary event handlers
		this.Loaded += InfoBarV2_Loaded;
		this.Unloaded += InfoBarV2_Unloaded;
		this.Closing += InfoBarV2_Closing;  // Critical for intercepting close button clicks
		this.Closed += InfoBarV2_Closed;

		// Initialize close button timer with short interval for responsive close handling
		// The timer is needed because InfoBar's close button handling has timing issues
		_closeButtonTimer = new DispatcherTimer
		{
			Interval = TimeSpan.FromMilliseconds(10)
		};
		_closeButtonTimer.Tick += CloseButtonTimer_Tick;

		// Initialize all transform objects that will be used for animations
		InitializeTransforms();

		// Set initial visual state - InfoBar should start hidden
		this.Visibility = Visibility.Collapsed;
		this.Opacity = 0;
		_lastKnownIsOpenState = false;

		// Register for IsOpen property changes - this is how to detect when ViewModel changes the property
		// This callback is essential for responding to two-way binding changes from the ViewModel
		// Track the registration token so we can unregister during cleanup
		_isOpenCallbackToken = this.RegisterPropertyChangedCallback(IsOpenProperty, OnIsOpenPropertyChanged);
	}

	// Override to enable text selection on the internal "Message" TextBlock after the template is applied.
	protected override void OnApplyTemplate()
	{
		base.OnApplyTemplate();

		// Enable selection each time the template is (re)applied
		EnableMessageTextSelection();
	}

	/// <summary>
	/// Initialize all transform objects needed for animations.
	/// Use multiple transform types to support different animation combinations.
	/// </summary>
	private void InitializeTransforms()
	{
		_translateTransform = new TranslateTransform();  // For slide animations
		_scaleTransform = new ScaleTransform();          // For scale animations
		_compositeTransform = new CompositeTransform();  // For complex combined animations

		// Group all transforms together so they can be applied simultaneously
		_transformGroup = new TransformGroup();
		_transformGroup.Children.Add(_translateTransform);
		_transformGroup.Children.Add(_scaleTransform);
		_transformGroup.Children.Add(_compositeTransform);

		// Apply the transform group to the InfoBar and set origin to center for scaling
		this.RenderTransform = _transformGroup;
		this.RenderTransformOrigin = new Point(0.5, 0.5);
	}

	#region Dependency Properties - Default Values Set Here

	// We can override these defaults in XAML.

	// Default: FadeAndScale animation type
	internal static readonly DependencyProperty AnimationTypeProperty =
		DependencyProperty.Register(
			nameof(AnimationType),
			typeof(InfoBarAnimationType),
			typeof(InfoBarV2),
			new PropertyMetadata(InfoBarAnimationType.FadeAndScale, OnAnimationTypeChanged)); // DEFAULT: FadeAndScale

	// Default: 300ms animation duration
	internal static readonly DependencyProperty AnimationDurationProperty =
		DependencyProperty.Register(
			nameof(AnimationDuration),
			typeof(TimeSpan),
			typeof(InfoBarV2),
			new PropertyMetadata(TimeSpan.FromMilliseconds(300), OnAnimationDurationChanged)); // DEFAULT: 300ms

	// Default: True - easing enabled
	internal static readonly DependencyProperty UseEasingProperty =
		DependencyProperty.Register(
			nameof(UseEasing),
			typeof(bool),
			typeof(InfoBarV2),
			new PropertyMetadata(true, OnUseEasingChanged)); // DEFAULT: True

	// Default: CubicEase with EaseOut mode
	internal static readonly DependencyProperty EasingFunctionProperty =
		DependencyProperty.Register(
			nameof(EasingFunction),
			typeof(EasingFunctionBase),
			typeof(InfoBarV2),
			new PropertyMetadata(new CubicEase { EasingMode = EasingMode.EaseOut }, OnEasingFunctionChanged)); // DEFAULT: CubicEase EaseOut

	// Default: 100.0 pixel slide distance
	internal static readonly DependencyProperty SlideDistanceProperty =
		DependencyProperty.Register(
			nameof(SlideDistance),
			typeof(double),
			typeof(InfoBarV2),
			new PropertyMetadata(100.0, OnSlideDistanceChanged)); // DEFAULT: 100.0

	// Default: 0.85 scale from value
	internal static readonly DependencyProperty ScaleFromProperty =
		DependencyProperty.Register(
			nameof(ScaleFrom),
			typeof(double),
			typeof(InfoBarV2),
			new PropertyMetadata(0.85, OnScaleFromChanged)); // DEFAULT: 0.85

	// Default: 1.0 scale to value (normal size)
	internal static readonly DependencyProperty ScaleToProperty =
		DependencyProperty.Register(
			nameof(ScaleTo),
			typeof(double),
			typeof(InfoBarV2),
			new PropertyMetadata(1.0, OnScaleToChanged)); // DEFAULT: 1.0

	// Default: True - animations enabled
	internal static readonly DependencyProperty EnableAnimationProperty =
		DependencyProperty.Register(
			nameof(EnableAnimation),
			typeof(bool),
			typeof(InfoBarV2),
			new PropertyMetadata(true, OnEnableAnimationChanged)); // DEFAULT: True

	// Default: Zero delay before animation starts
	internal static readonly DependencyProperty AnimationDelayProperty =
		DependencyProperty.Register(
			nameof(AnimationDelay),
			typeof(TimeSpan),
			typeof(InfoBarV2),
			new PropertyMetadata(TimeSpan.Zero, OnAnimationDelayChanged)); // DEFAULT: 0ms

	// Default: 250ms fade in duration (0.25 seconds)
	internal static readonly DependencyProperty FadeInDurationProperty =
		DependencyProperty.Register(
			nameof(FadeInDuration),
			typeof(TimeSpan),
			typeof(InfoBarV2),
			new PropertyMetadata(TimeSpan.FromMilliseconds(250), OnFadeInDurationChanged)); // DEFAULT: 250ms (0.25s)

	// Default: 400ms fade out duration (0.4 seconds)
	internal static readonly DependencyProperty FadeOutDurationProperty =
		DependencyProperty.Register(
			nameof(FadeOutDuration),
			typeof(TimeSpan),
			typeof(InfoBarV2),
			new PropertyMetadata(TimeSpan.FromMilliseconds(400), OnFadeOutDurationChanged)); // DEFAULT: 400ms (0.4s)

	// Default: 300ms scale in duration (0.3 seconds)
	internal static readonly DependencyProperty ScaleInDurationProperty =
		DependencyProperty.Register(
			nameof(ScaleInDuration),
			typeof(TimeSpan),
			typeof(InfoBarV2),
			new PropertyMetadata(TimeSpan.FromMilliseconds(300), OnScaleInDurationChanged)); // DEFAULT: 300ms (0.3s)

	// Default: 450ms scale out duration (0.45 seconds)
	internal static readonly DependencyProperty ScaleOutDurationProperty =
		DependencyProperty.Register(
			nameof(ScaleOutDuration),
			typeof(TimeSpan),
			typeof(InfoBarV2),
			new PropertyMetadata(TimeSpan.FromMilliseconds(450), OnScaleOutDurationChanged)); // DEFAULT: 450ms (0.45s)

	// Default: True - intercept close button clicks for animation
	internal static readonly DependencyProperty InterceptCloseButtonProperty =
		DependencyProperty.Register(
			nameof(InterceptCloseButton),
			typeof(bool),
			typeof(InfoBarV2),
			new PropertyMetadata(true)); // DEFAULT: True

	// Default: True - force close animation even for programmatic closes
	internal static readonly DependencyProperty ForceCloseAnimationProperty =
		DependencyProperty.Register(
			nameof(ForceCloseAnimation),
			typeof(bool),
			typeof(InfoBarV2),
			new PropertyMetadata(true)); // DEFAULT: True

	#endregion

	#region Properties

	internal InfoBarAnimationType AnimationType
	{
		get => (InfoBarAnimationType)GetValue(AnimationTypeProperty);
		set => SetValue(AnimationTypeProperty, value);
	}

	internal TimeSpan AnimationDuration
	{
		get => (TimeSpan)GetValue(AnimationDurationProperty);
		set => SetValue(AnimationDurationProperty, value);
	}

	internal bool UseEasing
	{
		get => (bool)GetValue(UseEasingProperty);
		set => SetValue(UseEasingProperty, value);
	}

	internal EasingFunctionBase EasingFunction
	{
		get => (EasingFunctionBase)GetValue(EasingFunctionProperty);
		set => SetValue(EasingFunctionProperty, value);
	}

	internal double SlideDistance
	{
		get => (double)GetValue(SlideDistanceProperty);
		set => SetValue(SlideDistanceProperty, value);
	}

	internal double ScaleFrom
	{
		get => (double)GetValue(ScaleFromProperty);
		set => SetValue(ScaleFromProperty, value);
	}

	internal double ScaleTo
	{
		get => (double)GetValue(ScaleToProperty);
		set => SetValue(ScaleToProperty, value);
	}

	internal bool EnableAnimation
	{
		get => (bool)GetValue(EnableAnimationProperty);
		set => SetValue(EnableAnimationProperty, value);
	}

	internal TimeSpan AnimationDelay
	{
		get => (TimeSpan)GetValue(AnimationDelayProperty);
		set => SetValue(AnimationDelayProperty, value);
	}

	internal TimeSpan FadeInDuration
	{
		get => (TimeSpan)GetValue(FadeInDurationProperty);
		set => SetValue(FadeInDurationProperty, value);
	}

	internal TimeSpan FadeOutDuration
	{
		get => (TimeSpan)GetValue(FadeOutDurationProperty);
		set => SetValue(FadeOutDurationProperty, value);
	}

	internal TimeSpan ScaleInDuration
	{
		get => (TimeSpan)GetValue(ScaleInDurationProperty);
		set => SetValue(ScaleInDurationProperty, value);
	}

	internal TimeSpan ScaleOutDuration
	{
		get => (TimeSpan)GetValue(ScaleOutDurationProperty);
		set => SetValue(ScaleOutDurationProperty, value);
	}

	internal bool InterceptCloseButton
	{
		get => (bool)GetValue(InterceptCloseButtonProperty);
		set => SetValue(InterceptCloseButtonProperty, value);
	}

	internal bool ForceCloseAnimation
	{
		get => (bool)GetValue(ForceCloseAnimationProperty);
		set => SetValue(ForceCloseAnimationProperty, value);
	}

	/// <summary>
	/// Indicates whether an animation is currently running.
	/// This property notifies observers and triggers the IsAnimatingChanged event.
	/// </summary>
	internal bool IsAnimating
	{
		get => _isAnimating;
		private set
		{
			if (_isAnimating != value)
			{
				_isAnimating = value;
				OnPropertyChanged();
				IsAnimatingChanged?.Invoke(this, value);
			}
		}
	}

	#endregion

	#region Events

	internal event TypedEventHandler<InfoBarV2, bool>? IsAnimatingChanged;
	internal event TypedEventHandler<InfoBarV2, InfoBarV2AnimationEventArgs>? AnimationStarting;
	internal event TypedEventHandler<InfoBarV2, InfoBarV2AnimationEventArgs>? AnimationCompleted;

	#endregion

	#region Property Changed Callbacks

	// All these callbacks recreate animations when properties change to ensure
	// the animations reflect the current property values
	private static void OnAnimationTypeChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is InfoBarV2 infoBar && !infoBar._isDisposed && !infoBar._isUnloading)
		{
			infoBar.RecreateAnimations();
		}
	}

	private static void OnAnimationDurationChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is InfoBarV2 infoBar && !infoBar._isDisposed && !infoBar._isUnloading)
		{
			infoBar.RecreateAnimations();
		}
	}

	private static void OnUseEasingChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is InfoBarV2 infoBar && !infoBar._isDisposed && !infoBar._isUnloading)
		{
			infoBar.RecreateAnimations();
		}
	}

	private static void OnEasingFunctionChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is InfoBarV2 infoBar && !infoBar._isDisposed && !infoBar._isUnloading)
		{
			infoBar.RecreateAnimations();
		}
	}

	private static void OnSlideDistanceChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is InfoBarV2 infoBar && !infoBar._isDisposed && !infoBar._isUnloading)
		{
			infoBar.RecreateAnimations();
		}
	}

	private static void OnScaleFromChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is InfoBarV2 infoBar && !infoBar._isDisposed && !infoBar._isUnloading)
		{
			infoBar.RecreateAnimations();
		}
	}

	private static void OnScaleToChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is InfoBarV2 infoBar && !infoBar._isDisposed && !infoBar._isUnloading)
		{
			infoBar.RecreateAnimations();
		}
	}

	private static void OnEnableAnimationChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is InfoBarV2 infoBar && !infoBar._isDisposed && !infoBar._isUnloading)
		{
			// If animations are disabled, stop any running animations immediately
			if (!(bool)e.NewValue)
			{
				infoBar.StopAllAnimations();
			}
		}
	}

	private static void OnAnimationDelayChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is InfoBarV2 infoBar && !infoBar._isDisposed && !infoBar._isUnloading)
		{
			infoBar.RecreateAnimations();
		}
	}

	private static void OnFadeInDurationChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is InfoBarV2 infoBar && !infoBar._isDisposed && !infoBar._isUnloading)
		{
			infoBar.RecreateAnimations();
		}
	}

	private static void OnFadeOutDurationChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is InfoBarV2 infoBar && !infoBar._isDisposed && !infoBar._isUnloading)
		{
			infoBar.RecreateAnimations();
		}
	}

	private static void OnScaleInDurationChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is InfoBarV2 infoBar && !infoBar._isDisposed && !infoBar._isUnloading)
		{
			infoBar.RecreateAnimations();
		}
	}

	private static void OnScaleOutDurationChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is InfoBarV2 infoBar && !infoBar._isDisposed && !infoBar._isUnloading)
		{
			infoBar.RecreateAnimations();
		}
	}

	#endregion

	#region Event Handlers

	private void InfoBarV2_Loaded(object sender, RoutedEventArgs e)
	{
		// Reset disposal state in case this is a new instance after navigation
		lock (_stateLock)
		{
			_isDisposed = false;
			_isUnloading = false;
		}

		// Create animations once the control is loaded and has access to the visual tree
		RecreateAnimations();
	}

	private void InfoBarV2_Unloaded(object sender, RoutedEventArgs e)
	{
		// Set unloading flag immediately to prevent new operations
		lock (_stateLock)
		{
			_isUnloading = true;
		}

		// Clean up all animations and timers when control is unloaded to prevent memory leaks
		// This is critical for NavigationCacheMode.Disabled scenarios
		PerformCompleteCleanup();
	}

	/// <summary>
	/// Perform complete cleanup of all resources, animations, and pending operations.
	/// This is critical for preventing crashes when NavigationCacheMode.Disabled is used.
	/// </summary>
	private void PerformCompleteCleanup()
	{
		try
		{
			// Stop all animations immediately
			StopAllAnimations();

			// Clean up animation resources
			CleanupAnimations();

			// Stop and detach timer to eliminate handler references
			if (_closeButtonTimer != null)
			{
				// unsubscribe to avoid retaining this via delegate
				_closeButtonTimer.Tick -= CloseButtonTimer_Tick;
				_closeButtonTimer.Stop();
			}

			// Cancel all pending DispatcherQueue operations
			CancelAllPendingDispatcherOperations();

			// Clear all event handlers to prevent memory leaks
			ClearAllEventHandlers();

			// Reset all state flags
			ResetAllStateToDefaults();

			// Unregister the IsOpen property-changed callback if registered
			if (_isOpenCallbackToken >= 0)
			{
				try
				{
					UnregisterPropertyChangedCallback(IsOpenProperty, _isOpenCallbackToken);
				}
				catch (Exception ex)
				{
					Logger.Write($"InfoBarV2 property callback unregister error: {ex.Message}");
				}
				finally
				{
					_isOpenCallbackToken = -1;
				}
			}

			// Mark as disposed
			lock (_stateLock)
			{
				_isDisposed = true;
			}
		}
		catch (Exception ex)
		{
			// Log cleanup errors but don't crash
			Logger.Write($"InfoBarV2 cleanup error: {ex.Message}");
		}
	}

	/// <summary>
	/// Cancel all pending DispatcherQueue operations to prevent crashes during navigation.
	/// </summary>
	private void CancelAllPendingDispatcherOperations()
	{
		lock (_pendingDispatcherOperations)
		{
			_pendingDispatcherOperations.Clear();
		}
	}

	/// <summary>
	/// Clear all event handlers to prevent memory leaks and crashes.
	/// </summary>
	private void ClearAllEventHandlers()
	{
		try
		{
			// Clear our custom events
			IsAnimatingChanged = null;
			AnimationStarting = null;
			AnimationCompleted = null;

			// Note: We don't unregister the built-in InfoBar events (Loaded, Unloaded, etc.)
			// because they're needed for proper lifecycle management
		}
		catch (Exception ex)
		{
			Logger.Write($"InfoBarV2 event handler cleanup error: {ex.Message}");
		}
	}

	/// <summary>
	/// Reset all internal state flags to their default values.
	/// </summary>
	private void ResetAllStateToDefaults()
	{
		_isAnimating = false;
		_pendingAnimationState = false;
		_hasPendingAnimation = false;
		_isInternalIsOpenChange = false;
		_lastKnownIsOpenState = false;
		_isClosingViaButton = false;
		_suppressCloseAnimation = false;
		_isHandlingCloseButton = false;
		_preventDefaultClose = false;
		_animationInProgress = false;
		_isCurrentlyShowingAnimation = false;
		_isCurrentlyHidingAnimation = false;
		_shouldCancelCurrentAnimation = false;
	}

	/// <summary>
	/// Critical method that handles the InfoBar's Closing event.
	/// This is where we intercept close button clicks to show custom animations.
	/// The main challenge was preventing infinite loops while maintaining proper binding.
	/// </summary>
	private void InfoBarV2_Closing(InfoBar sender, InfoBarClosingEventArgs args)
	{
		// Immediately return if we're disposed or unloading to prevent crashes
		if (_isDisposed || _isUnloading)
		{
			return;
		}

		// Only intercept the close if animations are enabled and we should handle close button clicks
		// The _isHandlingCloseButton flag prevents infinite loops when we set IsOpen=false after animation
		if (EnableAnimation && InterceptCloseButton && !_isHandlingCloseButton)
		{
			// Cancel the default close behavior so we can show our custom animation first
			args.Cancel = true;
			_isClosingViaButton = true;

			// Use safe DispatcherQueue operation to start animation on next UI cycle to avoid timing issues
			SafeDispatcherQueueTryEnqueue(() =>
			{
				AnimateInfoBarState(false);
			});
			return;
		}

		// If we're already handling the close button, allow the close to proceed normally
		// This happens after our animation completes and we actually want to close the InfoBar
		if (_isHandlingCloseButton)
		{
			_isHandlingCloseButton = false;
			return;
		}

		// For all other cases, allow default close behavior (no animation needed)
	}

	private void InfoBarV2_Closed(InfoBar sender, InfoBarClosedEventArgs args)
	{
		// Immediately return if we're disposed or unloading to prevent crashes
		if (_isDisposed || _isUnloading)
		{
			return;
		}

		// Handle cleanup after InfoBar has been closed
		if (_suppressCloseAnimation)
		{
			_suppressCloseAnimation = false;
			return;
		}

		// Update state tracking if InfoBar was closed without my custom animation
		if (!_isClosingViaButton && EnableAnimation && !this.IsOpen && _lastKnownIsOpenState)
		{
			_lastKnownIsOpenState = false;
		}

		// Reset all close-related flags
		_isClosingViaButton = false;
		_preventDefaultClose = false;
	}

	/// <summary>
	/// Timer tick handler for close button processing.
	/// This timer was added to work around timing issues with InfoBar's close button handling.
	/// </summary>
	private void CloseButtonTimer_Tick(object? sender, object e)
	{
		// Immediately return if we're disposed or unloading to prevent crashes
		if (_isDisposed || _isUnloading)
		{
			_closeButtonTimer?.Stop();
			return;
		}

		_closeButtonTimer.Stop();

		if (_isClosingViaButton && _preventDefaultClose)
		{
			_preventDefaultClose = false;

			// Start the custom hide animation using safe dispatcher operation
			SafeDispatcherQueueTryEnqueue(() =>
			{
				AnimateInfoBarState(false);
			});
		}
	}

	/// <summary>
	/// Safe wrapper for DispatcherQueue.TryEnqueue that prevents crashes during navigation.
	/// This tracks pending operations and cancels them if the control is disposed.
	/// </summary>
	private void SafeDispatcherQueueTryEnqueue(Action operation)
	{
		// Don't queue new operations if we're disposed or unloading
		if (_isDisposed || _isUnloading)
		{
			return;
		}

		// Track this operation
		lock (_pendingDispatcherOperations)
		{
			_pendingDispatcherOperations.Add(operation);
		}

		// Queue the operation with safety checks
		_ = this.DispatcherQueue.TryEnqueue(() =>
		{
			// Check if we're still valid before executing
			bool shouldExecute = false;
			lock (_pendingDispatcherOperations)
			{
				if (_pendingDispatcherOperations.Contains(operation) && !_isDisposed && !_isUnloading)
				{
					_ = _pendingDispatcherOperations.Remove(operation);
					shouldExecute = true;
				}
			}

			// Execute the operation only if it's still valid
			if (shouldExecute)
			{
				try
				{
					operation();
				}
				catch (Exception ex)
				{
					Logger.Write($"InfoBarV2 DispatcherQueue operation error: {ex.Message}");
				}
			}
		});
	}

	/// <summary>
	/// Critical callback that responds to IsOpen property changes from data binding.
	/// This is where we detect when the ViewModel changes the IsOpen property and trigger animations.
	/// Handles conflicting animation requests properly and prevent crashes during navigation.
	/// </summary>
	private void OnIsOpenPropertyChanged(DependencyObject sender, DependencyProperty dp)
	{
		// Immediately return if we're disposed or unloading to prevent crashes
		if (_isDisposed || _isUnloading)
		{
			return;
		}

		// Skip processing if this change was made internally to prevent infinite loops
		// This flag is set when we modify IsOpen programmatically during animation completion
		if (_isInternalIsOpenChange)
		{
			return;
		}

		bool newIsOpenValue = this.IsOpen;

		// Skip redundant property changes that don't actually change the state
		if (_lastKnownIsOpenState == newIsOpenValue)
		{
			return;
		}

		bool oldState = _lastKnownIsOpenState;
		_lastKnownIsOpenState = newIsOpenValue;

		// If animations are disabled, use default InfoBar behavior
		if (!EnableAnimation)
		{
			this.Visibility = this.IsOpen ? Visibility.Visible : Visibility.Collapsed;
			this.Opacity = this.IsOpen ? 1.0 : 0.0;
			ResetTransforms();
			return;
		}

		// Enhanced conflict handling: if there's an opposite animation in progress, interrupt it
		if (_animationInProgress)
		{
			// Check if the new request is opposite to current animation
			bool isOppositeRequest = (_isCurrentlyShowingAnimation && !newIsOpenValue) ||
									(_isCurrentlyHidingAnimation && newIsOpenValue);

			if (isOppositeRequest)
			{
				// Cancel current animation and immediately start the new one
				_shouldCancelCurrentAnimation = true;
				StopCurrentAnimationAndStartNew(newIsOpenValue);
				return;
			}
			else
			{
				// Same direction request, queue it normally
				_hasPendingAnimation = true;
				_pendingAnimationState = newIsOpenValue;
				return;
			}
		}

		// Handle programmatic close (when ViewModel sets IsOpen=false) with forced animation
		if (oldState && !newIsOpenValue && !_isClosingViaButton && ForceCloseAnimation)
		{
			AnimateInfoBarState(false);
			return;
		}

		// Start the appropriate animation based on the new IsOpen value
		AnimateInfoBarState(this.IsOpen);
	}

	#endregion

	#region Animation Methods

	/// <summary>
	/// Stop current animation and immediately start a new one in the opposite direction.
	/// This handles the case where user wants to open during close animation or vice versa.
	/// </summary>
	private void StopCurrentAnimationAndStartNew(bool shouldOpen)
	{
		// Don't start new animations if we're disposed or unloading
		if (_isDisposed || _isUnloading)
		{
			return;
		}

		// Stop current animations immediately
		try
		{
			_showStoryboard?.Stop();
			_hideStoryboard?.Stop();
		}
		catch (Exception ex)
		{
			Logger.Write($"InfoBarV2 failed to stop current animation: {ex.Message}");
		}

		// Reset animation state flags
		_animationInProgress = false;
		_isCurrentlyShowingAnimation = false;
		_isCurrentlyHidingAnimation = false;
		_shouldCancelCurrentAnimation = false;
		_hasPendingAnimation = false;

		// Immediately start the new animation
		AnimateInfoBarState(shouldOpen);
	}

	/// <summary>
	/// Main method that orchestrates show/hide animations.
	/// This method ensures animations are properly created and manages animation state.
	/// </summary>
	private void AnimateInfoBarState(bool shouldOpen)
	{
		// Don't start animations if we're disposed or unloading
		if (_isDisposed || _isUnloading)
		{
			return;
		}

		// Ensure storyboards are created before attempting animation
		if (_showStoryboard == null || _hideStoryboard == null)
		{
			RecreateAnimations();
			if (_showStoryboard == null || _hideStoryboard == null)
			{
				// Fallback to non-animated behavior if animation creation fails
				FallbackToNonAnimatedBehavior(shouldOpen);
				return;
			}
		}

		// Set animation state flags
		IsAnimating = true;
		_animationInProgress = true;
		_isCurrentlyShowingAnimation = shouldOpen;
		_isCurrentlyHidingAnimation = !shouldOpen;
		_shouldCancelCurrentAnimation = false;

		// Create event args for animation events
		InfoBarV2AnimationEventArgs eventArgs = new(
			animationType: this.AnimationType,
			isOpening: shouldOpen,
			duration: this.AnimationDuration);

		// Notify observers that animation is starting (with null check for safety)
		try
		{
			AnimationStarting?.Invoke(this, eventArgs);
		}
		catch (Exception ex)
		{
			Logger.Write($"InfoBarV2 AnimationStarting event error: {ex.Message}");
		}

		// Execute the appropriate animation
		if (shouldOpen)
		{
			ExecuteShowAnimation();
		}
		else
		{
			ExecuteHideAnimation();
		}
	}

	/// <summary>
	/// Fallback method when animations cannot be created or are disabled.
	/// Ensures InfoBar still functions correctly without animations.
	/// </summary>
	private void FallbackToNonAnimatedBehavior(bool shouldOpen)
	{
		// Don't perform fallback operations if we're disposed or unloading
		if (_isDisposed || _isUnloading)
		{
			return;
		}

		// Reset all animation state first
		ResetAllAnimationState();

		if (shouldOpen)
		{
			this.Visibility = Visibility.Visible;
			this.Opacity = 1.0;
			ResetTransforms();
			if (!this.IsOpen)
			{
				_isInternalIsOpenChange = true;
				this.IsOpen = true;
				_isInternalIsOpenChange = false;
			}
		}
		else
		{
			this.Visibility = Visibility.Collapsed;
			this.Opacity = 0.0;
			ResetTransforms();
			if (this.IsOpen)
			{
				_suppressCloseAnimation = true;
				_isInternalIsOpenChange = true;
				this.IsOpen = false;
				_isInternalIsOpenChange = false;
			}
		}

		_lastKnownIsOpenState = shouldOpen;
		_isClosingViaButton = false;
	}

	/// <summary>
	/// Reset all animation state flags to a clean state.
	/// This helps prevent state corruption when animations are interrupted.
	/// </summary>
	private void ResetAllAnimationState()
	{
		_animationInProgress = false;
		_isCurrentlyShowingAnimation = false;
		_isCurrentlyHidingAnimation = false;
		_shouldCancelCurrentAnimation = false;
		_hasPendingAnimation = false;
		IsAnimating = false;
	}

	/// <summary>
	/// Execute the show animation sequence.
	/// Sets initial state and starts the show storyboard.
	/// </summary>
	private void ExecuteShowAnimation()
	{
		// Don't execute if we're disposed or unloading
		if (_isDisposed || _isUnloading)
		{
			return;
		}

		// Make InfoBar visible before starting animation
		this.Visibility = Visibility.Visible;

		// Set initial state for the animation (invisible, scaled down, offset, etc.)
		SetInitialStateForShow();

		// Start the show animation with error handling
		try
		{
			_showStoryboard?.Begin();
		}
		catch (Exception ex)
		{
			// Fallback in case of animation failure to ensure InfoBar still works
			Logger.Write($"InfoBarV2 show animation failed: {ex.Message}");
			CompleteShowAnimation();
		}
	}

	/// <summary>
	/// Execute the hide animation sequence.
	/// Sets initial state and starts the hide storyboard.
	/// </summary>
	private void ExecuteHideAnimation()
	{
		// Don't execute if we're disposed or unloading
		if (_isDisposed || _isUnloading)
		{
			return;
		}

		// Ensure InfoBar starts from the visible state for hide animation
		SetInitialStateForHide();

		// Start the hide animation with error handling
		try
		{
			_hideStoryboard?.Begin();
		}
		catch (Exception ex)
		{
			// Fallback in case of animation failure to ensure InfoBar still works
			Logger.Write($"InfoBarV2 hide animation failed: {ex.Message}");
			CompleteHideAnimation();
		}
	}

	/// <summary>
	/// Set the initial visual state for show animations.
	/// Different animation types require different starting states.
	/// </summary>
	private void SetInitialStateForShow()
	{
		// Always start with opacity 0 for show animations
		this.Opacity = 0;

		// Set transform initial state based on animation type
		switch (AnimationType)
		{
			case InfoBarAnimationType.Slide:
				_translateTransform.Y = -SlideDistance;  // Start above normal position
				_scaleTransform.ScaleX = ScaleTo;        // Normal scale
				_scaleTransform.ScaleY = ScaleTo;
				break;

			case InfoBarAnimationType.Scale:
				_translateTransform.Y = 0;               // Normal position
				_scaleTransform.ScaleX = ScaleFrom;      // Start scaled down
				_scaleTransform.ScaleY = ScaleFrom;
				break;

			case InfoBarAnimationType.Fade:
				_translateTransform.Y = 0;               // Normal position and scale
				_scaleTransform.ScaleX = ScaleTo;
				_scaleTransform.ScaleY = ScaleTo;
				break;

			case InfoBarAnimationType.SlideAndScale:
				_translateTransform.Y = -SlideDistance;  // Start above and scaled down
				_scaleTransform.ScaleX = ScaleFrom;
				_scaleTransform.ScaleY = ScaleFrom;
				break;

			case InfoBarAnimationType.SlideAndFade:
				_translateTransform.Y = -SlideDistance;  // Start above normal position
				_scaleTransform.ScaleX = ScaleTo;        // Normal scale
				_scaleTransform.ScaleY = ScaleTo;
				break;

			case InfoBarAnimationType.ScaleAndFade:
				_translateTransform.Y = 0;               // Normal position
				_scaleTransform.ScaleX = ScaleFrom;      // Start scaled down
				_scaleTransform.ScaleY = ScaleFrom;
				break;

			case InfoBarAnimationType.All:
				_translateTransform.Y = -SlideDistance;  // Start above and scaled down
				_scaleTransform.ScaleX = ScaleFrom;
				_scaleTransform.ScaleY = ScaleFrom;
				break;

			case InfoBarAnimationType.FadeAndScale:
				_translateTransform.Y = 0;               // Normal position
				_scaleTransform.ScaleX = ScaleFrom;      // Start scaled down
				_scaleTransform.ScaleY = ScaleFrom;
				break;
			default:
				break;
		}
	}

	/// <summary>
	/// Set the initial visual state for hide animations.
	/// Hide animations should start from the fully visible state.
	/// </summary>
	private void SetInitialStateForHide()
	{
		// Start from fully visible state
		this.Opacity = 1;
		_translateTransform.Y = 0;
		_scaleTransform.ScaleX = ScaleTo;
		_scaleTransform.ScaleY = ScaleTo;
	}

	/// <summary>
	/// Reset all transforms to their default state.
	/// Used when animations are complete or disabled.
	/// </summary>
	private void ResetTransforms()
	{
		_translateTransform.Y = 0;
		_scaleTransform.ScaleX = ScaleTo;
		_scaleTransform.ScaleY = ScaleTo;
		_compositeTransform.TranslateY = 0;
		_compositeTransform.ScaleX = ScaleTo;
		_compositeTransform.ScaleY = ScaleTo;
	}

	/// <summary>
	/// Recreate all animation storyboards.
	/// Called when animation properties change or control is loaded.
	/// </summary>
	private void RecreateAnimations()
	{
		// Only create animations if control is loaded and has access to visual tree
		// and we're not disposed or unloading
		if (!this.IsLoaded || _isDisposed || _isUnloading)
		{
			return;
		}

		// Clean up existing animations before creating new ones
		CleanupAnimations();
		CreateShowAnimation();
		CreateHideAnimation();
	}

	/// <summary>
	/// Create the show animation storyboard with all necessary animations.
	/// This method builds the complete animation sequence for showing the InfoBar.
	/// </summary>
	private void CreateShowAnimation()
	{
		// Don't create animations if we're disposed or unloading
		if (_isDisposed || _isUnloading)
		{
			return;
		}

		_showStoryboard = new Storyboard();

		// Create opacity animation for fade-in effect
		DoubleAnimation opacityAnimation = new()
		{
			From = 0,
			To = 1,
			Duration = GetEffectiveFadeInDuration(),
			BeginTime = AnimationDelay
		};

		// Apply easing function if enabled
		if (UseEasing && EasingFunction != null)
		{
			opacityAnimation.EasingFunction = CreateShowEasingFunction();
		}

		// Target the InfoBar's Opacity property
		Storyboard.SetTarget(opacityAnimation, this);
		Storyboard.SetTargetProperty(opacityAnimation, "Opacity");
		_showStoryboard.Children.Add(opacityAnimation);

		// Add transform animations based on the selected animation type
		CreateTransformAnimationsForShow();

		// Wire up completion event handler
		_showStoryboard.Completed += ShowStoryboard_Completed;
	}

	/// <summary>
	/// Create transform animations for the show storyboard based on animation type.
	/// Different animation types require different combinations of transforms.
	/// </summary>
	private void CreateTransformAnimationsForShow()
	{
		TimeSpan scaleInDuration = GetEffectiveScaleInDuration();
		TimeSpan beginTime = AnimationDelay;

		switch (AnimationType)
		{
			case InfoBarAnimationType.Slide:
			case InfoBarAnimationType.SlideAndFade:
				CreateSlideAnimationForShow(new Duration(scaleInDuration), beginTime);
				break;

			case InfoBarAnimationType.Scale:
				CreateScaleAnimationForShow(new Duration(scaleInDuration), beginTime);
				break;

			case InfoBarAnimationType.ScaleAndFade:
			case InfoBarAnimationType.FadeAndScale:
				CreateScaleAnimationForShow(new Duration(scaleInDuration), beginTime);
				break;

			case InfoBarAnimationType.SlideAndScale:
			case InfoBarAnimationType.All:
				CreateSlideAnimationForShow(new Duration(scaleInDuration), beginTime);
				CreateScaleAnimationForShow(new Duration(scaleInDuration), beginTime);
				break;

			case InfoBarAnimationType.Fade:
				// Only opacity animation, no transform animations needed
				break;
			default:
				break;
		}
	}

	/// <summary>
	/// Create slide animation for show storyboard.
	/// Animates the Y position from negative offset to 0.
	/// </summary>
	private void CreateSlideAnimationForShow(Duration duration, TimeSpan beginTime)
	{
		DoubleAnimation slideAnimation = new()
		{
			From = -SlideDistance,
			To = 0,
			Duration = duration,
			BeginTime = beginTime
		};

		if (UseEasing && EasingFunction != null)
		{
			slideAnimation.EasingFunction = CreateShowEasingFunction();
		}

		// Target the TranslateTransform's Y property
		Storyboard.SetTarget(slideAnimation, _translateTransform);
		Storyboard.SetTargetProperty(slideAnimation, "Y");
		_showStoryboard?.Children.Add(slideAnimation);
	}

	/// <summary>
	/// Create scale animations for show storyboard.
	/// Animates both X and Y scale from ScaleFrom to ScaleTo.
	/// </summary>
	private void CreateScaleAnimationForShow(Duration duration, TimeSpan beginTime)
	{
		// Create separate animations for X and Y scale
		DoubleAnimation scaleXAnimation = new()
		{
			From = ScaleFrom,
			To = ScaleTo,
			Duration = duration,
			BeginTime = beginTime
		};

		DoubleAnimation scaleYAnimation = new()
		{
			From = ScaleFrom,
			To = ScaleTo,
			Duration = duration,
			BeginTime = beginTime
		};

		// Apply easing functions if enabled
		if (UseEasing && EasingFunction != null)
		{
			EasingFunctionBase? showEasing = CreateShowEasingFunction();
			scaleXAnimation.EasingFunction = showEasing;
			scaleYAnimation.EasingFunction = CreateShowEasingFunction();
		}

		// Target the ScaleTransform's properties
		Storyboard.SetTarget(scaleXAnimation, _scaleTransform);
		Storyboard.SetTargetProperty(scaleXAnimation, "ScaleX");
		_showStoryboard?.Children.Add(scaleXAnimation);

		Storyboard.SetTarget(scaleYAnimation, _scaleTransform);
		Storyboard.SetTargetProperty(scaleYAnimation, "ScaleY");
		_showStoryboard?.Children.Add(scaleYAnimation);
	}

	/// <summary>
	/// Create the hide animation storyboard with all necessary animations.
	/// This method builds the complete animation sequence for hiding the InfoBar.
	/// </summary>
	private void CreateHideAnimation()
	{
		// Don't create animations if we're disposed or unloading
		if (_isDisposed || _isUnloading)
		{
			return;
		}

		_hideStoryboard = new Storyboard();

		// Create opacity animation for fade-out effect
		DoubleAnimation opacityAnimation = new()
		{
			From = 1,
			To = 0,
			Duration = GetEffectiveFadeOutDuration(),
			BeginTime = AnimationDelay
		};

		if (UseEasing && EasingFunction != null)
		{
			opacityAnimation.EasingFunction = CreateHideEasingFunction();
		}

		// Target the InfoBar's Opacity property
		Storyboard.SetTarget(opacityAnimation, this);
		Storyboard.SetTargetProperty(opacityAnimation, "Opacity");
		_hideStoryboard.Children.Add(opacityAnimation);

		// Add transform animations based on the selected animation type
		CreateTransformAnimationsForHide();

		// Wire up completion event handler
		_hideStoryboard.Completed += HideStoryboard_Completed;
	}

	/// <summary>
	/// Create transform animations for the hide storyboard based on animation type.
	/// Mirror of the show animations but in reverse direction.
	/// </summary>
	private void CreateTransformAnimationsForHide()
	{
		TimeSpan scaleOutDuration = GetEffectiveScaleOutDuration();
		TimeSpan beginTime = AnimationDelay;

		switch (AnimationType)
		{
			case InfoBarAnimationType.Slide:
			case InfoBarAnimationType.SlideAndFade:
				CreateSlideAnimationForHide(new Duration(scaleOutDuration), beginTime);
				break;

			case InfoBarAnimationType.Scale:
				CreateScaleAnimationForHide(new Duration(scaleOutDuration), beginTime);
				break;

			case InfoBarAnimationType.ScaleAndFade:
			case InfoBarAnimationType.FadeAndScale:
				CreateScaleAnimationForHide(new Duration(scaleOutDuration), beginTime);
				break;

			case InfoBarAnimationType.SlideAndScale:
			case InfoBarAnimationType.All:
				CreateSlideAnimationForHide(new Duration(scaleOutDuration), beginTime);
				CreateScaleAnimationForHide(new Duration(scaleOutDuration), beginTime);
				break;

			case InfoBarAnimationType.Fade:
				// Only opacity animation, no transform animations needed
				break;
			default:
				break;
		}
	}

	/// <summary>
	/// Create slide animation for hide storyboard.
	/// Animates the Y position from 0 to negative offset.
	/// </summary>
	private void CreateSlideAnimationForHide(Duration duration, TimeSpan beginTime)
	{
		DoubleAnimation slideAnimation = new()
		{
			From = 0,
			To = -SlideDistance,
			Duration = duration,
			BeginTime = beginTime
		};

		if (UseEasing && EasingFunction != null)
		{
			slideAnimation.EasingFunction = CreateHideEasingFunction();
		}

		Storyboard.SetTarget(slideAnimation, _translateTransform);
		Storyboard.SetTargetProperty(slideAnimation, "Y");
		_hideStoryboard?.Children.Add(slideAnimation);
	}

	/// <summary>
	/// Create scale animations for hide storyboard.
	/// Animates both X and Y scale from ScaleTo to ScaleFrom.
	/// </summary>
	private void CreateScaleAnimationForHide(Duration duration, TimeSpan beginTime)
	{
		DoubleAnimation scaleXAnimation = new()
		{
			From = ScaleTo,
			To = ScaleFrom,
			Duration = duration,
			BeginTime = beginTime
		};

		DoubleAnimation scaleYAnimation = new()
		{
			From = ScaleTo,
			To = ScaleFrom,
			Duration = duration,
			BeginTime = beginTime
		};

		if (UseEasing && EasingFunction != null)
		{
			EasingFunctionBase? hideEasing = CreateHideEasingFunction();
			scaleXAnimation.EasingFunction = hideEasing;
			scaleYAnimation.EasingFunction = CreateHideEasingFunction();
		}

		Storyboard.SetTarget(scaleXAnimation, _scaleTransform);
		Storyboard.SetTargetProperty(scaleXAnimation, "ScaleX");
		_hideStoryboard?.Children.Add(scaleXAnimation);

		Storyboard.SetTarget(scaleYAnimation, _scaleTransform);
		Storyboard.SetTargetProperty(scaleYAnimation, "ScaleY");
		_hideStoryboard?.Children.Add(scaleYAnimation);
	}

	/// <summary>
	/// Create easing function for show animations.
	/// Uses EaseOut mode for smooth entry.
	/// </summary>
	private EasingFunctionBase? CreateShowEasingFunction()
	{
		if (!UseEasing || EasingFunction == null)
		{
			return null;
		}

		EasingFunctionBase? easing = CloneEasingFunction(EasingFunction);
		_ = (easing?.EasingMode = EasingMode.EaseOut);
		return easing;
	}

	/// <summary>
	/// Create easing function for hide animations.
	/// Uses EaseIn mode for smooth exit.
	/// </summary>
	private EasingFunctionBase? CreateHideEasingFunction()
	{
		if (!UseEasing || EasingFunction == null)
		{
			return null;
		}

		EasingFunctionBase? easing = CloneEasingFunction(EasingFunction);
		_ = (easing?.EasingMode = EasingMode.EaseIn);
		return easing;
	}

	/// <summary>
	/// Get the effective fade-in duration based on animation type.
	/// Different animation types may use different durations.
	/// </summary>
	private TimeSpan GetEffectiveFadeInDuration()
	{
		TimeSpan baseDuration = AnimationDuration;

		switch (AnimationType)
		{
			case InfoBarAnimationType.Fade:
			case InfoBarAnimationType.SlideAndFade:
			case InfoBarAnimationType.ScaleAndFade:
			case InfoBarAnimationType.FadeAndScale:
				return FadeInDuration;
			case InfoBarAnimationType.All:
				// For 'All' animation type, use the longer of fade or scale duration
				double maxDuration = Math.Max(FadeInDuration.TotalMilliseconds, ScaleInDuration.TotalMilliseconds);
				return TimeSpan.FromMilliseconds(maxDuration);
			case InfoBarAnimationType.Slide:
				return baseDuration;
			case InfoBarAnimationType.Scale:
				return baseDuration;
			case InfoBarAnimationType.SlideAndScale:
				return baseDuration;
			default:
				return baseDuration;
		}
	}

	/// <summary>
	/// Get the effective fade-out duration based on animation type.
	/// Mirror of GetEffectiveFadeInDuration for hide animations.
	/// </summary>
	private TimeSpan GetEffectiveFadeOutDuration()
	{
		TimeSpan baseDuration = AnimationDuration;

		switch (AnimationType)
		{
			case InfoBarAnimationType.Fade:
			case InfoBarAnimationType.SlideAndFade:
			case InfoBarAnimationType.ScaleAndFade:
			case InfoBarAnimationType.FadeAndScale:
				return FadeOutDuration;
			case InfoBarAnimationType.All:
				double maxDuration = Math.Max(FadeOutDuration.TotalMilliseconds, ScaleOutDuration.TotalMilliseconds);
				return TimeSpan.FromMilliseconds(maxDuration);
			case InfoBarAnimationType.Slide:
				return baseDuration;
			case InfoBarAnimationType.Scale:
				return baseDuration;
			case InfoBarAnimationType.SlideAndScale:
				return baseDuration;
			default:
				return baseDuration;
		}
	}

	/// <summary>
	/// Get the effective scale-in duration based on animation type.
	/// Used for transform animations during show.
	/// </summary>
	private TimeSpan GetEffectiveScaleInDuration()
	{
		TimeSpan baseDuration = AnimationDuration;

		return AnimationType switch
		{
			InfoBarAnimationType.Scale or InfoBarAnimationType.SlideAndScale or InfoBarAnimationType.ScaleAndFade or InfoBarAnimationType.FadeAndScale or InfoBarAnimationType.All => ScaleInDuration,
			_ => baseDuration,
		};
	}

	/// <summary>
	/// Get the effective scale-out duration based on animation type.
	/// Used for transform animations during hide.
	/// </summary>
	private TimeSpan GetEffectiveScaleOutDuration()
	{
		TimeSpan baseDuration = AnimationDuration;

		return AnimationType switch
		{
			InfoBarAnimationType.Scale or InfoBarAnimationType.SlideAndScale or InfoBarAnimationType.ScaleAndFade or InfoBarAnimationType.FadeAndScale or InfoBarAnimationType.All => ScaleOutDuration,
			_ => baseDuration,
		};
	}

	/// <summary>
	/// Clone an easing function to create independent instances.
	/// This prevents sharing easing function instances between animations.
	/// </summary>
	private static EasingFunctionBase? CloneEasingFunction(EasingFunctionBase? original)
	{
		if (original == null) return null;

		// Create appropriate easing function type with same properties
		return original switch
		{
			CubicEase cubic => new CubicEase { EasingMode = cubic.EasingMode },
			QuadraticEase quadratic => new QuadraticEase { EasingMode = quadratic.EasingMode },
			QuarticEase quartic => new QuarticEase { EasingMode = quartic.EasingMode },
			QuinticEase quintic => new QuinticEase { EasingMode = quintic.EasingMode },
			SineEase sine => new SineEase { EasingMode = sine.EasingMode },
			BackEase back => new BackEase { EasingMode = back.EasingMode, Amplitude = back.Amplitude },
			BounceEase bounce => new BounceEase { EasingMode = bounce.EasingMode, Bounces = bounce.Bounces, Bounciness = bounce.Bounciness },
			CircleEase circle => new CircleEase { EasingMode = circle.EasingMode },
			ElasticEase elastic => new ElasticEase { EasingMode = elastic.EasingMode, Oscillations = elastic.Oscillations, Springiness = elastic.Springiness },
			ExponentialEase exponential => new ExponentialEase { EasingMode = exponential.EasingMode, Exponent = exponential.Exponent },
			PowerEase power => new PowerEase { EasingMode = power.EasingMode, Power = power.Power },
			_ => new CubicEase { EasingMode = original.EasingMode }
		};
	}

	#endregion

	#region Animation Event Handlers

	/// <summary>
	/// Handle show storyboard completion.
	/// Called when the show animation finishes.
	/// Handles animation cancellation properly and prevent crashes during navigation.
	/// </summary>
	private void ShowStoryboard_Completed(object? sender, object e)
	{
		// Immediately return if we're disposed or unloading to prevent crashes
		if (_isDisposed || _isUnloading)
		{
			return;
		}

		// Check if animation was cancelled
		if (_shouldCancelCurrentAnimation)
		{
			_shouldCancelCurrentAnimation = false;
			return;
		}

		CompleteShowAnimation();
	}

	/// <summary>
	/// Handle hide storyboard completion.
	/// Called when the hide animation finishes.
	/// Handles animation cancellation properly and prevent crashes during navigation.
	/// </summary>
	private void HideStoryboard_Completed(object? sender, object e)
	{
		// Immediately return if we're disposed or unloading to prevent crashes
		if (_isDisposed || _isUnloading)
		{
			return;
		}

		// Check if animation was cancelled
		if (_shouldCancelCurrentAnimation)
		{
			_shouldCancelCurrentAnimation = false;
			return;
		}

		CompleteHideAnimation();
	}

	/// <summary>
	/// Complete the show animation sequence.
	/// Ensures final state is correct and updates properties.
	/// </summary>
	private void CompleteShowAnimation()
	{
		// Don't complete if we're disposed or unloading
		if (_isDisposed || _isUnloading)
		{
			return;
		}

		// Ensure final visual state is correct
		this.Visibility = Visibility.Visible;
		this.Opacity = 1;
		ResetTransforms();

		// Ensure IsOpen property reflects the shown state
		if (!this.IsOpen)
		{
			_isInternalIsOpenChange = true;
			this.IsOpen = true;
			_isInternalIsOpenChange = false;
		}

		// Create event args and notify observers
		InfoBarV2AnimationEventArgs eventArgs = new(
			animationType: this.AnimationType,
			isOpening: true,
			duration: this.AnimationDuration);

		// Safely invoke event with null check
		try
		{
			AnimationCompleted?.Invoke(this, eventArgs);
		}
		catch (Exception ex)
		{
			Logger.Write($"InfoBarV2 AnimationCompleted event error: {ex.Message}");
		}

		// Clean up animation state
		FinishAnimation();
	}

	/// <summary>
	/// Complete the hide animation sequence.
	/// This is the critical method that resolves binding and infinite loop issues.
	/// The approach here differentiates between close button clicks and programmatic closes.
	/// </summary>
	private void CompleteHideAnimation()
	{
		// Don't complete if we're disposed or unloading
		if (_isDisposed || _isUnloading)
		{
			return;
		}

		// Hide the InfoBar completely
		this.Visibility = Visibility.Collapsed;
		this.Opacity = 0;

		// Handle close button vs programmatic close differently
		// This prevents infinite loops while maintaining proper data binding
		if (_isClosingViaButton)
		{
			// Close button click scenario: we need to actually close the InfoBar
			// Use _isInternalIsOpenChange to prevent triggering another animation
			_isHandlingCloseButton = true;
			_suppressCloseAnimation = true;
			_isInternalIsOpenChange = true;
			this.IsOpen = false;  // This will close the InfoBar and update ViewModel
			_isInternalIsOpenChange = false;
			_lastKnownIsOpenState = false;
		}
		else
		{
			// Programmatic close scenario: ViewModel already updated, just track state
			_lastKnownIsOpenState = false;
		}

		// Create event args and notify observers
		InfoBarV2AnimationEventArgs eventArgs = new(
			animationType: this.AnimationType,
			isOpening: false,
			duration: this.AnimationDuration);

		// Safely invoke event with null check
		try
		{
			AnimationCompleted?.Invoke(this, eventArgs);
		}
		catch (Exception ex)
		{
			Logger.Write($"InfoBarV2 AnimationCompleted event error: {ex.Message}");
		}

		// Reset close button flag and clean up animation state
		_isClosingViaButton = false;
		FinishAnimation();
	}

	/// <summary>
	/// Finish animation sequence and handle any pending animations.
	/// Resets animation state and processes queued animations.
	/// </summary>
	private void FinishAnimation()
	{
		// Don't process if we're disposed or unloading
		if (_isDisposed || _isUnloading)
		{
			return;
		}

		// Reset animation state flags
		_isCurrentlyShowingAnimation = false;
		_isCurrentlyHidingAnimation = false;
		_animationInProgress = false;
		IsAnimating = false;

		// Process any pending animation requests that were queued during this animation
		if (_hasPendingAnimation)
		{
			_hasPendingAnimation = false;
			bool pendingState = _pendingAnimationState;

			// Use safe DispatcherQueue operation to avoid re-entrancy issues
			SafeDispatcherQueueTryEnqueue(() =>
			{
				// Only start pending animation if state actually needs to change
				if (this.IsOpen != pendingState)
				{
					_lastKnownIsOpenState = pendingState;
					AnimateInfoBarState(pendingState);
				}
			});
		}
	}

	#endregion

	#region Utility Methods

	/// <summary>
	/// Stop all running animations immediately.
	/// Used when animations need to be cancelled or control is being unloaded.
	/// </summary>
	private void StopAllAnimations()
	{
		try
		{
			_showStoryboard?.Stop();
			_hideStoryboard?.Stop();
		}
		catch (Exception ex)
		{
			// Log animation stop failures but don't crash
			Logger.Write($"InfoBarV2 stop animations failed: {ex.Message}");
		}

		// Reset all animation state completely
		ResetAllAnimationState();
		_closeButtonTimer?.Stop();
	}

	/// <summary>
	/// Clean up animation resources and event handlers.
	/// Called when recreating animations or unloading control.
	/// </summary>
	private void CleanupAnimations()
	{
		// Clean up show storyboard
		if (_showStoryboard != null)
		{
			_showStoryboard.Completed -= ShowStoryboard_Completed;
			_showStoryboard.Stop();
			_showStoryboard.Children.Clear();
			_showStoryboard = null;
		}

		// Clean up hide storyboard
		if (_hideStoryboard != null)
		{
			_hideStoryboard.Completed -= HideStoryboard_Completed;
			_hideStoryboard.Stop();
			_hideStoryboard.Children.Clear();
			_hideStoryboard = null;
		}
	}

	/// <summary>
	/// Enables text selection on the internal TextBlock named "Message".
	/// </summary>
	private void EnableMessageTextSelection()
	{
		// Skip if already done for current template, or if control is disposing/unloading.
		if (_messageTextSelectionEnabled || _isDisposed || _isUnloading)
		{
			return;
		}

		try
		{
			DependencyObject? messageElement = TryFindChildByName(this, "Message");
			if (messageElement is TextBlock messageTextBlock)
			{
				messageTextBlock.IsTextSelectionEnabled = true;
				_messageTextSelectionEnabled = true;
			}
		}
		catch (Exception ex)
		{
			Logger.Write($"InfoBarV2 EnableMessageTextSelection error: {ex.Message}");
		}
	}

	/// <summary>
	/// Recursively searches the visual tree beneath <paramref name="parent"/> for a FrameworkElement
	/// whose Name matches <paramref name="controlName"/>. Returns the first match or null.
	/// </summary>
	/// <param name="parent">Root element to begin search.</param>
	/// <param name="controlName">Name of the child control to locate.</param>
	/// <returns>The matching DependencyObject or null.</returns>
	private static DependencyObject? TryFindChildByName(DependencyObject parent, string controlName)
	{
		if (parent == null)
		{
			return null;
		}

		int childCount = VisualTreeHelper.GetChildrenCount(parent);
		for (int i = 0; i < childCount; i++)
		{
			DependencyObject child = VisualTreeHelper.GetChild(parent, i);

			if (child is FrameworkElement frameworkElement)
			{
				if (string.Equals(frameworkElement.Name, controlName, StringComparison.OrdinalIgnoreCase))
				{
					return child;
				}
			}

			DependencyObject? result = TryFindChildByName(child, controlName);
			if (result != null)
			{
				return result;
			}
		}

		return null;
	}

	#endregion

	#region INotifyPropertyChanged Implementation

	public event PropertyChangedEventHandler? PropertyChanged;

	private void OnPropertyChanged([CallerMemberName] string? propertyName = null)
	{
		PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
	}

	#endregion
}

#region Event Args Class

/// <summary>
/// Event arguments for InfoBarV2 animation events.
/// Provides information about the animation that started or completed.
/// </summary>
internal sealed class InfoBarV2AnimationEventArgs(
	InfoBarV2.InfoBarAnimationType animationType,
	bool isOpening,
	TimeSpan duration)
{
	internal InfoBarV2.InfoBarAnimationType AnimationType => animationType;
	internal bool IsOpening => isOpening;
	internal TimeSpan Duration => duration;
}

#endregion
