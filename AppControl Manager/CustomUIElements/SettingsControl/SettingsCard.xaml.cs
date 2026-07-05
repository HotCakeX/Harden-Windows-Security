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

// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// Source: https://github.com/CommunityToolkit/Windows/tree/main/components/SettingsControls/src
// License: https://github.com/CommunityToolkit/Windows/blob/main/License.md
// It's been modified to meet the Harden Windows Security repository's requirements.

using System.Collections;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;

namespace CommonCore.ToolKits;

/// <summary>
/// This is the base control to create consistent settings experiences, inline with the Windows 11 design language.
/// A SettingsCard can also be hosted within a SettingsExpander.
/// </summary>
[TemplatePart(Name = ActionIconPresenterHolder, Type = typeof(Viewbox))]
[TemplatePart(Name = HeaderPresenter, Type = typeof(ContentPresenter))]
[TemplatePart(Name = DescriptionPresenter, Type = typeof(ContentPresenter))]
[TemplatePart(Name = HeaderIconPresenterHolder, Type = typeof(Viewbox))]
[TemplatePart(Name = RootGrid, Type = typeof(FrameworkElement))]

[TemplateVisualState(Name = NormalState, GroupName = CommonStates)]
[TemplateVisualState(Name = PointerOverState, GroupName = CommonStates)]
[TemplateVisualState(Name = PressedState, GroupName = CommonStates)]
[TemplateVisualState(Name = DisabledState, GroupName = CommonStates)]

[TemplateVisualState(Name = BitmapHeaderIconEnabledState, GroupName = BitmapHeaderIconStates)]
[TemplateVisualState(Name = BitmapHeaderIconDisabledState, GroupName = BitmapHeaderIconStates)]

[TemplateVisualState(Name = RightState, GroupName = ContentAlignmentStates)]
[TemplateVisualState(Name = RightWrappedState, GroupName = ContentAlignmentStates)]
[TemplateVisualState(Name = RightWrappedNoIconState, GroupName = ContentAlignmentStates)]
[TemplateVisualState(Name = LeftState, GroupName = ContentAlignmentStates)]
[TemplateVisualState(Name = VerticalState, GroupName = ContentAlignmentStates)]

[TemplateVisualState(Name = NoContentSpacingState, GroupName = ContentSpacingStates)]
[TemplateVisualState(Name = ContentSpacingState, GroupName = ContentSpacingStates)]
[TemplateVisualState(Name = ContentSpacingNarrowState, GroupName = ContentSpacingStates)]
[TemplateVisualState(Name = VisibleState, GroupName = ContentVisibilityStates)]
[TemplateVisualState(Name = CollapsedState, GroupName = ContentVisibilityStates)]
internal partial class SettingsCard : ButtonBase
{
	internal const string CommonStates = "CommonStates";
	internal const string NormalState = "Normal";
	internal const string PointerOverState = "PointerOver";
	internal const string PressedState = "Pressed";
	internal const string DisabledState = "Disabled";

	internal const string BitmapHeaderIconStates = "BitmapHeaderIconStates";
	internal const string BitmapHeaderIconEnabledState = "BitmapHeaderIconEnabled";
	internal const string BitmapHeaderIconDisabledState = "BitmapHeaderIconDisabled";

	internal const string ContentAlignmentStates = "ContentAlignmentStates";
	internal const string RightState = "Right";
	internal const string RightWrappedState = "RightWrapped";
	internal const string RightWrappedNoIconState = "RightWrappedNoIcon";
	internal const string LeftState = "Left";
	internal const string VerticalState = "Vertical";

	internal const string ContentSpacingStates = "ContentSpacingStates";
	internal const string NoContentSpacingState = "NoContentSpacing";
	internal const string ContentSpacingState = "ContentSpacing";
	internal const string ContentSpacingNarrowState = "ContentSpacingNarrow";
	internal const string ContentVisibilityStates = "ContentVisibilityStates";
	internal const string VisibleState = "Visible";
	internal const string CollapsedState = "Collapsed";

	internal const string ActionIconPresenterHolder = "PART_ActionIconPresenterHolder";
	internal const string HeaderPresenter = "PART_HeaderPresenter";
	internal const string DescriptionPresenter = "PART_DescriptionPresenter";
	internal const string HeaderIconPresenterHolder = "PART_HeaderIconPresenterHolder";
	internal const string RootGrid = "PART_RootGrid";

	// Keeping these values aligned with the SettingsCardWrapThreshold resources in SettingsCard.xaml.
	private const double SettingsCardWrapThreshold = 476.0;
	private const double SettingsCardWrapNoIconThreshold = 286.0;

	private FrameworkElement? _rootGrid;

	/// <summary>
	/// Creates a new instance of the <see cref="SettingsCard"/> class.
	/// </summary>
	public SettingsCard() => DefaultStyleKey = typeof(SettingsCard);

	protected override void OnApplyTemplate()
	{
		DetachRootGridSizeChanged();
		base.OnApplyTemplate();
		_rootGrid = GetTemplateChild(RootGrid) as FrameworkElement;
		AttachRootGridSizeChanged();
		IsEnabledChanged -= OnIsEnabledChanged;
		OnActionIconChanged();
		OnHeaderChanged();
		OnHeaderIconChanged();
		OnDescriptionChanged();
		OnIsClickEnabledChanged();
		CheckInitialVisualState();
		UpdateContentVisibilityState();
		SetAccessibleContentName();
		IsEnabledChanged += OnIsEnabledChanged;
	}

	private void CheckInitialVisualState()
	{
		_ = VisualStateManager.GoToState(this, IsEnabled ? NormalState : DisabledState, true);

		// In NativeAOT, VisualStateGroups are not reliably retrievable via GetTemplateChild(...)
		// So query the groups from the templated root instead, and also ensure spacing is updated proactively.
		VisualStateGroup? contentAlignmentStatesGroup = GetRootGridVisualStateGroup(ContentAlignmentStates);
		if (contentAlignmentStatesGroup is not null)
		{
			contentAlignmentStatesGroup.CurrentStateChanged -= ContentAlignmentStates_Changed;
			contentAlignmentStatesGroup.CurrentStateChanged += ContentAlignmentStates_Changed;
		}

		UpdateContentAlignmentState();
		CheckHeaderIconState();
	}

	// We automatically set the AutomationProperties.Name of the Content if not configured.
	private void SetAccessibleContentName()
	{
		if (Header is string headerString && !string.IsNullOrEmpty(headerString))
		{
			// We don't want to override an AutomationProperties.Name that is manually set, or if the Content basetype is of type ButtonBase (the ButtonBase.Content will be used then)
			if (Content is UIElement element && string.IsNullOrEmpty(AutomationProperties.GetName(element)) && element.GetType().BaseType != typeof(ButtonBase) && element.GetType() != typeof(TextBlock))
			{
				AutomationProperties.SetName(element, headerString);
			}
		}
	}

	private void EnableButtonInteraction()
	{
		DisableButtonInteraction();

		IsTabStop = true;
		PointerEntered += Control_PointerEntered;
		PointerExited += Control_PointerExited;
		PointerCaptureLost += Control_PointerCaptureLost;
		PointerCanceled += Control_PointerCanceled;
		PreviewKeyDown += Control_PreviewKeyDown;
		PreviewKeyUp += Control_PreviewKeyUp;
	}

	private void DisableButtonInteraction()
	{
		IsTabStop = false;
		PointerEntered -= Control_PointerEntered;
		PointerExited -= Control_PointerExited;
		PointerCaptureLost -= Control_PointerCaptureLost;
		PointerCanceled -= Control_PointerCanceled;
		PreviewKeyDown -= Control_PreviewKeyDown;
		PreviewKeyUp -= Control_PreviewKeyUp;
	}

	private void Control_PreviewKeyUp(object sender, KeyRoutedEventArgs e)
	{
		if (e.Key == Windows.System.VirtualKey.Enter || e.Key == Windows.System.VirtualKey.Space || e.Key == Windows.System.VirtualKey.GamepadA)
		{
			_ = VisualStateManager.GoToState(this, NormalState, true);
		}
	}

	private void Control_PreviewKeyDown(object sender, KeyRoutedEventArgs e)
	{
		if (e.Key == Windows.System.VirtualKey.Enter || e.Key == Windows.System.VirtualKey.Space || e.Key == Windows.System.VirtualKey.GamepadA)
		{
			// Check if the active focus is on the card itself - only then we show the pressed state.
			if (GetFocusedElement() is SettingsCard)
			{
				_ = VisualStateManager.GoToState(this, PressedState, true);
			}
		}
	}

	/// <summary>
	/// Handles the PointerEntered event.
	/// </summary>
	public void Control_PointerEntered(object sender, PointerRoutedEventArgs e)
	{
		base.OnPointerEntered(e);
		_ = VisualStateManager.GoToState(this, PointerOverState, true);
	}

	/// <summary>
	/// Handles the PointerExited event.
	/// </summary>
	public void Control_PointerExited(object sender, PointerRoutedEventArgs e)
	{
		base.OnPointerExited(e);
		_ = VisualStateManager.GoToState(this, NormalState, true);
	}

	private void Control_PointerCaptureLost(object sender, PointerRoutedEventArgs e)
	{
		base.OnPointerCaptureLost(e);
		_ = VisualStateManager.GoToState(this, NormalState, true);
	}

	private void Control_PointerCanceled(object sender, PointerRoutedEventArgs e)
	{
		base.OnPointerCanceled(e);
		_ = VisualStateManager.GoToState(this, NormalState, true);
	}

	/// <summary>
	/// Handles the PointerPressed event.
	/// </summary>
	protected override void OnPointerPressed(PointerRoutedEventArgs e)
	{
		if (IsClickEnabled)
		{
			base.OnPointerPressed(e);
			_ = VisualStateManager.GoToState(this, PressedState, true);
		}
	}

	/// <summary>
	/// Handles the PointerReleased event.
	/// </summary>
	protected override void OnPointerReleased(PointerRoutedEventArgs e)
	{
		if (IsClickEnabled)
		{
			base.OnPointerReleased(e);
			_ = VisualStateManager.GoToState(this, NormalState, true);
		}
	}

	/// <summary>
	/// Creates AutomationPeer
	/// </summary>
	/// <returns>An automation peer for <see cref="SettingsCard"/>.</returns>
	protected override AutomationPeer OnCreateAutomationPeer() => new SettingsCardAutomationPeer(this);

	protected override void OnContentChanged(object oldContent, object newContent)
	{
		base.OnContentChanged(oldContent, newContent);
		UpdateContentVisibilityState();
		UpdateContentSpacingState(GetContentAlignmentStateName());
	}

	private void OnIsClickEnabledChanged()
	{
		OnActionIconChanged();
		if (IsClickEnabled)
		{
			EnableButtonInteraction();
		}
		else
		{
			DisableButtonInteraction();
		}
	}

	private void OnIsEnabledChanged(object sender, DependencyPropertyChangedEventArgs e)
	{
		_ = VisualStateManager.GoToState(this, IsEnabled ? NormalState : DisabledState, true);

		CheckHeaderIconState();
	}

	private void CheckHeaderIconState()
	{
		// The Disabled visual state will only set the right Foreground brush, but for images we need to lower the opacity so it looks disabled.

		if (HeaderIcon is BitmapIcon)
		{
			_ = VisualStateManager.GoToState(this, IsEnabled ? BitmapHeaderIconEnabledState : BitmapHeaderIconDisabledState, true);
		}
	}

	private void OnActionIconChanged()
	{
		if (GetTemplateChild(ActionIconPresenterHolder) is FrameworkElement actionIconPresenter)
		{
			actionIconPresenter.Visibility = IsClickEnabled && IsActionIconVisible ? Visibility.Visible : Visibility.Collapsed;
		}
	}

	private void OnHeaderIconChanged()
	{
		if (GetTemplateChild(HeaderIconPresenterHolder) is FrameworkElement headerIconPresenter)
		{
			headerIconPresenter.Visibility = HeaderIcon != null
				? Visibility.Visible
				: Visibility.Collapsed;
		}
	}

	private void OnDescriptionChanged()
	{
		if (GetTemplateChild(DescriptionPresenter) is FrameworkElement descriptionPresenter)
		{
			descriptionPresenter.Visibility = IsNullOrEmptyString(Description)
				? Visibility.Collapsed
				: Visibility.Visible;
		}

		UpdateContentSpacingState(GetContentAlignmentStateName());
	}

	private void OnHeaderChanged()
	{
		if (GetTemplateChild(HeaderPresenter) is FrameworkElement headerPresenter)
		{
			headerPresenter.Visibility = IsNullOrEmptyString(Header)
				? Visibility.Collapsed
				: Visibility.Visible;
		}

		UpdateContentSpacingState(GetContentAlignmentStateName());
	}

	private void ContentAlignmentStates_Changed(object sender, VisualStateChangedEventArgs e)
	{
		string contentAlignmentStateName = e.NewState?.Name ?? string.Empty;
		UpdateContentSpacingState(contentAlignmentStateName);
	}

	private void AttachRootGridSizeChanged() => _rootGrid?.SizeChanged += RootGrid_SizeChanged;

	private void DetachRootGridSizeChanged()
	{
		_rootGrid?.SizeChanged -= RootGrid_SizeChanged;
		_rootGrid = null;
	}

	private void RootGrid_SizeChanged(object sender, SizeChangedEventArgs e) => UpdateContentAlignmentState();

	private void UpdateContentAlignmentState()
	{
		string contentAlignmentState = GetContentAlignmentStateName();

		_ = VisualStateManager.GoToState(this, contentAlignmentState, true);
		UpdateContentSpacingState(contentAlignmentState);
	}

	private string GetContentAlignmentStateName()
	{
		if (ContentAlignment == ContentAlignment.Left)
		{
			return LeftState;
		}

		if (ContentAlignment == ContentAlignment.Vertical)
		{
			return VerticalState;
		}

		return GetRightContentAlignmentState();
	}

	private string GetRightContentAlignmentState()
	{
		double actualWidth = _rootGrid?.ActualWidth ?? ActualWidth;

		if (actualWidth < SettingsCardWrapNoIconThreshold)
		{
			return RightWrappedNoIconState;
		}

		if (actualWidth < SettingsCardWrapThreshold)
		{
			return RightWrappedState;
		}

		return RightState;
	}

	private void UpdateContentVisibilityState()
	{
		string contentVisibilityState = IsNullOrEmpty(Content) ? CollapsedState : VisibleState;
		_ = VisualStateManager.GoToState(this, contentVisibilityState, true);
	}

	private void UpdateContentSpacingState(string contentAlignmentStateName)
	{
		// If the Content and the Header or Description are not null, add spacing between the Content and the Header/Description.
		if (Content is null || (IsNullOrEmptyString(Header) && IsNullOrEmptyString(Description)))
		{
			_ = VisualStateManager.GoToState(this, NoContentSpacingState, true);
			return;
		}

		// Even smaller widths (RightWrappedNoIcon) need a bit more separation between the header text and the now-stacked content.
		if (contentAlignmentStateName == RightWrappedNoIconState)
		{
			_ = VisualStateManager.GoToState(this, ContentSpacingNarrowState, true);
			return;
		}

		if (contentAlignmentStateName == RightWrappedState || contentAlignmentStateName == VerticalState)
		{
			_ = VisualStateManager.GoToState(this, ContentSpacingState, true);
			return;
		}

		_ = VisualStateManager.GoToState(this, NoContentSpacingState, true);
	}

	private VisualStateGroup? GetRootGridVisualStateGroup(string groupName)
	{
		if (_rootGrid is null)
		{
			return null;
		}

		IEnumerable visualStateGroups = VisualStateManager.GetVisualStateGroups(_rootGrid);
		foreach (object visualStateGroupObject in visualStateGroups)
		{
			if (visualStateGroupObject is VisualStateGroup visualStateGroup && visualStateGroup.Name == groupName)
			{
				return visualStateGroup;
			}
		}

		return null;
	}

	private FrameworkElement? GetFocusedElement() => XamlRoot != null
			? FocusManager.GetFocusedElement(XamlRoot) as FrameworkElement
			: FocusManager.GetFocusedElement() as FrameworkElement;

	private static bool IsNullOrEmptyString(object obj)
	{
		if (obj == null)
		{
			return true;
		}

		if (obj is string objString && string.IsNullOrEmpty(objString))
		{
			return true;
		}

		return false;
	}

	private static bool IsNullOrEmpty(object obj)
	{
		if (obj == null)
		{
			return true;
		}

		// Object is not null, check for an empty string
		if (obj is string objString)
		{
			return objString.Length == 0;
		}

		// Object is not a string, check for an empty ICollection (faster)
		if (obj is ICollection objCollection)
		{
			return objCollection.Count == 0;
		}
		// Object is not an ICollection, check for an empty IEnumerable
		if (obj is IEnumerable objEnumerable)
		{
			IEnumerator enumerator = objEnumerable.GetEnumerator();

			try
			{
				if (enumerator.MoveNext())
				{
					_ = enumerator.Current;

					// Found an item, not empty
					return false;
				}
			}
			finally
			{
				if (enumerator is IDisposable disposable)
				{
					disposable.Dispose();
				}
			}

			return true;
		}

		// Not null and not a known type to test for emptiness
		return false;
	}
}

internal partial class SettingsCard : ButtonBase
{
	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="Header"/> property.
	/// </summary>
	public static readonly DependencyProperty HeaderProperty = DependencyProperty.Register(
		nameof(Header),
		typeof(object),
		typeof(SettingsCard),
		new PropertyMetadata(defaultValue: null, (d, e) => ((SettingsCard)d).OnHeaderPropertyChanged(e.OldValue, e.NewValue)));

	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="Description"/> property.
	/// </summary>
	public static readonly DependencyProperty DescriptionProperty = DependencyProperty.Register(
		nameof(Description),
		typeof(object),
		typeof(SettingsCard),
		new PropertyMetadata(defaultValue: null, (d, e) => ((SettingsCard)d).OnDescriptionPropertyChanged(e.OldValue, e.NewValue)));

	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="HeaderIcon"/> property.
	/// </summary>
	public static readonly DependencyProperty HeaderIconProperty = DependencyProperty.Register(
		nameof(HeaderIcon),
		typeof(IconElement),
		typeof(SettingsCard),
		new PropertyMetadata(defaultValue: null, (d, e) => ((SettingsCard)d).OnHeaderIconPropertyChanged((IconElement)e.OldValue, (IconElement)e.NewValue)));

	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="ActionIcon"/> property.
	/// </summary>
	public static readonly DependencyProperty ActionIconProperty = DependencyProperty.Register(
		nameof(ActionIcon),
		typeof(IconElement),
		typeof(SettingsCard),
		new PropertyMetadata(defaultValue: "\ue974"));

	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="ActionIconToolTip"/> property.
	/// </summary>
	public static readonly DependencyProperty ActionIconToolTipProperty = DependencyProperty.Register(
		nameof(ActionIconToolTip),
		typeof(string),
		typeof(SettingsCard),
		new PropertyMetadata(defaultValue: null));

	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="IsClickEnabled"/> property.
	/// </summary>
	public static readonly DependencyProperty IsClickEnabledProperty = DependencyProperty.Register(
		nameof(IsClickEnabled),
		typeof(bool),
		typeof(SettingsCard),
		new PropertyMetadata(defaultValue: false, (d, e) => ((SettingsCard)d).OnIsClickEnabledPropertyChanged((bool)e.OldValue, (bool)e.NewValue)));

	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="ContentAlignment"/> property.
	/// </summary>
	public static readonly DependencyProperty ContentAlignmentProperty = DependencyProperty.Register(
		nameof(ContentAlignment),
		typeof(ContentAlignment),
		typeof(SettingsCard),
		new PropertyMetadata(defaultValue: ContentAlignment.Right, (d, e) => ((SettingsCard)d).OnContentAlignmentPropertyChanged((ContentAlignment)e.OldValue, (ContentAlignment)e.NewValue)));

	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="IsActionIconVisible"/> property.
	/// </summary>
	public static readonly DependencyProperty IsActionIconVisibleProperty = DependencyProperty.Register(
		nameof(IsActionIconVisible),
		typeof(bool),
		typeof(SettingsCard),
		new PropertyMetadata(defaultValue: true, (d, e) => ((SettingsCard)d).OnIsActionIconVisiblePropertyChanged((bool)e.OldValue, (bool)e.NewValue)));

	/// <summary>
	/// Gets or sets the Header.
	/// </summary>
	public object Header
	{
		get => GetValue(HeaderProperty);
		set => SetValue(HeaderProperty, value);
	}

	/// <summary>
	/// Gets or sets the description.
	/// </summary>
#pragma warning disable CS0109 // Member does not hide an inherited member; new keyword is not required
	public new object Description
#pragma warning restore CS0109 // Member does not hide an inherited member; new keyword is not required
	{
		get => GetValue(DescriptionProperty);
		set => SetValue(DescriptionProperty, value);
	}

	/// <summary>
	/// Gets or sets the icon on the left.
	/// </summary>
	public IconElement HeaderIcon
	{
		get => (IconElement)GetValue(HeaderIconProperty);
		set => SetValue(HeaderIconProperty, value);
	}

	/// <summary>
	/// Gets or sets the icon that is shown when IsClickEnabled is set to true.
	/// </summary>
	public IconElement ActionIcon
	{
		get => (IconElement)GetValue(ActionIconProperty);
		set => SetValue(ActionIconProperty, value);
	}

	/// <summary>
	/// Gets or sets the tooltip of the ActionIcon.
	/// </summary>
	public string ActionIconToolTip
	{
		get => (string)GetValue(ActionIconToolTipProperty);
		set => SetValue(ActionIconToolTipProperty, value);
	}

	/// <summary>
	/// Gets or sets if the card can be clicked.
	/// </summary>
	public bool IsClickEnabled
	{
		get => (bool)GetValue(IsClickEnabledProperty);
		set => SetValue(IsClickEnabledProperty, value);
	}

	/// <summary>
	/// Gets or sets the alignment of the Content
	/// </summary>
	public ContentAlignment ContentAlignment
	{
		get => (ContentAlignment)GetValue(ContentAlignmentProperty);
		set => SetValue(ContentAlignmentProperty, value);
	}

	/// <summary>
	/// Gets or sets if the ActionIcon is shown.
	/// </summary>
	public bool IsActionIconVisible
	{
		get => (bool)GetValue(IsActionIconVisibleProperty);
		set => SetValue(IsActionIconVisibleProperty, value);
	}

	/// <summary>
	/// Called when the IsClickEnabled property changes.
	/// </summary>
	protected virtual void OnIsClickEnabledPropertyChanged(bool oldValue, bool newValue) => OnIsClickEnabledChanged();

	/// <summary>
	/// Called when the HeaderIcon property changes.
	/// </summary>
	protected virtual void OnHeaderIconPropertyChanged(IconElement oldValue, IconElement newValue) => OnHeaderIconChanged();

	/// <summary>
	/// Called when the Header property changes.
	/// </summary>
	protected virtual void OnHeaderPropertyChanged(object oldValue, object newValue) => OnHeaderChanged();

	/// <summary>
	/// Called when the Description property changes.
	/// </summary>
	protected virtual void OnDescriptionPropertyChanged(object oldValue, object newValue) => OnDescriptionChanged();

	/// <summary>
	/// Called when the IsActionIconVisible property changes.
	/// </summary>
	protected virtual void OnIsActionIconVisiblePropertyChanged(bool oldValue, bool newValue) => OnActionIconChanged();

	/// <summary>
	/// Called when the ContentAlignment property changes.
	/// </summary>
	protected virtual void OnContentAlignmentPropertyChanged(ContentAlignment oldValue, ContentAlignment newValue) => UpdateContentAlignmentState();
}

/// <summary>
/// The alignment of Content.
/// </summary>
internal enum ContentAlignment
{
	/// <summary>
	/// The Content is aligned to the right. Default state.
	/// </summary>
	Right,

	/// <summary>
	/// The Content is left-aligned while the Header, HeaderIcon and Description are collapsed. This is commonly used for Content types such as CheckBoxes, RadioButtons and custom layouts.
	/// </summary>
	Left,

	/// <summary>
	/// The Content is vertically aligned.
	/// </summary>
	Vertical
}

/// <summary>
/// AutomationPeer for SettingsCard
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="SettingsCard"/> class.
/// </remarks>
/// <param name="owner">SettingsCard</param>
internal sealed partial class SettingsCardAutomationPeer(SettingsCard owner) : ButtonBaseAutomationPeer(owner)
{
	/// <summary>
	/// Gets the control type for the element that is associated with the UI Automation peer.
	/// </summary>
	/// <returns>The control type.</returns>
	protected override AutomationControlType GetAutomationControlTypeCore() => Owner is SettingsCard { IsClickEnabled: true }
			? AutomationControlType.Button
			: AutomationControlType.Group;

	/// <summary>
	/// Called by GetClassName that gets a human readable name that, in addition to AutomationControlType,
	/// differentiates the control represented by this AutomationPeer.
	/// </summary>
	/// <returns>The string that contains the name.</returns>
	protected override string GetClassNameCore() => Owner.GetType().Name;

	protected override string GetNameCore()
	{
		// We only want to announce the button card name if it is clickable, else it's just a regular card that does not receive focus
		if (Owner is SettingsCard owner && owner.IsClickEnabled)
		{
			string name = AutomationProperties.GetName(owner);
			if (!string.IsNullOrEmpty(name))
			{
				return name;
			}
			else
			{
				if (owner.Header is string headerString && !string.IsNullOrEmpty(headerString))
				{
					return headerString;
				}
			}
		}

		return base.GetNameCore();
	}

	protected override object? GetPatternCore(PatternInterface patternInterface) =>
		 patternInterface == PatternInterface.Invoke
			? Owner is SettingsCard { IsClickEnabled: true }
				// Only provide Invoke pattern if the card is clickable
				? this
				// Not clickable, do not provide Invoke pattern
				: null
			: base.GetPatternCore(patternInterface);
}
