// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// Source: https://github.com/CommunityToolkit/Windows/tree/main/components/SettingsControls/src
// License: https://github.com/CommunityToolkit/Windows/blob/main/License.md
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

using System.Collections.Generic;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media.Animation;

#pragma warning disable CA1515, CA1062, CA2227, CA1030

namespace CommonCore.ToolKits;

internal static class ResourceDictionaryExtensions
{
	internal static void CopyFrom(this ResourceDictionary destination, ResourceDictionary source)
	{
		if (source.Source != null)
		{
			destination.Source = source.Source;
		}
		else
		{
			if (source.ThemeDictionaries != null)
			{
				foreach (KeyValuePair<object, object> theme in source.ThemeDictionaries)
				{
					if (theme.Value is ResourceDictionary themedResource)
					{
						ResourceDictionary themeDictionary = new();
						themeDictionary.CopyFrom(themedResource);
						destination.ThemeDictionaries[theme.Key] = themeDictionary;
					}
					else
					{
						destination.ThemeDictionaries[theme.Key] = theme.Value;
					}
				}
			}

			if (source.MergedDictionaries != null)
			{
				foreach (ResourceDictionary mergedResource in source.MergedDictionaries)
				{
					ResourceDictionary themeDictionary = new();
					themeDictionary.CopyFrom(mergedResource);
					destination.MergedDictionaries.Add(themeDictionary);
				}
			}

			foreach (KeyValuePair<object, object> item in source)
			{
				destination[item.Key] = item.Value;
			}
		}
	}
}

public static partial class StyleExtensions
{
	private sealed partial class StyleExtensionResourceDictionary : ResourceDictionary
	{
	}

	public static ResourceDictionary? GetResources(Style obj)
	{
		return (ResourceDictionary?)obj.GetValue(ResourcesProperty);
	}

	public static void SetResources(Style obj, ResourceDictionary? value)
	{
		obj.SetValue(ResourcesProperty, value);
	}

	public static readonly DependencyProperty ResourcesProperty = DependencyProperty.RegisterAttached(
		"Resources",
		typeof(ResourceDictionary),
		typeof(StyleExtensions),
		new PropertyMetadata(null, ResourcesChanged));

	private static void ResourcesChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e)
	{
		if (sender is not FrameworkElement frameworkElement)
		{
			return;
		}

		IList<ResourceDictionary>? mergedDictionaries = frameworkElement.Resources?.MergedDictionaries;
		if (mergedDictionaries == null)
		{
			return;
		}

		ResourceDictionary? existingResourceDictionary = mergedDictionaries.FirstOrDefault(c => c is StyleExtensionResourceDictionary);
		if (existingResourceDictionary != null)
		{
			_ = mergedDictionaries.Remove(existingResourceDictionary);
		}

		if (e.NewValue is ResourceDictionary resource)
		{
			StyleExtensionResourceDictionary clonedResources = new();
			clonedResources.CopyFrom(resource);
			mergedDictionaries.Add(clonedResources);
		}

		if (frameworkElement.IsLoaded)
		{
			ForceControlToReloadThemeResources(frameworkElement);
		}
	}

	private static void ForceControlToReloadThemeResources(FrameworkElement frameworkElement)
	{
		ElementTheme currentRequestedTheme = frameworkElement.RequestedTheme;
		frameworkElement.RequestedTheme = currentRequestedTheme == ElementTheme.Dark ? ElementTheme.Light : ElementTheme.Dark;
		frameworkElement.RequestedTheme = currentRequestedTheme;
	}
}

public enum ContentAlignment
{
	Right,
	Left,
	Vertical
}

public partial class SettingsCardAutomationPeer(SettingsCard owner) : ButtonBaseAutomationPeer(owner)
{
	protected override AutomationControlType GetAutomationControlTypeCore()
	{
		if (Owner is SettingsCard settingsCard && settingsCard.IsClickEnabled)
		{
			return AutomationControlType.Button;
		}

		return AutomationControlType.Group;
	}

	protected override string GetClassNameCore() => Owner.GetType().Name;

	protected override string GetNameCore()
	{
		if (Owner is SettingsCard owner && owner.IsClickEnabled)
		{
			string name = AutomationProperties.GetName(owner);
			if (!string.IsNullOrEmpty(name))
			{
				return name;
			}

			if (owner.Header is string headerString && !string.IsNullOrEmpty(headerString))
			{
				return headerString;
			}
		}

		return base.GetNameCore();
	}

	protected override object? GetPatternCore(PatternInterface patternInterface)
	{
		if (patternInterface == PatternInterface.Invoke)
		{
			if (Owner is SettingsCard settingsCard && settingsCard.IsClickEnabled)
			{
				return this;
			}

			return null;
		}

		return base.GetPatternCore(patternInterface);
	}
}

[TemplatePart(Name = ActionIconPresenterHolder, Type = typeof(Viewbox))]
[TemplatePart(Name = HeaderPresenter, Type = typeof(ContentPresenter))]
[TemplatePart(Name = DescriptionPresenter, Type = typeof(ContentPresenter))]
[TemplatePart(Name = HeaderIconPresenterHolder, Type = typeof(Viewbox))]
[TemplatePart(Name = "PART_RootGrid", Type = typeof(Grid))]
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
public partial class SettingsCard : ButtonBase
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

	internal const string ActionIconPresenterHolder = "PART_ActionIconPresenterHolder";
	internal const string HeaderPresenter = "PART_HeaderPresenter";
	internal const string DescriptionPresenter = "PART_DescriptionPresenter";
	internal const string HeaderIconPresenterHolder = "PART_HeaderIconPresenterHolder";

	private Grid? _rootGrid;

	public static readonly DependencyProperty HeaderProperty = DependencyProperty.Register(
		nameof(Header), typeof(object), typeof(SettingsCard), new PropertyMetadata(null, (d, e) => ((SettingsCard)d).OnHeaderPropertyChanged(e.OldValue, e.NewValue)));

	public static readonly DependencyProperty DescriptionProperty = DependencyProperty.Register(
		nameof(Description), typeof(object), typeof(SettingsCard), new PropertyMetadata(null, (d, e) => ((SettingsCard)d).OnDescriptionPropertyChanged(e.OldValue, e.NewValue)));

	public static readonly DependencyProperty HeaderIconProperty = DependencyProperty.Register(
		nameof(HeaderIcon), typeof(IconElement), typeof(SettingsCard), new PropertyMetadata(null, (d, e) => ((SettingsCard)d).OnHeaderIconPropertyChanged((IconElement?)e.OldValue, (IconElement?)e.NewValue)));

	public static readonly DependencyProperty ActionIconProperty = DependencyProperty.Register(
		nameof(ActionIcon), typeof(IconElement), typeof(SettingsCard), new PropertyMetadata("\ue974"));

	public static readonly DependencyProperty ActionIconToolTipProperty = DependencyProperty.Register(
		nameof(ActionIconToolTip), typeof(string), typeof(SettingsCard), new PropertyMetadata(null));

	public static readonly DependencyProperty IsClickEnabledProperty = DependencyProperty.Register(
		nameof(IsClickEnabled), typeof(bool), typeof(SettingsCard), new PropertyMetadata(false, (d, e) => ((SettingsCard)d).OnIsClickEnabledPropertyChanged((bool)e.OldValue, (bool)e.NewValue)));

	public static readonly DependencyProperty ContentAlignmentProperty = DependencyProperty.Register(
		nameof(ContentAlignment), typeof(ContentAlignment), typeof(SettingsCard), new PropertyMetadata(ContentAlignment.Right, (d, e) => ((SettingsCard)d).UpdateContentAlignmentState()));

	public static readonly DependencyProperty IsActionIconVisibleProperty = DependencyProperty.Register(
		nameof(IsActionIconVisible), typeof(bool), typeof(SettingsCard), new PropertyMetadata(true, (d, e) => ((SettingsCard)d).OnIsActionIconVisiblePropertyChanged((bool)e.OldValue, (bool)e.NewValue)));

	public object? Header
	{
		get => GetValue(HeaderProperty);
		set => SetValue(HeaderProperty, value);
	}

	public object? Description
	{
		get => GetValue(DescriptionProperty);
		set => SetValue(DescriptionProperty, value);
	}

	public IconElement? HeaderIcon
	{
		get => (IconElement?)GetValue(HeaderIconProperty);
		set => SetValue(HeaderIconProperty, value);
	}

	public IconElement? ActionIcon
	{
		get => (IconElement?)GetValue(ActionIconProperty);
		set => SetValue(ActionIconProperty, value);
	}

	public string? ActionIconToolTip
	{
		get => (string?)GetValue(ActionIconToolTipProperty);
		set => SetValue(ActionIconToolTipProperty, value);
	}

	public bool IsClickEnabled
	{
		get => (bool)GetValue(IsClickEnabledProperty);
		set => SetValue(IsClickEnabledProperty, value);
	}

	public ContentAlignment ContentAlignment
	{
		get => (ContentAlignment)GetValue(ContentAlignmentProperty);
		set => SetValue(ContentAlignmentProperty, value);
	}

	public bool IsActionIconVisible
	{
		get => (bool)GetValue(IsActionIconVisibleProperty);
		set => SetValue(IsActionIconVisibleProperty, value);
	}

	public SettingsCard() => DefaultStyleKey = typeof(SettingsCard);

	protected override void OnApplyTemplate()
	{
		base.OnApplyTemplate();

		_rootGrid?.SizeChanged -= OnRootGridSizeChanged;

		_rootGrid = GetTemplateChild("PART_RootGrid") as Grid;

		_rootGrid?.SizeChanged += OnRootGridSizeChanged;

		IsEnabledChanged -= OnIsEnabledChanged;
		OnActionIconChanged();
		OnHeaderChanged();
		OnHeaderIconChanged();
		OnDescriptionChanged();
		OnIsClickEnabledChanged();

		UpdateContentAlignmentState();
		UpdateContentVisibilityState();
		CheckHeaderIconState();

		SetAccessibleContentName();
		_ = RegisterPropertyChangedCallback(ContentProperty, OnContentChanged);
		IsEnabledChanged += OnIsEnabledChanged;

		_ = VisualStateManager.GoToState(this, IsEnabled ? NormalState : DisabledState, true);
	}

	private void OnRootGridSizeChanged(object sender, SizeChangedEventArgs e) => UpdateContentAlignmentState();

	private void UpdateContentAlignmentState()
	{
		if (_rootGrid == null)
		{
			return;
		}

		if (ContentAlignment == ContentAlignment.Left)
		{
			_ = VisualStateManager.GoToState(this, LeftState, true);
		}
		else if (ContentAlignment == ContentAlignment.Vertical)
		{
			_ = VisualStateManager.GoToState(this, VerticalState, true);
		}
		else
		{
			double width = _rootGrid.ActualWidth;
			double wrapThreshold = Application.Current.Resources.TryGetValue("SettingsCardWrapThreshold", out object? wtObj) && wtObj is double wt ? wt : 476.0;
			double wrapNoIconThreshold = Application.Current.Resources.TryGetValue("SettingsCardWrapNoIconThreshold", out object? wntObj) && wntObj is double wnt ? wnt : 286.0;

			_ = width <= wrapNoIconThreshold
				? VisualStateManager.GoToState(this, RightWrappedNoIconState, true)
				: width <= wrapThreshold
					? VisualStateManager.GoToState(this, RightWrappedState, true)
					: VisualStateManager.GoToState(this, RightState, true);
		}

		CheckVerticalSpacingState();
	}

	private void CheckVerticalSpacingState()
	{
		bool needsSpacing = ContentAlignment == ContentAlignment.Vertical ||
							(ContentAlignment == ContentAlignment.Right && _rootGrid != null && _rootGrid.ActualWidth <= 476.0);

		_ = needsSpacing && Content != null && (!IsNullOrEmptyString(Header) || !IsNullOrEmptyString(Description))
			? VisualStateManager.GoToState(this, ContentSpacingState, true)
			: VisualStateManager.GoToState(this, NoContentSpacingState, true);
	}

	private void UpdateContentVisibilityState()
	{
		bool isNullOrEmpty = false;
		if (Content == null)
		{
			isNullOrEmpty = true;
		}
		else if (Content is string str)
		{
			isNullOrEmpty = string.IsNullOrWhiteSpace(str);
		}
		else if (Content is System.Collections.IEnumerable enumerable)
		{
			System.Collections.IEnumerator enumerator = enumerable.GetEnumerator();
			isNullOrEmpty = !enumerator.MoveNext();
			if (enumerator is IDisposable disposable)
			{
				disposable.Dispose();
			}
		}

		_ = VisualStateManager.GoToState(this, isNullOrEmpty ? "Collapsed" : "Visible", true);
	}

	private void OnContentChanged(DependencyObject sender, DependencyProperty dp)
	{
		SetAccessibleContentName();
		UpdateContentVisibilityState();
		CheckVerticalSpacingState();
	}

	private void SetAccessibleContentName()
	{
		if (Header is string headerString && !string.IsNullOrEmpty(headerString))
		{
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
			if (GetFocusedElement() is SettingsCard)
			{
				_ = VisualStateManager.GoToState(this, PressedState, true);
			}
		}
	}

	public void Control_PointerEntered(object sender, PointerRoutedEventArgs e)
	{
		base.OnPointerEntered(e);
		_ = VisualStateManager.GoToState(this, PointerOverState, true);
	}

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

	protected override void OnPointerPressed(PointerRoutedEventArgs e)
	{
		if (IsClickEnabled)
		{
			base.OnPointerPressed(e);
			_ = VisualStateManager.GoToState(this, PressedState, true);
		}
	}

	protected override void OnPointerReleased(PointerRoutedEventArgs e)
	{
		if (IsClickEnabled)
		{
			base.OnPointerReleased(e);
			_ = VisualStateManager.GoToState(this, NormalState, true);
		}
	}

	protected override AutomationPeer OnCreateAutomationPeer() => new SettingsCardAutomationPeer(this);

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
			headerIconPresenter.Visibility = HeaderIcon != null ? Visibility.Visible : Visibility.Collapsed;
		}
	}

	private void OnDescriptionChanged()
	{
		if (GetTemplateChild(DescriptionPresenter) is FrameworkElement descriptionPresenter)
		{
			descriptionPresenter.Visibility = IsNullOrEmptyString(Description) ? Visibility.Collapsed : Visibility.Visible;
		}
		CheckVerticalSpacingState();
	}

	private void OnHeaderChanged()
	{
		if (GetTemplateChild(HeaderPresenter) is FrameworkElement headerPresenter)
		{
			headerPresenter.Visibility = IsNullOrEmptyString(Header) ? Visibility.Collapsed : Visibility.Visible;
		}
		CheckVerticalSpacingState();
	}

	private FrameworkElement? GetFocusedElement()
	{
		if (XamlRoot != null)
		{
			return FocusManager.GetFocusedElement(XamlRoot) as FrameworkElement;
		}

		return FocusManager.GetFocusedElement() as FrameworkElement;
	}

	private static bool IsNullOrEmptyString(object? obj)
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

	protected virtual void OnIsClickEnabledPropertyChanged(bool oldValue, bool newValue) => OnIsClickEnabledChanged();

	protected virtual void OnHeaderIconPropertyChanged(IconElement? oldValue, IconElement? newValue) => OnHeaderIconChanged();

	protected virtual void OnHeaderPropertyChanged(object? oldValue, object? newValue) => OnHeaderChanged();

	protected virtual void OnDescriptionPropertyChanged(object? oldValue, object? newValue) => OnDescriptionChanged();

	protected virtual void OnIsActionIconVisiblePropertyChanged(bool oldValue, bool newValue) => OnActionIconChanged();
}

public partial class SettingsExpanderItemStyleSelector : StyleSelector
{
	public Style DefaultStyle { get; set; } = new Style(typeof(SettingsCard));
	public Style ClickableStyle { get; set; } = new Style(typeof(SettingsCard));

	public SettingsExpanderItemStyleSelector()
	{
	}

	protected override Style SelectStyleCore(object item, DependencyObject container)
	{
		if (container is SettingsCard card && card.IsClickEnabled)
		{
			return ClickableStyle;
		}

		return DefaultStyle;
	}
}

public partial class SettingsExpanderAutomationPeer(SettingsExpander owner) : FrameworkElementAutomationPeer(owner)
{
	protected override AutomationControlType GetAutomationControlTypeCore() => AutomationControlType.Group;

	protected override string GetClassNameCore() => Owner.GetType().Name;

	protected override string GetNameCore()
	{
		string name = base.GetNameCore();

		if (Owner is SettingsExpander owner)
		{
			if (!string.IsNullOrEmpty(AutomationProperties.GetName(owner)))
			{
				name = AutomationProperties.GetName(owner);
			}
			else
			{
				if (owner.Header is string headerString && !string.IsNullOrEmpty(headerString))
				{
					name = headerString;
				}
			}
		}
		return name;
	}

	public void RaiseExpandedChangedEvent(bool newValue)
	{
		ExpandCollapseState newState = newValue ? ExpandCollapseState.Expanded : ExpandCollapseState.Collapsed;
		ExpandCollapseState oldState = newState == ExpandCollapseState.Expanded ? ExpandCollapseState.Collapsed : ExpandCollapseState.Expanded;

		RaisePropertyChangedEvent(ExpandCollapsePatternIdentifiers.ExpandCollapseStateProperty, oldState, newState);
	}
}

[TemplatePart(Name = "RootGrid", Type = typeof(Grid))]
[TemplatePart(Name = "ExpanderContent", Type = typeof(FrameworkElement))]
internal sealed partial class SettingsExpanderInner : Expander
{
	public static readonly DependencyProperty ContentHeightProperty = DependencyProperty.Register(
		nameof(ContentHeight), typeof(double), typeof(SettingsExpanderInner), new PropertyMetadata(0.0));

	public static readonly DependencyProperty NegativeContentHeightProperty = DependencyProperty.Register(
		nameof(NegativeContentHeight), typeof(double), typeof(SettingsExpanderInner), new PropertyMetadata(0.0));

	public static readonly DependencyProperty TopCornerRadiusProperty = DependencyProperty.Register(
		nameof(TopCornerRadius), typeof(CornerRadius), typeof(SettingsExpanderInner), new PropertyMetadata(default(CornerRadius)));

	public static readonly DependencyProperty BottomCornerRadiusProperty = DependencyProperty.Register(
		nameof(BottomCornerRadius), typeof(CornerRadius), typeof(SettingsExpanderInner), new PropertyMetadata(default(CornerRadius)));

	public double ContentHeight
	{
		get => (double)GetValue(ContentHeightProperty);
		set => SetValue(ContentHeightProperty, value);
	}

	public double NegativeContentHeight
	{
		get => (double)GetValue(NegativeContentHeightProperty);
		set => SetValue(NegativeContentHeightProperty, value);
	}

	public CornerRadius TopCornerRadius
	{
		get => (CornerRadius)GetValue(TopCornerRadiusProperty);
		set => SetValue(TopCornerRadiusProperty, value);
	}

	public CornerRadius BottomCornerRadius
	{
		get => (CornerRadius)GetValue(BottomCornerRadiusProperty);
		set => SetValue(BottomCornerRadiusProperty, value);
	}

	public SettingsExpanderInner()
	{
		DefaultStyleKey = typeof(SettingsExpanderInner);

		_ = RegisterPropertyChangedCallback(CornerRadiusProperty, (s, e) =>
		{
			CornerRadius cr = CornerRadius;
			TopCornerRadius = new CornerRadius(cr.TopLeft, cr.TopRight, 0, 0);
			BottomCornerRadius = new CornerRadius(0, 0, cr.BottomRight, cr.BottomLeft);
		});
	}

	protected override void OnApplyTemplate()
	{
		base.OnApplyTemplate();

		if (GetTemplateChild("ExpanderContent") is FrameworkElement expanderContent)
		{
			expanderContent.SizeChanged += (s, e) =>
			{
				ContentHeight = e.NewSize.Height;
				NegativeContentHeight = -e.NewSize.Height;

				// Directly updating the animation keyframes here for Native AOT compatibility
				UpdateAnimationKeyFrames();
			};
		}
	}

	private void UpdateAnimationKeyFrames()
	{
		if (GetTemplateChild("RootGrid") is FrameworkElement rootGrid)
		{
			IList<VisualStateGroup>? groups = VisualStateManager.GetVisualStateGroups(rootGrid);
			if (groups != null)
			{
				VisualStateGroup? expandStates = groups.FirstOrDefault(g => g.Name == "ExpandStates");
				if (expandStates != null)
				{
					// Update the specific keyframes in the 4 visual states
					UpdateKeyFrame(expandStates, "ExpandUp", ContentHeight, isStartFrame: true);
					UpdateKeyFrame(expandStates, "CollapseDown", ContentHeight, isStartFrame: false);
					UpdateKeyFrame(expandStates, "ExpandDown", NegativeContentHeight, isStartFrame: true);
					UpdateKeyFrame(expandStates, "CollapseUp", NegativeContentHeight, isStartFrame: false);
				}
			}
		}
	}

	private static void UpdateKeyFrame(VisualStateGroup group, string stateName, double value, bool isStartFrame)
	{
		VisualState? state = group.States.FirstOrDefault(s => s.Name == stateName);
		if (state?.Storyboard != null)
		{
			DoubleAnimationUsingKeyFrames? anim = state.Storyboard.Children.OfType<DoubleAnimationUsingKeyFrames>().FirstOrDefault();
			if (anim != null)
			{
				if (isStartFrame && anim.KeyFrames.Count > 0)
				{
					if (anim.KeyFrames[0] is DiscreteDoubleKeyFrame ddk)
					{
						ddk.Value = value;
					}
				}
				else if (!isStartFrame && anim.KeyFrames.Count > 1)
				{
					if (anim.KeyFrames[1] is SplineDoubleKeyFrame sdk)
					{
						sdk.Value = value;
					}
				}
			}
		}
	}
}

[TemplatePart(Name = PART_ItemsRepeater, Type = typeof(ItemsRepeater))]
[TemplatePart(Name = PART_Expander, Type = typeof(SettingsExpanderInner))]
[ContentProperty(Name = nameof(Content))]
public partial class SettingsExpander : Control
{
	private const string PART_ItemsRepeater = "PART_ItemsRepeater";
	private const string PART_Expander = "PART_Expander";
	private ItemsRepeater? _itemsRepeater;
	private SettingsExpanderInner? _expander;

	public event EventHandler? Expanded;
	public event EventHandler? Collapsed;

	public static readonly DependencyProperty ItemsProperty = DependencyProperty.Register(
		nameof(Items), typeof(IList<object>), typeof(SettingsExpander), new PropertyMetadata(null, OnItemsConnectedPropertyChanged));

	public static readonly DependencyProperty ItemsSourceProperty = DependencyProperty.Register(
		nameof(ItemsSource), typeof(object), typeof(SettingsExpander), new PropertyMetadata(null, OnItemsConnectedPropertyChanged));

	public static readonly DependencyProperty ItemTemplateProperty = DependencyProperty.Register(
		nameof(ItemTemplate), typeof(object), typeof(SettingsExpander), new PropertyMetadata(null));

	public static readonly DependencyProperty ItemContainerStyleSelectorProperty = DependencyProperty.Register(
		nameof(ItemContainerStyleSelector), typeof(StyleSelector), typeof(SettingsExpander), new PropertyMetadata(null));

	public static readonly DependencyProperty HeaderProperty = DependencyProperty.Register(
		nameof(Header), typeof(object), typeof(SettingsExpander), new PropertyMetadata(null));

	public static readonly DependencyProperty DescriptionProperty = DependencyProperty.Register(
		nameof(Description), typeof(object), typeof(SettingsExpander), new PropertyMetadata(null));

	public static readonly DependencyProperty HeaderIconProperty = DependencyProperty.Register(
		nameof(HeaderIcon), typeof(IconElement), typeof(SettingsExpander), new PropertyMetadata(null));

	public static readonly DependencyProperty ContentProperty = DependencyProperty.Register(
		nameof(Content), typeof(object), typeof(SettingsExpander), new PropertyMetadata(null));

	public static readonly DependencyProperty ItemsHeaderProperty = DependencyProperty.Register(
		nameof(ItemsHeader), typeof(UIElement), typeof(SettingsExpander), new PropertyMetadata(null));

	public static readonly DependencyProperty ItemsFooterProperty = DependencyProperty.Register(
		nameof(ItemsFooter), typeof(UIElement), typeof(SettingsExpander), new PropertyMetadata(null));

	public static readonly DependencyProperty IsExpandedProperty = DependencyProperty.Register(
		nameof(IsExpanded), typeof(bool), typeof(SettingsExpander), new PropertyMetadata(false, (d, e) => ((SettingsExpander)d).OnIsExpandedPropertyChanged((bool)e.OldValue, (bool)e.NewValue)));

	public static readonly DependencyProperty InnerCornerRadiusProperty = DependencyProperty.Register(
		nameof(InnerCornerRadius), typeof(CornerRadius), typeof(SettingsExpander), new PropertyMetadata(default(CornerRadius)));

	public IList<object>? Items
	{
		get => (IList<object>?)GetValue(ItemsProperty);
		set => SetValue(ItemsProperty, value);
	}

	public object? ItemsSource
	{
		get => GetValue(ItemsSourceProperty);
		set => SetValue(ItemsSourceProperty, value);
	}

	public object? ItemTemplate
	{
		get => GetValue(ItemTemplateProperty);
		set => SetValue(ItemTemplateProperty, value);
	}

	public StyleSelector? ItemContainerStyleSelector
	{
		get => (StyleSelector?)GetValue(ItemContainerStyleSelectorProperty);
		set => SetValue(ItemContainerStyleSelectorProperty, value);
	}

	public object? Header
	{
		get => GetValue(HeaderProperty);
		set => SetValue(HeaderProperty, value);
	}

	public object? Description
	{
		get => GetValue(DescriptionProperty);
		set => SetValue(DescriptionProperty, value);
	}

	public IconElement? HeaderIcon
	{
		get => (IconElement?)GetValue(HeaderIconProperty);
		set => SetValue(HeaderIconProperty, value);
	}

	public object? Content
	{
		get => GetValue(ContentProperty);
		set => SetValue(ContentProperty, value);
	}

	public UIElement? ItemsHeader
	{
		get => (UIElement?)GetValue(ItemsHeaderProperty);
		set => SetValue(ItemsHeaderProperty, value);
	}

	public UIElement? ItemsFooter
	{
		get => (UIElement?)GetValue(ItemsFooterProperty);
		set => SetValue(ItemsFooterProperty, value);
	}

	public bool IsExpanded
	{
		get => (bool)GetValue(IsExpandedProperty);
		set => SetValue(IsExpandedProperty, value);
	}

	public CornerRadius InnerCornerRadius
	{
		get => (CornerRadius)GetValue(InnerCornerRadiusProperty);
		set => SetValue(InnerCornerRadiusProperty, value);
	}

	public SettingsExpander()
	{
		DefaultStyleKey = typeof(SettingsExpander);
		Items = new List<object>();

		_ = RegisterPropertyChangedCallback(CornerRadiusProperty, (s, e) =>
		{
			CornerRadius cr = CornerRadius;
			InnerCornerRadius = new CornerRadius(0, 0, cr.BottomRight, cr.BottomLeft);
		});
	}

	protected override void OnApplyTemplate()
	{
		base.OnApplyTemplate();
		SetAccessibleName();

		_itemsRepeater?.ElementPrepared -= ItemsRepeater_ElementPrepared;

		if (_expander != null)
		{
			_expander.Expanding -= Expander_Expanding;
			_expander.Collapsed -= Expander_Collapsed;
		}

		_itemsRepeater = GetTemplateChild(PART_ItemsRepeater) as ItemsRepeater;
		_expander = GetTemplateChild(PART_Expander) as SettingsExpanderInner;

		if (_itemsRepeater != null)
		{
			_itemsRepeater.ElementPrepared += ItemsRepeater_ElementPrepared;
			UpdateItemsSource();
		}

		if (_expander != null)
		{
			_expander.IsExpanded = IsExpanded;
			_expander.Expanding += Expander_Expanding;
			_expander.Collapsed += Expander_Collapsed;
		}
	}

	private void Expander_Expanding(Expander sender, ExpanderExpandingEventArgs args)
	{
		IsExpanded = true;
	}

	private void Expander_Collapsed(Expander sender, ExpanderCollapsedEventArgs args)
	{
		IsExpanded = false;
	}

	private void SetAccessibleName()
	{
		if (string.IsNullOrEmpty(AutomationProperties.GetName(this)))
		{
			if (Header is string headerString && !string.IsNullOrEmpty(headerString))
			{
				AutomationProperties.SetName(this, headerString);
			}
		}
	}

	protected override AutomationPeer OnCreateAutomationPeer()
	{
		return new SettingsExpanderAutomationPeer(this);
	}

	private void OnIsExpandedChanged(bool oldValue, bool newValue)
	{
		if (_expander != null && _expander.IsExpanded != newValue)
		{
			_expander.IsExpanded = newValue;
		}

		SettingsExpanderAutomationPeer? peer = FrameworkElementAutomationPeer.FromElement(this) as SettingsExpanderAutomationPeer;
		peer?.RaiseExpandedChangedEvent(newValue);
	}

	protected virtual void OnIsExpandedPropertyChanged(bool oldValue, bool newValue)
	{
		OnIsExpandedChanged(oldValue, newValue);

		if (newValue)
		{
			Expanded?.Invoke(this, EventArgs.Empty);
		}
		else
		{
			Collapsed?.Invoke(this, EventArgs.Empty);
		}
	}

	private static void OnItemsConnectedPropertyChanged(DependencyObject dependencyObject, DependencyPropertyChangedEventArgs args)
	{
		if (dependencyObject is SettingsExpander expander)
		{
			expander.UpdateItemsSource();
		}
	}

	private void UpdateItemsSource()
	{
		if (_itemsRepeater != null)
		{
			object? datasource = ItemsSource ?? Items;
			_itemsRepeater.ItemsSource = datasource;
		}
	}

	private void ItemsRepeater_ElementPrepared(ItemsRepeater sender, ItemsRepeaterElementPreparedEventArgs args)
	{
		if (ItemContainerStyleSelector != null && args.Element is FrameworkElement element && element.ReadLocalValue(StyleProperty) == DependencyProperty.UnsetValue)
		{
			element.Style = ItemContainerStyleSelector.SelectStyle(null, element);
		}
	}
}
