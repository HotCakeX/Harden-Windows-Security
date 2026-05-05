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
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Markup;

namespace CommonCore.ToolKits;

/// <summary>
///  The SettingsExpander is a collapsible control to host multiple SettingsCards.
/// </summary>
//// Note: ItemsRepeater will request all the available horizontal space: https://github.com/microsoft/microsoft-ui-xaml/issues/3842
[TemplatePart(Name = PART_ItemsRepeater, Type = typeof(ItemsRepeater))]
[TemplatePart(Name = PART_Expander, Type = typeof(SettingsExpanderInnerExpander))]
[TemplatePart(Name = PART_ItemsRoot, Type = typeof(Grid))]
internal sealed partial class SettingsExpander : Control
{
	private const string PART_ItemsRepeater = "PART_ItemsRepeater";
	private const string PART_Expander = "PART_Expander";
	private const string PART_ItemsRoot = "PART_ItemsRoot";

	private ItemsRepeater? _itemsRepeater;
	private SettingsExpanderInnerExpander? _expander;
	private Grid? _itemsRoot;
	private long _cornerRadiusPropertyChangedToken;
	private long _expanderIsExpandedPropertyChangedToken;
	private bool _itemsRepeaterElementPreparedAttached;

	/// <summary>
	/// The SettingsExpander is a collapsible control to host multiple SettingsCards.
	/// </summary>
	public SettingsExpander()
	{
		DefaultStyleKey = typeof(SettingsExpander);
		Items = new List<object>();
		AttachCornerRadiusPropertyChangedCallback();
		Loaded += SettingsExpander_Loaded;
		Unloaded += SettingsExpander_Unloaded;
	}

	private void SettingsExpander_Loaded(object sender, RoutedEventArgs args)
	{
		AttachCornerRadiusPropertyChangedCallback();
		AttachExpanderEvents();
		AttachItemsRepeaterEvents();
		UpdateExpanderState();
		UpdateCornerRadius();
		OnItemsConnectedPropertyChanged(this, null!);
	}

	private void SettingsExpander_Unloaded(object sender, RoutedEventArgs args)
	{
		DetachExpanderEvents();
		DetachItemsRepeaterEvents();
		DetachCornerRadiusPropertyChangedCallback();
	}

	protected override void OnApplyTemplate()
	{
		DetachExpanderEvents();
		DetachItemsRepeaterEvents();
		base.OnApplyTemplate();
		SetAccessibleName();

		_expander = GetTemplateChild(PART_Expander) as SettingsExpanderInnerExpander;
		_itemsRoot = GetTemplateChild(PART_ItemsRoot) as Grid;
		_itemsRepeater = GetTemplateChild(PART_ItemsRepeater) as ItemsRepeater;

		AttachExpanderEvents();
		UpdateExpanderState();
		UpdateCornerRadius();

		if (_itemsRepeater != null)
		{
			AttachItemsRepeaterEvents();

			// Update it's source based on our current items properties.
			OnItemsConnectedPropertyChanged(this, null!); // Can't get it to accept type here? (DependencyPropertyChangedEventArgs)EventArgs.Empty
		}
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

	/// <summary>
	/// Creates AutomationPeer
	/// </summary>
	/// <returns>An automation peer for <see cref="SettingsExpander"/>.</returns>
	protected override AutomationPeer OnCreateAutomationPeer() => new SettingsExpanderAutomationPeer(this);

	private void OnIsExpandedChanged(bool oldValue, bool newValue)
	{
		UpdateExpanderState();

		SettingsExpanderAutomationPeer? peer = FrameworkElementAutomationPeer.FromElement(this) as SettingsExpanderAutomationPeer;
		peer?.RaiseExpandedChangedEvent(newValue);
	}

	private void AttachExpanderEvents()
	{
		if (_expander is not null && _expanderIsExpandedPropertyChangedToken == 0)
		{
			_expanderIsExpandedPropertyChangedToken = _expander.RegisterPropertyChangedCallback(Expander.IsExpandedProperty, OnExpanderIsExpandedPropertyChanged);
		}
	}

	private void DetachExpanderEvents()
	{
		if (_expander is not null)
		{
			if (_expanderIsExpandedPropertyChangedToken != 0)
			{
				_expander.UnregisterPropertyChangedCallback(Expander.IsExpandedProperty, _expanderIsExpandedPropertyChangedToken);
			}

			_expanderIsExpandedPropertyChangedToken = 0;
		}
	}

	private void OnExpanderIsExpandedPropertyChanged(DependencyObject sender, DependencyProperty property)
	{
		if (_expander is not null)
		{
			IsExpanded = _expander.IsExpanded;
		}
	}

	private void UpdateExpanderState()
	{
		if (_expander is not null && _expander.IsExpanded != IsExpanded)
		{
			_expander.IsExpanded = IsExpanded;
		}
	}

	private void OnCornerRadiusPropertyChanged(DependencyObject sender, DependencyProperty property) => UpdateCornerRadius();

	private void AttachCornerRadiusPropertyChangedCallback()
	{
		if (_cornerRadiusPropertyChangedToken == 0)
		{
			_cornerRadiusPropertyChangedToken = RegisterPropertyChangedCallback(CornerRadiusProperty, OnCornerRadiusPropertyChanged);
		}
	}

	private void DetachCornerRadiusPropertyChangedCallback()
	{
		if (_cornerRadiusPropertyChangedToken != 0)
		{
			UnregisterPropertyChangedCallback(CornerRadiusProperty, _cornerRadiusPropertyChangedToken);
			_cornerRadiusPropertyChangedToken = 0;
		}
	}

	private void UpdateCornerRadius()
	{
		CornerRadius cornerRadius = CornerRadius;
		CornerRadius topCornerRadius = new(cornerRadius.TopLeft, cornerRadius.TopRight, 0, 0);
		CornerRadius bottomCornerRadius = new(0, 0, cornerRadius.BottomRight, cornerRadius.BottomLeft);

		if (_expander is not null)
		{
			_expander.TopCornerRadius = topCornerRadius;
			_expander.BottomCornerRadius = bottomCornerRadius;
		}

		_ = (_itemsRoot?.CornerRadius = bottomCornerRadius);
	}
}

internal partial class SettingsExpander
{
	/// <summary>
	/// Fires when the SettingsExpander is opened
	/// </summary>
	public event EventHandler? Expanded;

	/// <summary>
	/// Fires when the expander is closed
	/// </summary>
	public event EventHandler? Collapsed;
}

//// Implement properties for ItemsControl like behavior.
internal partial class SettingsExpander
{
	/// <summary>
	/// Gets or sets the collection of items to display.
	/// </summary>
	public IList<object> Items
	{
		get => (IList<object>)GetValue(ItemsProperty); set => SetValue(ItemsProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="Items"/> DependencyProperty.
	/// </summary>
	public static readonly DependencyProperty ItemsProperty =
		DependencyProperty.Register(nameof(Items), typeof(IList<object>), typeof(SettingsExpander), new PropertyMetadata(null, OnItemsConnectedPropertyChanged));

	/// <summary>
	/// Gets or sets the value to use for the inner <see cref="ItemsRepeater.ItemsSource"/>.
	/// </summary>
	public object ItemsSource
	{
		get => GetValue(ItemsSourceProperty); set => SetValue(ItemsSourceProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="ItemsSource"/> DependencyProperty.
	/// </summary>
	public static readonly DependencyProperty ItemsSourceProperty =
		DependencyProperty.Register(nameof(ItemsSource), typeof(object), typeof(SettingsExpander), new PropertyMetadata(null, OnItemsConnectedPropertyChanged));

	/// <summary>
	/// Gets or sets the value to use for the inner <see cref="ItemsRepeater.ItemTemplate"/>.
	/// </summary>
	public object ItemTemplate
	{
		get => GetValue(ItemTemplateProperty); set => SetValue(ItemTemplateProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="ItemTemplate"/> DependencyProperty.
	/// </summary>
	public static readonly DependencyProperty ItemTemplateProperty =
		DependencyProperty.Register(nameof(ItemTemplate), typeof(object), typeof(SettingsExpander), new PropertyMetadata(null));

	/// <summary>
	/// Gets or sets the value to use for the ItemContainerStyle applied to the inner <see cref="ItemsRepeater"/>.
	/// </summary>
	public StyleSelector ItemContainerStyleSelector
	{
		get => (StyleSelector)GetValue(ItemContainerStyleSelectorProperty); set => SetValue(ItemContainerStyleSelectorProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="ItemContainerStyleSelector"/> DependencyProperty.
	/// </summary>
	public static readonly DependencyProperty ItemContainerStyleSelectorProperty =
		DependencyProperty.Register(nameof(ItemContainerStyleSelector), typeof(StyleSelector), typeof(SettingsExpander), new PropertyMetadata(null));

	private static void OnItemsConnectedPropertyChanged(DependencyObject dependencyObject, DependencyPropertyChangedEventArgs args)
	{
		if (dependencyObject is SettingsExpander expander && expander._itemsRepeater is not null)
		{
			object datasource = expander.ItemsSource;

			datasource ??= expander.Items;

			expander._itemsRepeater.ItemsSource = datasource;
		}
	}

	private void ItemsRepeater_ElementPrepared(ItemsRepeater sender, ItemsRepeaterElementPreparedEventArgs args)
	{
		if (ItemContainerStyleSelector != null &&
			args.Element is FrameworkElement element &&
			element.ReadLocalValue(StyleProperty) == DependencyProperty.UnsetValue)
		{
			// TODO: Get item from args.Index?
			element.Style = ItemContainerStyleSelector.SelectStyle(null, element);
		}
	}

	private void AttachItemsRepeaterEvents()
	{
		if (_itemsRepeater is not null && !_itemsRepeaterElementPreparedAttached)
		{
			_itemsRepeater.ElementPrepared += ItemsRepeater_ElementPrepared;
			_itemsRepeaterElementPreparedAttached = true;
		}
	}

	private void DetachItemsRepeaterEvents()
	{
		if (_itemsRepeater is not null && _itemsRepeaterElementPreparedAttached)
		{
			_itemsRepeater.ElementPrepared -= ItemsRepeater_ElementPrepared;
			_itemsRepeaterElementPreparedAttached = false;
		}
	}
}

[ContentProperty(Name = nameof(Content))]
internal partial class SettingsExpander
{
	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="Header"/> property.
	/// </summary>
	public static readonly DependencyProperty HeaderProperty = DependencyProperty.Register(
		nameof(Header),
		typeof(object),
		typeof(SettingsExpander),
		new PropertyMetadata(defaultValue: null));

	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="Description"/> property.
	/// </summary>
	public static readonly DependencyProperty DescriptionProperty = DependencyProperty.Register(
		nameof(Description),
		typeof(object),
		typeof(SettingsExpander),
		new PropertyMetadata(defaultValue: null));

	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="HeaderIcon"/> property.
	/// </summary>
	public static readonly DependencyProperty HeaderIconProperty = DependencyProperty.Register(
		nameof(HeaderIcon),
		typeof(IconElement),
		typeof(SettingsExpander),
		new PropertyMetadata(defaultValue: null));

	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="Content"/> property.
	/// </summary>
	public static readonly DependencyProperty ContentProperty = DependencyProperty.Register(
		nameof(Content),
		typeof(object),
		typeof(SettingsExpander),
		new PropertyMetadata(defaultValue: null));

	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="ItemsHeader"/> property.
	/// </summary>
	public static readonly DependencyProperty ItemsHeaderProperty = DependencyProperty.Register(
		nameof(ItemsHeader),
		typeof(UIElement),
		typeof(SettingsExpander),
		new PropertyMetadata(defaultValue: null));

	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="ItemsFooter"/> property.
	/// </summary>
	public static readonly DependencyProperty ItemsFooterProperty = DependencyProperty.Register(
		nameof(ItemsFooter),
		typeof(UIElement),
		typeof(SettingsExpander),
		new PropertyMetadata(defaultValue: null));

	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="IsExpanded"/> property.
	/// </summary>
	public static readonly DependencyProperty IsExpandedProperty = DependencyProperty.Register(
	 nameof(IsExpanded),
	 typeof(bool),
	 typeof(SettingsExpander),
	 new PropertyMetadata(defaultValue: false, (d, e) => ((SettingsExpander)d).OnIsExpandedPropertyChanged((bool)e.OldValue, (bool)e.NewValue)));

	/// <summary>
	/// Gets or sets the Header.
	/// </summary>
	public object Header
	{
		get => GetValue(HeaderProperty);
		set => SetValue(HeaderProperty, value);
	}

	/// <summary>
	/// Gets or sets the Description.
	/// </summary>
#pragma warning disable CS0109 // Member does not hide an inherited member; new keyword is not required
	public new object Description
#pragma warning restore CS0109 // Member does not hide an inherited member; new keyword is not required
	{
		get => GetValue(DescriptionProperty);
		set => SetValue(DescriptionProperty, value);
	}

	/// <summary>
	/// Gets or sets the HeaderIcon.
	/// </summary>
	public IconElement HeaderIcon
	{
		get => (IconElement)GetValue(HeaderIconProperty);
		set => SetValue(HeaderIconProperty, value);
	}

	/// <summary>
	/// Gets or sets the Content.
	/// </summary>
	public object Content
	{
		get => GetValue(ContentProperty);
		set => SetValue(ContentProperty, value);
	}

	/// <summary>
	/// Gets or sets the ItemsFooter.
	/// </summary>
	public UIElement ItemsHeader
	{
		get => (UIElement)GetValue(ItemsHeaderProperty);
		set => SetValue(ItemsHeaderProperty, value);
	}

	/// <summary>
	/// Gets or sets the ItemsFooter.
	/// </summary>
	public UIElement ItemsFooter
	{
		get => (UIElement)GetValue(ItemsFooterProperty);
		set => SetValue(ItemsFooterProperty, value);
	}

	/// <summary>
	/// Gets or sets the IsExpanded state.
	/// </summary>
	public bool IsExpanded
	{
		get => (bool)GetValue(IsExpandedProperty);
		set => SetValue(IsExpandedProperty, value);
	}

	private void OnIsExpandedPropertyChanged(bool oldValue, bool newValue)
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
}

/// <summary>
/// AutomationPeer for SettingsExpander
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="SettingsExpander"/> class.
/// </remarks>
/// <param name="owner">SettingsExpander</param>
internal sealed partial class SettingsExpanderAutomationPeer(SettingsExpander owner) : FrameworkElementAutomationPeer(owner)
{
	/// <summary>
	/// Gets the control type for the element that is associated with the UI Automation peer.
	/// </summary>
	/// <returns>The control type.</returns>
	protected override AutomationControlType GetAutomationControlTypeCore() => AutomationControlType.Group;

	/// <summary>
	/// Called by GetClassName that gets a human readable name that, in addition to AutomationControlType,
	/// differentiates the control represented by this AutomationPeer.
	/// </summary>
	/// <returns>The string that contains the name.</returns>
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

	/// <summary>
	/// Raises the property changed event for this AutomationPeer for the provided identifier.
	/// Narrator does not announce this due to: https://github.com/microsoft/microsoft-ui-xaml/issues/3469
	/// </summary>
	/// <param name="newValue">New Expanded state</param>
	public void RaiseExpandedChangedEvent(bool newValue)
	{
		ExpandCollapseState newState = newValue ? ExpandCollapseState.Expanded : ExpandCollapseState.Collapsed;

		ExpandCollapseState oldState = (newState == ExpandCollapseState.Expanded) ? ExpandCollapseState.Collapsed : ExpandCollapseState.Expanded;

		RaisePropertyChangedEvent(ExpandCollapsePatternIdentifiers.ExpandCollapseStateProperty, oldState, newState);
	}
}

/// <summary>
/// <see cref="StyleSelector"/> used by <see cref="SettingsExpander"/> to choose the proper <see cref="SettingsCard"/> container style (clickable or not).
/// </summary>
internal sealed partial class SettingsExpanderItemStyleSelector : StyleSelector
{
	/// <summary>
	/// Gets or sets the default <see cref="Style"/>.
	/// </summary>
	public Style DefaultStyle { get; set; }

	/// <summary>
	/// Gets or sets the <see cref="Style"/> when clickable.
	/// </summary>
	public Style ClickableStyle { get; set; }

	/// <summary>
	/// Initializes a new instance of the <see cref="SettingsExpanderItemStyleSelector"/> class.
	/// </summary>
#pragma warning disable CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
	public SettingsExpanderItemStyleSelector()
#pragma warning restore CS8618 // Non-nullable field must contain a non-null value when exiting constructor. Consider declaring as nullable.
	{
	}

	protected override Style SelectStyleCore(object item, DependencyObject container)
	{
		if (container is SettingsCard card && card.IsClickEnabled)
		{
			return ClickableStyle;
		}
		else
		{
			return DefaultStyle;
		}
	}
}

/// <summary>
/// Inner expander used by <see cref="SettingsExpander"/> so template-only state can stay Native AOT compatible.
/// </summary>
[TemplatePart(Name = ExpanderHeaderPart, Type = typeof(ToggleButton))]
internal sealed partial class SettingsExpanderInnerExpander : Expander
{
	private const string ExpanderHeaderPart = "ExpanderHeader";

	private ToggleButton? _expanderHeader;
	private long _isExpandedPropertyChangedToken;
	private bool _headerEventsAttached;

	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="TopCornerRadius"/> property.
	/// </summary>
	public static readonly DependencyProperty TopCornerRadiusProperty = DependencyProperty.Register(
		nameof(TopCornerRadius),
		typeof(CornerRadius),
		typeof(SettingsExpanderInnerExpander),
		new PropertyMetadata(defaultValue: default(CornerRadius)));

	/// <summary>
	/// The backing <see cref="DependencyProperty"/> for the <see cref="BottomCornerRadius"/> property.
	/// </summary>
	public static readonly DependencyProperty BottomCornerRadiusProperty = DependencyProperty.Register(
		nameof(BottomCornerRadius),
		typeof(CornerRadius),
		typeof(SettingsExpanderInnerExpander),
		new PropertyMetadata(defaultValue: default(CornerRadius)));

	/// <summary>
	/// Gets or sets the top-only corner radius used by upward expansion states.
	/// </summary>
	public CornerRadius TopCornerRadius
	{
		get => (CornerRadius)GetValue(TopCornerRadiusProperty);
		set => SetValue(TopCornerRadiusProperty, value);
	}

	/// <summary>
	/// Gets or sets the bottom-only corner radius used by downward expansion states.
	/// </summary>
	public CornerRadius BottomCornerRadius
	{
		get => (CornerRadius)GetValue(BottomCornerRadiusProperty);
		set => SetValue(BottomCornerRadiusProperty, value);
	}

	public SettingsExpanderInnerExpander()
	{
		AttachIsExpandedPropertyChangedCallback();
		Loaded += SettingsExpanderInnerExpander_Loaded;
		Unloaded += SettingsExpanderInnerExpander_Unloaded;
	}

	private void SettingsExpanderInnerExpander_Loaded(object sender, RoutedEventArgs args)
	{
		AttachIsExpandedPropertyChangedCallback();
		AttachHeaderEvents();
		UpdateHeaderCheckedState();
	}

	private void SettingsExpanderInnerExpander_Unloaded(object sender, RoutedEventArgs args)
	{
		DetachHeaderEvents();
		DetachIsExpandedPropertyChangedCallback();
	}

	protected override void OnApplyTemplate()
	{
		DetachHeaderEvents();
		base.OnApplyTemplate();
		_expanderHeader = GetTemplateChild(ExpanderHeaderPart) as ToggleButton;
		AttachHeaderEvents();
		UpdateHeaderCheckedState();
	}

	private void AttachHeaderEvents()
	{
		if (_expanderHeader is not null && !_headerEventsAttached)
		{
			_expanderHeader.Checked += ExpanderHeader_CheckedChanged;
			_expanderHeader.Unchecked += ExpanderHeader_CheckedChanged;
			_headerEventsAttached = true;
		}
	}

	private void DetachHeaderEvents()
	{
		if (_expanderHeader is not null && _headerEventsAttached)
		{
			_expanderHeader.Checked -= ExpanderHeader_CheckedChanged;
			_expanderHeader.Unchecked -= ExpanderHeader_CheckedChanged;
			_headerEventsAttached = false;
		}
	}

	private void ExpanderHeader_CheckedChanged(object sender, RoutedEventArgs args)
	{
		if (_expanderHeader is not null)
		{
			IsExpanded = _expanderHeader.IsChecked == true;
		}
	}

	private void OnIsExpandedPropertyChanged(DependencyObject sender, DependencyProperty property) => UpdateHeaderCheckedState();

	private void AttachIsExpandedPropertyChangedCallback()
	{
		if (_isExpandedPropertyChangedToken == 0)
		{
			_isExpandedPropertyChangedToken = RegisterPropertyChangedCallback(IsExpandedProperty, OnIsExpandedPropertyChanged);
		}
	}

	private void DetachIsExpandedPropertyChangedCallback()
	{
		if (_isExpandedPropertyChangedToken != 0)
		{
			UnregisterPropertyChangedCallback(IsExpandedProperty, _isExpandedPropertyChangedToken);
			_isExpandedPropertyChangedToken = 0;
		}
	}

	private void UpdateHeaderCheckedState()
	{
		if (_expanderHeader is not null && _expanderHeader.IsChecked != IsExpanded)
		{
			_expanderHeader.IsChecked = IsExpanded;
		}
	}
}
