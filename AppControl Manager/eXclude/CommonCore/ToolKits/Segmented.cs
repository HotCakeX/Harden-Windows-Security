// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// Source: https://github.com/CommunityToolkit/Windows/tree/main/components/Segmented/src
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
using System.Runtime.InteropServices;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Markup;
using Windows.System;

namespace CommonCore.ToolKits;

internal sealed partial class EqualPanel : Panel
{
	private double _maxItemWidth;
	private double _maxItemHeight;
	private int _visibleItemsCount;

	public static readonly DependencyProperty SpacingProperty = DependencyProperty.Register(
		nameof(Spacing), typeof(double), typeof(EqualPanel), new PropertyMetadata(default(double), OnEqualPanelPropertyChanged));

	public static readonly DependencyProperty OrientationProperty = DependencyProperty.Register(
		nameof(Orientation), typeof(Orientation), typeof(EqualPanel), new PropertyMetadata(Orientation.Horizontal, OnEqualPanelPropertyChanged));

	public double Spacing
	{
		get => (double)GetValue(SpacingProperty);
		set => SetValue(SpacingProperty, value);
	}

	public Orientation Orientation
	{
		get => (Orientation)GetValue(OrientationProperty);
		set => SetValue(OrientationProperty, value);
	}

	internal EqualPanel()
	{
		Orientation = Orientation.Horizontal;
		_ = RegisterPropertyChangedCallback(HorizontalAlignmentProperty, OnAlignmentChanged);
	}

	protected override Windows.Foundation.Size MeasureOverride(Windows.Foundation.Size availableSize)
	{
		_maxItemWidth = 0;
		_maxItemHeight = 0;

		List<UIElement> elements = Children.Where(static e => e.Visibility == Visibility.Visible).ToList();
		_visibleItemsCount = elements.Count;

		foreach (UIElement? child in CollectionsMarshal.AsSpan(elements))
		{
			child.Measure(availableSize);
			_maxItemWidth = Math.Max(_maxItemWidth, child.DesiredSize.Width);
			_maxItemHeight = Math.Max(_maxItemHeight, child.DesiredSize.Height);
		}

		if (_visibleItemsCount <= 0) return new Windows.Foundation.Size(0, 0);

		bool stretch = Orientation switch
		{
			Orientation.Horizontal => HorizontalAlignment is HorizontalAlignment.Stretch && !double.IsInfinity(availableSize.Width),
			Orientation.Vertical or _ => VerticalAlignment is VerticalAlignment.Stretch && !double.IsInfinity(availableSize.Height),
		};

		UVCoord uvSize = new(0, 0, Orientation);
		UVCoord maxItemSize = new(_maxItemWidth, _maxItemHeight, Orientation);
		double availableU = Orientation is Orientation.Horizontal ? availableSize.Width : availableSize.Height;

		if (stretch)
		{
			double totalU = availableU - (Spacing * (_visibleItemsCount - 1));
			maxItemSize.U = totalU / _visibleItemsCount;
			uvSize.U = availableU;
			uvSize.V = maxItemSize.V;
		}
		else
		{
			uvSize.U = (maxItemSize.U * _visibleItemsCount) + (Spacing * (_visibleItemsCount - 1));
			uvSize.V = maxItemSize.V;
		}

		if (Orientation == Orientation.Horizontal) { _maxItemWidth = maxItemSize.U; _maxItemHeight = maxItemSize.V; }
		else { _maxItemWidth = maxItemSize.V; _maxItemHeight = maxItemSize.U; }

		return new Windows.Foundation.Size(uvSize.X, uvSize.Y);
	}

	protected override Windows.Foundation.Size ArrangeOverride(Windows.Foundation.Size finalSize)
	{
		UVCoord pos = new(0, 0, Orientation);
		double currentMaxItemU = (Orientation == Orientation.Horizontal) ? _maxItemWidth : _maxItemHeight;
		double finalSizeU = (Orientation == Orientation.Horizontal) ? finalSize.Width : finalSize.Height;

		if (finalSizeU > _visibleItemsCount * currentMaxItemU + (Spacing * (_visibleItemsCount - 1)))
		{
			currentMaxItemU = (finalSizeU - (Spacing * (_visibleItemsCount - 1))) / _visibleItemsCount;
		}

		if (Orientation == Orientation.Horizontal) _maxItemWidth = currentMaxItemU;
		else _maxItemHeight = currentMaxItemU;

		foreach (UIElement? child in Children.Where(static e => e.Visibility == Visibility.Visible))
		{
			child.Arrange(new Windows.Foundation.Rect(pos.X, pos.Y, _maxItemWidth, _maxItemHeight));
			pos.U += currentMaxItemU + Spacing;
		}
		return finalSize;
	}

	private void OnAlignmentChanged(DependencyObject sender, DependencyProperty dp) => InvalidateMeasure();
	private static void OnEqualPanelPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e) => ((EqualPanel)d).InvalidateMeasure();

	private struct UVCoord(double x, double y, Orientation orientation)
	{
		private readonly bool _horizontal = orientation is Orientation.Horizontal;
		internal double X { get; set; } = x;
		internal double Y { get; set; } = y;
		internal double U { readonly get => _horizontal ? X : Y; set { if (_horizontal) X = value; else Y = value; } }
		internal double V { readonly get => _horizontal ? Y : X; set { if (_horizontal) Y = value; else X = value; } }
	}
}

[ContentProperty(Name = nameof(Content))]
internal sealed partial class SegmentedItem : ListViewItem
{
	internal const string IconLeftState = "IconLeft";
	internal const string IconTopState = "IconTop";
	internal const string IconOnlyState = "IconOnly";
	internal const string ContentOnlyState = "ContentOnly";
	internal const string HorizontalState = "Horizontal";
	internal const string VerticalState = "Vertical";
	private bool _isVertical;

	public static readonly DependencyProperty ItemHoverMarginProperty = DependencyProperty.Register(
		nameof(ItemHoverMargin), typeof(Thickness), typeof(SegmentedItem), new PropertyMetadata(new Thickness(0)));

	public Thickness ItemHoverMargin
	{
		get => (Thickness)GetValue(ItemHoverMarginProperty);
		set => SetValue(ItemHoverMarginProperty, value);
	}

	public static readonly DependencyProperty IconProperty = DependencyProperty.Register(nameof(Icon), typeof(IconElement), typeof(SegmentedItem), new PropertyMetadata(null, (d, e) => ((SegmentedItem)d).UpdateVisualStates()));
	public IconElement Icon { get => (IconElement)GetValue(IconProperty); set => SetValue(IconProperty, value); }

	internal SegmentedItem()
	{
		DefaultStyleKey = typeof(SegmentedItem);
		_ = RegisterPropertyChangedCallback(VisibilityProperty, OnVisibilityChanged);

		// Listen for Loaded to calculate initial margin
		Loaded += SegmentedItem_Loaded;
	}

	private void SegmentedItem_Loaded(object sender, RoutedEventArgs e)
	{
		Loaded -= SegmentedItem_Loaded;
		UpdateMargin();
	}

	private void OnVisibilityChanged(DependencyObject sender, DependencyProperty dp) { if (Parent is Segmented { ItemsPanelRoot: Panel panel }) panel.InvalidateMeasure(); }
	protected override void OnApplyTemplate() { base.OnApplyTemplate(); UpdateVisualStates(); UpdateMargin(); }
	protected override void OnContentChanged(object oldContent, object newContent) { base.OnContentChanged(oldContent, newContent); UpdateVisualStates(); }
	internal void UpdateOrientation(Orientation orientation) { _isVertical = orientation is Orientation.Vertical; UpdateVisualStates(); }

	// Call this when items change or layout updates
	internal void UpdateMargin()
	{
		Thickness left = new(3, 3, 1, 3);
		Thickness middle = new(1, 3, 1, 3);
		Thickness right = new(1, 3, 3, 3);
		Thickness single = new(3, 3, 3, 3); // Fallback for single item

		ItemsControl listView = ItemsControl.ItemsControlFromItemContainer(this);
		if (listView == null) { ItemHoverMargin = new Thickness(0); return; }

		int index = listView.IndexFromContainer(this);
		int count = listView.Items.Count;

		ItemHoverMargin = count == 1 ? single : index == 0 ? left : index == count - 1 ? right : middle;
	}

	private void UpdateVisualStates()
	{
		string contentState = (Icon is null, Content is null) switch
		{
			(false, false) => _isVertical ? IconTopState : IconLeftState,
			(false, true) => IconOnlyState,
			(true, false) => ContentOnlyState,
			(true, true) => ContentOnlyState,
		};
		_ = VisualStateManager.GoToState(this, contentState, true);
		_ = VisualStateManager.GoToState(this, _isVertical ? VerticalState : HorizontalState, true);
	}
}

internal sealed partial class Segmented : ListViewBase
{
	private int _internalSelectedIndex = -1;
	private bool _hasLoaded;

	public static readonly DependencyProperty OrientationProperty = DependencyProperty.Register(nameof(Orientation), typeof(Orientation), typeof(Segmented), new PropertyMetadata(Orientation.Horizontal, (d, e) => ((Segmented)d).OnOrientationChanged()));
	public Orientation Orientation { get => (Orientation)GetValue(OrientationProperty); set => SetValue(OrientationProperty, value); }

	internal Segmented()
	{
		DefaultStyleKey = typeof(Segmented);
		_ = RegisterPropertyChangedCallback(SelectedIndexProperty, OnSelectedIndexChanged);
		_ = RegisterPropertyChangedCallback(HorizontalAlignmentProperty, OnHorizontalAlignmentChanged);
		Loaded += Segmented_Loaded;
	}

	private void Segmented_Loaded(object sender, RoutedEventArgs e)
	{
		Loaded -= Segmented_Loaded;
		SyncPanelProperties();
		UpdateItemMargins();
	}

	protected override DependencyObject GetContainerForItemOverride() => new SegmentedItem();
	protected override bool IsItemItsOwnContainerOverride(object item) => item is SegmentedItem;

	protected override void OnApplyTemplate()
	{
		base.OnApplyTemplate();
		if (!_hasLoaded) { SelectedIndex = -1; SelectedIndex = _internalSelectedIndex; _hasLoaded = true; }
		PreviewKeyDown -= Segmented_PreviewKeyDown; PreviewKeyDown += Segmented_PreviewKeyDown;
		SyncPanelProperties();
	}

	protected override void PrepareContainerForItemOverride(DependencyObject element, object item)
	{
		base.PrepareContainerForItemOverride(element, item);
		if (element is SegmentedItem segmentedItem)
		{
			segmentedItem.UpdateOrientation(Orientation);
			// We might need to schedule a margin update after all items are generated
			// But doing it here helps for individual items
			segmentedItem.UpdateMargin();
		}
	}

	protected override void OnItemsChanged(object e)
	{
		base.OnItemsChanged(e);
		// When items change, index based margins might change
		UpdateItemMargins();
	}

	private void UpdateItemMargins()
	{
		// Defer slightly to ensure containers exist
		if (Items.Count == 0) return;

		for (int i = 0; i < Items.Count; i++)
		{
			if (ContainerFromIndex(i) is SegmentedItem item)
			{
				item.UpdateMargin();
			}
		}
	}

	private void Segmented_PreviewKeyDown(object sender, KeyRoutedEventArgs e)
	{
		int dir = e.Key switch { VirtualKey.Left or VirtualKey.Up => -1, VirtualKey.Right or VirtualKey.Down => 1, _ => 0 };
		if (FlowDirection == FlowDirection.RightToLeft && (e.Key == VirtualKey.Left || e.Key == VirtualKey.Right)) dir *= -1;
		if (dir is not 0) e.Handled = MoveFocus(dir);
	}

	private bool MoveFocus(int adjustment)
	{
		SegmentedItem? currentContainerItem = (XamlRoot != null) ? FocusManager.GetFocusedElement(XamlRoot) as SegmentedItem : FocusManager.GetFocusedElement() as SegmentedItem;

		if (currentContainerItem is null) return false;
		int index = Math.Clamp(Items.IndexOf(ItemFromContainer(currentContainerItem)) + adjustment, 0, Items.Count);
		if (index == Items.IndexOf(ItemFromContainer(currentContainerItem)) || ContainerFromIndex(index) is not SegmentedItem newItem) return false;
		_ = newItem.Focus(FocusState.Keyboard);
		return true;
	}

	private void OnSelectedIndexChanged(DependencyObject sender, DependencyProperty dp) { if (_internalSelectedIndex == -1 && SelectedIndex > -1) _internalSelectedIndex = SelectedIndex; }

	private void OnOrientationChanged()
	{
		SyncPanelProperties();
		for (int i = 0; i < Items.Count; i++) if (ContainerFromIndex(i) is SegmentedItem item) item.UpdateOrientation(Orientation);
	}

	private void OnHorizontalAlignmentChanged(DependencyObject sender, DependencyProperty dp) => SyncPanelProperties();

	private void SyncPanelProperties()
	{
		// Try to find the EqualPanel if ItemsPanelRoot is null (sometimes happens early)
		if (ItemsPanelRoot is EqualPanel panel)
		{
			panel.Orientation = Orientation;
			panel.HorizontalAlignment = HorizontalAlignment;
		}
		else
		{
			// Fallback: try to find it in visual tree if needed, or wait for Loaded
		}
	}
}
