// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// Source: https://github.com/CommunityToolkit/Windows/tree/main/components/Sizers/src
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

using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using Windows.System;

namespace CommonCore.ToolKits;

internal abstract class SizerBase : UserControl
{
	// Visual Elements
	private protected Grid? _rootGrid;
	private protected Rectangle? _thumb;

	// State
	private bool _pressed;
	private bool _dragging;
	private bool _pointerEntered;

	// Constants
	private const double ThumbWidth = 4;
	private const double ThumbHeight = 24;
	private const double ThumbRadius = 2;
	private const double DragIncrement = 1d;
	private const double KeyboardIncrement = 8d;

	protected SizerBase()
	{
		// Default Properties
		IsTabStop = true;
		UseSystemFocusVisuals = true;

		// Accessibility - Enable Focus Engagement (Gamepad support)
		IsFocusEngagementEnabled = true;

		// Default to Left/Top so the splitter snaps to the edge of the cell by default.
		HorizontalAlignment = HorizontalAlignment.Left;
		VerticalAlignment = VerticalAlignment.Top;

		MinHeight = 8;
		MinWidth = 8;
		ManipulationMode = ManipulationModes.TranslateX | ManipulationModes.TranslateY;

		// Build UI
		_rootGrid = new();

		Binding cornerRadiusBinding = new()
		{
			Source = this,
			Path = new PropertyPath(nameof(CornerRadius)),
			Mode = BindingMode.OneWay
		};
		_rootGrid.SetBinding(Grid.CornerRadiusProperty, cornerRadiusBinding);

		// Transparent background is critical for hit-testing the empty space around the thumb
		_rootGrid.Background = new SolidColorBrush(Microsoft.UI.Colors.Transparent);

		_thumb = new()
		{
			Name = "PART_Thumb",
			Width = ThumbWidth,
			Height = ThumbHeight,
			RadiusX = ThumbRadius,
			RadiusY = ThumbRadius,
			Margin = new Thickness(4),
			HorizontalAlignment = HorizontalAlignment.Center,
			VerticalAlignment = VerticalAlignment.Center
		};

		Binding foregroundBinding = new()
		{
			Source = this,
			Path = new PropertyPath(nameof(Foreground)),
			Mode = BindingMode.OneWay
		};
		_thumb.SetBinding(Shape.FillProperty, foregroundBinding);

		_rootGrid.Children.Add(_thumb);
		Content = _rootGrid;

		// Event Subscription
		Loaded += SizerBase_Loaded;
		Unloaded += SizerBase_Unloaded;

		PointerEntered += OnPointerEntered;
		PointerExited += OnPointerExited;
		PointerPressed += OnPointerPressed;
		PointerReleased += OnPointerReleased;
		ManipulationStarted += OnManipulationStarted;
		ManipulationDelta += OnManipulationDelta;
		ManipulationCompleted += OnManipulationCompleted;
		IsEnabledChanged += OnIsEnabledChanged;
		KeyDown += OnKeyDown;

		// React to Theme Changes
		ActualThemeChanged += OnActualThemeChanged;
	}

	// Abstract methods for the child class (GridSplitter) to implement
	protected abstract void OnDragStarting();
	protected abstract bool OnDragHorizontal(double horizontalChange);
	protected abstract bool OnDragVertical(double verticalChange);

	// Hook for cleaning up resources after drag
	protected virtual void OnDragCompleted() { }

	protected virtual void OnLoaded(RoutedEventArgs e) { }

	private void SizerBase_Loaded(object sender, RoutedEventArgs e)
	{
		// Set Default Foreground if not provided. It's important to be set in OnLoaded.
		if (ReadLocalValue(ForegroundProperty) == DependencyProperty.UnsetValue)
		{
			Foreground = Application.Current.Resources.TryGetValue("SystemControlStrongFillColorDefaultBrush", out object? res) && res is Brush b
				? b
				: new SolidColorBrush(Microsoft.UI.Colors.Gray);
		}

		UpdateVisualState();
		OnLoaded(e); // Call child implementation
		OnOrientationChanged(); // Set correct cursor
	}

	private void SizerBase_Unloaded(object sender, RoutedEventArgs e)
	{
		Loaded -= SizerBase_Loaded;
		Unloaded -= SizerBase_Unloaded;
		PointerEntered -= OnPointerEntered;
		PointerExited -= OnPointerExited;
		PointerPressed -= OnPointerPressed;
		PointerReleased -= OnPointerReleased;
		ManipulationStarted -= OnManipulationStarted;
		ManipulationDelta -= OnManipulationDelta;
		ManipulationCompleted -= OnManipulationCompleted;
		IsEnabledChanged -= OnIsEnabledChanged;
		KeyDown -= OnKeyDown;
		ActualThemeChanged -= OnActualThemeChanged;
	}

	private void OnActualThemeChanged(FrameworkElement sender, object args) => UpdateVisualState();

	private void OnPointerEntered(object sender, PointerRoutedEventArgs e)
	{
		_pointerEntered = true;
		if (!_pressed && !_dragging && IsEnabled) UpdateVisualState();
	}

	private void OnPointerExited(object sender, PointerRoutedEventArgs e)
	{
		_pointerEntered = false;
		if (!_pressed && !_dragging && IsEnabled) UpdateVisualState();
	}

	private void OnPointerPressed(object sender, PointerRoutedEventArgs e)
	{
		_pressed = true;
		if (IsEnabled) UpdateVisualState();
	}

	private void OnPointerReleased(object sender, PointerRoutedEventArgs e)
	{
		_pressed = false;
		if (IsEnabled) UpdateVisualState();
	}

	private void OnManipulationStarted(object sender, ManipulationStartedRoutedEventArgs e)
	{
		_dragging = true;
		UpdateVisualState();
		OnDragStarting();
	}

	private void OnManipulationCompleted(object sender, ManipulationCompletedRoutedEventArgs e)
	{
		_dragging = false;
		_pressed = false;
		UpdateVisualState();
		OnDragCompleted();
	}

	private void OnManipulationDelta(object sender, ManipulationDeltaRoutedEventArgs e)
	{
		double horizontalChange = Math.Truncate(e.Cumulative.Translation.X / DragIncrement) * DragIncrement;
		double verticalChange = Math.Truncate(e.Cumulative.Translation.Y / DragIncrement) * DragIncrement;

		if (FlowDirection == FlowDirection.RightToLeft) horizontalChange *= -1;

		_ = Orientation == Orientation.Vertical ? OnDragHorizontal(horizontalChange) : OnDragVertical(verticalChange);
	}

	private void OnKeyDown(object sender, KeyRoutedEventArgs e)
	{
		if (_dragging) return;
		OnDragStarting();

		if (Orientation == Orientation.Vertical)
		{
			double change = KeyboardIncrement;
			if (FlowDirection == FlowDirection.RightToLeft) change *= -1;

			if (e.Key == VirtualKey.Left) _ = OnDragHorizontal(-change);
			else if (e.Key == VirtualKey.Right) _ = OnDragHorizontal(change);
		}
		else
		{
			if (e.Key == VirtualKey.Up) _ = OnDragVertical(-KeyboardIncrement);
			else if (e.Key == VirtualKey.Down) _ = OnDragVertical(KeyboardIncrement);
		}
	}

	private void OnIsEnabledChanged(object sender, DependencyPropertyChangedEventArgs e) => UpdateVisualState();


	public static readonly DependencyProperty OrientationProperty =
		DependencyProperty.Register(nameof(Orientation), typeof(Orientation), typeof(SizerBase), new PropertyMetadata(Orientation.Vertical, (d, e) => ((SizerBase)d).OnOrientationChanged()));

	public Orientation Orientation
	{
		get => (Orientation)GetValue(OrientationProperty);
		set => SetValue(OrientationProperty, value);
	}

	private void OnOrientationChanged()
	{
		if (_thumb == null) return;
		if (Orientation == Orientation.Vertical)
		{
			_thumb.Width = ThumbWidth;
			_thumb.Height = ThumbHeight;
			ProtectedCursor = InputSystemCursor.Create(InputSystemCursorShape.SizeWestEast);
		}
		else
		{
			_thumb.Width = ThumbHeight;
			_thumb.Height = ThumbWidth;
			ProtectedCursor = InputSystemCursor.Create(InputSystemCursorShape.SizeNorthSouth);
		}
	}

	private void UpdateVisualState()
	{
		if (_rootGrid == null || _thumb == null) return;

		static Brush GetBrush(string key)
		{
			if (Application.Current.Resources.TryGetValue(key, out object? res) && res is Brush b) return b;
			return new SolidColorBrush(Microsoft.UI.Colors.Transparent);
		}

		if (!IsEnabled)
		{
			_rootGrid.Background = GetBrush("ControlAltFillColorDisabledBrush");
			_thumb.Opacity = 0.45;
		}
		else if (_pressed || _dragging)
		{
			_rootGrid.Background = GetBrush("ControlAltFillColorQuarternaryBrush");
			_thumb.Opacity = 1.0;
		}
		else if (_pointerEntered)
		{
			_rootGrid.Background = GetBrush("ControlAltFillColorTertiaryBrush");
			_thumb.Opacity = 1.0;
		}
		else
		{
			_rootGrid.Background = GetBrush("ControlAltFillColorTransparentBrush");
			_thumb.Opacity = 1.0;
		}
	}

	protected static bool IsValidHeight(FrameworkElement target, double newHeight, double parentActualHeight)
	{
		double minHeight = target.MinHeight;
		if (newHeight < 0 || (!double.IsNaN(minHeight) && newHeight < minHeight)) return false;
		double maxHeight = target.MaxHeight;
		if (!double.IsNaN(maxHeight) && newHeight > maxHeight) return false;
		return newHeight <= parentActualHeight;
	}

	protected static bool IsValidWidth(FrameworkElement target, double newWidth, double parentActualWidth)
	{
		double minWidth = target.MinWidth;
		if (newWidth < 0 || (!double.IsNaN(minWidth) && newWidth < minWidth)) return false;
		double maxWidth = target.MaxWidth;
		if (!double.IsNaN(maxWidth) && newWidth > maxWidth) return false;
		return newWidth <= parentActualWidth;
	}
}

/// <summary>
/// GridSplitter Implementation
/// </summary>
internal sealed partial class GridSplitter : SizerBase
{
	internal enum GridResizeDirection { Auto, Columns, Rows }
	internal enum GridResizeBehavior { BasedOnAlignment, CurrentAndNext, PreviousAndCurrent, PreviousAndNext }

	private GridResizeDirection _resizeDirection;
	private GridResizeBehavior _resizeBehavior = GridResizeBehavior.BasedOnAlignment;
	private double _currentSize;
	private double _siblingSize;

	// Cached references resolved once in OnDragStarting and reused during drag
	private Grid? _cachedResizable;
	private ColumnDefinition? _cachedCurrentColumn;
	private ColumnDefinition? _cachedSiblingColumn;
	private RowDefinition? _cachedCurrentRow;
	private RowDefinition? _cachedSiblingRow;

	internal GridSplitter() : base() { }

	public static readonly DependencyProperty ResizeDirectionProperty =
		DependencyProperty.Register(nameof(ResizeDirection), typeof(GridResizeDirection), typeof(GridSplitter), new PropertyMetadata(GridResizeDirection.Auto, OnResizeDirectionChanged));

	public GridResizeDirection ResizeDirection
	{
		get => (GridResizeDirection)GetValue(ResizeDirectionProperty);
		set => SetValue(ResizeDirectionProperty, value);
	}

	private static void OnResizeDirectionChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is GridSplitter splitter && e.NewValue is GridResizeDirection dir && dir != GridResizeDirection.Auto)
		{
			splitter.Orientation = dir == GridResizeDirection.Rows ? Orientation.Horizontal : Orientation.Vertical;
		}
	}

	protected override void OnLoaded(RoutedEventArgs e)
	{
		base.OnLoaded(e);

		// Determine general direction (Columns or Rows)
		_resizeDirection = GetResizeDirection();

		// Update Orientation (Horizontal splitter is for Rows, Vertical for Columns)
		Orientation = _resizeDirection == GridResizeDirection.Rows ? Orientation.Horizontal : Orientation.Vertical;

		// Recalculate Behavior based on the alignment
		_resizeBehavior = GetResizeBehavior();
	}

	protected override void OnDragStarting()
	{
		// Re-calculate state on drag start
		_resizeDirection = GetResizeDirection();
		Orientation = _resizeDirection == GridResizeDirection.Rows ? Orientation.Horizontal : Orientation.Vertical;
		_resizeBehavior = GetResizeBehavior();

		// The parent of a GridSplitter must always be a Grid.
		_cachedResizable = (Grid)this.Parent;

		int columnIndex = Grid.GetColumn(this);
		int rowIndex = Grid.GetRow(this);

		int targetColumnIdx = GetTargetIndex(columnIndex);
		int siblingColumnIdx = GetSiblingIndex(columnIndex);
		int targetRowIdx = GetTargetIndex(rowIndex);
		int siblingRowIdx = GetSiblingIndex(rowIndex);

		_cachedCurrentColumn = (targetColumnIdx >= 0 && targetColumnIdx < _cachedResizable.ColumnDefinitions.Count)
			? _cachedResizable.ColumnDefinitions[targetColumnIdx]
			: null;
		_cachedSiblingColumn = (siblingColumnIdx >= 0 && siblingColumnIdx < _cachedResizable.ColumnDefinitions.Count)
			? _cachedResizable.ColumnDefinitions[siblingColumnIdx]
			: null;
		_cachedCurrentRow = (targetRowIdx >= 0 && targetRowIdx < _cachedResizable.RowDefinitions.Count)
			? _cachedResizable.RowDefinitions[targetRowIdx]
			: null;
		_cachedSiblingRow = (siblingRowIdx >= 0 && siblingRowIdx < _cachedResizable.RowDefinitions.Count)
			? _cachedResizable.RowDefinitions[siblingRowIdx]
			: null;

		if (Orientation == Orientation.Horizontal)
		{
			_currentSize = _cachedCurrentRow?.ActualHeight ?? -1;
			_siblingSize = _cachedSiblingRow?.ActualHeight ?? -1;
		}
		else
		{
			_currentSize = _cachedCurrentColumn?.ActualWidth ?? -1;
			_siblingSize = _cachedSiblingColumn?.ActualWidth ?? -1;
		}
	}

	protected override void OnDragCompleted()
	{
		// Release references to UI elements to allow GC if necessary
		_cachedResizable = null;
		_cachedCurrentColumn = null;
		_cachedSiblingColumn = null;
		_cachedCurrentRow = null;
		_cachedSiblingRow = null;
	}

	protected override bool OnDragHorizontal(double horizontalChange)
	{
		if (_cachedCurrentColumn == null || _cachedSiblingColumn == null || _cachedResizable == null) return false;

		double currentChange = _currentSize + horizontalChange;
		double siblingChange = _siblingSize + (horizontalChange * -1);

		if (!IsValidColumnWidth(_cachedCurrentColumn, currentChange) || !IsValidColumnWidth(_cachedSiblingColumn, siblingChange)) return false;

		if (!IsStarColumn(_cachedCurrentColumn))
		{
			bool changed = SetColumnWidth(_cachedCurrentColumn, currentChange, GridUnitType.Pixel);
			if (!IsStarColumn(_cachedSiblingColumn)) changed = SetColumnWidth(_cachedSiblingColumn, siblingChange, GridUnitType.Pixel);
			return changed;
		}
		else if (!IsStarColumn(_cachedSiblingColumn))
		{
			return SetColumnWidth(_cachedSiblingColumn, siblingChange, GridUnitType.Pixel);
		}
		else
		{
			if (!IsValidColumnWidth(_cachedCurrentColumn, currentChange) || !IsValidColumnWidth(_cachedSiblingColumn, siblingChange)) return false;

			foreach (ColumnDefinition? col in _cachedResizable.ColumnDefinitions)
			{
				if (col == _cachedCurrentColumn) _ = SetColumnWidth(_cachedCurrentColumn, currentChange, GridUnitType.Star);
				else if (col == _cachedSiblingColumn) _ = SetColumnWidth(_cachedSiblingColumn, siblingChange, GridUnitType.Star);
				else if (IsStarColumn(col)) col.Width = new GridLength(col.ActualWidth, GridUnitType.Star);
			}
			return true;
		}
	}

	protected override bool OnDragVertical(double verticalChange)
	{
		if (_cachedCurrentRow == null || _cachedSiblingRow == null || _cachedResizable == null) return false;

		double currentChange = _currentSize + verticalChange;
		double siblingChange = _siblingSize + (verticalChange * -1);

		if (!IsValidRowHeight(_cachedCurrentRow, currentChange) || !IsValidRowHeight(_cachedSiblingRow, siblingChange)) return false;

		if (!IsStarRow(_cachedCurrentRow))
		{
			bool changed = SetRowHeight(_cachedCurrentRow, currentChange, GridUnitType.Pixel);
			if (!IsStarRow(_cachedSiblingRow)) changed = SetRowHeight(_cachedSiblingRow, siblingChange, GridUnitType.Pixel);
			return changed;
		}
		else if (!IsStarRow(_cachedSiblingRow))
		{
			return SetRowHeight(_cachedSiblingRow, siblingChange, GridUnitType.Pixel);
		}
		else
		{
			if (!IsValidRowHeight(_cachedCurrentRow, currentChange) || !IsValidRowHeight(_cachedSiblingRow, siblingChange)) return false;

			foreach (RowDefinition? row in _cachedResizable.RowDefinitions)
			{
				if (row == _cachedCurrentRow) _ = SetRowHeight(_cachedCurrentRow, currentChange, GridUnitType.Star);
				else if (row == _cachedSiblingRow) _ = SetRowHeight(_cachedSiblingRow, siblingChange, GridUnitType.Star);
				else if (IsStarRow(row)) row.Height = new GridLength(row.ActualHeight, GridUnitType.Star);
			}
			return true;
		}
	}

	private static bool IsStarColumn(ColumnDefinition def) => ((GridLength)def.GetValue(ColumnDefinition.WidthProperty)).IsStar;
	private static bool IsStarRow(RowDefinition def) => ((GridLength)def.GetValue(RowDefinition.HeightProperty)).IsStar;

	private bool SetColumnWidth(ColumnDefinition col, double width, GridUnitType unit)
	{
		double min = col.MinWidth;
		if (!double.IsNaN(min) && width < min) width = min;
		double max = col.MaxWidth;
		if (!double.IsNaN(max) && width > max) width = max;

		if (width > ActualWidth)
		{
			col.Width = new GridLength(width, unit);
			return true;
		}
		return false;
	}

	private bool IsValidColumnWidth(ColumnDefinition col, double width)
	{
		double min = col.MinWidth;
		if (!double.IsNaN(min) && width < min) return false;
		double max = col.MaxWidth;
		if (!double.IsNaN(max) && width > max) return false;
		return width > ActualWidth;
	}

	private bool SetRowHeight(RowDefinition row, double height, GridUnitType unit)
	{
		double min = row.MinHeight;
		if (!double.IsNaN(min) && height < min) height = min;
		double max = row.MaxHeight;
		if (!double.IsNaN(max) && height > max) height = max;

		if (height > ActualHeight)
		{
			row.Height = new GridLength(height, unit);
			return true;
		}
		return false;
	}

	private bool IsValidRowHeight(RowDefinition row, double height)
	{
		double min = row.MinHeight;
		if (!double.IsNaN(min) && height < min) return false;
		double max = row.MaxHeight;
		if (!double.IsNaN(max) && height > max) return false;
		return height > ActualHeight;
	}

	private int GetTargetIndex(int index) => _resizeBehavior switch
	{
		GridResizeBehavior.CurrentAndNext => index,
		GridResizeBehavior.PreviousAndNext => index - 1,
		GridResizeBehavior.PreviousAndCurrent => index - 1,
		_ => -1
	};

	private int GetSiblingIndex(int index) => _resizeBehavior switch
	{
		GridResizeBehavior.CurrentAndNext => index + 1,
		GridResizeBehavior.PreviousAndNext => index + 1,
		GridResizeBehavior.PreviousAndCurrent => index,
		_ => -1
	};

	private GridResizeDirection GetResizeDirection()
	{
		if (ResizeDirection != GridResizeDirection.Auto) return ResizeDirection;

		// Fallback checks
		if (HorizontalAlignment != HorizontalAlignment.Stretch) return GridResizeDirection.Columns;
		if (VerticalAlignment != VerticalAlignment.Stretch) return GridResizeDirection.Rows;
		return ActualWidth <= ActualHeight ? GridResizeDirection.Columns : GridResizeDirection.Rows;
	}

	private GridResizeBehavior GetResizeBehavior()
	{
		if (_resizeBehavior != GridResizeBehavior.BasedOnAlignment) return _resizeBehavior;

		if (_resizeDirection == GridResizeDirection.Columns)
		{
			return HorizontalAlignment switch
			{
				HorizontalAlignment.Left => GridResizeBehavior.PreviousAndCurrent,
				HorizontalAlignment.Stretch => GridResizeBehavior.PreviousAndCurrent,
				HorizontalAlignment.Right => GridResizeBehavior.CurrentAndNext,
				_ => GridResizeBehavior.PreviousAndNext
			};
		}
		else
		{
			return VerticalAlignment switch
			{
				VerticalAlignment.Top => GridResizeBehavior.PreviousAndCurrent,
				VerticalAlignment.Stretch => GridResizeBehavior.PreviousAndCurrent,
				VerticalAlignment.Bottom => GridResizeBehavior.CurrentAndNext,
				_ => GridResizeBehavior.PreviousAndNext
			};
		}
	}
}
