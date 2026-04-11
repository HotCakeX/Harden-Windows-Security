// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// Source: https://github.com/CommunityToolkit/Windows/tree/main/components/Primitives/src
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
using System.Diagnostics;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Foundation;

#pragma warning disable CA1515

namespace CommonCore.ToolKits;

/// <summary>
/// Options for how to calculate the layout of <see cref="WrapGrid"/> items.
/// </summary>
public enum StretchChild
{
	/// <summary>
	/// Don't apply any additional stretching logic
	/// </summary>
	None,

	/// <summary>
	/// Make the last child stretch to fill the available space
	/// </summary>
	Last
}

/// <summary>
/// WrapPanel is a panel that position child control vertically or horizontally based on the orientation and when max width / max height is reached a new row (in case of horizontal) or column (in case of vertical) is created to fit new controls.
/// </summary>
public sealed partial class WrapPanel : Panel
{
	/// <summary>
	/// Gets or sets a uniform Horizontal distance (in pixels) between items when <see cref="Orientation"/> is set to Horizontal,
	/// or between columns of items when <see cref="Orientation"/> is set to Vertical.
	/// </summary>
	public double HorizontalSpacing
	{
		get => (double)GetValue(HorizontalSpacingProperty);
		set => SetValue(HorizontalSpacingProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="HorizontalSpacing"/> dependency property.
	/// </summary>
	public static readonly DependencyProperty HorizontalSpacingProperty =
		DependencyProperty.Register(
			nameof(HorizontalSpacing),
			typeof(double),
			typeof(WrapPanel),
			new PropertyMetadata(0d, LayoutPropertyChanged));

	/// <summary>
	/// Gets or sets a uniform Vertical distance (in pixels) between items when <see cref="Orientation"/> is set to Vertical,
	/// or between rows of items when <see cref="Orientation"/> is set to Horizontal.
	/// </summary>
	public double VerticalSpacing
	{
		get => (double)GetValue(VerticalSpacingProperty);
		set => SetValue(VerticalSpacingProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="VerticalSpacing"/> dependency property.
	/// </summary>
	public static readonly DependencyProperty VerticalSpacingProperty =
		DependencyProperty.Register(
			nameof(VerticalSpacing),
			typeof(double),
			typeof(WrapPanel),
			new PropertyMetadata(0d, LayoutPropertyChanged));

	/// <summary>
	/// Gets or sets the orientation of the WrapPanel.
	/// Horizontal means that child controls will be added horizontally until the width of the panel is reached, then a new row is added to add new child controls.
	/// Vertical means that children will be added vertically until the height of the panel is reached, then a new column is added.
	/// </summary>
	public Orientation Orientation
	{
		get => (Orientation)GetValue(OrientationProperty);
		set => SetValue(OrientationProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="Orientation"/> dependency property.
	/// </summary>
	public static readonly DependencyProperty OrientationProperty =
		DependencyProperty.Register(
			nameof(Orientation),
			typeof(Orientation),
			typeof(WrapPanel),
			new PropertyMetadata(Orientation.Horizontal, LayoutPropertyChanged));

	/// <summary>
	/// Gets or sets the distance between the border and its child object.
	/// </summary>
	/// <returns>
	/// The dimensions of the space between the border and its child as a Thickness value.
	/// Thickness is a structure that stores dimension values using pixel measures.
	/// </returns>
	public Thickness Padding
	{
		get => (Thickness)GetValue(PaddingProperty);
		set => SetValue(PaddingProperty, value);
	}

	/// <summary>
	/// Identifies the Padding dependency property.
	/// </summary>
	/// <returns>The identifier for the <see cref="Padding"/> dependency property.</returns>
	public static readonly DependencyProperty PaddingProperty =
		DependencyProperty.Register(
			nameof(Padding),
			typeof(Thickness),
			typeof(WrapPanel),
			new PropertyMetadata(default(Thickness), LayoutPropertyChanged));

	/// <summary>
	/// Gets or sets a value indicating how to arrange child items
	/// </summary>
	/// <remarks>
	/// When the available size provided to the panel is infinite (for example,
	/// when placed in a container with Auto sizing), the last child will not be
	/// stretched. Attempting to stretch in this scenario would cause the element
	/// to expand to an infinite size and result in a runtime exception.
	/// </remarks>
	public StretchChild StretchChild
	{
		get => (StretchChild)GetValue(StretchChildProperty);
		set => SetValue(StretchChildProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="StretchChild"/> dependency property.
	/// </summary>
	/// <returns>The identifier for the <see cref="StretchChild"/> dependency property.</returns>
	public static readonly DependencyProperty StretchChildProperty =
		DependencyProperty.Register(
			nameof(StretchChild),
			typeof(StretchChild),
			typeof(WrapPanel),
			new PropertyMetadata(StretchChild.None, LayoutPropertyChanged));

	private static void LayoutPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is WrapPanel wp)
		{
			wp.InvalidateMeasure();
			wp.InvalidateArrange();
		}
	}

	private readonly List<Row> _rows = new();

	protected override Size MeasureOverride(Size availableSize)
	{
		Size childAvailableSize = new(
			availableSize.Width - Padding.Left - Padding.Right,
			availableSize.Height - Padding.Top - Padding.Bottom);

		foreach (UIElement child in Children)
		{
			child.Measure(childAvailableSize);
		}

		Size requiredSize = UpdateRows(availableSize);
		return requiredSize;
	}

	protected override Size ArrangeOverride(Size finalSize)
	{
		if ((Orientation == Orientation.Horizontal && finalSize.Width < DesiredSize.Width) ||
			(Orientation == Orientation.Vertical && finalSize.Height < DesiredSize.Height))
		{
			// We haven't received our desired size. We need to refresh the rows.
			_ = UpdateRows(finalSize);
		}

		if (_rows.Count > 0)
		{
			// Now that we have all the data, we do the actual arrange pass
			int childIndex = 0;
			foreach (Row row in _rows)
			{
				foreach (UvRect rect in row.ChildrenRects)
				{
					UIElement child = Children[childIndex++];
					while (child.Visibility == Visibility.Collapsed)
					{
						// Collapsed children are not added into the rows,
						// we skip them.
						child = Children[childIndex++];
					}

					UvRect arrangeRect = new()
					{
						Position = rect.Position,
						Size = new UvMeasure { U = rect.Size.U, V = row.Size.V },
					};

					Rect finalRect = arrangeRect.ToRect(Orientation);
					child.Arrange(finalRect);
				}
			}
		}

		return finalSize;
	}

	private Size UpdateRows(Size availableSize)
	{
		_rows.Clear();

		UvMeasure paddingStart = new(Orientation, Padding.Left, Padding.Top);
		UvMeasure paddingEnd = new(Orientation, Padding.Right, Padding.Bottom);

		if (Children.Count == 0)
		{
			Size emptySize = paddingStart.Add(paddingEnd).ToSize(Orientation);
			return emptySize;
		}

		UvMeasure parentMeasure = new(Orientation, availableSize.Width, availableSize.Height);
		UvMeasure spacingMeasure = new(Orientation, HorizontalSpacing, VerticalSpacing);
		UvMeasure position = new(Orientation, Padding.Left, Padding.Top);

		Row currentRow = new(new List<UvRect>(), default);
		UvMeasure finalMeasure = new(Orientation, width: 0.0, height: 0.0);

		void Arrange(UIElement child, bool isLast = false)
		{
			if (child.Visibility == Visibility.Collapsed)
			{
				return; // if an item is collapsed, avoid adding the spacing
			}

			UvMeasure desiredMeasure = new(Orientation, child.DesiredSize);
			if ((desiredMeasure.U + position.U + paddingEnd.U) > parentMeasure.U || position.U >= parentMeasure.U)
			{
				// next row!
				position.U = paddingStart.U;
				position.V += currentRow.Size.V + spacingMeasure.V;

				_rows.Add(currentRow);
				currentRow = new Row(new List<UvRect>(), default);
			}

			// Stretch the last item to fill the available space
			// if the parent measure is not infinite
			if (isLast && !double.IsInfinity(parentMeasure.U))
			{
				desiredMeasure.U = parentMeasure.U - position.U;
			}

			currentRow.Add(position, desiredMeasure);

			// adjust the location for the next items
			position.U += desiredMeasure.U + spacingMeasure.U;
			finalMeasure.U = Math.Max(finalMeasure.U, position.U);
		}

		int lastIndex = Children.Count - 1;
		for (int i = 0; i < lastIndex; i++)
		{
			Arrange(Children[i]);
		}

		Arrange(Children[lastIndex], StretchChild == StretchChild.Last);
		if (currentRow.ChildrenRects.Count > 0)
		{
			_rows.Add(currentRow);
		}

		if (_rows.Count == 0)
		{
			Size emptySize = paddingStart.Add(paddingEnd).ToSize(Orientation);
			return emptySize;
		}

		// Get max V here before computing final rect
		UvRect lastRowRect = _rows.Last().Rect;
		finalMeasure.V = lastRowRect.Position.V + lastRowRect.Size.V;
		Size finalRect = finalMeasure.Add(paddingEnd).ToSize(Orientation);
		return finalRect;
	}

	[DebuggerDisplay("U = {U} V = {V}")]
	private struct UvMeasure
	{
		internal static UvMeasure Zero => default;

		internal double U { get; set; }

		internal double V { get; set; }

		public UvMeasure(Orientation orientation, Size size) : this(orientation, size.Width, size.Height) { }

		public UvMeasure(Orientation orientation, double width, double height)
		{
			if (orientation == Orientation.Horizontal)
			{
				U = width;
				V = height;
			}
			else
			{
				U = height;
				V = width;
			}
		}

		public UvMeasure Add(double u, double v) => new() { U = U + u, V = V + v };

		public UvMeasure Add(UvMeasure measure) => Add(measure.U, measure.V);

		public readonly Size ToSize(Orientation orientation) => orientation == Orientation.Horizontal ? new Size(U, V) : new Size(V, U);
	}

	private struct UvRect
	{
		public UvMeasure Position { get; set; }

		public UvMeasure Size { get; set; }

		public readonly Rect ToRect(Orientation orientation) => orientation switch
		{
			Orientation.Vertical => new Rect(Position.V, Position.U, Size.V, Size.U),
			Orientation.Horizontal => new Rect(Position.U, Position.V, Size.U, Size.V),
			_ => ThrowArgumentException()
		};

		private static Rect ThrowArgumentException() => throw new ArgumentException("The input orientation is not valid.");
	}

	private struct Row(List<WrapPanel.UvRect> childrenRects, WrapPanel.UvMeasure size)
	{
		public List<UvRect> ChildrenRects { get; } = childrenRects;

		public UvMeasure Size { get; set; } = size;

		public UvRect Rect => ChildrenRects.Count > 0 ?
			new UvRect { Position = ChildrenRects[0].Position, Size = Size } :
			new UvRect { Position = UvMeasure.Zero, Size = Size };

		public void Add(UvMeasure position, UvMeasure size)
		{
			ChildrenRects.Add(new UvRect { Position = position, Size = size });
			Size = new UvMeasure
			{
				U = position.U + size.U,
				V = Math.Max(Size.V, size.V),
			};
		}
	}
}
