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

using Microsoft.UI.Xaml;

namespace CommonCore.ToolKits;

internal sealed partial class PropertySizer : SizerBase
{
	private double _currentSize;

	internal PropertySizer() : base()
	{
		// Default properties specific to PropertySizer
		HorizontalAlignment = HorizontalAlignment.Stretch;
		VerticalAlignment = VerticalAlignment.Stretch;
	}

	public static readonly DependencyProperty BindingProperty =
		DependencyProperty.Register(nameof(Binding), typeof(double), typeof(PropertySizer), new PropertyMetadata(0d));

	public double Binding
	{
		get => (double)GetValue(BindingProperty);
		set => SetValue(BindingProperty, value);
	}

	public static readonly DependencyProperty MinimumProperty =
		DependencyProperty.Register(nameof(Minimum), typeof(double), typeof(PropertySizer), new PropertyMetadata(0d));

	public double Minimum
	{
		get => (double)GetValue(MinimumProperty);
		set => SetValue(MinimumProperty, value);
	}

	public static readonly DependencyProperty MaximumProperty =
		DependencyProperty.Register(nameof(Maximum), typeof(double), typeof(PropertySizer), new PropertyMetadata(0d));

	public double Maximum
	{
		get => (double)GetValue(MaximumProperty);
		set => SetValue(MaximumProperty, value);
	}

	public static readonly DependencyProperty IsDragInvertedProperty =
		DependencyProperty.Register(nameof(IsDragInverted), typeof(bool), typeof(PropertySizer), new PropertyMetadata(false));

	public bool IsDragInverted
	{
		get => (bool)GetValue(IsDragInvertedProperty);
		set => SetValue(IsDragInvertedProperty, value);
	}

	protected override void OnDragStarting()
	{
		if (ReadLocalValue(BindingProperty) != DependencyProperty.UnsetValue)
		{
			_currentSize = Binding;
		}
	}

	protected override bool OnDragHorizontal(double horizontalChange) => ApplySizeChange(horizontalChange);

	protected override bool OnDragVertical(double verticalChange) => ApplySizeChange(verticalChange);

	private bool ApplySizeChange(double change)
	{
		change = IsDragInverted ? -change : change;
		double newSize = _currentSize + change;

		// Check Minimum
		if (ReadLocalValue(MinimumProperty) != DependencyProperty.UnsetValue && newSize < Minimum)
		{
			SetValue(BindingProperty, Minimum);
		}
		// Check Maximum
		else if (ReadLocalValue(MaximumProperty) != DependencyProperty.UnsetValue && newSize > Maximum)
		{
			SetValue(BindingProperty, Maximum);
		}
		else
		{
			SetValue(BindingProperty, newSize);
		}

		return true;
	}
}
