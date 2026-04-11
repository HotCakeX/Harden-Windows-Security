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

using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Data;
using Microsoft.UI.Xaml.Markup;

#pragma warning disable CA1515, CA1716

namespace CommonCore.ToolKits;

/// <summary>
/// <see cref="Case"/> is the value container for the <see cref="SwitchPresenter"/>.
/// </summary>
[ContentProperty(Name = nameof(Content))]
public partial class Case : DependencyObject
{
	/// <summary>
	/// Gets or sets the Content to display when this case is active.
	/// </summary>
	public object Content
	{
		get => GetValue(ContentProperty);
		set => SetValue(ContentProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="Content"/> property.
	/// </summary>
	public static readonly DependencyProperty ContentProperty =
		DependencyProperty.Register(nameof(Content), typeof(object), typeof(Case), new PropertyMetadata(null));

	/// <summary>
	/// Gets or sets a value indicating whether this is the default case to display when no values match the specified value in the <see cref="SwitchPresenter"/>. There should only be a single default case provided. Do not set the <see cref="TargetValue"/> property when setting <see cref="IsDefault"/> to <c>true</c>. Default is <c>false</c>.
	/// </summary>
	public bool IsDefault
	{
		get => (bool)GetValue(IsDefaultProperty);
		set => SetValue(IsDefaultProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="IsDefault"/> property.
	/// </summary>
	public static readonly DependencyProperty IsDefaultProperty =
		DependencyProperty.Register(nameof(IsDefault), typeof(bool), typeof(Case), new PropertyMetadata(false));

	/// <summary>
	/// Gets or sets the <see cref="TargetValue"/> that this case represents. If it matches the <see cref="SwitchPresenter.TargetValue"/> this case's <see cref="Content"/> will be displayed in the presenter.
	/// </summary>
	public object TargetValue
	{
		get => GetValue(TargetValueProperty);
		set => SetValue(TargetValueProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="TargetValue"/> property.
	/// </summary>
	public static readonly DependencyProperty TargetValueProperty =
		DependencyProperty.Register(nameof(TargetValue), typeof(object), typeof(Case), new PropertyMetadata(null));

	/// <summary>
	/// Initializes a new instance of the <see cref="Case"/> class.
	/// </summary>
	public Case() { }
}

/// <summary>
/// An collection of <see cref="Case"/> to help with XAML interop.
/// </summary>
public partial class CaseCollection : DependencyObjectCollection
{
	/// <summary>
	/// Initializes a new instance of the <see cref="CaseCollection"/> class.
	/// </summary>
	public CaseCollection() { }
}

/// <summary>
/// Internal helpers for use between <see cref="SwitchPresenter"/> and <see cref="SwitchConverter"/>.
/// The logic here is the main code which looks across a <see cref="CaseCollection"/> to match a specific <see cref="Case"/> with a given value while converting types based on the <see cref="SwitchPresenter.TargetType"/> property. This will handle <see cref="Enum"/> values as well as values compatible with the <see cref="XamlBindingHelper.ConvertValue(Type, object)"/> method.
/// </summary>
internal static partial class SwitchHelpers
{
	/// <summary>
	/// Extension method for a set of cases to find the matching case given its value and type.
	/// </summary>
	/// <param name="switchCases">The collection of <see cref="Case"/>s in a <see cref="CaseCollection"/></param>
	/// <param name="value">The value of the <see cref="Case"/> to find</param>
	/// <param name="targetType">The desired type of the result for automatic conversion</param>
	/// <returns>The discovered value, the default value, or <c>null</c></returns>
	internal static Case? EvaluateCases(this CaseCollection switchCases, object value, Type targetType)
	{
		if (switchCases == null || switchCases.Count == 0)
		{
			// If we have no cases, then we can't match anything.
			return null;
		}

		Case? xdefault = null;
		Case? newcase = null;

		foreach (DependencyObject item in switchCases)
		{
			if (item is Case xcase)
			{
				if (xcase.IsDefault)
				{
					// If there are multiple default cases provided, this will override and just grab the last one, the developer will have to fix this in their XAML. We call this out in the case comments.
					xdefault = xcase;
					continue;
				}

				if (CompareValues(value, xcase.TargetValue, targetType))
				{
					newcase = xcase;
					break;
				}
			}
		}

		if (newcase == null && xdefault != null)
		{
			// Inject default if we found one without matching anything
			newcase = xdefault;
		}

		return newcase;
	}

	/// <summary>
	/// Compares two values using the TargetType.
	/// </summary>
	/// <param name="compare">Our main value in our SwitchPresenter.</param>
	/// <param name="value">The value from the case to compare to.</param>
	/// <param name="targetType">The desired type of the result for automatic conversion.</param>
	/// <returns>true if the two values are equal</returns>
	internal static bool CompareValues(object compare, object value, Type targetType)
	{
		if (compare == null || value == null)
		{
			return compare == value;
		}

		if (targetType == null || (targetType == compare.GetType() && targetType == value.GetType()))
		{
			// Default direct object comparison or we're all the proper type
			return compare.Equals(value);
		}
		else if (compare.GetType() == targetType)
		{
			// If we have a TargetType and the first value is the right type
			// Then our 2nd value isn't, so convert to string and coerce.
			object valueBase2 = ConvertValue(targetType, value);

			return compare.Equals(valueBase2);
		}

		// Neither of our two values matches the type so
		// we'll convert both to a String and try and coerce it to the proper type.
		object compareBase = ConvertValue(targetType, compare);
		object valueBase = ConvertValue(targetType, value);

		return compareBase.Equals(valueBase);
	}

	/// <summary>
	/// Helper method to convert a value from a source type to a target type.
	/// </summary>
	/// <param name="targetType">The target type</param>
	/// <param name="value">The value to convert</param>
	/// <returns>The converted value</returns>
	internal static object ConvertValue(Type targetType, object value)
	{
		if (targetType.IsInstanceOfType(value))
		{
			return value;
		}
		else if (targetType.IsEnum && value is string str)
		{
			if (Enum.TryParse(targetType, str, ignoreCase: true, out object? result))
			{
				return result;
			}

			static object ThrowExceptionForKeyNotFound()
			{
				throw new InvalidOperationException("The requested enum value was not present in the provided type.");
			}

			return ThrowExceptionForKeyNotFound();
		}
		else
		{
			return XamlBindingHelper.ConvertValue(targetType, value);
		}
	}
}

/// <summary>
/// A helper <see cref="IValueConverter"/> which can automatically translate incoming data to a set of resulting values defined in XAML.
/// </summary>
[ContentProperty(Name = nameof(SwitchCases))]
public sealed partial class SwitchConverter : DependencyObject, IValueConverter
{
	/// <summary>
	/// Gets a value representing the collection of cases to evaluate.
	/// </summary>
	public CaseCollection SwitchCases => (CaseCollection)GetValue(SwitchCasesProperty);

	/// <summary>
	/// Identifies the <see cref="SwitchCases"/> property.
	/// </summary>
	public static readonly DependencyProperty SwitchCasesProperty =
		DependencyProperty.Register(nameof(SwitchCases), typeof(CaseCollection), typeof(SwitchConverter), new PropertyMetadata(null));

	/// <summary>
	/// Gets or sets a value indicating which type to first cast and compare provided values against.
	/// </summary>
	public Type TargetType
	{
		get => (Type)GetValue(TargetTypeProperty);
		set => SetValue(TargetTypeProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="TargetType"/> property.
	/// </summary>
	public static readonly DependencyProperty TargetTypeProperty =
		DependencyProperty.Register(nameof(TargetType), typeof(Type), typeof(SwitchConverter), new PropertyMetadata(null));

	/// <summary>
	/// Initializes a new instance of the <see cref="SwitchConverter"/> class.
	/// </summary>
	public SwitchConverter() => SetValue(SwitchCasesProperty, new CaseCollection());

	public object Convert(object value, Type targetType, object parameter, string language)
	{
		Case? result = SwitchCases.EvaluateCases(value, TargetType ?? targetType);

		return result?.Content!;
	}

	public object ConvertBack(object value, Type targetType, object parameter, string language)
	{
		throw new NotImplementedException();
	}
}

/// <summary>
/// The <see cref="SwitchPresenter"/> is a <see cref="ContentPresenter"/> which can allow a developer to mimic a <c>switch</c> statement within XAML.
/// When provided a set of <see cref="Case"/>s and a <see cref="TargetValue"/>, it will pick the matching <see cref="Case"/> with the corresponding <see cref="Case.TargetValue"/>.
/// </summary>
[ContentProperty(Name = nameof(SwitchCases))]
public sealed partial class SwitchPresenter : ContentPresenter
{
	/// <summary>
	/// Gets the current <see cref="Case"/> which is being displayed.
	/// </summary>
	public Case? CurrentCase
	{
		get => (Case?)GetValue(CurrentCaseProperty);
		private set => SetValue(CurrentCaseProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="CurrentCase"/> property.
	/// </summary>
	public static readonly DependencyProperty CurrentCaseProperty =
		DependencyProperty.Register(nameof(CurrentCase), typeof(Case), typeof(SwitchPresenter), new PropertyMetadata(null));

	/// <summary>
	/// Gets a value representing the collection of cases to evaluate.
	/// </summary>
	public CaseCollection SwitchCases => (CaseCollection)GetValue(SwitchCasesProperty);

	/// <summary>
	/// Identifies the <see cref="SwitchCases"/> property.
	/// </summary>
	public static readonly DependencyProperty SwitchCasesProperty =
		DependencyProperty.Register(nameof(SwitchCases), typeof(CaseCollection), typeof(SwitchPresenter), new PropertyMetadata(null, OnSwitchCasesPropertyChanged));

	/// <summary>
	/// Gets or sets a value indicating the value to compare all cases against. When this value is bound to and changes, the presenter will automatically evaluate cases and select the new appropriate content from the switch.
	/// </summary>
	public object TargetValue
	{
		get => GetValue(TargetValueProperty);
		set => SetValue(TargetValueProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="TargetValue"/> property.
	/// </summary>
	public static readonly DependencyProperty TargetValueProperty =
		DependencyProperty.Register(nameof(TargetValue), typeof(object), typeof(SwitchPresenter), new PropertyMetadata(null, OnTargetValuePropertyChanged));

	/// <summary>
	/// Gets or sets a value indicating which type to first cast and compare provided values against.
	/// </summary>
	public Type TargetType
	{
		get => (Type)GetValue(TargetTypeProperty);
		set => SetValue(TargetTypeProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="TargetType"/> property.
	/// </summary>
	public static readonly DependencyProperty TargetTypeProperty =
		DependencyProperty.Register(nameof(TargetType), typeof(Type), typeof(SwitchPresenter), new PropertyMetadata(null));

	private static void OnTargetValuePropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		// When our Switch's expression changes, re-evaluate.
		if (d is SwitchPresenter xswitch)
		{
			xswitch.EvaluateCases();
		}
	}

	private static void OnSwitchCasesPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		// If our collection somehow changes, we should re-evaluate.
		if (d is SwitchPresenter xswitch)
		{
			xswitch.EvaluateCases();
		}
	}

	/// <summary>
	/// Initializes a new instance of the <see cref="SwitchPresenter"/> class.
	/// </summary>
	public SwitchPresenter()
	{
		SetValue(SwitchCasesProperty, new CaseCollection());

		Loaded += SwitchPresenter_Loaded;
	}

	private void SwitchPresenter_Loaded(object sender, RoutedEventArgs e)
	{
		// In case we're in a template, we may have loaded cases later.
		EvaluateCases();
	}

	protected override void OnApplyTemplate()
	{
		base.OnApplyTemplate();

		EvaluateCases();
	}

	private void EvaluateCases()
	{
		if (CurrentCase?.TargetValue != null &&
			CurrentCase.TargetValue.Equals(TargetValue))
		{
			// If the current case we're on already matches our current value,
			// then we don't have any work to do.
			return;
		}

		Case? result = SwitchCases.EvaluateCases(TargetValue, TargetType);

		// Only bother changing things around if we actually have a new case. (this should handle prior null case as well)
		if (result != CurrentCase)
		{
			// If we don't have any cases or default, setting these to null is what we want to be blank again.
			Content = result?.Content;
			CurrentCase = result;
		}
	}
}
