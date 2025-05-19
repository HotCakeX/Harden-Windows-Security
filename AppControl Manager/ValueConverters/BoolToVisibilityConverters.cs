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
using Microsoft.UI.Xaml.Data;
using System;

namespace AppControlManager.ValueConverters;

/// <summary>
/// Converts a boolean value to a Visibility value (Visible or Collapsed).
/// </summary>
public class BoolToVisibilityConverter : IValueConverter
{
    /// <summary>
    /// Converts a boolean value to a Visibility value.
    /// </summary>
    /// <param name="value">The boolean value to convert.</param>
    /// <param name="targetType">The type of the target property.</param>
    /// <param name="parameter">An optional parameter (not used).</param>
    /// <param name="language">The language (not used).</param>
    /// <returns>Visibility.Visible if value is true, Visibility.Collapsed otherwise.</returns>
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        return value is bool boolValue && boolValue ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>
    /// Converts a Visibility value back to a boolean value.
    /// </summary>
    /// <param name="value">The Visibility value to convert.</param>
    /// <param name="targetType">The type of the target property.</param>
    /// <param name="parameter">An optional parameter (not used).</param>
    /// <param name="language">The language (not used).</param>
    /// <returns>true if value is Visibility.Visible, false otherwise.</returns>
    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        return value is Visibility visibility && visibility == Visibility.Visible;
    }
}

/// <summary>
/// Converts a boolean value to a Visibility value (Collapsed or Visible).
/// </summary>
public class BoolToVisibilityInverterConverter : IValueConverter
{
    /// <summary>
    /// Converts a boolean value to a Visibility value (inverted).
    /// </summary>
    /// <param name="value">The boolean value to convert.</param>
    /// <param name="targetType">The type of the target property.</param>
    /// <param name="parameter">An optional parameter (not used).</param>
    /// <param name="language">The language (not used).</param>
    /// <returns>Visibility.Collapsed if value is true, Visibility.Visible otherwise.</returns>
    public object Convert(object value, Type targetType, object parameter, string language)
    {
        return value is bool boolValue && boolValue ? Visibility.Collapsed : Visibility.Visible;
    }

    /// <summary>
    /// Converts a Visibility value back to a boolean value (inverted).
    /// </summary>
    /// <param name="value">The Visibility value to convert.</param>
    /// <param name="targetType">The type of the target property.</param>
    /// <param name="parameter">An optional parameter (not used).</param>
    /// <param name="language">The language (not used).</param>
    /// <returns>true if value is Visibility.Collapsed, false otherwise.</returns>
    public object ConvertBack(object value, Type targetType, object parameter, string language)
    {
        return value is Visibility visibility && visibility == Visibility.Collapsed;
    }
}