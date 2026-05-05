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

namespace CommonCore.ToolKits;

internal static class ResourceDictionaryExtensions
{
	/// <summary>
	/// Copies  the <see cref="ResourceDictionary"/> provided as a parameter into the calling dictionary, includes overwriting the source location, theme dictionaries, and merged dictionaries.
	/// </summary>
	/// <param name="destination">ResourceDictionary to copy values to.</param>
	/// <param name="source">ResourceDictionary to copy values from.</param>
	internal static void CopyFrom(this ResourceDictionary destination, ResourceDictionary source)
	{
		if (source.Source != null)
		{
			destination.Source = source.Source;
		}
		else
		{
			// Clone theme dictionaries
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

			// Clone merged dictionaries
			if (source.MergedDictionaries != null)
			{
				foreach (ResourceDictionary? mergedResource in source.MergedDictionaries)
				{
					ResourceDictionary themeDictionary = new();
					themeDictionary.CopyFrom(mergedResource);
					destination.MergedDictionaries.Add(themeDictionary);
				}
			}

			// Clone all contents
			foreach (KeyValuePair<object, object> item in source)
			{
				destination[item.Key] = item.Value;
			}
		}
	}
}

/// <summary>
/// Helper class for setting a ResourceDictionary on a Style.
/// </summary>
internal static partial class StyleExtensions
{
	// Used to distinct normal ResourceDictionary and the one we add.
	private sealed partial class StyleExtensionResourceDictionary : ResourceDictionary
	{
	}

	/// <summary>
	/// Get a ResourceDictionary from a Style.
	/// </summary>
	public static ResourceDictionary GetResources(Style obj) => (ResourceDictionary)obj.GetValue(ResourcesProperty);

	/// <summary>
	/// Set the <see cref="ResourcesProperty"/> on a Style to a ResourceDictionary value.
	/// </summary>
	public static void SetResources(Style obj, ResourceDictionary value) => obj.SetValue(ResourcesProperty, value);

	/// <summary>
	/// Attached property to set a Style to a ResourceDictionary value.
	/// </summary>
	public static readonly DependencyProperty ResourcesProperty = DependencyProperty.RegisterAttached("Resources", typeof(ResourceDictionary), typeof(StyleExtensions), new PropertyMetadata(null, ResourcesChanged));

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
			// Remove the existing resource dictionary
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
			// Only force if the style was applied after the control was loaded
			ForceControlToReloadThemeResources(frameworkElement);
		}
	}

	private static void ForceControlToReloadThemeResources(FrameworkElement frameworkElement)
	{
		// To force the refresh of all resource references.
		// Note: Doesn't work when in high-contrast.
		ElementTheme currentRequestedTheme = frameworkElement.RequestedTheme;
		frameworkElement.RequestedTheme = currentRequestedTheme == ElementTheme.Dark
			? ElementTheme.Light
			: ElementTheme.Dark;
		frameworkElement.RequestedTheme = currentRequestedTheme;
	}
}
