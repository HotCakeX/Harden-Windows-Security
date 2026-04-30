// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// Source 1: https://github.com/CommunityToolkit/Windows/tree/main/components/SettingsControls/src
// Source 2: https://github.com/CommunityToolkit/Windows/tree/main/components/Triggers/src
// Source 3: https://github.com/CommunityToolkit/Windows/blob/main/components/Helpers/src/WeakEventListener.cs
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

using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Globalization;
using System.Linq;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Data;
using Windows.Foundation.Collections;

#pragma warning disable IDE0059, CA1005, CA1721

namespace CommonCore.ToolKits;

internal sealed partial class CornerRadiusConverter : IValueConverter
{
	public object Convert(object value, Type targetType, object parameter, string language)
	{
		if (value is CornerRadius cornerRadius)
		{
			return new CornerRadius(0, 0, cornerRadius.BottomRight, cornerRadius.BottomLeft);
		}
		else
		{
			return value;
		}
	}

	public object ConvertBack(object value, Type targetType, object parameter, string language) => value;
}

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

/// <summary>
/// A conditional state trigger that functions
/// based on the target control's width or height.
/// </summary>
internal sealed class ControlSizeTrigger : StateTriggerBase
{
	/// <summary>
	/// Gets or sets a value indicating
	/// whether this trigger will be active or not.
	/// </summary>
	public bool CanTrigger
	{
		get => (bool)GetValue(CanTriggerProperty);
		set => SetValue(CanTriggerProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="CanTrigger"/> DependencyProperty.
	/// </summary>
	public static readonly DependencyProperty CanTriggerProperty = DependencyProperty.Register(
		nameof(CanTrigger),
		typeof(bool),
		typeof(ControlSizeTrigger),
		new PropertyMetadata(true, (d, e) => ((ControlSizeTrigger)d).UpdateTrigger()));

	/// <summary>
	/// Gets or sets the max width at which to trigger.
	/// This value is exclusive, meaning this trigger
	/// could be active if the value is less than MaxWidth.
	/// </summary>
	public double MaxWidth
	{
		get => (double)GetValue(MaxWidthProperty);
		set => SetValue(MaxWidthProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="MaxWidth"/> DependencyProperty.
	/// </summary>
	public static readonly DependencyProperty MaxWidthProperty = DependencyProperty.Register(
		nameof(MaxWidth),
		typeof(double),
		typeof(ControlSizeTrigger),
		new PropertyMetadata(double.PositiveInfinity, (d, e) => ((ControlSizeTrigger)d).UpdateTrigger()));

	/// <summary>
	/// Gets or sets the min width at which to trigger.
	/// This value is inclusive, meaning this trigger
	/// could be active if the value is >= MinWidth.
	/// </summary>
	public double MinWidth
	{
		get => (double)GetValue(MinWidthProperty);
		set => SetValue(MinWidthProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="MinWidth"/> DependencyProperty.
	/// </summary>
	public static readonly DependencyProperty MinWidthProperty = DependencyProperty.Register(
		nameof(MinWidth),
		typeof(double),
		typeof(ControlSizeTrigger),
		new PropertyMetadata(0.0, (d, e) => ((ControlSizeTrigger)d).UpdateTrigger()));

	/// <summary>
	/// Gets or sets the max height at which to trigger.
	/// This value is exclusive, meaning this trigger
	/// could be active if the value is less than MaxHeight.
	/// </summary>
	public double MaxHeight
	{
		get => (double)GetValue(MaxHeightProperty);
		set => SetValue(MaxHeightProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="MaxHeight"/> DependencyProperty.
	/// </summary>
	public static readonly DependencyProperty MaxHeightProperty = DependencyProperty.Register(
		nameof(MaxHeight),
		typeof(double),
		typeof(ControlSizeTrigger),
		new PropertyMetadata(double.PositiveInfinity, (d, e) => ((ControlSizeTrigger)d).UpdateTrigger()));

	/// <summary>
	/// Gets or sets the min height at which to trigger.
	/// This value is inclusive, meaning this trigger
	/// could be active if the value is >= MinHeight.
	/// </summary>
	public double MinHeight
	{
		get => (double)GetValue(MinHeightProperty);
		set => SetValue(MinHeightProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="MinHeight"/> DependencyProperty.
	/// </summary>
	public static readonly DependencyProperty MinHeightProperty = DependencyProperty.Register(
		nameof(MinHeight),
		typeof(double),
		typeof(ControlSizeTrigger),
		new PropertyMetadata(0.0, (d, e) => ((ControlSizeTrigger)d).UpdateTrigger()));

	/// <summary>
	/// Gets or sets the element whose width will observed
	/// for the trigger.
	/// </summary>
	public FrameworkElement TargetElement
	{
		get => (FrameworkElement)GetValue(TargetElementProperty);
		set => SetValue(TargetElementProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="TargetElement"/> DependencyProperty.
	/// </summary>
	/// <remarks>
	/// Using a DependencyProperty as the backing store for TargetElement. This enables animation, styling, binding, etc.
	/// </remarks>
	public static readonly DependencyProperty TargetElementProperty = DependencyProperty.Register(
		nameof(TargetElement),
		typeof(FrameworkElement),
		typeof(ControlSizeTrigger),
		new PropertyMetadata(null, OnTargetElementPropertyChanged));

	/// <summary>
	/// Gets a value indicating whether the trigger is active.
	/// </summary>
	public bool IsActive { get; private set; }

	private static void OnTargetElementPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		((ControlSizeTrigger)d).UpdateTargetElement((FrameworkElement)e.OldValue, (FrameworkElement)e.NewValue);
	}

	// Handle event to get current values
	private void OnTargetElementSizeChanged(object sender, SizeChangedEventArgs e) => UpdateTrigger();

	private void UpdateTargetElement(FrameworkElement oldValue, FrameworkElement newValue)
	{
		oldValue?.SizeChanged -= OnTargetElementSizeChanged;
		newValue?.SizeChanged += OnTargetElementSizeChanged;
		UpdateTrigger();
	}

	// Logic to evaluate and apply trigger value
	private void UpdateTrigger()
	{
		if (TargetElement == null || !CanTrigger)
		{
			SetActive(false);
			return;
		}

		bool activate = MinWidth <= TargetElement.ActualWidth &&
						TargetElement.ActualWidth < MaxWidth &&
						MinHeight <= TargetElement.ActualHeight &&
						TargetElement.ActualHeight < MaxHeight;

		IsActive = activate;
		SetActive(activate);
	}
}

/// <summary>
/// Enables a state if the value is equal to another value
/// </summary>
/// <remarks>
/// <para>
/// Example: Trigger if a value is null
/// <code lang="xaml">
///     &lt;triggers:EqualsStateTrigger Value="{x:Bind MyObject, Mode=OneWay}" EqualTo="{x:Null}" />
/// </code>
/// </para>
/// </remarks>
internal sealed class IsEqualStateTrigger : StateTriggerBase
{
	private void UpdateTrigger() => SetActive(AreValuesEqual(Value, To, true));

	/// <summary>
	/// Gets or sets the value for comparison.
	/// </summary>
	public object Value
	{
		get => GetValue(ValueProperty); set => SetValue(ValueProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="Value"/> DependencyProperty
	/// </summary>
	public static readonly DependencyProperty ValueProperty =
		DependencyProperty.Register(nameof(Value), typeof(object), typeof(IsEqualStateTrigger), new PropertyMetadata(null, OnValuePropertyChanged));

	private static void OnValuePropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		IsEqualStateTrigger obj = (IsEqualStateTrigger)d;
		obj.UpdateTrigger();
	}

	/// <summary>
	/// Gets or sets the value to compare equality to.
	/// </summary>
	public object To
	{
		get => GetValue(ToProperty); set => SetValue(ToProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="To"/> DependencyProperty
	/// </summary>
	public static readonly DependencyProperty ToProperty = DependencyProperty.Register(nameof(To), typeof(object), typeof(IsEqualStateTrigger), new PropertyMetadata(null, OnValuePropertyChanged));

	internal static bool AreValuesEqual(object value1, object value2, bool convertType)
	{
		if (Equals(value1, value2))
		{
			return true;
		}

		// If they are the same type but fail with Equals check, don't bother with conversion.
		if (value1 is not null && value2 is not null && convertType
			&& value1.GetType() != value2.GetType())
		{
			// Try the conversion in both ways:
			return ConvertTypeEquals(value1, value2) || ConvertTypeEquals(value2, value1);
		}

		return false;
	}

	private static bool ConvertTypeEquals(object? value1, object value2)
	{
		// Let's see if we can convert:
		value1 = value2 is Enum
			? ConvertToEnum(value2.GetType(), value1)
			: Convert.ChangeType(value1, value2.GetType(), CultureInfo.InvariantCulture);

		return value2.Equals(value1);
	}

	private static object? ConvertToEnum(Type enumType, object? value)
	{
		// value cannot be the same type of enum now
		return value switch
		{
			string str => Enum.TryParse(enumType, str, out object? e) ? e : null,
			int or uint or byte or sbyte or long or ulong or short or ushort
				=> Enum.ToObject(enumType, value),
			_ => null
		};
	}
}

/// <summary>
/// Enables a state if an Object is <c>null</c> or a String/IEnumerable is empty
/// </summary>
internal sealed class IsNullOrEmptyStateTrigger : StateTriggerBase
{
	/// <summary>
	/// Gets or sets the value used to check for <c>null</c> or empty.
	/// </summary>
	public object Value
	{
		get => GetValue(ValueProperty); set => SetValue(ValueProperty, value);
	}

	/// <summary>
	/// Identifies the <see cref="Value"/> DependencyProperty
	/// </summary>
	public static readonly DependencyProperty ValueProperty =
		DependencyProperty.Register(nameof(Value), typeof(object), typeof(IsNullOrEmptyStateTrigger), new PropertyMetadata(null, OnValuePropertyChanged));

	/// <summary>
	/// Creates a new instance of <see cref="IsNullOrEmptyStateTrigger"/>.
	/// </summary>
	public IsNullOrEmptyStateTrigger() => UpdateTrigger();

	private void UpdateTrigger()
	{
		object val = Value;

		SetActive(IsNullOrEmpty(val));

		if (val == null)
		{
			return;
		}

		// Try to listen for various notification events
		// Starting with INorifyCollectionChanged
		if (val is INotifyCollectionChanged valNotifyCollection)
		{
#pragma warning disable CS8622 // Nullability of reference types in type of parameter doesn't match the target delegate (possibly because of nullability attributes).
			WeakEventListener<IsNullOrEmptyStateTrigger, object, NotifyCollectionChangedEventArgs> weakEvent = new(this)
			{
				OnEventAction = static (instance, source, args) => instance.SetActive(IsNullOrEmpty(source)),
				OnDetachAction = (weakEventListener) => valNotifyCollection.CollectionChanged -= weakEventListener.OnEvent
			};

			valNotifyCollection.CollectionChanged += weakEvent.OnEvent;
#pragma warning restore CS8622 // Nullability of reference types in type of parameter doesn't match the target delegate (possibly because of nullability attributes).
			return;
		}

		// Not INotifyCollectionChanged, try IObservableVector
		if (val is IObservableVector<object> valObservableVector)
		{
			WeakEventListener<IsNullOrEmptyStateTrigger, object, IVectorChangedEventArgs> weakEvent = new(this)
			{
				OnEventAction = static (instance, source, args) => instance.SetActive(IsNullOrEmpty(source)),
				OnDetachAction = (weakEventListener) => valObservableVector.VectorChanged -= weakEventListener.OnEvent
			};

			valObservableVector.VectorChanged += weakEvent.OnEvent;
			return;
		}

		// Not INotifyCollectionChanged, try IObservableMap
		if (val is IObservableMap<object, object> valObservableMap)
		{
			WeakEventListener<IsNullOrEmptyStateTrigger, object, IMapChangedEventArgs<object>> weakEvent = new(this)
			{
				OnEventAction = static (instance, source, args) => instance.SetActive(IsNullOrEmpty(source)),
				OnDetachAction = (weakEventListener) => valObservableMap.MapChanged -= weakEventListener.OnEvent
			};

			valObservableMap.MapChanged += weakEvent.OnEvent;
		}
	}

	private static void OnValuePropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		IsNullOrEmptyStateTrigger obj = (IsNullOrEmptyStateTrigger)d;
		obj.UpdateTrigger();
	}

	private static bool IsNullOrEmpty(object val)
	{
		if (val == null)
		{
			return true;
		}

		// Object is not null, check for an empty string
		if (val is string valString)
		{
			return valString.Length == 0;
		}

		// Object is not a string, check for an empty ICollection (faster)
		if (val is ICollection valCollection)
		{
			return valCollection.Count == 0;
		}

		// Object is not an ICollection, check for an empty IEnumerable
		if (val is IEnumerable valEnumerable)
		{
			foreach (object? item in valEnumerable)
			{
				// Found an item, not empty
				return false;
			}

			return true;
		}

		// Not null and not a known type to test for emptiness
		return false;
	}
}

/// <summary>
/// Implements a weak event listener that allows the owner to be garbage
/// collected if its only remaining link is an event handler.
/// </summary>
/// <typeparam name="TInstance">Type of instance listening for the event.</typeparam>
/// <typeparam name="TSource">Type of source for the event.</typeparam>
/// <typeparam name="TEventArgs">Type of event arguments for the event.</typeparam>
[EditorBrowsable(EditorBrowsableState.Never)]
internal sealed class WeakEventListener<TInstance, TSource, TEventArgs> where TInstance : class
{
	/// <summary>
	/// WeakReference to the instance listening for the event.
	/// </summary>
	private readonly WeakReference<TInstance> _weakInstance;

	/// <summary>
	/// Initializes a new instance of the <see cref="WeakEventListener{TInstance, TSource, TEventArgs}"/> class.
	/// </summary>
	/// <param name="instance">Instance subscribing to the event.</param>
	public WeakEventListener(TInstance instance)
	{
		ArgumentNullException.ThrowIfNull(instance);

		_weakInstance = new WeakReference<TInstance>(instance);
	}

	/// <summary>
	/// Gets or sets the method to call when the event fires.
	/// </summary>
	public Action<TInstance, TSource, TEventArgs>? OnEventAction { get; set; }

	/// <summary>
	/// Gets or sets the method to call when detaching from the event.
	/// </summary>
	public Action<WeakEventListener<TInstance, TSource, TEventArgs>>? OnDetachAction { get; set; }

	/// <summary>
	/// Handler for the subscribed event calls OnEventAction to handle it.
	/// </summary>
	/// <param name="source">Event source.</param>
	/// <param name="eventArgs">Event arguments.</param>
	public void OnEvent(TSource source, TEventArgs eventArgs)
	{
		if (_weakInstance.TryGetTarget(out TInstance? target))
		{
			// Call registered action
			OnEventAction?.Invoke(target, source, eventArgs);
		}
		else
		{
			// Detach from event
			Detach();
		}
	}

	/// <summary>
	/// Detaches from the subscribed event.
	/// </summary>
	public void Detach()
	{
		OnDetachAction?.Invoke(this);
		OnDetachAction = null;
	}
}
