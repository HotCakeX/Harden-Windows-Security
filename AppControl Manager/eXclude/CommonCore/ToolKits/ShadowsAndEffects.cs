// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// Source: https://github.com/CommunityToolkit/Windows
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

/*
Sourced from the following files:

"Windows\components\Extensions\src\Shadows\AttachedShadowBase.cs"
"Windows\components\Extensions\src\Shadows\IAttachedShadow.cs"
"Windows\components\Media\src\Shadows\AttachedCardShadow.cs"
"Windows\components\Extensions\src\Shadows\Effects.cs"
"Windows\components\Media\src\Effects\BlurEffect.cs"
"Windows\components\Media\src\Pipelines\PipelineBuilder.Effects.Internals.cs"
"Windows\components\Media\src\Extensions\System.Collections.Generic\GenericExtensions.cs"
"Windows\components\Media\src\Visuals\PipelineVisualFactory.cs"
"Windows\components\Media\src\Visuals\PipelineVisualFactoryBase.cs"
"Windows\components\Media\src\Visuals\AttachedVisualFactoryBase.cs"
"Windows\components\Media\src\Pipelines\PipelineBuilder.Initialization.cs"
"Windows\components\Media\src\Helpers\Cache\CompositionObjectCache{T}.cs"
"Windows\components\Media\src\Extensions\UIElementExtensions.cs"
 */

using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.Globalization;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using Microsoft.Graphics.Canvas.Effects;
using Microsoft.Graphics.Canvas.Geometry;
using Microsoft.UI;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Windows.Graphics.Effects;
using Windows.UI;

#pragma warning disable CA1062, CA1515, CA1724, CA1716, CA2227

namespace CommonCore.ToolKits;

/// <summary>
/// Interface representing the common properties found within an attached shadow, <see cref="AttachedShadowBase"/> for implementation.
/// </summary>
public interface IAttachedShadow
{
	/// <summary>
	/// Gets or sets the blur radius of the shadow.
	/// </summary>
	double BlurRadius { get; set; }

	/// <summary>
	/// Gets or sets the opacity of the shadow.
	/// </summary>
	double Opacity { get; set; }

	/// <summary>
	/// Gets or sets the offset of the shadow as a string representation of a <see cref="System.Numerics.Vector3"/>.
	/// </summary>
	string Offset { get; set; }

	/// <summary>
	/// Gets or sets the color of the shadow.
	/// </summary>
	Color Color { get; set; }

	/// <summary>
	/// Get the associated <see cref="AttachedShadowElementContext"/> for the specified <see cref="FrameworkElement"/>.
	/// </summary>
	/// <returns>The <see cref="AttachedShadowElementContext"/> for the element.</returns>
	AttachedShadowElementContext? GetElementContext(FrameworkElement element);

	/// <summary>
	/// Gets an enumeration over the current list of <see cref="AttachedShadowElementContext"/> of elements using this shared shadow definition.
	/// </summary>
	/// <returns>Enumeration of <see cref="AttachedShadowElementContext"/> objects.</returns>
	IEnumerable<AttachedShadowElementContext> EnumerateElementContexts();
}


/// <summary>
/// The base class for attached shadows.
/// </summary>
public abstract partial class AttachedShadowBase : DependencyObject, IAttachedShadow
{
	/// <summary>
	/// The <see cref="DependencyProperty"/> for <see cref="BlurRadius"/>.
	/// </summary>
	public static readonly DependencyProperty BlurRadiusProperty =
		DependencyProperty.Register(nameof(BlurRadius), typeof(double), typeof(AttachedShadowBase), new PropertyMetadata(12d, OnDependencyPropertyChanged));

	/// <summary>
	/// The <see cref="DependencyProperty"/> for <see cref="Color"/>.
	/// </summary>
	public static readonly DependencyProperty ColorProperty =
		DependencyProperty.Register(nameof(Color), typeof(Color), typeof(AttachedShadowBase), new PropertyMetadata(Colors.Black, OnDependencyPropertyChanged));

	/// <summary>
	/// The <see cref="DependencyProperty"/> for <see cref="Opacity"/>.
	/// </summary>
	public static readonly DependencyProperty OffsetProperty =
		DependencyProperty.Register(
			nameof(Offset),
			typeof(string), // Needs to be string as we can't convert in XAML natively from Vector3, see https://github.com/microsoft/microsoft-ui-xaml/issues/3896
			typeof(AttachedShadowBase),
			new PropertyMetadata(string.Empty, OnDependencyPropertyChanged));

	/// <summary>
	/// The <see cref="DependencyProperty"/> for <see cref="Opacity"/>
	/// </summary>
	public static readonly DependencyProperty OpacityProperty =
		DependencyProperty.Register(nameof(Opacity), typeof(double), typeof(AttachedShadowBase), new PropertyMetadata(1d, OnDependencyPropertyChanged));

	/// <summary>
	/// Gets or sets the collection of <see cref="AttachedShadowElementContext"/> for each element this <see cref="AttachedShadowBase"/> is connected to.
	/// </summary>
	private ConditionalWeakTable<FrameworkElement, AttachedShadowElementContext> ShadowElementContextTable { get; set; } = new();

	public double BlurRadius
	{
		get => (double)GetValue(BlurRadiusProperty);
		set => SetValue(BlurRadiusProperty, value);
	}

	public double Opacity
	{
		get => (double)GetValue(OpacityProperty);
		set => SetValue(OpacityProperty, value);
	}

	public string Offset
	{
		get => (string)GetValue(OffsetProperty);
		set => SetValue(OffsetProperty, value);
	}

	public Color Color
	{
		get => (Color)GetValue(ColorProperty);
		set => SetValue(ColorProperty, value);
	}

	/// <summary>
	/// Gets a value indicating whether or not OnSizeChanged should be called when <see cref="FrameworkElement.SizeChanged"/> is fired.
	/// </summary>
	protected internal abstract bool SupportsOnSizeChangedEvent { get; }

	/// <summary>
	/// Use this method as the <see cref="PropertyChangedCallback"/> for <see cref="DependencyProperty">DependencyProperties</see> in derived classes.
	/// </summary>
	protected static void OnDependencyPropertyChanged(object sender, DependencyPropertyChangedEventArgs args)
	{
		(sender as AttachedShadowBase)?.CallPropertyChangedForEachElement(args.Property, args.OldValue, args.NewValue);
	}

	internal void ConnectElement(FrameworkElement element)
	{
		if (ShadowElementContextTable.TryGetValue(element, out AttachedShadowElementContext? _))
		{
			return;
		}

		AttachedShadowElementContext context = new(this, element);
		ShadowElementContextTable.Add(element, context);
	}

	internal void DisconnectElement(FrameworkElement element)
	{
		if (ShadowElementContextTable.TryGetValue(element, out AttachedShadowElementContext? context))
		{
			context.DisconnectFromElement();
			_ = ShadowElementContextTable.Remove(element);
		}
	}

	/// <summary>
	/// Override to handle when the <see cref="AttachedShadowElementContext"/> for an element is being initialized.
	/// </summary>
	/// <param name="context">The <see cref="AttachedShadowElementContext"/> that is being initialized.</param>
	protected internal virtual void OnElementContextInitialized(AttachedShadowElementContext context)
	{
		OnPropertyChanged(context, OpacityProperty, Opacity, Opacity);
		OnPropertyChanged(context, BlurRadiusProperty, BlurRadius, BlurRadius);
		OnPropertyChanged(context, ColorProperty, Color, Color);
		OnPropertyChanged(context, OffsetProperty, Offset, Offset);
		UpdateShadowClip(context);
		UpdateShadowMask(context);
		SetElementChildVisual(context);
	}

	/// <summary>
	/// Override to handle when the <see cref="AttachedShadowElementContext"/> for an element is being uninitialized.
	/// </summary>
	/// <param name="context">The <see cref="AttachedShadowElementContext"/> that is being uninitialized.</param>
	protected internal virtual void OnElementContextUninitialized(AttachedShadowElementContext context)
	{
		ElementCompositionPreview.SetElementChildVisual(context.Element, null);
		context.ClearAndDisposeResources();
	}

	public AttachedShadowElementContext? GetElementContext(FrameworkElement element)
	{
		if (ShadowElementContextTable.TryGetValue(element, out AttachedShadowElementContext? context))
		{
			return context;
		}

		return null;
	}

	public IEnumerable<AttachedShadowElementContext> EnumerateElementContexts()
	{
		foreach (KeyValuePair<FrameworkElement, AttachedShadowElementContext> kvp in ShadowElementContextTable)
		{
			yield return kvp.Value;
		}
	}

	/// <summary>
	/// Sets <see cref="AttachedShadowElementContext.SpriteVisual"/> as a child visual on <see cref="AttachedShadowElementContext.Element"/>
	/// </summary>
	/// <param name="context">The <see cref="AttachedShadowElementContext"/> this operation will be performed on.</param>
	protected virtual void SetElementChildVisual(AttachedShadowElementContext context)
	{
		ElementCompositionPreview.SetElementChildVisual(context.Element, context.SpriteVisual);
	}

	private void CallPropertyChangedForEachElement(DependencyProperty property, object oldValue, object newValue)
	{
		foreach (KeyValuePair<FrameworkElement, AttachedShadowElementContext> context in ShadowElementContextTable)
		{
			if (context.Value.IsInitialized)
			{
				OnPropertyChanged(context.Value, property, oldValue, newValue);
			}
		}
	}

	/// <summary>
	/// Get a <see cref="CompositionBrush"/> in the shape of the element that is casting the shadow.
	/// </summary>
	/// <returns>A <see cref="CompositionBrush"/> representing the shape of an element.</returns>
	protected virtual CompositionBrush? GetShadowMask(AttachedShadowElementContext context)
	{
		return null;
	}

	/// <summary>
	/// Get the <see cref="CompositionClip"/> for the shadow's <see cref="SpriteVisual"/>
	/// </summary>
	/// <returns>A <see cref="CompositionClip"/> for the extent of the shadowed area.</returns>
	protected virtual CompositionClip? GetShadowClip(AttachedShadowElementContext context)
	{
		return null;
	}

	/// <summary>
	/// Update the mask that gives the shadow its shape.
	/// </summary>
	protected void UpdateShadowMask(AttachedShadowElementContext context)
	{
		if (!context.IsInitialized || context.Shadow == null)
		{
			return;
		}

		context.Shadow.Mask = GetShadowMask(context);
	}

	/// <summary>
	/// Update the clipping on the shadow's <see cref="SpriteVisual"/>.
	/// </summary>
	protected void UpdateShadowClip(AttachedShadowElementContext context)
	{
		if (!context.IsInitialized || context.SpriteVisual == null)
		{
			return;
		}

		context.SpriteVisual.Clip = GetShadowClip(context);
	}

	/// <summary>
	/// This method is called when a DependencyProperty is changed.
	/// </summary>
	protected virtual void OnPropertyChanged(AttachedShadowElementContext context, DependencyProperty property, object oldValue, object newValue)
	{
		if (!context.IsInitialized || context.Shadow == null)
		{
			return;
		}

		if (property == BlurRadiusProperty)
		{
			context.Shadow.BlurRadius = (float)(double)newValue;
		}
		else if (property == OpacityProperty)
		{
			context.Shadow.Opacity = (float)(double)newValue;
		}
		else if (property == ColorProperty && newValue is Color color)
		{
			context.Shadow.Color = color;
		}
		else if (property == OffsetProperty && newValue is string value)
		{
			context.Shadow.Offset = ShadowHelpers.ToVector3(value);
		}
	}

	/// <summary>
	/// This method is called when the element size changes, and <see cref="SupportsOnSizeChangedEvent"/> = <see cref="bool">true</see>.
	/// </summary>
	/// <param name="context">The <see cref="AttachedShadowElementContext"/> for the <see cref="FrameworkElement"/> firing its SizeChanged event</param>
	/// <param name="newSize">The new size of the <see cref="FrameworkElement"/></param>
	/// <param name="previousSize">The previous size of the <see cref="FrameworkElement"/></param>
	protected internal virtual void OnSizeChanged(AttachedShadowElementContext context, Size newSize, Size previousSize)
	{
	}
}

/// <summary>
/// Class which maintains the context of a <see cref="DropShadow"/> for a particular <see cref="UIElement"/> linked to the definition of that shadow provided by the <see cref="AttachedShadowBase"/> implementation being used.
/// </summary>
public sealed class AttachedShadowElementContext
{
	private bool _isConnected;

	private readonly Dictionary<string, object> _resources = new();

	internal long? VisibilityToken { get; set; }

	/// <summary>
	/// Gets a value indicating whether or not this <see cref="AttachedShadowElementContext"/> has been initialized.
	/// </summary>
	public bool IsInitialized { get; private set; }

	/// <summary>
	/// Gets the <see cref="AttachedShadowBase"/> that contains this <see cref="AttachedShadowElementContext"/>.
	/// </summary>
	public AttachedShadowBase Parent { get; private set; }

	/// <summary>
	/// Gets the <see cref="FrameworkElement"/> this instance is attached to
	/// </summary>
	public FrameworkElement Element { get; private set; }

	/// <summary>
	/// Gets the <see cref="Visual"/> for the <see cref="FrameworkElement"/> this instance is attached to.
	/// </summary>
	public Visual? ElementVisual { get; private set; }

	/// <summary>
	/// Gets the <see cref="Windows.UI.Composition.Compositor"/> for this instance.
	/// </summary>
	public Compositor? Compositor { get; private set; }

	/// <summary>
	/// Gets the <see cref="SpriteVisual"/> that contains the <see cref="DropShadow">shadow</see> for this instance
	/// </summary>
	public SpriteVisual? SpriteVisual { get; private set; }

	/// <summary>
	/// Gets the <see cref="DropShadow"/> that is rendered on this instance's <see cref="Element"/>
	/// </summary>
	public DropShadow? Shadow { get; private set; }

	/// <summary>
	/// Connects a <see cref="FrameworkElement"/> to its parent <see cref="AttachedShadowBase"/> definition.
	/// </summary>
	/// <param name="parent">The <see cref="AttachedShadowBase"/> that is using this context.</param>
	/// <param name="element">The <see cref="FrameworkElement"/> that a shadow is being attached to.</param>
	internal AttachedShadowElementContext(AttachedShadowBase parent, FrameworkElement element)
	{
		if (_isConnected)
		{
			throw new InvalidOperationException("This AttachedShadowElementContext has already been connected to an element");
		}

		_isConnected = true;
		Parent = parent ?? throw new ArgumentNullException(nameof(parent));
		Element = element ?? throw new ArgumentNullException(nameof(element));
		Element.Loaded += OnElementLoaded;
		Element.Unloaded += OnElementUnloaded;
		Initialize();
	}

	internal void DisconnectFromElement()
	{
		if (!_isConnected)
		{
			return;
		}

		Uninitialize();

		Element.Loaded -= OnElementLoaded;
		Element.Unloaded -= OnElementUnloaded;

		_isConnected = false;
	}

	private void Initialize(bool forceIfNotLoaded = false)
	{
		if (IsInitialized || !_isConnected || (!Element.IsLoaded && !forceIfNotLoaded))
		{
			return;
		}

		IsInitialized = true;

		ElementVisual = ElementCompositionPreview.GetElementVisual(Element);
		Compositor = ElementVisual.Compositor;

		Shadow = Compositor.CreateDropShadow();

		SpriteVisual = Compositor.CreateSpriteVisual();
		SpriteVisual.RelativeSizeAdjustment = Vector2.One;
		SpriteVisual.Shadow = Shadow;

		if (Parent.SupportsOnSizeChangedEvent)
		{
			Element.SizeChanged += OnElementSizeChanged;
		}

		Parent.OnElementContextInitialized(this);
	}

	private void Uninitialize()
	{
		if (!IsInitialized)
		{
			return;
		}

		IsInitialized = false;

		if (Element != null)
		{
			ElementCompositionPreview.SetElementChildVisual(Element, null);
			Element.SizeChanged -= OnElementSizeChanged;
		}

		Parent.OnElementContextUninitialized(this);

		if (SpriteVisual != null)
		{
			SpriteVisual.Shadow = null;
			SpriteVisual.Dispose();
		}

		Shadow?.Dispose();

		SpriteVisual = null;
		Shadow = null;
		ElementVisual = null;
	}

	private void OnElementUnloaded(object sender, RoutedEventArgs e)
	{
		Uninitialize();
	}

	private void OnElementLoaded(object sender, RoutedEventArgs e)
	{
		Initialize();
	}

	private void OnElementSizeChanged(object sender, SizeChangedEventArgs e)
	{
		Parent.OnSizeChanged(this, e.NewSize, e.PreviousSize);
	}

	/// <summary>
	/// Adds a resource to this instance's resource dictionary with the specified key
	/// </summary>
	/// <typeparam name="T">The type of the resource being added.</typeparam>
	/// <param name="key">Key to use to lookup the resource later.</param>
	/// <param name="resource">Object to store within the resource dictionary.</param>
	/// <returns>The added resource</returns>
	public T AddResource<T>(string key, T resource)
		where T : notnull
	{
		if (_resources.ContainsKey(key))
		{
			_resources[key] = resource;
		}
		else
		{
			_resources.Add(key, resource);
		}

		return resource;
	}

	/// <summary>
	/// Retrieves a resource with the specified key and type if it exists
	/// </summary>
	/// <typeparam name="T">The type of the resource being retrieved.</typeparam>
	/// <param name="key">Key to use to lookup the resource.</param>
	/// <param name="resource">Object to retrieved from the resource dictionary or default value.</param>
	/// <returns>True if the resource exists, false otherwise</returns>
	public bool TryGetResource<T>(string key, out T? resource)
	{
		if (_resources.TryGetValue(key, out var objResource) && objResource is T tResource)
		{
			resource = tResource;
			return true;
		}

		resource = default;
		return false;
	}

	/// <summary>
	/// Retries a resource with the specified key and type
	/// </summary>
	/// <typeparam name="T">The type of the resource being retrieved.</typeparam>
	/// <param name="key">Key to use to lookup the resource.</param>
	/// <returns>The resource if available, otherwise default value.</returns>
	public T? GetResource<T>(string key)
	{
		if (TryGetResource(key, out T? resource))
		{
			return resource;
		}

		return default;
	}

	/// <summary>
	/// Removes an existing resource with the specified key and type
	/// </summary>
	/// <typeparam name="T">The type of the resource being removed.</typeparam>
	/// <param name="key">Key to use to lookup the resource.</param>
	/// <returns>The resource that was removed, if any</returns>
	public T? RemoveResource<T>(string key)
	{
		if (_resources.TryGetValue(key, out var objResource))
		{
			_ = _resources.Remove(key);
			if (objResource is T resource)
			{
				return resource;
			}
		}

		return default;
	}

	/// <summary>
	/// Removes an existing resource with the specified key and type, and <see cref="IDisposable.Dispose">disposes</see> it
	/// </summary>
	/// <typeparam name="T">The type of the resource being removed.</typeparam>
	/// <param name="key">Key to use to lookup the resource.</param>
	/// <returns>The resource that was removed, if any</returns>
	public T? RemoveAndDisposeResource<T>(string key)
		where T : IDisposable
	{
		if (_resources.TryGetValue(key, out var objResource))
		{
			_ = _resources.Remove(key);
			if (objResource is T resource)
			{
				resource.Dispose();
				return resource;
			}
		}

		return default;
	}

	/// <summary>
	/// Adds a resource to this instance's collection with the specified key
	/// </summary>
	/// <typeparam name="T">The type of the resource being added.</typeparam>
	/// <returns>The resource that was added</returns>
	internal T AddResource<T>(TypedResourceKey<T> key, T resource)
		where T : notnull => AddResource(key.Key, resource);

	/// <summary>
	/// Retrieves a resource with the specified key and type if it exists
	/// </summary>
	/// <typeparam name="T">The type of the resource being retrieved.</typeparam>
	/// <returns>True if the resource exists, false otherwise</returns>
	internal bool TryGetResource<T>(TypedResourceKey<T> key, out T? resource) => TryGetResource(key.Key, out resource);

	/// <summary>
	/// Retries a resource with the specified key and type
	/// </summary>
	/// <typeparam name="T">The type of the resource being retrieved.</typeparam>
	/// <returns>The resource if it exists or a default value.</returns>
	internal T? GetResource<T>(TypedResourceKey<T> key) => GetResource<T>(key.Key);

	/// <summary>
	/// Removes an existing resource with the specified key and type
	/// </summary>
	/// <typeparam name="T">The type of the resource being removed.</typeparam>
	/// <returns>The resource that was removed, if any</returns>
	internal T? RemoveResource<T>(TypedResourceKey<T> key) => RemoveResource<T>(key.Key);

	/// <summary>
	/// Removes an existing resource with the specified key and type, and <see cref="IDisposable.Dispose">disposes</see> it
	/// </summary>
	/// <typeparam name="T">The type of the resource being removed.</typeparam>
	/// <returns>The resource that was removed, if any</returns>
	internal T? RemoveAndDisposeResource<T>(TypedResourceKey<T> key)
		where T : IDisposable => RemoveAndDisposeResource<T>(key.Key);

	/// <summary>
	/// Disposes of any resources that implement <see cref="IDisposable"/> and then clears all resources
	/// </summary>
	public void ClearAndDisposeResources()
	{
		foreach (KeyValuePair<string, object> kvp in _resources)
		{
			(kvp.Value as IDisposable)?.Dispose();
		}

		_resources.Clear();
	}
}

/// <summary>
/// A generic class that can be used to retrieve keyed resources of the specified type.
/// </summary>
/// <typeparam name="TValue">The <see cref="Type"/> of resource the <see cref="TypedResourceKey{TValue}"/> will retrieve.</typeparam>
/// <remarks>
/// Initializes a new instance of the <see cref="TypedResourceKey{TValue}"/> class  with the specified key.
/// </remarks>
/// <param name="key">The resource's key</param>
internal sealed class TypedResourceKey<TValue>(string key)
{

	/// <summary>
	/// Gets the key of the resource to be retrieved.
	/// </summary>
	public string Key { get; } = key;

	/// <summary>
	/// Implicit operator for transforming a string into a <see cref="TypedResourceKey{TValue}"/> key.
	/// </summary>
	/// <param name="key">The key string.</param>
	public static implicit operator TypedResourceKey<TValue>(string key) => new(key);
}

internal static class ShadowHelpers
{
	/// <summary>
	/// Converts an angle bracketed <see cref="string"/> value to its unbracketed form (e.g. "&lt;float, float&gt;" to "float, float").
	/// If the value is already unbracketed, this method will return the value unchanged.
	/// </summary>
	/// <param name="text">A bracketed <see cref="string"/> value.</param>
	/// <returns>The unbracketed <see cref="string"/> value.</returns>
	private static string Unbracket(string text)
	{
		if (text.Length >= 2 &&
			text[0] == '<' &&
			text[^1] == '>')
		{
			text = text[1..^1];
		}

		return text;
	}

	public static Vector3 ToVector3(this string text)
	{
		if (text.Length == 0)
		{
			return Vector3.Zero;
		}
		else
		{
			text = Unbracket(text);

			if (!text.Contains(','))
			{
				if (float.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out float x))
				{
					return new(x);
				}
			}
			else
			{
				string[] values = text.Split(',');

				if (values.Length == 3)
				{
					if (float.TryParse(values[0], NumberStyles.Float, CultureInfo.InvariantCulture, out float x) &&
						float.TryParse(values[1], NumberStyles.Float, CultureInfo.InvariantCulture, out float y) &&
						float.TryParse(values[2], NumberStyles.Float, CultureInfo.InvariantCulture, out float z))
					{
						return new(x, y, z);
					}
				}
				else if (values.Length == 2)
				{
					return new(text.ToVector2(), 0);
				}
			}
		}

		return Throw(text);

		static Vector3 Throw(string text) => throw new FormatException($"Cannot convert \"{text}\" to {nameof(Vector3)}. Use the format \"float, float, float\"");
	}

	public static Vector2 ToVector2(this string text)
	{
		if (text.Length == 0)
		{
			return Vector2.Zero;
		}
		else
		{
			// The format <x> or <x, y> is supported
			text = Unbracket(text);

			// Skip allocations when only a component is used
			if (!text.Contains(','))
			{
				if (float.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out float x))
				{
					return new(x);
				}
			}
			else
			{
				string[] values = text.Split(',');

				if (values.Length == 2)
				{
					if (float.TryParse(values[0], NumberStyles.Float, CultureInfo.InvariantCulture, out float x) &&
						float.TryParse(values[1], NumberStyles.Float, CultureInfo.InvariantCulture, out float y))
					{
						return new(x, y);
					}
				}
			}
		}

		return Throw(text);

		static Vector2 Throw(string text) => throw new FormatException($"Cannot convert \"{text}\" to {nameof(Vector2)}. Use the format \"float, float\"");
	}
}

/// <summary>
/// A performant rectangular <see cref="DropShadow"/> which can be attached to any <see cref="FrameworkElement"/>. It uses Win2D to create a clipped area of the outline of the element such that transparent elements don't see the shadow below them, and the shadow can be attached without having to project to another surface. It is animatable, can be shared via a resource, and used in a <see cref="Style"/>.
/// </summary>
/// <remarks>
/// This shadow will not work on <see cref="FrameworkElement"/> which is directly clipping to its bounds (e.g. a <see cref="Windows.UI.Xaml.Controls.Border"/> using a <see cref="Windows.UI.Xaml.Controls.Control.CornerRadius"/>). An extra <see cref="Windows.UI.Xaml.Controls.Border"/> can instead be applied around the clipped border with the Shadow to create the desired effect. Most existing controls due to how they're templated will not encounter this behavior or require this workaround.
/// </remarks>
public sealed class AttachedCardShadow : AttachedShadowBase
{
	private const float MaxBlurRadius = 72;

	private static readonly TypedResourceKey<CompositionGeometricClip> ClipResourceKey = "Clip";
	private static readonly TypedResourceKey<CompositionPathGeometry> PathGeometryResourceKey = "PathGeometry";
	private static readonly TypedResourceKey<CompositionMaskBrush> OpacityMaskBrushResourceKey = "OpacityMask";
	private static readonly TypedResourceKey<ShapeVisual> OpacityMaskShapeVisualResourceKey = "OpacityMaskShapeVisual";
	private static readonly TypedResourceKey<CompositionRoundedRectangleGeometry> OpacityMaskGeometryResourceKey = "OpacityMaskGeometry";
	private static readonly TypedResourceKey<CompositionSpriteShape> OpacityMaskSpriteShapeResourceKey = "OpacityMaskSpriteShape";
	private static readonly TypedResourceKey<CompositionVisualSurface> OpacityMaskShapeVisualSurfaceResourceKey = "OpacityMaskShapeVisualSurface";
	private static readonly TypedResourceKey<CompositionSurfaceBrush> OpacityMaskShapeVisualSurfaceBrushResourceKey = "OpacityMaskShapeVisualSurfaceBrush";
	private static readonly TypedResourceKey<CompositionVisualSurface> OpacityMaskVisualSurfaceResourceKey = "OpacityMaskVisualSurface";
	private static readonly TypedResourceKey<CompositionSurfaceBrush> OpacityMaskSurfaceBrushResourceKey = "OpacityMaskSurfaceBrush";
	private static readonly TypedResourceKey<SpriteVisual> OpacityMaskVisualResourceKey = "OpacityMaskVisual";
	private static readonly TypedResourceKey<CompositionRoundedRectangleGeometry> RoundedRectangleGeometryResourceKey = "RoundedGeometry";
	private static readonly TypedResourceKey<CompositionSpriteShape> ShapeResourceKey = "Shape";
	private static readonly TypedResourceKey<ShapeVisual> ShapeVisualResourceKey = "ShapeVisual";
	private static readonly TypedResourceKey<CompositionSurfaceBrush> SurfaceBrushResourceKey = "SurfaceBrush";
	private static readonly TypedResourceKey<CompositionVisualSurface> VisualSurfaceResourceKey = "VisualSurface";

	/// <summary>
	/// The <see cref="DependencyProperty"/> for <see cref="CornerRadius"/>
	/// </summary>
	public static readonly DependencyProperty CornerRadiusProperty =
		DependencyProperty.Register(
			nameof(CornerRadius),
			typeof(double),
			typeof(AttachedCardShadow),
			new PropertyMetadata(4d, OnDependencyPropertyChanged)); // Default WinUI ControlCornerRadius is 4

	/// <summary>
	/// The <see cref="DependencyProperty"/> for <see cref="InnerContentClipMode"/>.
	/// </summary>
	public static readonly DependencyProperty InnerContentClipModeProperty =
		DependencyProperty.Register(
			nameof(InnerContentClipMode),
			typeof(InnerContentClipMode),
			typeof(AttachedCardShadow),
			new PropertyMetadata(InnerContentClipMode.CompositionGeometricClip, OnDependencyPropertyChanged));

	/// <summary>
	/// Gets or sets the roundness of the shadow's corners.
	/// </summary>
	public double CornerRadius
	{
		get => (double)GetValue(CornerRadiusProperty);
		set => SetValue(CornerRadiusProperty, value);
	}

	/// <summary>
	/// Gets or sets the mode use to clip inner content from the shadow.
	/// </summary>
	public InnerContentClipMode InnerContentClipMode
	{
		get => (InnerContentClipMode)GetValue(InnerContentClipModeProperty);
		set => SetValue(InnerContentClipModeProperty, value);
	}

	protected internal override bool SupportsOnSizeChangedEvent => true;

	protected internal override void OnElementContextInitialized(AttachedShadowElementContext context)
	{
		UpdateVisualOpacityMask(context);
		base.OnElementContextInitialized(context);
	}

	protected override void OnPropertyChanged(AttachedShadowElementContext context, DependencyProperty property, object oldValue, object newValue)
	{
		if (property == CornerRadiusProperty)
		{
			UpdateShadowClip(context);
			UpdateVisualOpacityMask(context);

			CompositionRoundedRectangleGeometry? geometry = context.GetResource(RoundedRectangleGeometryResourceKey);
			_ = (geometry?.CornerRadius = new Vector2((float)(double)newValue));
		}
		else if (property == InnerContentClipModeProperty)
		{
			UpdateShadowClip(context);
			UpdateVisualOpacityMask(context);
			SetElementChildVisual(context);
		}
		else
		{
			base.OnPropertyChanged(context, property, oldValue, newValue);
		}
	}

	protected override CompositionBrush? GetShadowMask(AttachedShadowElementContext context)
	{
		if (context.Compositor == null)
		{
			return null;
		}

		// Create rounded rectangle geometry and add it to a shape
		CompositionRoundedRectangleGeometry geometry = context.GetResource(RoundedRectangleGeometryResourceKey) ?? context.AddResource(
			RoundedRectangleGeometryResourceKey,
			context.Compositor.CreateRoundedRectangleGeometry());
		geometry.CornerRadius = new Vector2((float)CornerRadius);

		CompositionSpriteShape shape = context.GetResource(ShapeResourceKey) ?? context.AddResource(ShapeResourceKey, context.Compositor.CreateSpriteShape(geometry));
		shape.FillBrush = context.Compositor.CreateColorBrush(Colors.Black);

		// Create a ShapeVisual so that our geometry can be rendered to a visual
		ShapeVisual shapeVisual = context.GetResource(ShapeVisualResourceKey) ??
						  context.AddResource(ShapeVisualResourceKey, context.Compositor.CreateShapeVisual());
		shapeVisual.Shapes.Add(shape);

		// Create a CompositionVisualSurface, which renders our ShapeVisual to a texture
		CompositionVisualSurface visualSurface = context.GetResource(VisualSurfaceResourceKey) ??
							context.AddResource(VisualSurfaceResourceKey, context.Compositor.CreateVisualSurface());
		visualSurface.SourceVisual = shapeVisual;

		// Create a CompositionSurfaceBrush to render our CompositionVisualSurface to a brush.
		// Now we have a rounded rectangle brush that can be used on as the mask for our shadow.
		CompositionSurfaceBrush surfaceBrush = context.GetResource(SurfaceBrushResourceKey) ?? context.AddResource(
			SurfaceBrushResourceKey,
			context.Compositor.CreateSurfaceBrush(visualSurface));

		geometry.Size = visualSurface.SourceSize = shapeVisual.Size = context.Element.RenderSize.ToVector2();

		return surfaceBrush;
	}

	protected override CompositionClip? GetShadowClip(AttachedShadowElementContext context)
	{
		if (InnerContentClipMode != InnerContentClipMode.CompositionGeometricClip
			|| context.Compositor == null)
		{
			_ = context.RemoveAndDisposeResource(PathGeometryResourceKey);
			_ = context.RemoveAndDisposeResource(ClipResourceKey);

			return null;
		}

		// The way this shadow works without the need to project on another element is because
		// we're clipping the inner part of the shadow which would be cast on the element
		// itself away. This method is creating an outline so that we are only showing the
		// parts of the shadow that are outside the element's context.
		// Note: This does cause an issue if the element does clip itself to its bounds, as then
		// the shadowed area is clipped as well.
		CompositionPathGeometry pathGeom = context.GetResource(PathGeometryResourceKey) ??
					   context.AddResource(PathGeometryResourceKey, context.Compositor.CreatePathGeometry());
		CompositionGeometricClip clip = context.GetResource(ClipResourceKey) ?? context.AddResource(ClipResourceKey, context.Compositor.CreateGeometricClip(pathGeom));

		// Create rounded rectangle geometry at a larger size that compensates for the size of the stroke,
		// as we want the inside edge of the stroke to match the edges of the element.
		// Additionally, the inside edge of the stroke will have a smaller radius than the radius we specified.
		// Using "(StrokeThickness / 2) + Radius" as our rectangle's radius will give us an inside stroke radius that matches the radius we want.
		using CanvasGeometry canvasRectangle = CanvasGeometry.CreateRoundedRectangle(
			null,
			-MaxBlurRadius / 2,
			-MaxBlurRadius / 2,
			(float)context.Element.ActualWidth + MaxBlurRadius,
			(float)context.Element.ActualHeight + MaxBlurRadius,
			(MaxBlurRadius / 2) + (float)CornerRadius,
			(MaxBlurRadius / 2) + (float)CornerRadius);

		using CanvasGeometry canvasStroke = canvasRectangle.Stroke(MaxBlurRadius);

		pathGeom.Path = new CompositionPath(canvasStroke);

		return clip;
	}

	/// <summary>
	/// Updates the <see cref="CompositionBrush"/> used to mask <paramref name="context"/>.<see cref="AttachedShadowElementContext.SpriteVisual">SpriteVisual</see>.
	/// </summary>
	/// <param name="context">The <see cref="AttachedShadowElementContext"/> whose <see cref="SpriteVisual"/> will be masked.</param>
	private void UpdateVisualOpacityMask(AttachedShadowElementContext context)
	{
		if (InnerContentClipMode != InnerContentClipMode.CompositionMaskBrush
			|| context.Compositor == null)
		{
			_ = context.RemoveAndDisposeResource(OpacityMaskShapeVisualResourceKey);
			_ = context.RemoveAndDisposeResource(OpacityMaskGeometryResourceKey);
			_ = context.RemoveAndDisposeResource(OpacityMaskSpriteShapeResourceKey);
			_ = context.RemoveAndDisposeResource(OpacityMaskShapeVisualSurfaceResourceKey);
			_ = context.RemoveAndDisposeResource(OpacityMaskShapeVisualSurfaceBrushResourceKey);

			return;
		}

		// Create ShapeVisual, and CompositionSpriteShape with geometry, these will provide the visuals for the opacity mask.
		ShapeVisual shapeVisual = context.GetResource(OpacityMaskShapeVisualResourceKey) ??
			context.AddResource(OpacityMaskShapeVisualResourceKey, context.Compositor.CreateShapeVisual());

		CompositionRoundedRectangleGeometry geometry = context.GetResource(OpacityMaskGeometryResourceKey) ??
			context.AddResource(OpacityMaskGeometryResourceKey, context.Compositor.CreateRoundedRectangleGeometry());
		CompositionSpriteShape shape = context.GetResource(OpacityMaskSpriteShapeResourceKey) ??
			context.AddResource(OpacityMaskSpriteShapeResourceKey, context.Compositor.CreateSpriteShape(geometry));

		// Set the attributes of the geometry, and add the CompositionSpriteShape to the ShapeVisual.
		// The geometry will have a thick outline and no fill, meaning that when used as a mask,
		// the shadow will only be rendered on the outer area covered by the outline, clipping out its inner portion.
		geometry.Offset = new Vector2(MaxBlurRadius / 2);
		geometry.CornerRadius = new Vector2((MaxBlurRadius / 2) + (float)CornerRadius);
		shape.StrokeThickness = MaxBlurRadius;
		shape.StrokeBrush ??= context.Compositor.CreateColorBrush(Colors.Black);

		if (!shapeVisual.Shapes.Contains(shape))
		{
			shapeVisual.Shapes.Add(shape);
		}

		// Create CompositionVisualSurface using the ShapeVisual as the source visual.
		CompositionVisualSurface visualSurface = context.GetResource(OpacityMaskShapeVisualSurfaceResourceKey) ??
			context.AddResource(OpacityMaskShapeVisualSurfaceResourceKey, context.Compositor.CreateVisualSurface());
		visualSurface.SourceVisual = shapeVisual;

		geometry.Size = new Vector2((float)context.Element.ActualWidth, (float)context.Element.ActualHeight) + new Vector2(MaxBlurRadius);
		shapeVisual.Size = visualSurface.SourceSize = new Vector2((float)context.Element.ActualWidth, (float)context.Element.ActualHeight) + new Vector2(MaxBlurRadius * 2);

		// Create a CompositionSurfaceBrush using the CompositionVisualSurface as the source, this essentially converts the ShapeVisual into a brush.
		// This brush can then be used as a mask.
		CompositionSurfaceBrush opacityMask = context.GetResource(OpacityMaskShapeVisualSurfaceBrushResourceKey) ??
			context.AddResource(OpacityMaskShapeVisualSurfaceBrushResourceKey, context.Compositor.CreateSurfaceBrush());
		opacityMask.Surface = visualSurface;
	}

	protected override void SetElementChildVisual(AttachedShadowElementContext context)
	{
		if (context.TryGetResource(OpacityMaskShapeVisualSurfaceBrushResourceKey, out CompositionSurfaceBrush? opacityMask)
			&& context.Compositor != null)
		{
			// If the resource for OpacityMaskShapeVisualSurfaceBrushResourceKey exists it means this.InnerContentClipMode == CompositionVisualSurface,
			// which means we need to take some steps to set up an opacity mask.

			// Create a CompositionVisualSurface, and use the SpriteVisual containing the shadow as the source.
			CompositionVisualSurface shadowVisualSurface = context.GetResource(OpacityMaskVisualSurfaceResourceKey) ??
				context.AddResource(OpacityMaskVisualSurfaceResourceKey, context.Compositor.CreateVisualSurface());
			shadowVisualSurface.SourceVisual = context.SpriteVisual;

			if (context.SpriteVisual != null)
			{
				context.SpriteVisual.RelativeSizeAdjustment = Vector2.Zero;
				context.SpriteVisual.Size = new Vector2((float)context.Element.ActualWidth, (float)context.Element.ActualHeight);
			}

			// Adjust the offset and size of the CompositionVisualSurface to accommodate the thick outline of the shape created in UpdateVisualOpacityMask().
			shadowVisualSurface.SourceOffset = new Vector2(-MaxBlurRadius);
			shadowVisualSurface.SourceSize = new Vector2((float)context.Element.ActualWidth, (float)context.Element.ActualHeight) + new Vector2(MaxBlurRadius * 2);

			// Create a CompositionSurfaceBrush from the CompositionVisualSurface. This allows us to render the shadow in a brush.
			CompositionSurfaceBrush shadowSurfaceBrush = context.GetResource(OpacityMaskSurfaceBrushResourceKey) ??
				context.AddResource(OpacityMaskSurfaceBrushResourceKey, context.Compositor.CreateSurfaceBrush());
			shadowSurfaceBrush.Surface = shadowVisualSurface;
			shadowSurfaceBrush.Stretch = CompositionStretch.None;

			// Create a CompositionMaskBrush, using the CompositionSurfaceBrush of the shadow as the source,
			// and the CompositionSurfaceBrush created in UpdateVisualOpacityMask() as the mask.
			// This creates a brush that renders the shadow with its inner portion clipped out.
			CompositionMaskBrush maskBrush = context.GetResource(OpacityMaskBrushResourceKey) ??
				context.AddResource(OpacityMaskBrushResourceKey, context.Compositor.CreateMaskBrush());
			maskBrush.Source = shadowSurfaceBrush;
			maskBrush.Mask = opacityMask;

			// Create a SpriteVisual and set its brush to the CompositionMaskBrush created in the previous step,
			// then set it as the child of the element in the context.
			SpriteVisual visual = context.GetResource(OpacityMaskVisualResourceKey) ??
				context.AddResource(OpacityMaskVisualResourceKey, context.Compositor.CreateSpriteVisual());
			visual.RelativeSizeAdjustment = Vector2.One;
			visual.Offset = new Vector3(-MaxBlurRadius, -MaxBlurRadius, 0);
			visual.Size = new Vector2(MaxBlurRadius * 2);
			visual.Brush = maskBrush;
			ElementCompositionPreview.SetElementChildVisual(context.Element, visual);
		}
		else
		{
			base.SetElementChildVisual(context);

			// Reset context.SpriteVisual.Size and RelativeSizeAdjustment to default values
			// as they may be changed in the block above.
			if (context.SpriteVisual != null)
			{
				context.SpriteVisual.Size = Vector2.Zero;
				context.SpriteVisual.RelativeSizeAdjustment = Vector2.One;
			}

			_ = context.RemoveAndDisposeResource(OpacityMaskVisualSurfaceResourceKey);
			_ = context.RemoveAndDisposeResource(OpacityMaskSurfaceBrushResourceKey);
			_ = context.RemoveAndDisposeResource(OpacityMaskVisualResourceKey);
			_ = context.RemoveAndDisposeResource(OpacityMaskBrushResourceKey);
		}
	}

	/// <inheritdoc />
	protected internal override void OnSizeChanged(AttachedShadowElementContext context, Size newSize, Size previousSize)
	{
		Vector2 sizeAsVec2 = newSize.ToVector2();

		if (context.TryGetResource(RoundedRectangleGeometryResourceKey, out CompositionRoundedRectangleGeometry? geometry)
			&& geometry != null)
		{
			geometry.Size = sizeAsVec2;
		}

		if (context.TryGetResource(VisualSurfaceResourceKey, out CompositionVisualSurface? visualSurface)
			&& visualSurface != null)
		{
			visualSurface.SourceSize = sizeAsVec2;
		}

		if (context.TryGetResource(ShapeVisualResourceKey, out ShapeVisual? shapeVisual)
			&& shapeVisual != null)
		{
			shapeVisual.Size = sizeAsVec2;
		}

		if (context.TryGetResource(OpacityMaskVisualSurfaceResourceKey, out CompositionVisualSurface? opacityMaskVisualSurface)
			&& opacityMaskVisualSurface != null)
		{
			opacityMaskVisualSurface.SourceSize = sizeAsVec2 + new Vector2(MaxBlurRadius * 2);
		}

		if (context.SpriteVisual != null
			&& InnerContentClipMode is InnerContentClipMode.CompositionMaskBrush)
		{
			context.SpriteVisual.Size = sizeAsVec2;
		}

		UpdateShadowClip(context);
		UpdateVisualOpacityMask(context);

		base.OnSizeChanged(context, newSize, previousSize);
	}
}

/// <summary>
/// The method that each instance of <see cref="AttachedCardShadow"/> uses when clipping its inner content.
/// </summary>
public enum InnerContentClipMode
{
	/// <summary>
	/// Do not clip inner content.
	/// </summary>
	None,

	/// <summary>
	/// Use <see cref="Windows.UI.Composition.CompositionMaskBrush"/> to clip inner content.
	/// </summary>
	/// <remarks>
	/// This mode has better performance than <see cref="CompositionGeometricClip"/>.
	/// </remarks>
	CompositionMaskBrush,

	/// <summary>
	/// Use <see cref="Windows.UI.Composition.CompositionGeometricClip"/> to clip inner content.
	/// </summary>
	/// <remarks>
	/// Content clipped in this mode will have smoother corners than when using <see cref="CompositionMaskBrush"/>.
	/// </remarks>
	CompositionGeometricClip
}

/// <summary>
/// Helper class for attaching <see cref="AttachedShadowBase"/> shadows to <see cref="FrameworkElement"/>s.
/// </summary>
public static class Effects
{
	/// <summary>
	/// Gets the shadow attached to a <see cref="FrameworkElement"/> by getting the value of the <see cref="ShadowProperty"/> property.
	/// </summary>
	/// <param name="obj">The <see cref="FrameworkElement"/> the <see cref="AttachedShadowBase"/> is attached to.</param>
	/// <returns>The <see cref="AttachedShadowBase"/> that is attached to the <paramref name="obj">FrameworkElement.</paramref></returns>
	public static AttachedShadowBase GetShadow(FrameworkElement obj)
	{
		return (AttachedShadowBase)obj.GetValue(ShadowProperty);
	}

	/// <summary>
	/// Attaches a shadow to an element by setting the <see cref="ShadowProperty"/> property.
	/// </summary>
	/// <param name="obj">The <see cref="FrameworkElement"/> to attach the shadow to.</param>
	/// <param name="value">The <see cref="AttachedShadowBase"/> that will be attached to the element</param>
	public static void SetShadow(FrameworkElement obj, AttachedShadowBase value)
	{
		obj.SetValue(ShadowProperty, value);
	}

	/// <summary>
	/// Attached <see cref="DependencyProperty"/> for setting an <see cref="AttachedShadowBase"/> to a <see cref="FrameworkElement"/>.
	/// </summary>
	public static readonly DependencyProperty ShadowProperty =
		DependencyProperty.RegisterAttached("Shadow", typeof(AttachedShadowBase), typeof(Effects), new PropertyMetadata(null, OnShadowChanged));

	private static void OnShadowChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is not FrameworkElement element)
		{
			return;
		}

		if (e.OldValue is AttachedShadowBase oldShadow)
		{
			oldShadow.DisconnectElement(element);
		}

		if (e.NewValue is AttachedShadowBase newShadow)
		{
			newShadow.ConnectElement(element);
		}
	}
}

/// <summary>
/// A gaussian blur effect
/// </summary>
/// <remarks>This effect maps to the Win2D <see cref="Graphics.Canvas.Effects.GaussianBlurEffect"/> effect</remarks>
public sealed class BlurEffect : PipelineEffect
{
	/// <summary>
	/// Gets or sets the blur amount for the effect (must be a positive value)
	/// </summary>
	public double Amount
	{
		get; set => field = Math.Max(value, 0);
	}

	/// <summary>
	/// Gets the unique id for the effect, if <see cref="PipelineEffect.IsAnimatable"/> is set.
	/// </summary>
	internal string? Id { get; private set; }

	public override PipelineBuilder AppendToBuilder(PipelineBuilder builder)
	{
		if (IsAnimatable)
		{
			builder = builder.Blur((float)Amount, out string id);

			Id = id;

			return builder;
		}

		return builder.Blur((float)Amount);
	}
}

/// <summary>
/// A base pipeline effect.
/// </summary>
public abstract class PipelineEffect : DependencyObject, IPipelineEffect
{
	public CompositionBrush? Brush { get; private set; }

	/// <summary>
	/// Gets or sets a value indicating whether the effect can be animated.
	/// </summary>
	public bool IsAnimatable { get; set; }

	public abstract PipelineBuilder AppendToBuilder(PipelineBuilder builder);

	public virtual void NotifyCompositionBrushInUse(CompositionBrush brush)
	{
		Brush = brush;
	}
}

/// <summary>
/// The base <see langword="interface"/> for all the builder effects to be used in a <see cref="CompositionBrush"/>.
/// </summary>
public interface IPipelineEffect
{
	/// <summary>
	/// Gets the current <see cref="CompositionBrush"/> instance, if one is in use.
	/// </summary>
	CompositionBrush? Brush { get; }

	/// <summary>
	/// Appends the current effect to the input <see cref="PipelineBuilder"/> instance.
	/// </summary>
	/// <param name="builder">The source <see cref="PipelineBuilder"/> instance to add the effect to.</param>
	/// <returns>A new <see cref="PipelineBuilder"/> with the new effects added to it.</returns>
	PipelineBuilder AppendToBuilder(PipelineBuilder builder);

	/// <summary>
	/// Notifies that a given <see cref="CompositionBrush"/> is now in use.
	/// </summary>
	/// <param name="brush">The <see cref="CompositionBrush"/> in use.</param>
	void NotifyCompositionBrushInUse(CompositionBrush brush);
}

/// <summary>
/// A <see langword="class"/> that allows to build custom effects pipelines and create <see cref="CompositionBrush"/> instances from them
/// </summary>
public sealed partial class PipelineBuilder
{
	/// <summary>
	/// The <see cref="Func{TResult}"/> instance used to produce the output <see cref="IGraphicsEffectSource"/> for this pipeline
	/// </summary>
	private readonly Func<ValueTask<IGraphicsEffectSource>> sourceProducer;

	/// <summary>
	/// The collection of animation properties present in the current pipeline
	/// </summary>
	private readonly IReadOnlyCollection<string> animationProperties;

	/// <summary>
	/// The collection of info on the parameters that need to be initialized after creating the final <see cref="CompositionBrush"/>
	/// </summary>
	private readonly IReadOnlyDictionary<string, Func<ValueTask<CompositionBrush>>> lazyParameters;

	public static string ToUppercaseAsciiLetters(Guid input)
	{
		// Composition IDs must only be composed of characters in the [A-Z0-9_] set,
		// and also have the restriction that the initial character cannot be a digit.
		// Because of this, we need to prepend an underscore to a serialized guid to
		// avoid cases where the first character is a digit. Additionally, we're forced
		// to use ToUpper() here because ToString("N") currently returns a lowercase
		// hexadecimal string. Note: this extension might be improved once we move to
		// .NET 5 in the WinUI 3 release, by using string.Create<TState>(...) to only
		// have a single string allocation, and then using Guid.TryFormat(...) to
		// serialize the guid in place over the Span<char> starting from the second
		// character. For now, this implementation is fine on UWP and still fast enough.
		return $"_{input.ToString("N").ToUpper()}";
	}

	/// <summary>
	/// Initializes a new instance of the <see cref="PipelineBuilder"/> class.
	/// </summary>
	/// <param name="factory">A <see cref="Func{TResult}"/> instance that will return the initial <see cref="CompositionBrush"/></param>
	internal PipelineBuilder(Func<ValueTask<CompositionBrush>> factory)
	{
		string id = ToUppercaseAsciiLetters(Guid.NewGuid());

		sourceProducer = () => new ValueTask<IGraphicsEffectSource>(new CompositionEffectSourceParameter(id));
		animationProperties = Array.Empty<string>();
		lazyParameters = new Dictionary<string, Func<ValueTask<CompositionBrush>>> { { id, factory } };
	}

	/// <summary>
	/// Initializes a new instance of the <see cref="PipelineBuilder"/> class.
	/// </summary>
	/// <param name="factory">A <see cref="Func{TResult}"/> instance that will produce the new <see cref="IGraphicsEffectSource"/> to add to the pipeline</param>
	/// <param name="animations">The collection of animation properties for the new effect</param>
	/// <param name="lazy">The collection of <see cref="CompositionBrush"/> instances that needs to be initialized for the new effect</param>
	private PipelineBuilder(
		Func<ValueTask<IGraphicsEffectSource>> factory,
		IReadOnlyCollection<string> animations,
		IReadOnlyDictionary<string, Func<ValueTask<CompositionBrush>>> lazy)
	{
		sourceProducer = factory;
		animationProperties = animations;
		lazyParameters = lazy;
	}

	/// <summary>
	/// Initializes a new instance of the <see cref="PipelineBuilder"/> class.
	/// </summary>
	/// <param name="source">The source pipeline to attach the new effect to</param>
	/// <param name="factory">A <see cref="Func{TResult}"/> instance that will produce the new <see cref="IGraphicsEffectSource"/> to add to the pipeline</param>
	/// <param name="animations">The collection of animation properties for the new effect</param>
	/// <param name="lazy">The collection of <see cref="CompositionBrush"/> instances that needs to be initialized for the new effect</param>
	private PipelineBuilder(
		PipelineBuilder source,
		Func<ValueTask<IGraphicsEffectSource>> factory,
		IReadOnlyCollection<string>? animations = null,
		IReadOnlyDictionary<string, Func<ValueTask<CompositionBrush>>>? lazy = null)
		: this(
			factory,
			animations?.Merge(source.animationProperties) ?? source.animationProperties,
			lazy?.Merge(source.lazyParameters) ?? source.lazyParameters)
	{
	}

	/// <summary>
	/// Builds a <see cref="CompositionBrush"/> instance from the current effects pipeline
	/// </summary>
	/// <returns>A <see cref="Task{T}"/> that returns the final <see cref="CompositionBrush"/> instance to use</returns>
	[Pure]
	public async Task<CompositionBrush> BuildAsync()
	{

		Compositor compositor = CompositionTarget.GetCompositorForCurrentThread();

		// Validate the pipeline
		IGraphicsEffect effect = await sourceProducer() as IGraphicsEffect ?? throw new InvalidOperationException("The pipeline doesn't contain a valid effects sequence");

		// Build the effects factory
		CompositionEffectFactory factory = animationProperties.Count > 0
			? compositor.CreateEffectFactory(effect, animationProperties)
			: compositor.CreateEffectFactory(effect);

		// Create the effect factory and apply the final effect
		CompositionEffectBrush effectBrush = factory.CreateBrush();
		foreach (KeyValuePair<string, Func<ValueTask<CompositionBrush>>> pair in lazyParameters)
		{
			effectBrush.SetSourceParameter(pair.Key, await pair.Value());
		}

		return effectBrush;
	}

	/// <summary>
	/// Adds a new <see cref="GaussianBlurEffect"/> to the current pipeline
	/// </summary>
	/// <param name="blur">The blur amount to apply</param>
	/// <param name="target">The target property to animate the resulting effect.</param>
	/// <param name="mode">The <see cref="EffectBorderMode"/> parameter for the effect, defaults to <see cref="EffectBorderMode.Hard"/></param>
	/// <param name="optimization">The <see cref="EffectOptimization"/> parameter to use, defaults to <see cref="EffectOptimization.Balanced"/></param>
	/// <returns>A new <see cref="PipelineBuilder"/> instance to use to keep adding new effects</returns>
	[Pure]
	internal PipelineBuilder Blur(
		float blur,
		out string target,
		EffectBorderMode mode = EffectBorderMode.Hard,
		EffectOptimization optimization = EffectOptimization.Balanced)
	{
		string name = ToUppercaseAsciiLetters(Guid.NewGuid());

		target = $"{name}.{nameof(GaussianBlurEffect.BlurAmount)}";

		async ValueTask<IGraphicsEffectSource> Factory() => new GaussianBlurEffect
		{
			BlurAmount = blur,
			BorderMode = mode,
			Optimization = optimization,
			Source = await sourceProducer(),
			Name = name
		};

		return new PipelineBuilder(this, Factory, new[] { target });
	}

	/// <summary>
	/// Adds a new <see cref="GaussianBlurEffect"/> to the current pipeline
	/// </summary>
	/// <param name="blur">The blur amount to apply</param>
	/// <param name="mode">The <see cref="EffectBorderMode"/> parameter for the effect, defaults to <see cref="EffectBorderMode.Hard"/></param>
	/// <param name="optimization">The <see cref="EffectOptimization"/> parameter to use, defaults to <see cref="EffectOptimization.Balanced"/></param>
	/// <returns>A new <see cref="PipelineBuilder"/> instance to use to keep adding new effects</returns>
	[Pure]
	public PipelineBuilder Blur(float blur, EffectBorderMode mode = EffectBorderMode.Hard, EffectOptimization optimization = EffectOptimization.Balanced)
	{
		async ValueTask<IGraphicsEffectSource> Factory() => new GaussianBlurEffect
		{
			BlurAmount = blur,
			BorderMode = mode,
			Optimization = optimization,
			Source = await sourceProducer()
		};

		return new PipelineBuilder(this, Factory);
	}

	/// <summary>
	/// Starts an <see cref="ExpressionAnimation"/> to keep the size of the source <see cref="Visual"/> in sync with the target <see cref="UIElement"/>
	/// </summary>
	/// <param name="source">The <see cref="Visual"/> to start the animation on</param>
	/// <param name="target">The target <see cref="UIElement"/> to read the size updates from</param>
	public static void BindSize(Visual source, UIElement target)
	{
		Visual visual = ElementCompositionPreview.GetElementVisual(target);
		ExpressionAnimation bindSizeAnimation = source.Compositor.CreateExpressionAnimation($"{nameof(visual)}.Size");

		bindSizeAnimation.SetReferenceParameter(nameof(visual), visual);

		// Start the animation
		source.StartAnimation("Size", bindSizeAnimation);
	}
}

/// <summary>
/// An extension <see langword="class"/> for the <see cref="System.Collections.Generic"/> <see langword="namespace"/>
/// </summary>
internal static class GenericExtensions
{
	/// <summary>
	/// Merges the two input <see cref="IReadOnlyDictionary{TKey,TValue}"/> instances and makes sure no duplicate keys are present
	/// </summary>
	/// <typeparam name="TKey">The type of keys in the input dictionaries</typeparam>
	/// <typeparam name="TValue">The type of values in the input dictionaries</typeparam>
	/// <param name="a">The first <see cref="IReadOnlyDictionary{TKey,TValue}"/> to merge</param>
	/// <param name="b">The second <see cref="IReadOnlyDictionary{TKey,TValue}"/> to merge</param>
	/// <returns>An <see cref="IReadOnlyDictionary{TKey,TValue}"/> instance with elements from both <paramref name="a"/> and <paramref name="b"/></returns>
	[Pure]
	public static IReadOnlyDictionary<TKey, TValue> Merge<TKey, TValue>(
		this IReadOnlyDictionary<TKey, TValue> a,
		IReadOnlyDictionary<TKey, TValue> b)
		where TKey : notnull
	{
		if (a.Keys.FirstOrDefault(b.ContainsKey) is TKey key)
		{
			throw new InvalidOperationException($"The key {key} already exists in the current pipeline");
		}

		return new Dictionary<TKey, TValue>(a.Concat(b));
	}

	/// <summary>
	/// Merges the two input <see cref="IReadOnlyCollection{T}"/> instances and makes sure no duplicate items are present
	/// </summary>
	/// <typeparam name="T">The type of elements in the input collections</typeparam>
	/// <param name="a">The first <see cref="IReadOnlyCollection{T}"/> to merge</param>
	/// <param name="b">The second <see cref="IReadOnlyCollection{T}"/> to merge</param>
	/// <returns>An <see cref="IReadOnlyCollection{T}"/> instance with elements from both <paramref name="a"/> and <paramref name="b"/></returns>
	[Pure]
	public static IReadOnlyCollection<T> Merge<T>(this IReadOnlyCollection<T> a, IReadOnlyCollection<T> b)
	{
		if (a.Any(b.Contains))
		{
			throw new InvalidOperationException("The input collection has at least an item already present in the second collection");
		}

		return a.Concat(b).ToArray();
	}
}

/// <summary>
/// A builder type for <see cref="SpriteVisual"/> instance to apply to UI elements.
/// </summary>
[ContentProperty(Name = nameof(Effects))]
public sealed class PipelineVisualFactory : PipelineVisualFactoryBase
{
	/// <summary>
	/// Gets or sets the source for the current pipeline (defaults to a <see cref="BackdropSourceExtension"/> with <see cref="AcrylicBackgroundSource.Backdrop"/> source).
	/// </summary>
	public PipelineBuilder? Source { get; set; }

	/// <summary>
	/// Gets or sets the collection of effects to use in the current pipeline.
	/// </summary>
	public IList<PipelineEffect> Effects
	{
		get
		{
			if (GetValue(EffectsProperty) is not IList<PipelineEffect> effects)
			{
				effects = new List<PipelineEffect>();

				SetValue(EffectsProperty, effects);
			}

			return effects;
		}
		set => SetValue(EffectsProperty, value);
	}

	/// <summary>
	/// Identifies the <seealso cref="Effects"/> dependency property.
	/// </summary>
	public static readonly DependencyProperty EffectsProperty = DependencyProperty.Register(
		nameof(Effects),
		typeof(IList<PipelineEffect>),
		typeof(PipelineVisualFactory),
		new PropertyMetadata(null));

	public override async ValueTask<Visual> GetAttachedVisualAsync(UIElement element)
	{
		SpriteVisual visual = (SpriteVisual)await base.GetAttachedVisualAsync(element);

		foreach (IPipelineEffect effect in Effects)
		{
			effect.NotifyCompositionBrushInUse(visual.Brush);
		}

		return visual;
	}

	protected override PipelineBuilder OnPipelineRequested()
	{
		PipelineBuilder builder = Source ?? FromBackdrop();

		foreach (IPipelineEffect effect in Effects)
		{
			builder = effect.AppendToBuilder(builder);
		}

		return builder;
	}

	/// <summary>
	/// Starts a new <see cref="PipelineBuilder"/> pipeline from the <see cref="CompositionBrush"/> returned by <see cref="Compositor.CreateBackdropBrush"/>
	/// </summary>
	/// <returns>A new <see cref="PipelineBuilder"/> instance to use to keep adding new effects</returns>
	[Pure]
	public static PipelineBuilder FromBackdrop()
	{
		static ValueTask<CompositionBrush> Factory()
		{
			Compositor compositor = CompositionTarget.GetCompositorForCurrentThread();

			CompositionBrush brush = BackdropBrushCache.GetValue(compositor, c => c.CreateBackdropBrush());

			return new ValueTask<CompositionBrush>(brush);
		}

		return new PipelineBuilder(Factory);
	}

	/// <summary>
	/// The cache manager for backdrop brushes
	/// </summary>
	private static readonly CompositionObjectCache<CompositionBrush> BackdropBrushCache = new();

}

/// <summary>
/// A base class that extends <see cref="AttachedVisualFactoryBase"/> by leveraging the <see cref="PipelineBuilder"/> APIs.
/// </summary>
public abstract class PipelineVisualFactoryBase : AttachedVisualFactoryBase
{
	public override async ValueTask<Visual> GetAttachedVisualAsync(UIElement element)
	{
		SpriteVisual visual = ElementCompositionPreview.GetElementVisual(element).Compositor.CreateSpriteVisual();

		visual.Brush = await OnPipelineRequested().BuildAsync();

		return visual;
	}

	/// <summary>
	/// A method that builds and returns the <see cref="PipelineBuilder"/> pipeline to use in the current instance.
	/// </summary>
	/// <returns>A <see cref="PipelineBuilder"/> instance to create the <see cref="Visual"/> to display.</returns>
	protected abstract PipelineBuilder OnPipelineRequested();
}

/// <summary>
/// A type responsible for creating <see cref="Visual"/> instances to attach to target elements.
/// </summary>
public abstract class AttachedVisualFactoryBase : DependencyObject
{
	/// <summary>
	/// Creates a <see cref="Visual"/> to attach to the target element.
	/// </summary>
	/// <param name="element">The target <see cref="UIElement"/> the visual will be attached to.</param>
	/// <returns>A <see cref="Visual"/> instance that the caller will attach to the target element.</returns>
	public abstract ValueTask<Visual> GetAttachedVisualAsync(UIElement element);
}

/// <summary>
/// A <see langword="class"/> used to cache reusable <see cref="CompositionObject"/> instances in each UI thread
/// </summary>
/// <typeparam name="T">The type of instances to cache</typeparam>
internal sealed class CompositionObjectCache<T>
	where T : CompositionObject
{
	/// <summary>
	/// The cache of weak references of type <typeparamref name="T"/>, to avoid memory leaks
	/// </summary>
	private readonly ConditionalWeakTable<Compositor, WeakReference<T>> cache = new();

	/// <summary>
	/// Tries to retrieve a valid <typeparamref name="T"/> instance from the cache, and uses the provided factory if an existing item is not found
	/// </summary>
	/// <param name="compositor">The current <see cref="Compositor"/> instance to get the value for</param>
	/// <param name="producer">A <see cref="Func{TResult}"/> instance used to produce a <typeparamref name="T"/> instance</param>
	/// <returns>A <typeparamref name="T"/> instance that is linked to <paramref name="compositor"/></returns>
	public T GetValue(Compositor compositor, Func<Compositor, T> producer)
	{
		lock (cache)
		{
			if (cache.TryGetValue(compositor, out WeakReference<T>? reference) &&
				reference.TryGetTarget(out T? instance))
			{
				return instance;
			}

			// Create a new instance when needed
			T fallback = producer(compositor);
			cache.AddOrUpdate(compositor, new WeakReference<T>(fallback));

			return fallback;
		}
	}
}

/// <summary>
/// Attached properties to support attaching custom pipelines to UI elements.
/// </summary>
public static class UIElementExtensions
{
	/// <summary>
	/// Identifies the VisualFactory XAML attached property.
	/// </summary>
	public static readonly DependencyProperty VisualFactoryProperty = DependencyProperty.RegisterAttached(
		"VisualFactory",
		typeof(AttachedVisualFactoryBase),
		typeof(UIElementExtensions),
		new PropertyMetadata(null, OnVisualFactoryPropertyChanged));

	/// <summary>
	/// Gets the value of <see cref="VisualFactoryProperty"/>.
	/// </summary>
	/// <param name="element">The <see cref="UIElement"/> to get the value for.</param>
	/// <returns>The retrieved <see cref="AttachedVisualFactoryBase"/> item.</returns>
	public static AttachedVisualFactoryBase GetVisualFactory(UIElement element)
	{
		return (AttachedVisualFactoryBase)element.GetValue(VisualFactoryProperty);
	}

	/// <summary>
	/// Sets the value of <see cref="VisualFactoryProperty"/>.
	/// </summary>
	/// <param name="element">The <see cref="UIElement"/> to set the value for.</param>
	/// <param name="value">The <see cref="AttachedVisualFactoryBase"/> value to set.</param>
	public static void SetVisualFactory(UIElement element, AttachedVisualFactoryBase value)
	{
		element.SetValue(VisualFactoryProperty, value);
	}

	/// <summary>
	/// Callback to apply the visual for <see cref="VisualFactoryProperty"/>.
	/// </summary>
	/// <param name="d">The target object the property was changed for.</param>
	/// <param name="e">The <see cref="DependencyPropertyChangedEventArgs"/> instance for the current event.</param>
	private static async void OnVisualFactoryPropertyChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		UIElement element = (UIElement)d;
		Visual attachedVisual = await ((AttachedVisualFactoryBase)e.NewValue).GetAttachedVisualAsync(element);

		attachedVisual.RelativeSizeAdjustment = Vector2.One;

		ElementCompositionPreview.SetElementChildVisual(element, attachedVisual);
	}
}
