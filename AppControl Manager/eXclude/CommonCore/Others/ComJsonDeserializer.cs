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
using System.Text.Json;

namespace CommonCore.Others;

internal static class ComJsonDeserializer
{
	/// <summary>
	/// Deserializes arbitrary JSON produced by the ComManager.
	/// - Objects become Dictionary<string, object> with OrdinalIgnoreCase keys.
	/// - Arrays become List<object>.
	/// - Numbers prefer Int64 when integral; otherwise Decimal when exact; otherwise Double; as a last resort, raw JSON text as string.
	/// - Strings, booleans, and null are preserved as-is.
	/// </summary>
	/// <param name="json">The JSON text returned by ComManager.exe.</param>
	/// <returns>
	/// Root object represented as:
	/// - Dictionary<string, object> for JSON objects
	/// - List<object> for JSON arrays
	/// - string, long, decimal, double, bool, or null for primitives
	/// </returns>
	/// <exception cref="ArgumentNullException">Thrown when <paramref name="json"/> is null or whitespace.</exception>
	/// <exception cref="InvalidOperationException">Thrown when the JSON cannot be parsed.</exception>
	internal static object? DeserializeComManagerJson(string json)
	{
		if (string.IsNullOrWhiteSpace(json))
		{
			throw new ArgumentNullException(nameof(json), "JSON input is null or whitespace.");
		}
		using JsonDocument doc = JsonDocument.Parse(json);
		JsonElement root = doc.RootElement;
		return ConvertElement(root);
	}

	/// <summary>
	/// - If the root is an array of objects, returns a List<Dictionary<string, object>>.
	/// - If the root is a single object, returns a list with that single dictionary.
	/// - Otherwise throws to surface unexpected shapes early.
	/// </summary>
	/// <param name="json">The JSON text returned by ComManager.exe.</param>
	/// <returns>List of instance dictionaries with OrdinalIgnoreCase keys.</returns>
	/// <exception cref="InvalidOperationException">Thrown when the root is neither an object nor an array of objects.</exception>
	internal static List<Dictionary<string, object?>> DeserializeInstances(string json)
	{
		object? root = DeserializeComManagerJson(json);

		// Root array case: expect an array of objects
		if (root is List<object?> list)
		{
			List<Dictionary<string, object?>> instances = new(list.Count);
			for (int i = 0; i < list.Count; i++)
			{
				object? item = list[i];
				if (item is Dictionary<string, object?> obj)
				{
					instances.Add(obj);
				}
				else
				{
					throw new InvalidOperationException("Expected an array of objects in the JSON root.");
				}
			}
			return instances;
		}

		// Single object case
		if (root is Dictionary<string, object?> single)
		{
			List<Dictionary<string, object?>> instances = new(1)
			{
				single
			};
			return instances;
		}

		throw new InvalidOperationException("Unexpected JSON shape: expected an object or an array of objects.");
	}

	/// <summary>
	/// Recursively converts a JsonElement into primitives and collections.
	/// </summary>
	private static object? ConvertElement(JsonElement element)
	{
		switch (element.ValueKind)
		{
			case JsonValueKind.Null:
			case JsonValueKind.Undefined:
				return null;

			case JsonValueKind.String:
				return element.GetString();

			case JsonValueKind.True:
				return true;

			case JsonValueKind.False:
				return false;

			case JsonValueKind.Number:
				return ConvertNumber(element);

			case JsonValueKind.Array:
				{
					List<object?> list = [];
					foreach (JsonElement child in element.EnumerateArray())
					{
						object? item = ConvertElement(child);
						list.Add(item);
					}
					return list;
				}

			case JsonValueKind.Object:
				return ConvertObject(element);

			default:
				return null;
		}
	}

	/// <summary>
	/// Converts a JSON object into a case-insensitive dictionary of properties.
	/// </summary>
	private static Dictionary<string, object?> ConvertObject(JsonElement obj)
	{
		Dictionary<string, object?> map = new(StringComparer.OrdinalIgnoreCase);
		foreach (JsonProperty prop in obj.EnumerateObject())
		{
			object? value = ConvertElement(prop.Value);
			map[prop.Name] = value;
		}
		return map;
	}

	/// <summary>
	/// Converts a JSON number with best precision:
	/// - Prefer Int64 for integral numbers that fit.
	/// - Otherwise use Decimal when it parses exactly (covers large 64-bit unsigned JSON integers).
	/// - Otherwise use Double.
	/// - As a final fallback, return the raw text to preserve representation.
	/// </summary>
	private static object ConvertNumber(JsonElement element)
	{
		if (element.TryGetInt64(out long int64Value))
			return int64Value;

		if (element.TryGetDecimal(out decimal decimalValue))
			return decimalValue;

		if (element.TryGetDouble(out double doubleValue))
			return doubleValue;

		return element.GetRawText();
	}

	/// <summary>
	/// Normalizes an arbitrary object from <see cref="ComJsonDeserializer"/> into a list of strings.
	/// </summary>
	internal static List<string> CoerceToStringList(object? value)
	{
		List<string> result = [];

		if (value is null)
		{
			return result;
		}

		// Single string
		if (value is string s)
		{
			result.Add(s);
			return result;
		}

		// List<object?> coming from ComJsonDeserializer for JSON arrays
		if (value is List<object?> objectList)
		{
			for (int i = 0; i < objectList.Count; i++)
			{
				object? elem = objectList[i];
				if (elem is string elemStr && !string.IsNullOrWhiteSpace(elemStr))
				{
					result.Add(elemStr);
				}
			}
			return result;
		}

		if (value is List<string> stringList)
		{
			for (int i = 0; i < stringList.Count; i++)
			{
				string elemStr = stringList[i];
				if (!string.IsNullOrWhiteSpace(elemStr))
				{
					result.Add(elemStr);
				}
			}
			return result;
		}

		return result;
	}
}
