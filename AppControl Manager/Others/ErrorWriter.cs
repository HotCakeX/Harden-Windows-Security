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

using System;
using System.Collections.Generic;
using System.Text;

namespace AppControlManager.Others;

internal static class ErrorWriter
{
	/// <summary>
	/// When an exception is raised by the app, writes the full details to the log file for review
	/// </summary>
	/// <param name="ex"></param>
	/// <returns></returns>
	internal static string FormatException(Exception ex)
	{
		StringBuilder sb = new();

		_ = sb.AppendLine("==== Unhandled Exception ====");
		_ = sb.AppendLine($"Message: {ex.Message}");
		_ = sb.AppendLine($"Type: {ex.GetType().FullName}");
		_ = sb.AppendLine($"Source: {ex.Source}");
		_ = sb.AppendLine("Stack Trace:");
		_ = sb.AppendLine(ex.StackTrace);

		// Log inner exceptions (if any)
		Exception? inner = ex.InnerException;
		int depth = 1;
		while (inner is not null)
		{
			_ = sb.AppendLine();
			_ = sb.AppendLine($"-- Inner Exception {depth} --");
			_ = sb.AppendLine($"Message: {inner.Message}");
			_ = sb.AppendLine($"Type: {inner.GetType().FullName}");
			_ = sb.AppendLine($"Source: {inner.Source}");
			_ = sb.AppendLine("Stack Trace:");
			_ = sb.AppendLine(inner.StackTrace);

			inner = inner.InnerException;
			depth++;
		}

		_ = sb.AppendLine("==============================");
		return sb.ToString();
	}


	/// <summary>
	/// When an exception is raised by the app, writes the full details to the log file for review.
	/// This version handles all types of exception hierarchies including AggregateExceptions and deeply nested scenarios.
	/// </summary>
	/// <param name="ex">The exception to format</param>
	/// <returns>Formatted string containing complete exception details</returns>
	internal static string FormatExceptionEx(Exception ex)
	{
		StringBuilder sb = new();
		HashSet<Exception> visited = new(ReferenceEqualityComparer.Instance);

		_ = sb.AppendLine("==== Exception Details ====");
		FormatExceptionRecursive(ex, sb, visited, 0, "Main");
		_ = sb.AppendLine("==============================");

		return sb.ToString();
	}

	/// <summary>
	/// Recursive helper method to format exception details in any exception hierarchy.
	/// Handles:
	/// - Direct exception formatting
	/// - AggregateException.InnerExceptions collections
	/// - Regular Exception.InnerException chains
	/// - Any combination and nesting of the above
	/// </summary>
	/// <param name="exception">Current exception to format</param>
	/// <param name="sb">StringBuilder to append formatted text to</param>
	/// <param name="visited">Set of already visited exceptions to prevent cycles</param>
	/// <param name="depth">Current nesting depth for indentation</param>
	/// <param name="label">Label to identify this exception (e.g., "Main", "Inner", "Aggregate Item 1")</param>
	private static void FormatExceptionRecursive(Exception exception, StringBuilder sb, HashSet<Exception> visited, int depth, string label)
	{
		// Prevent infinite loops from circular exception references
		if (!visited.Add(exception))
		{
			string circularIndent = new(' ', depth * 2);
			_ = sb.AppendLine($"{circularIndent}-- {label} Exception (Already Processed - Circular Reference) --");
			return;
		}

		// Format current exception details
		string indentString = new(' ', depth * 2);
		_ = sb.AppendLine($"{indentString}-- {label} Exception --");
		_ = sb.AppendLine($"{indentString}Message: {exception.Message}");
		_ = sb.AppendLine($"{indentString}Type: {exception.GetType().FullName}");
		_ = sb.AppendLine($"{indentString}Source: {exception.Source}");
		_ = sb.AppendLine($"{indentString}Stack Trace:");

		// Handle stack trace with proper indentation
		if (!string.IsNullOrEmpty(exception.StackTrace))
		{
			string[] stackLines = exception.StackTrace.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
			foreach (string line in stackLines)
			{
				_ = sb.AppendLine($"{indentString}{line}");
			}
		}
		else
		{
			_ = sb.AppendLine($"{indentString}(No stack trace available)");
		}

		// Handle AggregateException's inner exceptions collection
		if (exception is AggregateException aggregateEx)
		{
			if (aggregateEx.InnerExceptions.Count > 0)
			{
				_ = sb.AppendLine($"{indentString}Aggregate Inner Exceptions ({aggregateEx.InnerExceptions.Count} total):");

				for (int i = 0; i < aggregateEx.InnerExceptions.Count; i++)
				{
					Exception innerEx = aggregateEx.InnerExceptions[i];
					string aggregateLabel = $"Aggregate Item {i + 1}";
					_ = sb.AppendLine();
					FormatExceptionRecursive(innerEx, sb, visited, depth + 1, aggregateLabel);
				}
			}
		}

		// Handle regular InnerException chain (applies to ALL exception types)
		// This is crucial for formatting nested exceptions in non-AggregateException hierarchies
		if (exception.InnerException != null)
		{
			_ = sb.AppendLine();
			FormatExceptionRecursive(exception.InnerException, sb, visited, depth + 1, "Inner");
		}
	}
}
