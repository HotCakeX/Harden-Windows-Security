using System;
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
}
