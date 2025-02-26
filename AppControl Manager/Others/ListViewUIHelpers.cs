using System.Text;
using AppControlManager.IntelGathering;
using Microsoft.UI.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.Foundation;

namespace AppControlManager.Others;

internal static class ListViewUIHelpers
{
	// An offscreen TextBlock for measurement
	private static readonly TextBlock tb = new()
	{
		// It's important to make sure this matches the header text style so column texts will be aligned properly
		FontWeight = FontWeights.Bold,
		Margin = new Thickness(10, 0, 2, 0),
		TextWrapping = TextWrapping.NoWrap,
		Padding = new Thickness(5),
	};

	// Padding to add to each column (in pixels)
	private const double padding = 15;

	/// <summary>
	/// Measures the width (in pixels) required to display the given text.
	/// If text is empty or null, the padding will be the only width returned.
	/// </summary>
	internal static double MeasureTextWidth(string? text)
	{
		tb.Text = text;

		tb.Measure(new Size(double.PositiveInfinity, double.PositiveInfinity));

		return tb.DesiredSize.Width + padding;
	}

	/// <summary>
	/// Converts the properties of a FileIdentity row into a labeled, formatted string for copying to clipboard.
	/// </summary>
	/// <param name="row">The selected FileIdentity row from the ListView.</param>
	/// <returns>A formatted string of the row's properties with labels.</returns>
	internal static string ConvertRowToText(FileIdentity row)
	{
		// Use StringBuilder to format each property with its label for easy reading
		return new StringBuilder()
			.AppendLine($"File Name: {row.FileName}")
			.AppendLine($"Signature Status: {row.SignatureStatus}")
			.AppendLine($"Original File Name: {row.OriginalFileName}")
			.AppendLine($"Internal Name: {row.InternalName}")
			.AppendLine($"File Description: {row.FileDescription}")
			.AppendLine($"Product Name: {row.ProductName}")
			.AppendLine($"File Version: {row.FileVersion}")
			.AppendLine($"Package Family Name: {row.PackageFamilyName}")
			.AppendLine($"SHA256 Hash: {row.SHA256Hash}")
			.AppendLine($"SHA1 Hash: {row.SHA1Hash}")
			.AppendLine($"Signing Scenario: {row.SISigningScenario}")
			.AppendLine($"File Path: {row.FilePath}")
			.AppendLine($"SHA1 Page Hash: {row.SHA1PageHash}")
			.AppendLine($"SHA256 Page Hash: {row.SHA256PageHash}")
			.AppendLine($"Has WHQL Signer: {row.HasWHQLSigner}")
			.AppendLine($"File Publishers: {row.FilePublishersToDisplay}")
			.AppendLine($"Is ECC Signed: {row.IsECCSigned}")
			.AppendLine($"Opus Data: {row.Opus}")
			.ToString();
	}
}
