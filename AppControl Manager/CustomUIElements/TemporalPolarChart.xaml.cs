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
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Windows.UI;
using WinRT;

namespace AppControlManager.CustomUIElements;

internal enum TemporalPolarChartMode
{
	Hourly,
	Monthly,
	DayOfWeek
}

internal sealed class TemporalPolarChartModeOption(string displayName, TemporalPolarChartMode mode)
{
	internal string DisplayName => displayName;
	internal TemporalPolarChartMode Mode => mode;
	public override string ToString() => DisplayName;
}

internal sealed class TemporalPolarRingVisual(double x, double y, double diameter, SolidColorBrush stroke, double strokeThickness, double opacity)
{
	internal double X => x;
	internal double Y => y;
	internal double Diameter => diameter;
	internal SolidColorBrush Stroke => stroke;
	internal double StrokeThickness => strokeThickness;
	internal double Opacity => opacity;
}

internal readonly struct TemporalPolarLineVisual(double x1, double y1, double x2, double y2)
{
	internal double X1 => x1;
	internal double Y1 => y1;
	internal double X2 => x2;
	internal double Y2 => y2;
}

internal readonly struct TemporalPolarTextVisual(string text, double x, double y, double width, double fontSize)
{
	internal string Text => text;
	internal double X => x;
	internal double Y => y;
	internal double Width => width;
	internal double FontSize => fontSize;
}

internal sealed class TemporalPolarShapeVisual(PathGeometry data, SolidColorBrush fill, SolidColorBrush stroke, double opacity, double strokeThickness, string tooltip)
{
	internal PathGeometry Data => data;
	internal SolidColorBrush Fill => fill;
	internal SolidColorBrush Stroke => stroke;
	internal double Opacity => opacity;
	internal double StrokeThickness => strokeThickness;
	internal string Tooltip => tooltip;
}

internal sealed partial class TemporalPolarChart : UserControl, INPCImplant
{
	private static readonly Color Series1Color = Color.FromArgb(255, 59, 130, 246);
	private static readonly Color Series2Color = Color.FromArgb(255, 34, 197, 94);
	private const double StartAngleDegrees = -90;
	private TemporalPolarChartModeOption _selectedModeOption = new("Hourly", TemporalPolarChartMode.Hourly);
	private static readonly string[] MonthlyLabels = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
	private static readonly string[] DayOfWeekLabels = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];
	private static readonly string[] HourlyLabels =
	[
		"00", "01", "02", "03", "04", "05",
		"06", "07", "08", "09", "10", "11",
		"12", "13", "14", "15", "16", "17",
		"18", "19", "20", "21", "22", "23"
	];

	internal TemporalPolarChart()
	{
		InitializeComponent();
		_selectedModeOption = ModeOptions[0];
		Bindings.Update();
	}

	public event PropertyChangedEventHandler? PropertyChanged;
	void INPCImplant.RaisePropertyChanged(string? propertyName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

	public List<InteractiveLineChartPoint>? Series1Items
	{
		get; set
		{
			if (!ReferenceEquals(field, value))
			{
				field = value;
				RenderChart();
			}
		}
	}

	public List<InteractiveLineChartPoint>? Series2Items
	{
		get; set
		{
			if (!ReferenceEquals(field, value))
			{
				field = value;
				RenderChart();
			}
		}
	}

	public string Series1Name
	{
		get; set
		{
			if (!string.Equals(field, value, StringComparison.OrdinalIgnoreCase))
			{
				field = value;
				UpdateLegendText(0, 0);
				Bindings.Update();
			}
		}
	} = "Series 1";

	public string Series2Name
	{
		get; set
		{
			if (!string.Equals(field, value, StringComparison.OrdinalIgnoreCase))
			{
				field = value;
				UpdateLegendText(0, 0);
				Bindings.Update();
			}
		}
	} = "Series 2";

	public double? SelectedRangeMinimum
	{
		get; set
		{
			if (!Nullable.Equals(field, value))
			{
				field = value;
				RenderChart();
			}
		}
	}

	public double? SelectedRangeMaximum
	{
		get; set
		{
			if (!Nullable.Equals(field, value))
			{
				field = value;
				RenderChart();
			}
		}
	}

	internal readonly List<TemporalPolarChartModeOption> ModeOptions =
	[
		new("Hourly", TemporalPolarChartMode.Hourly),
		new("Monthly", TemporalPolarChartMode.Monthly),
		new("Day of week", TemporalPolarChartMode.DayOfWeek)
	];

	internal TemporalPolarChartModeOption SelectedModeOption
	{
		get => _selectedModeOption;
		private set
		{
			if (!ReferenceEquals(_selectedModeOption, value))
			{
				_selectedModeOption = value;
				Bindings.Update();
				RenderChart();
			}
		}
	}

	internal readonly SolidColorBrush Series1Brush = new(Series1Color);
	internal readonly SolidColorBrush Series2Brush = new(Series2Color);
	internal readonly ObservableCollection<TemporalPolarRingVisual> RingVisuals = [];
	internal readonly ObservableCollection<TemporalPolarLineVisual> LineVisuals = [];
	internal readonly ObservableCollection<TemporalPolarTextVisual> TextVisuals = [];
	internal readonly ObservableCollection<TemporalPolarShapeVisual> ShapeVisuals = [];
	internal string Series1LegendText { get; private set => this.SP(ref field, value); } = "Series 1: 0";
	internal string Series2LegendText { get; private set => this.SP(ref field, value); } = "Series 2: 0";
	internal Visibility EmptyMessageVisibility { get; private set => this.SP(ref field, value); } = Visibility.Collapsed;

	internal async void ExportCurrentViewToSvg_Click()
	{
		try
		{
			string svgContent = ExportCurrentViewToSvg();
			if (string.IsNullOrWhiteSpace(svgContent))
			{
				return;
			}
			string? savePath = FileDialogHelper.ShowSaveFileDialog("SVG Image (*.svg)|*.svg", "Event_Activity_Pattern.svg");
			if (string.IsNullOrWhiteSpace(savePath))
			{
				return;
			}
			if (!savePath.EndsWith(".svg", StringComparison.OrdinalIgnoreCase))
			{
				savePath += ".svg";
			}
			await File.WriteAllTextAsync(savePath, svgContent);
		}
		catch (Exception ex)
		{
			Logger.Write(ex);
		}
	}

	internal string ExportCurrentViewToSvg()
	{
		int bucketCount = GetBucketCount(SelectedModeOption.Mode);
		string[] labels = BuildLabels(SelectedModeOption.Mode);
		double[] series1Values = new double[bucketCount];
		double[] series2Values = new double[bucketCount];
		FillBuckets(Series1Items, SelectedModeOption.Mode, series1Values);
		FillBuckets(Series2Items, SelectedModeOption.Mode, series2Values);
		double maximumValue = GetMaximumValue(series1Values, series2Values, out double series1Total, out double series2Total);
		if (maximumValue <= 0)
		{
			return string.Empty;
		}
		UpdateLegendText(series1Total, series2Total);
		StringBuilder builder = new(4096);
		const double centerX = 450;
		const double centerY = 255;
		const double radius = 150;
		_ = builder.AppendLine("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 900 460'>");
		_ = builder.AppendLine("<rect x='0' y='0' width='900' height='460' fill='#1b1b1b' rx='10'/>");
		_ = builder.AppendLine("<text x='450' y='34' font-family='Segoe UI' font-size='20' font-weight='600' text-anchor='middle' fill='#FFFFFF'>Event Activity Pattern</text>");
		_ = builder.AppendLine(string.Create(CultureInfo.InvariantCulture, $"<circle cx='340' cy='64' r='6' fill='{ColorToHex(Series1Color)}'/><text x='355' y='68' font-family='Segoe UI' font-size='13' fill='#D0D0D0'>{EscapeSvgText(Series1LegendText)}</text>"));
		_ = builder.AppendLine(string.Create(CultureInfo.InvariantCulture, $"<circle cx='500' cy='64' r='6' fill='{ColorToHex(Series2Color)}'/><text x='515' y='68' font-family='Segoe UI' font-size='13' fill='#D0D0D0'>{EscapeSvgText(Series2LegendText)}</text>"));
		AppendSvgPolygon(builder, centerX, centerY, radius, maximumValue, series2Values, Series2Color, 0.48);
		AppendSvgPolygon(builder, centerX, centerY, radius, maximumValue, series1Values, Series1Color, 0.55);
		for (int index = 1; index <= 4; index++)
		{
			double ringRadius = radius * index / 4;
			bool isBoundaryRing = index == 4;
			double strokeWidth = isBoundaryRing ? 1.35 : 0.85;
			string strokeColor = isBoundaryRing ? "#8E8E8E" : "#787878";
			double opacity = isBoundaryRing ? 0.96 : 0.32;
			_ = builder.AppendLine(string.Create(CultureInfo.InvariantCulture, $"<circle cx='{centerX:0.##}' cy='{centerY:0.##}' r='{ringRadius:0.##}' fill='none' stroke='{strokeColor}' stroke-width='{strokeWidth:0.##}' opacity='{opacity:0.##}'/>"));
		}
		for (int index = 0; index < labels.Length; index++)
		{
			double angle = GetAngle(index, labels.Length);
			double cos = Math.Cos(angle);
			double sin = Math.Sin(angle);
			double x = centerX + (cos * radius);
			double y = centerY + (sin * radius);
			double labelX = centerX + (cos * (radius + 12));
			double labelY = centerY + (sin * (radius + 12));
			_ = builder.AppendLine(string.Create(CultureInfo.InvariantCulture, $"<line x1='{centerX:0.##}' y1='{centerY:0.##}' x2='{x:0.##}' y2='{y:0.##}' stroke='#666666' stroke-width='1' opacity='0.38'/>"));
			_ = builder.AppendLine(string.Create(CultureInfo.InvariantCulture, $"<text x='{labelX:0.##}' y='{labelY + 4:0.##}' font-family='Segoe UI' font-size='12' text-anchor='middle' fill='#FFFFFF'>{EscapeSvgText(labels[index])}</text>"));
		}
		_ = builder.AppendLine("</svg>");
		return builder.ToString();
	}


	private void TemporalPolarChart_Loaded() => RenderChart();

	private void RootGrid_SizeChanged() => RenderChart();

	private void ChartCanvas_SizeChanged() => RenderChart();

	[DynamicWindowsRuntimeCast(typeof(ComboBox))]
	private void ModeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		if (sender is ComboBox comboBox && comboBox.SelectedItem is TemporalPolarChartModeOption option)
		{
			SelectedModeOption = option;
		}
	}

	private void RenderChart()
	{
		ClearVisuals();
		double canvasWidth = GetSafeDimension(ChartCanvas.ActualWidth, 1);
		double canvasHeight = GetSafeDimension(ChartCanvas.ActualHeight, 1);
		if (canvasWidth <= 1 || canvasHeight <= 1)
		{
			return;
		}
		int bucketCount = GetBucketCount(SelectedModeOption.Mode);
		string[] labels = BuildLabels(SelectedModeOption.Mode);
		double[] series1Values = new double[bucketCount];
		double[] series2Values = new double[bucketCount];
		FillBuckets(Series1Items, SelectedModeOption.Mode, series1Values);
		FillBuckets(Series2Items, SelectedModeOption.Mode, series2Values);
		double maximumValue = GetMaximumValue(series1Values, series2Values, out double series1Total, out double series2Total);
		UpdateLegendText(series1Total, series2Total);
		if (maximumValue <= 0)
		{
			EmptyMessageVisibility = Visibility.Visible;
			Bindings.Update();
			return;
		}
		double centerX = canvasWidth / 2;
		double centerY = canvasHeight / 2;
		double radius = Math.Max(70, Math.Min(canvasWidth, canvasHeight) * 0.37);
		BuildGrid(centerX, centerY, radius, labels);
		AddSeriesShape(centerX, centerY, radius, maximumValue, labels, series2Values, Series2Name, Series2Color, 0.70, 2.8);
		AddSeriesShape(centerX, centerY, radius, maximumValue, labels, series1Values, Series1Name, Series1Color, 0.78, 2.8);
		EmptyMessageVisibility = Visibility.Collapsed;
		Bindings.Update();
	}

	private void ClearVisuals()
	{
		RingVisuals.Clear();
		LineVisuals.Clear();
		TextVisuals.Clear();
		ShapeVisuals.Clear();
	}

	private void FillBuckets(List<InteractiveLineChartPoint>? source, TemporalPolarChartMode mode, double[] buckets)
	{
		if (source is null)
		{
			return;
		}
		foreach (InteractiveLineChartPoint point in CollectionsMarshal.AsSpan(source))
		{
			if (!PointIsInSelectedRange(point.X))
			{
				continue;
			}
			long ticks = (long)Math.Clamp(point.X, DateTime.MinValue.Ticks, DateTime.MaxValue.Ticks);
			DateTime dateTime = new(ticks);
			int bucketIndex = GetBucketIndex(dateTime, mode);
			if (bucketIndex >= 0 && bucketIndex < buckets.Length)
			{
				buckets[bucketIndex] += Math.Max(1, point.Y);
			}
		}
	}

	private bool PointIsInSelectedRange(double x)
	{
		if (!SelectedRangeMinimum.HasValue || !SelectedRangeMaximum.HasValue)
		{
			return true;
		}
		double minimum = Math.Min(SelectedRangeMinimum.Value, SelectedRangeMaximum.Value);
		double maximum = Math.Max(SelectedRangeMinimum.Value, SelectedRangeMaximum.Value);
		return x >= minimum && x <= maximum;
	}

	private static int GetBucketCount(TemporalPolarChartMode mode) => mode switch
	{
		TemporalPolarChartMode.Hourly => 24,
		TemporalPolarChartMode.Monthly => 12,
		TemporalPolarChartMode.DayOfWeek => 7,
		_ => 24
	};

	private static int GetBucketIndex(DateTime dateTime, TemporalPolarChartMode mode) => mode switch
	{
		TemporalPolarChartMode.Hourly => dateTime.Hour,
		TemporalPolarChartMode.Monthly => dateTime.Month - 1,
		TemporalPolarChartMode.DayOfWeek => ((int)dateTime.DayOfWeek + 6) % 7,
		_ => dateTime.Hour
	};

	private static string[] BuildLabels(TemporalPolarChartMode mode) => mode switch
	{
		TemporalPolarChartMode.Hourly => HourlyLabels,
		TemporalPolarChartMode.Monthly => MonthlyLabels,
		TemporalPolarChartMode.DayOfWeek => DayOfWeekLabels,
		_ => HourlyLabels
	};

	private void BuildGrid(double centerX, double centerY, double radius, string[] labels)
	{
		const int ringCount = 4;
		SolidColorBrush innerRingBrush = new(Color.FromArgb(255, 120, 120, 120));
		SolidColorBrush boundaryRingBrush = new(Color.FromArgb(255, 142, 142, 142));
		for (int index = 1; index <= ringCount; index++)
		{
			double ringRadius = radius * index / ringCount;
			double diameter = ringRadius * 2;
			bool isBoundaryRing = index == ringCount;
			SolidColorBrush stroke = isBoundaryRing ? boundaryRingBrush : innerRingBrush;
			double strokeThickness = isBoundaryRing ? 1.35 : 0.85;
			double opacity = isBoundaryRing ? 0.96 : 0.32;
			RingVisuals.Add(new TemporalPolarRingVisual(centerX - ringRadius, centerY - ringRadius, diameter, stroke, strokeThickness, opacity));
		}
		for (int index = 0; index < labels.Length; index++)
		{
			double angle = GetAngle(index, labels.Length);
			double cos = Math.Cos(angle);
			double sin = Math.Sin(angle);
			double spokeX = centerX + (cos * radius);
			double spokeY = centerY + (sin * radius);
			LineVisuals.Add(new TemporalPolarLineVisual(centerX, centerY, spokeX, spokeY));
			double labelDistance = radius + 12;
			double labelX = centerX + (cos * labelDistance);
			double labelY = centerY + (sin * labelDistance);
			TextVisuals.Add(new TemporalPolarTextVisual(labels[index], labelX - 18, labelY - 8, 36, labels.Length == 24 ? 10 : 12));
		}
	}

	private void AddSeriesShape(double centerX, double centerY, double radius, double maximumValue, string[] labels, double[] values, string seriesName, Color color, double opacity, double strokeThickness)
	{
		PathFigure figure = new()
		{
			IsClosed = true,
			IsFilled = true
		};
		double maximumDataRadius = Math.Max(0, radius - Math.Max(2.5, strokeThickness));
		StringBuilder tooltipBuilder = new(256);
		_ = tooltipBuilder.AppendLine(seriesName);
		for (int index = 0; index < values.Length; index++)
		{
			double value = values[index];
			double pointRadius = maximumDataRadius * Math.Clamp(value / maximumValue, 0, 1);
			double angle = GetAngle(index, values.Length);
			Point point = new(centerX + (Math.Cos(angle) * pointRadius), centerY + (Math.Sin(angle) * pointRadius));
			if (index == 0)
			{
				figure.StartPoint = point;
			}
			else
			{
				figure.Segments.Add(new LineSegment { Point = point });
			}
			_ = tooltipBuilder.Append(labels[index]);
			_ = tooltipBuilder.Append(": ");
			_ = tooltipBuilder.AppendLine(FormatNumber(value));
		}
		PathGeometry geometry = new();
		geometry.Figures.Add(figure);
		Color fillColor = Color.FromArgb((byte)Math.Round(142 * opacity), color.R, color.G, color.B);
		ShapeVisuals.Add(new TemporalPolarShapeVisual(geometry, new SolidColorBrush(fillColor), new SolidColorBrush(color), opacity, strokeThickness, tooltipBuilder.ToString().TrimEnd()));
	}

	private static double GetMaximumValue(double[] series1Values, double[] series2Values, out double series1Total, out double series2Total)
	{
		series1Total = 0;
		series2Total = 0;
		double maximumValue = 0;
		for (int index = 0; index < series1Values.Length; index++)
		{
			series1Total += series1Values[index];
			series2Total += series2Values[index];
			maximumValue = Math.Max(maximumValue, Math.Max(series1Values[index], series2Values[index]));
		}
		return maximumValue;
	}

	private void UpdateLegendText(double series1Total, double series2Total)
	{
		Series1LegendText = string.Create(CultureInfo.InvariantCulture, $"{Series1Name}: {FormatNumber(series1Total)}");
		Series2LegendText = string.Create(CultureInfo.InvariantCulture, $"{Series2Name}: {FormatNumber(series2Total)}");
	}

	private static void AppendSvgPolygon(StringBuilder builder, double centerX, double centerY, double radius, double maximumValue, double[] values, Color color, double opacity)
	{
		const double polygonStrokeWidth = 3;
		double maximumDataRadius = Math.Max(0, radius - polygonStrokeWidth);
		StringBuilder pointsBuilder = new(values.Length * 20);
		for (int index = 0; index < values.Length; index++)
		{
			double pointRadius = maximumDataRadius * Math.Clamp(values[index] / maximumValue, 0, 1);
			double angle = GetAngle(index, values.Length);
			double x = centerX + (Math.Cos(angle) * pointRadius);
			double y = centerY + (Math.Sin(angle) * pointRadius);
			_ = pointsBuilder.Append(string.Create(CultureInfo.InvariantCulture, $"{x:0.##},{y:0.##} "));
		}
		Color fillColor = Color.FromArgb((byte)Math.Round(180 * opacity), color.R, color.G, color.B);
		_ = builder.AppendLine(string.Create(CultureInfo.InvariantCulture, $"<polygon points='{pointsBuilder.ToString().Trim()}' fill='{ColorToHex(fillColor)}' stroke='{ColorToHex(color)}' stroke-width='{polygonStrokeWidth:0.##}' opacity='{opacity:0.##}'/>"));
	}

	private static double GetAngle(int index, int count) => (StartAngleDegrees + (360.0 / count * index)) * Math.PI / 180.0;

	private static double GetSafeDimension(double value, double fallback) => double.IsFinite(value) && value > 0 ? value : fallback;

	private static string FormatNumber(double value)
	{
		if (Math.Abs(value) >= 1000000)
		{
			return string.Create(CultureInfo.InvariantCulture, $"{value / 1000000:0.#}M");
		}
		if (Math.Abs(value) >= 1000)
		{
			return string.Create(CultureInfo.InvariantCulture, $"{value / 1000:0.#}K");
		}
		return value.ToString("0.#", CultureInfo.InvariantCulture);
	}

	private static string ColorToHex(Color color) => string.Create(CultureInfo.InvariantCulture, $"#{color.R:X2}{color.G:X2}{color.B:X2}");

	private static string EscapeSvgText(string value) => value.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&apos;");

}
