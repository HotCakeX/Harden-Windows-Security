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
using Microsoft.UI;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Windows.UI;

namespace AppControlManager.CustomUIElements;

internal sealed class InteractiveLineChartPoint(
	double x,
	double y,
	string xText,
	string yText,
	string? fileName = null,
	string? computerName = null,
	string? policyName = null,
	string? publisherName = null,
	string? processName = null,
	string? directory = null,
	string? detailsText = null)
{
	public double X => x;
	public double Y => y;
	public string XText => xText;
	public string YText => yText;
	public string? FileName => fileName;
	public string? ComputerName => computerName;
	public string? PolicyName => policyName;
	public string? PublisherName => publisherName;
	public string? ProcessName => processName;
	public string? Directory => directory;
	public string? DetailsText => detailsText;
}

internal readonly struct InteractiveLineChartAxisLabel(string text, double x, double y, double width, double fontSize) : IEquatable<InteractiveLineChartAxisLabel>
{
	public string Text => text;
	public double X => x;
	public double Y => y;
	public double Width => width;
	public double FontSize => fontSize;

	public bool Equals(InteractiveLineChartAxisLabel other) =>
		EqualityComparer<string>.Default.Equals(Text, other.Text) &&
		X.Equals(other.X) &&
		Y.Equals(other.Y) &&
		Width.Equals(other.Width) &&
		FontSize.Equals(other.FontSize);

	public override bool Equals(object? obj) => obj is InteractiveLineChartAxisLabel other && Equals(other);

	public override int GetHashCode() => HashCode.Combine(Text, X, Y, Width, FontSize);

	public static bool operator ==(InteractiveLineChartAxisLabel left, InteractiveLineChartAxisLabel right) => left.Equals(right);

	public static bool operator !=(InteractiveLineChartAxisLabel left, InteractiveLineChartAxisLabel right) => !left.Equals(right);
}

internal readonly struct InteractiveLineChartLineVisual(double x1, double y1, double x2, double y2) : IEquatable<InteractiveLineChartLineVisual>
{
	public double X1 => x1;
	public double Y1 => y1;
	public double X2 => x2;
	public double Y2 => y2;

	public bool Equals(InteractiveLineChartLineVisual other) =>
		X1.Equals(other.X1) &&
		Y1.Equals(other.Y1) &&
		X2.Equals(other.X2) &&
		Y2.Equals(other.Y2);

	public override bool Equals(object? obj) => obj is InteractiveLineChartLineVisual other && Equals(other);

	public override int GetHashCode() => HashCode.Combine(X1, Y1, X2, Y2);

	public static bool operator ==(InteractiveLineChartLineVisual left, InteractiveLineChartLineVisual right) => left.Equals(right);

	public static bool operator !=(InteractiveLineChartLineVisual left, InteractiveLineChartLineVisual right) => !left.Equals(right);
}

internal sealed class InteractiveLineChartRangeSelectionChangedEventArgs(bool isActive, double minimumX, double maximumX) : EventArgs
{
	public bool IsActive => isActive;
	public double MinimumX => minimumX;
	public double MaximumX => maximumX;
}

internal enum InteractiveLineChartDisplayMode
{
	Both,
	Series1Only,
	Series2Only
}

internal enum InteractiveLineChartBucketKind
{
	Second,
	Minute,
	Hour,
	Day,
	Week,
	Month,
	Quarter,
	Year
}
internal enum InteractiveLineChartRangeSelectionDragMode
{
	None,
	LeftHandle,
	RightHandle,
	Selection
}

internal sealed partial class InteractiveLineChart : UserControl, INPCImplant
{
	private readonly struct BucketDefinition(long ticks, InteractiveLineChartBucketKind kind)
	{
		internal long Ticks => ticks;
		internal InteractiveLineChartBucketKind Kind => kind;
	}

	private readonly struct RenderedPoint(InteractiveLineChartPoint point, double screenX, double screenY)
	{
		internal InteractiveLineChartPoint Point => point;
		internal double ScreenX => screenX;
		internal double ScreenY => screenY;
	}

	private readonly struct SavedChartState(
		double viewMinX,
		double viewMaxX,
		InteractiveLineChartDisplayMode displayMode,
		bool rangeSelectionActive,
		double? selectedRangeMinimum,
		double? selectedRangeMaximum)
	{
		internal double ViewMinX => viewMinX;
		internal double ViewMaxX => viewMaxX;
		internal InteractiveLineChartDisplayMode DisplayMode => displayMode;
		internal bool RangeSelectionActive => rangeSelectionActive;
		internal double? SelectedRangeMinimum => selectedRangeMinimum;
		internal double? SelectedRangeMaximum => selectedRangeMaximum;
	}

	private static readonly Dictionary<string, SavedChartState> SavedChartStates = new(StringComparer.OrdinalIgnoreCase);

	private sealed class BucketAccumulator
	{
		internal double Count;
		private Dictionary<string, int>? _files;
		private Dictionary<string, int>? _computers;

		internal void Add(InteractiveLineChartPoint point)
		{
			Count += Math.Max(1, point.Y);
			AddValue(ref _files, GetFileNameOnly(point.FileName));
			AddValue(ref _computers, point.ComputerName);
		}

		internal string BuildDetailsText(string seriesName, string countText)
		{
			StringBuilder builder = new(256);
			_ = builder.Append(seriesName);
			_ = builder.Append(": ");
			_ = builder.Append(countText);
			AppendTopValues(builder, "Top files", _files);
			AppendTopValues(builder, "Top computers", _computers);
			return builder.ToString();
		}

		private static void AddValue(ref Dictionary<string, int>? dictionary, string? value)
		{
			if (string.IsNullOrWhiteSpace(value))
			{
				return;
			}

			dictionary ??= new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
			ref int count = ref CollectionsMarshal.GetValueRefOrAddDefault(dictionary, value, out bool exists);
			count = exists ? count + 1 : 1;
		}

		private static string? GetFileNameOnly(string? value)
		{
			if (string.IsNullOrWhiteSpace(value))
			{
				return null;
			}

			try
			{
				string fileName = Path.GetFileName(value);
				return string.IsNullOrWhiteSpace(fileName) ? value : fileName;
			}
			catch
			{
				return value;
			}
		}

		private static void AppendTopValues(StringBuilder builder, string title, Dictionary<string, int>? values)
		{
			if (values is null || values.Count == 0)
			{
				return;
			}

			string? firstKey = null;
			string? secondKey = null;
			string? thirdKey = null;
			int firstValue = 0;
			int secondValue = 0;
			int thirdValue = 0;

			foreach (KeyValuePair<string, int> item in values)
			{
				if (item.Value > firstValue)
				{
					thirdKey = secondKey;
					thirdValue = secondValue;
					secondKey = firstKey;
					secondValue = firstValue;
					firstKey = item.Key;
					firstValue = item.Value;
				}
				else if (item.Value > secondValue)
				{
					thirdKey = secondKey;
					thirdValue = secondValue;
					secondKey = item.Key;
					secondValue = item.Value;
				}
				else if (item.Value > thirdValue)
				{
					thirdKey = item.Key;
					thirdValue = item.Value;
				}
			}

			_ = builder.AppendLine();
			_ = builder.Append(title);
			_ = builder.Append(':');
			AppendTopValue(builder, firstKey, firstValue);
			AppendTopValue(builder, secondKey, secondValue);
			AppendTopValue(builder, thirdKey, thirdValue);
		}

		private static void AppendTopValue(StringBuilder builder, string? key, int value)
		{
			if (string.IsNullOrWhiteSpace(key))
			{
				return;
			}
			string countSuffix = " (" + value.ToString(CultureInfo.InvariantCulture) + ")";
			_ = builder.AppendLine();
			_ = builder.Append("  ");
			_ = builder.Append(key);
			_ = builder.Append(countSuffix);
		}

	}

	private static readonly BucketDefinition[] BucketDefinitions =
	[
		new(TimeSpan.FromSeconds(1).Ticks, InteractiveLineChartBucketKind.Second),
		new(TimeSpan.FromSeconds(5).Ticks, InteractiveLineChartBucketKind.Second),
		new(TimeSpan.FromSeconds(10).Ticks, InteractiveLineChartBucketKind.Second),
		new(TimeSpan.FromSeconds(30).Ticks, InteractiveLineChartBucketKind.Second),
		new(TimeSpan.FromMinutes(1).Ticks, InteractiveLineChartBucketKind.Minute),
		new(TimeSpan.FromMinutes(5).Ticks, InteractiveLineChartBucketKind.Minute),
		new(TimeSpan.FromMinutes(15).Ticks, InteractiveLineChartBucketKind.Minute),
		new(TimeSpan.FromMinutes(30).Ticks, InteractiveLineChartBucketKind.Minute),
		new(TimeSpan.FromHours(1).Ticks, InteractiveLineChartBucketKind.Hour),
		new(TimeSpan.FromHours(6).Ticks, InteractiveLineChartBucketKind.Hour),
		new(TimeSpan.FromHours(12).Ticks, InteractiveLineChartBucketKind.Hour),
		new(TimeSpan.FromDays(1).Ticks, InteractiveLineChartBucketKind.Day),
		new(TimeSpan.FromDays(7).Ticks, InteractiveLineChartBucketKind.Week),
		new(TimeSpan.FromDays(30).Ticks, InteractiveLineChartBucketKind.Month),
		new(TimeSpan.FromDays(90).Ticks, InteractiveLineChartBucketKind.Quarter),
		new(TimeSpan.FromDays(365).Ticks, InteractiveLineChartBucketKind.Year)
	];

	private readonly List<RenderedPoint> _renderedSeries1 = [];
	private readonly List<RenderedPoint> _renderedSeries2 = [];
	private readonly List<InteractiveLineChartPoint> _visibleSeries1 = [];
	private readonly List<InteractiveLineChartPoint> _visibleSeries2 = [];
	private InteractiveLineChartDisplayMode _displayMode = InteractiveLineChartDisplayMode.Both;
	private bool _viewInitialized;
	private bool _isDragging;
	private double _dragStartX;
	private double _dragStartViewMinX;
	private double _dragStartViewMaxX;
	private double _fullMinX;
	private double _fullMaxX;
	private double _viewMinX;
	private double _viewMaxX;
	private double _visibleMinY;
	private double _visibleMaxY;
	private BucketDefinition _activeBucketDefinition = BucketDefinitions[0];
	private const double RangeSelectionHandleWidth = 24;
	private double? _selectedRangeMinimum;
	private double? _selectedRangeMaximum;
	private bool _rangeSelectionActive;
	private double _rangeSelectionMinimumX;
	private double _rangeSelectionMaximumX;
	private double _rangeSelectionMinimumRatio;
	private double _rangeSelectionMaximumRatio;
	private double _rangeSelectionDragStartMinimumRatio;
	private double _rangeSelectionDragStartMaximumRatio;
	private bool _rangeSelectionRatiosInitialized;
	private readonly InputCursor _rangeSelectionResizeCursor = InputSystemCursor.Create(InputSystemCursorShape.SizeWestEast);
	private readonly InputCursor _rangeSelectionMoveCursor = InputSystemCursor.Create(InputSystemCursorShape.SizeAll);
	private InteractiveLineChartRangeSelectionDragMode _rangeSelectionDragMode;
	private double _rangeSelectionDragStartPointerX;
	private double _rangeSelectionDragStartMinimumX;
	private double _rangeSelectionDragStartMaximumX;
	private double _lastObservedCanvasWidth = double.NaN;
	private double _lastObservedCanvasHeight = double.NaN;
	private double _pendingCanvasWidth;
	private double _pendingCanvasHeight;
	private bool _chartLayoutRenderQueued;
	private bool _chartIsLoaded;

	internal InteractiveLineChart() => InitializeComponent();

	public event PropertyChangedEventHandler? PropertyChanged;
	void INPCImplant.RaisePropertyChanged(string? propertyName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));

	public List<InteractiveLineChartPoint>? Series1Items
	{
		get; set
		{
			if (!ReferenceEquals(field, value))
			{
				field = value;
				ResetViewToFullRange();
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
				ResetViewToFullRange();
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
				Bindings.Update();
			}
		}
	} = "Series 2";

	public string ChartStateKey
	{
		get; set
		{
			if (!string.Equals(field, value, StringComparison.OrdinalIgnoreCase))
			{
				field = value;
			}
		}
	} = string.Empty;

	public bool UseDateTimeAxis
	{
		get; set
		{
			if (field != value)
			{
				field = value;
				RenderChart();
			}
		}
	} = true;

	public double? SelectedRangeMinimum
	{
		get => _selectedRangeMinimum;
		set
		{
			if (!Nullable.Equals(_selectedRangeMinimum, value))
			{
				_selectedRangeMinimum = value;
				SyncRangeSelectionFromBoundValues();
			}
		}
	}

	public double? SelectedRangeMaximum
	{
		get => _selectedRangeMaximum;
		set
		{
			if (!Nullable.Equals(_selectedRangeMaximum, value))
			{
				_selectedRangeMaximum = value;
				SyncRangeSelectionFromBoundValues();
			}
		}
	}

	public event EventHandler<InteractiveLineChartRangeSelectionChangedEventArgs>? RangeSelectionChanged;

	internal readonly SolidColorBrush Series1Brush = new(Colors.OrangeRed);
	internal readonly SolidColorBrush Series2Brush = new(Colors.LimeGreen);
	internal readonly ObservableCollection<InteractiveLineChartAxisLabel> XAxisLabels = [];
	internal readonly ObservableCollection<InteractiveLineChartAxisLabel> YAxisLabels = [];
	internal readonly ObservableCollection<InteractiveLineChartLineVisual> HorizontalGridLines = [];
	internal readonly ObservableCollection<InteractiveLineChartLineVisual> VerticalGridLines = [];
	internal string Series1PathData { get; private set => this.SP(ref field, value); } = "M 0,0";
	internal string Series2PathData { get; private set => this.SP(ref field, value); } = "M 0,0";
	internal Visibility Series1PathVisibility { get; private set => this.SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility Series2PathVisibility { get; private set => this.SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility Series1LegendVisibility { get; private set => this.SP(ref field, value); } = Visibility.Visible;
	internal Visibility Series2LegendVisibility { get; private set => this.SP(ref field, value); } = Visibility.Visible;
	internal double PlotLeft { get; private set => this.SP(ref field, value); }
	internal double PlotTop { get; private set => this.SP(ref field, value); }
	internal double PlotWidth { get; private set => this.SP(ref field, value); }
	internal double PlotHeight { get; private set => this.SP(ref field, value); }
	internal double PlotRight { get; private set => this.SP(ref field, value); }
	internal double PlotBottom { get; private set => this.SP(ref field, value); }
	internal Visibility CrosshairVisibility { get; private set => this.SP(ref field, value); } = Visibility.Collapsed;
	internal double CrosshairX { get; private set => this.SP(ref field, value); }
	internal double CrosshairY { get; private set => this.SP(ref field, value); }
	internal double Series1MarkerX { get; private set => this.SP(ref field, value); }
	internal double Series1MarkerY { get; private set => this.SP(ref field, value); }
	internal double Series2MarkerX { get; private set => this.SP(ref field, value); }
	internal double Series2MarkerY { get; private set => this.SP(ref field, value); }
	internal Visibility Series1MarkerVisibility { get; private set => this.SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility Series2MarkerVisibility { get; private set => this.SP(ref field, value); } = Visibility.Collapsed;
	internal double TooltipX { get; private set => this.SP(ref field, value); }
	internal double TooltipY { get; private set => this.SP(ref field, value); }
	internal double TooltipWidth { get; private set => this.SP(ref field, value); } = 260;
	internal string TooltipHeaderText { get; private set => this.SP(ref field, value); } = string.Empty;
	internal string TooltipSeries1Text { get; private set => this.SP(ref field, value); } = string.Empty;
	internal string TooltipSeries2Text { get; private set => this.SP(ref field, value); } = string.Empty;
	internal string TooltipBlockedText { get; private set => this.SP(ref field, value); } = string.Empty;
	internal string TooltipAllowedText { get; private set => this.SP(ref field, value); } = string.Empty;
	internal string TooltipSingleTitleText { get; private set => this.SP(ref field, value); } = string.Empty;
	internal string TooltipSingleBodyText { get; private set => this.SP(ref field, value); } = string.Empty;
	internal string TooltipBlockedHeaderText { get; private set => this.SP(ref field, value); } = string.Empty;
	internal string TooltipBlockedDetailsText { get; private set => this.SP(ref field, value); } = string.Empty;
	internal string TooltipAllowedHeaderText { get; private set => this.SP(ref field, value); } = string.Empty;
	internal string TooltipAllowedDetailsText { get; private set => this.SP(ref field, value); } = string.Empty;
	internal string TooltipSingleHeaderText { get; private set => this.SP(ref field, value); } = string.Empty;
	internal string TooltipSingleDetailsText { get; private set => this.SP(ref field, value); } = string.Empty;
	internal SolidColorBrush TooltipSingleBrush { get; private set => this.SP(ref field, value); } = new(Colors.LimeGreen);
	internal Visibility TooltipBothVisibility { get; private set => this.SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility TooltipSingleVisibility { get; private set => this.SP(ref field, value); } = Visibility.Collapsed;
	internal string ZoomStatusText { get; private set => this.SP(ref field, value); } = "100%";
	internal double RangeSelectionLeft { get; private set => this.SP(ref field, value); }
	internal double RangeSelectionWidth { get; private set => this.SP(ref field, value); }
	internal double RangeSelectionLeftHandleX { get; private set => this.SP(ref field, value); }
	internal double RangeSelectionRightHandleX { get; private set => this.SP(ref field, value); }
	internal Visibility RangeSelectionOverlayVisibility { get; private set => this.SP(ref field, value); } = Visibility.Collapsed;
	internal Visibility RangeSelectionClearButtonVisibility { get; private set => this.SP(ref field, value); } = Visibility.Collapsed;
	internal string RangeSelectionButtonText { get; private set => this.SP(ref field, value); } = "Select range";

	internal async void ExportCurrentViewToSvg_Click()
	{
		try
		{
			string svgContent = ExportCurrentViewToSvg();
			if (string.IsNullOrWhiteSpace(svgContent))
			{
				return;
			}

			string? savePath = FileDialogHelper.ShowSaveFileDialog("SVG Image (*.svg)|*.svg", "Events_Trend.svg");
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
		UpdateVisibleAggregates();
		UpdateVisibleYRange();
		const double exportPlotLeft = 70;
		const double exportPlotTop = 35;
		const double exportPlotWidth = 780;
		const double exportPlotHeight = 230;
		double exportPlotBottom = exportPlotTop + exportPlotHeight;
		StringBuilder builder = new();
		_ = builder.AppendLine("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 -40 900 340'>");
		_ = builder.AppendLine("<style>.title { font-family: 'Segoe UI', sans-serif; font-size: 16px; font-weight: bold; text-anchor: middle; fill: #FFFFFF; }.label { font-family: 'Segoe UI', sans-serif; font-size: 11px; fill: #A0A0A0; }.legend { font-family: 'Segoe UI', sans-serif; font-size: 12px; fill: #D0D0D0; }</style>");
		_ = builder.AppendLine("<rect x='0' y='-40' width='900' height='380' fill='#2b1f25' rx='8' />");
		_ = builder.AppendLine("<text x='450' y='-15' class='title'>Events Trend</text>");
		_ = builder.AppendLine($"<circle cx='35' cy='2' r='5' fill='{BrushToHex(Series1Brush)}' /><text x='48' y='6' class='legend'>{EscapeSvgText(Series1Name)}</text>");
		_ = builder.AppendLine($"<circle cx='125' cy='2' r='5' fill='{BrushToHex(Series2Brush)}' /><text x='138' y='6' class='legend'>{EscapeSvgText(Series2Name)}</text>");

		for (int index = 0; index <= 5; index++)
		{
			double ratio = index / 5.0;
			double y = exportPlotTop + (exportPlotHeight * ratio);
			double value = _visibleMaxY - ((_visibleMaxY - _visibleMinY) * ratio);
			_ = builder.AppendLine(string.Create(CultureInfo.InvariantCulture, $"<line x1='{exportPlotLeft:0.##}' x2='{exportPlotLeft + exportPlotWidth:0.##}' y1='{y:0.##}' y2='{y:0.##}' stroke='#404040' stroke-width='1' stroke-dasharray='4 4' opacity='0.55' />"));
			_ = builder.AppendLine(string.Create(CultureInfo.InvariantCulture, $"<text x='{exportPlotLeft - 12:0.##}' y='{y + 4:0.##}' text-anchor='end' class='label'>{FormatNumber(value)}</text>"));
		}

		int xLabelCount = GetXLabelCount(exportPlotWidth);
		for (int index = 0; index < xLabelCount; index++)
		{
			double ratio = xLabelCount == 1 ? 0 : index / (double)(xLabelCount - 1);
			double value = _viewMinX + ((_viewMaxX - _viewMinX) * ratio);
			double x = exportPlotLeft + (exportPlotWidth * ratio);
			_ = builder.AppendLine(string.Create(CultureInfo.InvariantCulture, $"<line x1='{x:0.##}' x2='{x:0.##}' y1='{exportPlotTop:0.##}' y2='{exportPlotBottom:0.##}' stroke='#303030' stroke-width='1' stroke-dasharray='3 5' opacity='0.35' />"));
			_ = builder.AppendLine(string.Create(CultureInfo.InvariantCulture, $"<text x='{x:0.##}' y='{exportPlotBottom + 22:0.##}' text-anchor='middle' class='label'>{EscapeSvgText(FormatXValue(value))}</text>"));
		}

		if (ShouldShowSeries1() && _visibleSeries1.Count > 1)
		{
			_ = builder.AppendLine($"<path d='{BuildSvgPath(_visibleSeries1, exportPlotLeft, exportPlotTop, exportPlotWidth, exportPlotHeight)}' fill='none' stroke='{BrushToHex(Series1Brush)}' stroke-width='3' stroke-linejoin='round' stroke-linecap='round' />");
		}

		if (ShouldShowSeries2() && _visibleSeries2.Count > 1)
		{
			_ = builder.AppendLine($"<path d='{BuildSvgPath(_visibleSeries2, exportPlotLeft, exportPlotTop, exportPlotWidth, exportPlotHeight)}' fill='none' stroke='{BrushToHex(Series2Brush)}' stroke-width='3' stroke-linejoin='round' stroke-linecap='round' />");
		}

		_ = builder.AppendLine("</svg>");
		return builder.ToString();
	}

	private void InteractiveLineChart_Loaded()
	{
		_chartIsLoaded = true;
		ClearExplicitCanvasSize();
		QueueRenderForActualCanvasSize(forceRender: true);
	}

	private void InteractiveLineChart_Unloaded()
	{
		_chartIsLoaded = false;
		_chartLayoutRenderQueued = false;
	}

	private void InteractiveLineChart_LayoutUpdated() => QueueRenderForActualCanvasSize(forceRender: false);

	private void ChartCanvas_SizeChanged() => QueueRenderForActualCanvasSize(forceRender: true);

	// When range selection is not enabled, pressing the button will enable it.
	// If it's already enabled, pressing the button will trigger recalculation because the chart is designed so zooming in and out while range selection is visible/active does not trigger data recalculation as it degrades user experience, so this button can be used instead.
	private void RangeSelectionButton_Click()
	{
		if (!_viewInitialized)
		{
			ResetViewToFullRange();
		}
		if (!_viewInitialized || _viewMaxX <= _viewMinX)
		{
			return;
		}
		if (!_rangeSelectionActive)
		{
			double visibleRange = _viewMaxX - _viewMinX;
			SetActiveRangeSelection(_viewMinX + (visibleRange * 0.25), _viewMinX + (visibleRange * 0.75));
			RaiseRangeSelectionChanged();
		}
		else
		{
			// Apply the current selection on demand so zoom changes recalculate only when requested.
			RaiseRangeSelectionChanged();
		}
		UpdateRangeSelectionVisuals();
		SaveCurrentChartState();
	}

	private void ClearRangeSelectionButton_Click()
	{
		ClearRangeSelection();
		RangeSelectionChanged?.Invoke(this, new InteractiveLineChartRangeSelectionChangedEventArgs(false, 0, 0));
	}

	private void RangeSelectionLeftHandle_PointerPressed(object sender, PointerRoutedEventArgs e) =>
		BeginRangeSelectionDrag(e, InteractiveLineChartRangeSelectionDragMode.LeftHandle);

	private void RangeSelectionRightHandle_PointerPressed(object sender, PointerRoutedEventArgs e) =>
		BeginRangeSelectionDrag(e, InteractiveLineChartRangeSelectionDragMode.RightHandle);

	private void RangeSelectionArea_PointerPressed(object sender, PointerRoutedEventArgs e) =>
		BeginRangeSelectionDrag(e, InteractiveLineChartRangeSelectionDragMode.Selection);

	private void RangeSelectionHandle_PointerEntered() => ProtectedCursor = _rangeSelectionResizeCursor;

	private void RangeSelectionArea_PointerEntered() => ProtectedCursor = _rangeSelectionMoveCursor;

	private void RangeSelectionInteractiveElement_PointerExited()
	{
		if (_rangeSelectionDragMode == InteractiveLineChartRangeSelectionDragMode.None)
		{
			ProtectedCursor = null;
		}
	}

	private void BeginRangeSelectionDrag(PointerRoutedEventArgs e, InteractiveLineChartRangeSelectionDragMode dragMode)
	{
		if (!_rangeSelectionActive || !_viewInitialized)
		{
			return;
		}
		PointerPoint pointerPoint = e.GetCurrentPoint(ChartCanvas);
		EnsureRangeSelectionRatios();
		NormalizeRangeSelectionRatios();
		_rangeSelectionDragMode = dragMode;
		_rangeSelectionDragStartPointerX = pointerPoint.Position.X;
		_rangeSelectionDragStartMinimumX = _rangeSelectionMinimumX;
		_rangeSelectionDragStartMaximumX = _rangeSelectionMaximumX;
		_rangeSelectionDragStartMinimumRatio = _rangeSelectionMinimumRatio;
		_rangeSelectionDragStartMaximumRatio = _rangeSelectionMaximumRatio;
		ProtectedCursor = dragMode == InteractiveLineChartRangeSelectionDragMode.Selection ? _rangeSelectionMoveCursor : _rangeSelectionResizeCursor;
		_isDragging = false;
		_ = ChartCanvas.CapturePointer(e.Pointer);
		e.Handled = true;
	}

	private void UpdateRangeSelectionDrag(double pointerX)
	{
		if (!_viewInitialized || PlotWidth <= 1 || _rangeSelectionDragMode == InteractiveLineChartRangeSelectionDragMode.None)
		{
			return;
		}
		EnsureRangeSelectionRatios();
		NormalizeRangeSelectionRatios();
		double minimumRatioDistance = Math.Clamp(RangeSelectionHandleWidth / Math.Max(1, PlotWidth), 0.002, 0.25);
		double pointerRatio = Math.Clamp((pointerX - PlotLeft) / PlotWidth, 0, 1);
		if (_rangeSelectionDragMode == InteractiveLineChartRangeSelectionDragMode.LeftHandle)
		{
			// Math.Clamp requires the maximum argument to be greater than or equal to the minimum argument.
			// When the right handle is near the left edge, keep the bound valid instead of throwing during pointer movement.
			double maximumMinimumRatio = Math.Max(0, _rangeSelectionMaximumRatio - minimumRatioDistance);
			double newMinimumRatio = Math.Min(pointerRatio, maximumMinimumRatio);
			SetActiveRangeSelectionFromRatios(newMinimumRatio, _rangeSelectionMaximumRatio);
		}
		else if (_rangeSelectionDragMode == InteractiveLineChartRangeSelectionDragMode.RightHandle)
		{
			// Math.Clamp requires the minimum argument to be less than or equal to the maximum argument.
			// When the left handle is near the right edge, keep the bound valid instead of throwing during pointer movement.
			double minimumMaximumRatio = Math.Min(1, _rangeSelectionMinimumRatio + minimumRatioDistance);
			double newMaximumRatio = Math.Max(pointerRatio, minimumMaximumRatio);
			SetActiveRangeSelectionFromRatios(_rangeSelectionMinimumRatio, newMaximumRatio);
		}
		else if (_rangeSelectionDragMode == InteractiveLineChartRangeSelectionDragMode.Selection)
		{
			double ratioDelta = (pointerX - _rangeSelectionDragStartPointerX) / PlotWidth;
			double selectedRatioWidth = Math.Clamp(_rangeSelectionDragStartMaximumRatio - _rangeSelectionDragStartMinimumRatio, 0, 1);
			double newMinimumRatio = _rangeSelectionDragStartMinimumRatio + ratioDelta;
			double newMaximumRatio = _rangeSelectionDragStartMaximumRatio + ratioDelta;
			if (newMinimumRatio < 0)
			{
				newMinimumRatio = 0;
				newMaximumRatio = selectedRatioWidth;
			}
			if (newMaximumRatio > 1)
			{
				newMaximumRatio = 1;
				newMinimumRatio = 1 - selectedRatioWidth;
			}
			SetActiveRangeSelectionFromRatios(newMinimumRatio, newMaximumRatio);
		}
	}

	private void NormalizeRangeSelectionRatios()
	{
		if (!double.IsFinite(_rangeSelectionMinimumRatio) || !double.IsFinite(_rangeSelectionMaximumRatio))
		{
			_rangeSelectionMinimumRatio = 0.25;
			_rangeSelectionMaximumRatio = 0.75;
			_rangeSelectionRatiosInitialized = true;
			return;
		}
		double normalizedMinimumRatio = Math.Clamp(Math.Min(_rangeSelectionMinimumRatio, _rangeSelectionMaximumRatio), 0, 1);
		double normalizedMaximumRatio = Math.Clamp(Math.Max(_rangeSelectionMinimumRatio, _rangeSelectionMaximumRatio), 0, 1);
		_rangeSelectionMinimumRatio = normalizedMinimumRatio;
		_rangeSelectionMaximumRatio = normalizedMaximumRatio;
		_rangeSelectionRatiosInitialized = true;
	}

	private void EnsureRangeSelectionRatios()
	{
		if (_rangeSelectionRatiosInitialized || !_viewInitialized || _viewMaxX <= _viewMinX)
		{
			return;
		}
		UpdateRangeSelectionRatiosFromValues();
	}

	private void UpdateRangeSelectionRatiosFromValues()
	{
		if (!_viewInitialized || _viewMaxX <= _viewMinX)
		{
			return;
		}
		double denominator = _viewMaxX - _viewMinX;
		_rangeSelectionMinimumRatio = Math.Clamp((_rangeSelectionMinimumX - _viewMinX) / denominator, 0, 1);
		_rangeSelectionMaximumRatio = Math.Clamp((_rangeSelectionMaximumX - _viewMinX) / denominator, 0, 1);
		_rangeSelectionRatiosInitialized = true;
	}

	private void UpdateRangeSelectionValuesFromRatios()
	{
		if (!_viewInitialized || _viewMaxX <= _viewMinX)
		{
			return;
		}
		double viewRange = _viewMaxX - _viewMinX;
		_rangeSelectionMinimumX = _viewMinX + (viewRange * _rangeSelectionMinimumRatio);
		_rangeSelectionMaximumX = _viewMinX + (viewRange * _rangeSelectionMaximumRatio);
		_selectedRangeMinimum = _rangeSelectionMinimumX;
		_selectedRangeMaximum = _rangeSelectionMaximumX;
		_rangeSelectionRatiosInitialized = false;
	}

	private void SetActiveRangeSelectionFromRatios(double minimumRatio, double maximumRatio)
	{
		_rangeSelectionMinimumRatio = Math.Clamp(Math.Min(minimumRatio, maximumRatio), 0, 1);
		_rangeSelectionMaximumRatio = Math.Clamp(Math.Max(minimumRatio, maximumRatio), 0, 1);
		_rangeSelectionRatiosInitialized = true;
		UpdateRangeSelectionValuesFromRatios();
		_rangeSelectionActive = true;
		UpdateRangeSelectionVisuals();
		SaveCurrentChartState();
	}

	private void SetActiveRangeSelection(double minimumX, double maximumX)
	{
		double minimumRange = Math.Max(1, (_fullMaxX - _fullMinX) / 10000);
		double normalizedMinimum = Math.Clamp(Math.Min(minimumX, maximumX), _fullMinX, _fullMaxX);
		double normalizedMaximum = Math.Clamp(Math.Max(minimumX, maximumX), _fullMinX, _fullMaxX);
		if (normalizedMaximum - normalizedMinimum < minimumRange)
		{
			normalizedMaximum = Math.Min(_fullMaxX, normalizedMinimum + minimumRange);
			normalizedMinimum = Math.Max(_fullMinX, normalizedMaximum - minimumRange);
		}
		_rangeSelectionMinimumX = normalizedMinimum;
		_rangeSelectionMaximumX = normalizedMaximum;
		_selectedRangeMinimum = normalizedMinimum;
		_selectedRangeMaximum = normalizedMaximum;
		_rangeSelectionRatiosInitialized = false;
		UpdateRangeSelectionRatiosFromValues();
		_rangeSelectionActive = true;
		UpdateRangeSelectionVisuals();
		SaveCurrentChartState();
	}

	private void SyncRangeSelectionFromBoundValues()
	{
		if (_selectedRangeMinimum.HasValue && _selectedRangeMaximum.HasValue)
		{
			double minimumX = Math.Min(_selectedRangeMinimum.Value, _selectedRangeMaximum.Value);
			double maximumX = Math.Max(_selectedRangeMinimum.Value, _selectedRangeMaximum.Value);
			if (maximumX > minimumX)
			{
				_rangeSelectionMinimumX = minimumX;
				_rangeSelectionMaximumX = maximumX;
				_rangeSelectionRatiosInitialized = false;
				UpdateRangeSelectionRatiosFromValues();
				_rangeSelectionActive = true;
				UpdateRangeSelectionVisuals();
				SaveCurrentChartState();
				return;
			}
		}
		ClearRangeSelectionVisualsOnly();
		SaveCurrentChartState();
	}

	private void ClearRangeSelection()
	{
		_selectedRangeMinimum = null;
		_selectedRangeMaximum = null;
		_rangeSelectionRatiosInitialized = false;
		ProtectedCursor = null;
		ClearRangeSelectionVisualsOnly();
		SaveCurrentChartState();
	}

	private void ClearRangeSelectionVisualsOnly()
	{
		_rangeSelectionActive = false;
		_rangeSelectionDragMode = InteractiveLineChartRangeSelectionDragMode.None;
		RangeSelectionLeft = 0;
		RangeSelectionWidth = 0;
		RangeSelectionLeftHandleX = 0;
		RangeSelectionRightHandleX = 0;
		RangeSelectionOverlayVisibility = Visibility.Collapsed;
		RangeSelectionClearButtonVisibility = Visibility.Collapsed;
		RangeSelectionButtonText = "Select range";
		ProtectedCursor = null;
	}

	private void HideRangeSelectionVisualsPreservingState()
	{
		RangeSelectionLeft = 0;
		RangeSelectionWidth = 0;
		RangeSelectionLeftHandleX = 0;
		RangeSelectionRightHandleX = 0;
		RangeSelectionOverlayVisibility = Visibility.Collapsed;
		RangeSelectionClearButtonVisibility = _rangeSelectionActive ? Visibility.Visible : Visibility.Collapsed;
		RangeSelectionButtonText = _rangeSelectionActive ? "Reapply Range" : "Select range";
	}

	private void UpdateRangeSelectionVisuals()
	{
		if (!_rangeSelectionActive || _rangeSelectionMaximumX <= _rangeSelectionMinimumX)
		{
			ClearRangeSelectionVisualsOnly();
			return;
		}
		if (!_viewInitialized || PlotWidth <= 1)
		{
			HideRangeSelectionVisualsPreservingState();
			return;
		}
		_rangeSelectionRatiosInitialized = false;
		UpdateRangeSelectionRatiosFromValues();
		double left = PlotLeft + (PlotWidth * _rangeSelectionMinimumRatio);
		double right = PlotLeft + (PlotWidth * _rangeSelectionMaximumRatio);
		double visibleLeft = Math.Clamp(Math.Min(left, right), PlotLeft, PlotRight);
		double visibleRight = Math.Clamp(Math.Max(left, right), PlotLeft, PlotRight);
		RangeSelectionLeft = visibleLeft;
		RangeSelectionWidth = Math.Max(0, visibleRight - visibleLeft);
		RangeSelectionLeftHandleX = Math.Clamp(left - (RangeSelectionHandleWidth / 2), PlotLeft - (RangeSelectionHandleWidth / 2), PlotRight - (RangeSelectionHandleWidth / 2));
		RangeSelectionRightHandleX = Math.Clamp(right - (RangeSelectionHandleWidth / 2), PlotLeft - (RangeSelectionHandleWidth / 2), PlotRight - (RangeSelectionHandleWidth / 2));
		RangeSelectionOverlayVisibility = Visibility.Visible;
		RangeSelectionClearButtonVisibility = Visibility.Visible;
		RangeSelectionButtonText = "Reapply Range";
	}

	private void RaiseRangeSelectionChanged()
	{
		if (!_rangeSelectionActive)
		{
			RangeSelectionChanged?.Invoke(this, new InteractiveLineChartRangeSelectionChangedEventArgs(false, 0, 0));
			return;
		}
		RangeSelectionChanged?.Invoke(this, new InteractiveLineChartRangeSelectionChangedEventArgs(true, _rangeSelectionMinimumX, _rangeSelectionMaximumX));
	}

	private void QueueRenderForActualCanvasSize(bool forceRender)
	{
		if (!_chartIsLoaded || !TryGetActualCanvasSize(out double canvasWidth, out double canvasHeight))
		{
			return;
		}

		if (!forceRender && AreClose(canvasWidth, _lastObservedCanvasWidth) && AreClose(canvasHeight, _lastObservedCanvasHeight))
		{
			return;
		}

		_lastObservedCanvasWidth = canvasWidth;
		_lastObservedCanvasHeight = canvasHeight;
		_pendingCanvasWidth = canvasWidth;
		_pendingCanvasHeight = canvasHeight;

		if (_chartLayoutRenderQueued)
		{
			return;
		}

		_chartLayoutRenderQueued = true;
		_ = DispatcherQueue.TryEnqueue(ApplyActualCanvasSizeAndRender);
	}

	private void ApplyActualCanvasSizeAndRender()
	{
		_chartLayoutRenderQueued = false;
		ClearExplicitCanvasSize();

		if (!_chartIsLoaded || _pendingCanvasWidth <= 1 || _pendingCanvasHeight <= 1)
		{
			return;
		}

		RenderChart();
	}

	private void ClearExplicitCanvasSize()
	{
		if (!double.IsNaN(ChartCanvas.Width))
		{
			ChartCanvas.Width = double.NaN;
		}

		if (!double.IsNaN(ChartCanvas.Height))
		{
			ChartCanvas.Height = double.NaN;
		}
	}

	private bool TryGetActualCanvasSize(out double canvasWidth, out double canvasHeight)
	{
		canvasWidth = ChartCanvas.ActualWidth;
		canvasHeight = ChartCanvas.ActualHeight;
		return double.IsFinite(canvasWidth) && double.IsFinite(canvasHeight) && canvasWidth > 1 && canvasHeight > 1;
	}

	private static bool AreClose(double first, double second) => double.IsFinite(first) && double.IsFinite(second) && Math.Abs(first - second) < 0.5;

	private void ShowBothButton_Click()
	{
		_displayMode = InteractiveLineChartDisplayMode.Both;
		SaveCurrentChartState();
		RenderChart();
	}

	private void ShowSeries1Button_Click()
	{
		_displayMode = InteractiveLineChartDisplayMode.Series1Only;
		SaveCurrentChartState();
		RenderChart();
	}

	private void ShowSeries2Button_Click()
	{
		_displayMode = InteractiveLineChartDisplayMode.Series2Only;
		SaveCurrentChartState();
		RenderChart();
	}

	private void ResetZoomButton_Click()
	{
		ResetViewToFullRange(restoreSavedState: false);
		if (_rangeSelectionActive)
		{
			UpdateRangeSelectionVisuals();
		}
		SaveCurrentChartState();
		RenderChart();
	}

	private void ZoomInRepeatButton_Click() => ZoomAtPlotCenter(0.82);

	private void ZoomOutRepeatButton_Click() => ZoomAtPlotCenter(1.22);

	private void ZoomAtPlotCenter(double factor)
	{
		if (!_viewInitialized)
		{
			ResetViewToFullRange();
		}
		if (!_viewInitialized)
		{
			return;
		}
		double anchorX = PlotWidth > 1 ? PlotLeft + (PlotWidth / 2) : GetSafeDimension(ChartCanvas.ActualWidth, 1) / 2;
		ZoomAt(anchorX, factor);
	}

	private void ChartCanvas_PointerPressed(object sender, PointerRoutedEventArgs e)
	{
		PointerPoint pointerPoint = e.GetCurrentPoint(ChartCanvas);
		if (pointerPoint.Properties.IsLeftButtonPressed || pointerPoint.PointerDeviceType == PointerDeviceType.Touch)
		{
			_isDragging = true;
			_dragStartX = pointerPoint.Position.X;
			_dragStartViewMinX = _viewMinX;
			_dragStartViewMaxX = _viewMaxX;
			_ = ChartCanvas.CapturePointer(e.Pointer);
		}
	}

	private void ChartCanvas_PointerReleased(object sender, PointerRoutedEventArgs e)
	{
		if (_rangeSelectionDragMode != InteractiveLineChartRangeSelectionDragMode.None)
		{
			_rangeSelectionDragMode = InteractiveLineChartRangeSelectionDragMode.None;
			ProtectedCursor = null;
			ChartCanvas.ReleasePointerCapture(e.Pointer);
			SaveCurrentChartState();
			RaiseRangeSelectionChanged();
			e.Handled = true;
			return;
		}
		_isDragging = false;
		ChartCanvas.ReleasePointerCapture(e.Pointer);
	}

	private void ChartCanvas_PointerMoved(object sender, PointerRoutedEventArgs e)
	{
		Point position = e.GetCurrentPoint(ChartCanvas).Position;
		if (_rangeSelectionDragMode != InteractiveLineChartRangeSelectionDragMode.None)
		{
			UpdateRangeSelectionDrag(position.X);
			e.Handled = true;
			return;
		}
		if (_isDragging)
		{
			PanView(position.X - _dragStartX);
		}
		UpdateCrosshair(position.X, position.Y);
	}

	private void ChartCanvas_PointerExited()
	{
		if (!_isDragging)
		{
			HideInteractiveOverlays();
		}
	}

	private void ChartCanvas_PointerWheelChanged(object sender, PointerRoutedEventArgs e)
	{
		PointerPoint pointerPoint = e.GetCurrentPoint(ChartCanvas);
		int delta = pointerPoint.Properties.MouseWheelDelta;
		if (delta == 0)
		{
			return;
		}

		double zoomFactor = delta > 0 ? 0.82 : 1.22;
		ZoomAt(pointerPoint.Position.X, zoomFactor);
		UpdateCrosshair(pointerPoint.Position.X, pointerPoint.Position.Y);
		e.Handled = true;
	}

	private void ChartCanvas_ManipulationDelta(object sender, ManipulationDeltaRoutedEventArgs e)
	{
		if (e.Delta.Scale != 1.0)
		{
			ZoomAt(PlotLeft + (PlotWidth / 2), 1.0 / e.Delta.Scale);
		}
	}

	private void ResetViewToFullRange(bool restoreSavedState = true)
	{
		if (!TryGetFullXRange(out double minX, out double maxX))
		{
			_viewInitialized = false;
			return;
		}
		_fullMinX = minX;
		_fullMaxX = maxX;
		if (restoreSavedState && TryRestoreSavedChartState())
		{
			_viewInitialized = true;
			return;
		}
		_viewMinX = minX;
		_viewMaxX = maxX;
		_viewInitialized = true;
	}

	private bool TryRestoreSavedChartState()
	{
		string key = GetSavedChartStateKey();
		if (!SavedChartStates.TryGetValue(key, out SavedChartState savedState))
		{
			return false;
		}
		double fullRange = _fullMaxX - _fullMinX;
		double savedRange = savedState.ViewMaxX - savedState.ViewMinX;
		if (fullRange <= 0 || savedRange <= 0 || savedRange > fullRange)
		{
			_ = SavedChartStates.Remove(key);
			return false;
		}
		double restoredMinimum = Math.Clamp(savedState.ViewMinX, _fullMinX, _fullMaxX);
		double restoredMaximum = Math.Clamp(savedState.ViewMaxX, _fullMinX, _fullMaxX);
		if (restoredMaximum <= restoredMinimum)
		{
			_ = SavedChartStates.Remove(key);
			return false;
		}
		_viewMinX = restoredMinimum;
		_viewMaxX = restoredMaximum;
		_displayMode = savedState.DisplayMode;
		RestoreRangeSelectionFromSavedState(savedState);
		return true;
	}

	private void RestoreRangeSelectionFromSavedState(SavedChartState savedState)
	{
		if (!savedState.RangeSelectionActive || !savedState.SelectedRangeMinimum.HasValue || !savedState.SelectedRangeMaximum.HasValue)
		{
			return;
		}
		double minimumX = Math.Clamp(Math.Min(savedState.SelectedRangeMinimum.Value, savedState.SelectedRangeMaximum.Value), _fullMinX, _fullMaxX);
		double maximumX = Math.Clamp(Math.Max(savedState.SelectedRangeMinimum.Value, savedState.SelectedRangeMaximum.Value), _fullMinX, _fullMaxX);
		if (maximumX <= minimumX)
		{
			return;
		}
		_rangeSelectionMinimumX = minimumX;
		_rangeSelectionMaximumX = maximumX;
		_selectedRangeMinimum = minimumX;
		_selectedRangeMaximum = maximumX;
		_rangeSelectionRatiosInitialized = false;
		UpdateRangeSelectionRatiosFromValues();
		_rangeSelectionActive = true;
	}

	private void SaveCurrentChartState()
	{
		if (!_viewInitialized || _viewMaxX <= _viewMinX || _fullMaxX <= _fullMinX)
		{
			return;
		}
		string key = GetSavedChartStateKey();
		double fullRange = _fullMaxX - _fullMinX;
		double visibleRange = _viewMaxX - _viewMinX;
		bool viewIsFullRange = visibleRange >= fullRange * 0.995;
		if (viewIsFullRange && !_rangeSelectionActive && _displayMode == InteractiveLineChartDisplayMode.Both)
		{
			_ = SavedChartStates.Remove(key);
			return;
		}
		double? selectedRangeMinimum = _rangeSelectionActive ? _rangeSelectionMinimumX : null;
		double? selectedRangeMaximum = _rangeSelectionActive ? _rangeSelectionMaximumX : null;
		SavedChartStates[key] = new SavedChartState(_viewMinX, _viewMaxX, _displayMode, _rangeSelectionActive, selectedRangeMinimum, selectedRangeMaximum);
	}

	private string GetSavedChartStateKey() => string.Create(CultureInfo.InvariantCulture, $"{ChartStateKey}|{Series1Name}|{Series2Name}|{UseDateTimeAxis}|{_fullMinX:R}|{_fullMaxX:R}");

	private void RenderChart()
	{
		UpdatePlotArea();
		UpdateLegendVisibility();
		HideInteractiveOverlays();
		if (!_viewInitialized)
		{
			ResetViewToFullRange();
		}

		if (!_viewInitialized || PlotWidth <= 1 || PlotHeight <= 1)
		{
			ClearRenderedChart();
			return;
		}

		UpdateVisibleAggregates();
		UpdateVisibleYRange();
		bool series1HasSegments = BuildPath(_visibleSeries1, _renderedSeries1, out string series1PathData);
		bool series2HasSegments = BuildPath(_visibleSeries2, _renderedSeries2, out string series2PathData);
		Series1PathData = series1PathData;
		Series2PathData = series2PathData;
		Series1PathVisibility = ShouldShowSeries1() && series1HasSegments ? Visibility.Visible : Visibility.Collapsed;
		Series2PathVisibility = ShouldShowSeries2() && series2HasSegments ? Visibility.Visible : Visibility.Collapsed;
		BuildAxisLabelsAndGridLines();
		UpdateZoomStatusText();
		UpdateRangeSelectionVisuals();
		Bindings.Update();
	}

	private void UpdateVisibleAggregates()
	{
		long visibleTicks = Math.Max(1, (long)Math.Round(_viewMaxX - _viewMinX));
		_activeBucketDefinition = SelectBucketDefinition(visibleTicks);
		BuildAggregatedSeries(Series1Items, _activeBucketDefinition.Ticks, _visibleSeries1, Series1Name);
		BuildAggregatedSeries(Series2Items, _activeBucketDefinition.Ticks, _visibleSeries2, Series2Name);
	}

	private void BuildAggregatedSeries(List<InteractiveLineChartPoint>? source, long bucketTicks, List<InteractiveLineChartPoint> target, string seriesName)
	{
		target.Clear();
		if (source is null || source.Count == 0)
		{
			return;
		}

		SortedDictionary<long, BucketAccumulator> buckets = new();
		foreach (InteractiveLineChartPoint point in CollectionsMarshal.AsSpan(source))
		{
			if (point.X < _viewMinX || point.X > _viewMaxX)
			{
				continue;
			}

			long bucketStart = AlignTicksToBucket((long)point.X, bucketTicks);
			if (!buckets.TryGetValue(bucketStart, out BucketAccumulator? accumulator))
			{
				accumulator = new BucketAccumulator();
				buckets.Add(bucketStart, accumulator);
			}
			accumulator.Add(point);
		}

		if (buckets.Count == 0)
		{
			return;
		}

		long firstBucket = AlignTicksToBucket((long)_viewMinX, bucketTicks);
		long lastBucket = AlignTicksToBucket((long)_viewMaxX, bucketTicks);
		for (long bucketStart = firstBucket; bucketStart <= lastBucket; bucketStart += bucketTicks)
		{
			_ = buckets.TryGetValue(bucketStart, out BucketAccumulator? accumulator);
			double count = accumulator?.Count ?? 0;
			DateTime bucketDateTime = new(Math.Clamp(bucketStart, DateTime.MinValue.Ticks, DateTime.MaxValue.Ticks));
			string xText = FormatBucketText(bucketDateTime, _activeBucketDefinition.Kind);
			string yText = count.ToString("0.#", CultureInfo.InvariantCulture);
			string detailsText = accumulator?.BuildDetailsText(seriesName, yText) ?? string.Create(CultureInfo.InvariantCulture, $"{seriesName}: 0");
			target.Add(new InteractiveLineChartPoint(bucketStart, count, xText, yText, detailsText: detailsText));
			if (bucketStart > long.MaxValue - bucketTicks)
			{
				break;
			}
		}
	}

	private double ComputeTooltipWidth(bool useTwoSectionTooltip)
	{
		double availableWidth = Math.Max(180, PlotWidth - 12);
		double contentWidthCap = useTwoSectionTooltip ? 520 : 340;
		double preferredWidth = useTwoSectionTooltip ? PlotWidth * 0.46 : PlotWidth * 0.34;
		double minimumWidth = useTwoSectionTooltip ? Math.Min(380, availableWidth) : Math.Min(250, availableWidth);
		double maximumWidth = Math.Min(contentWidthCap, Math.Max(minimumWidth, availableWidth));
		return Math.Clamp(preferredWidth, minimumWidth, maximumWidth);
	}

	private static BucketDefinition SelectBucketDefinition(long visibleTicks)
	{
		const int targetMaximumBuckets = 140;
		foreach (BucketDefinition bucketDefinition in BucketDefinitions)
		{
			if ((visibleTicks / (double)bucketDefinition.Ticks) <= targetMaximumBuckets)
			{
				return bucketDefinition;
			}
		}
		return BucketDefinitions[^1];
	}

	private static long AlignTicksToBucket(long ticks, long bucketTicks) => ticks - (ticks % bucketTicks);

	private static string FormatBucketText(DateTime dateTime, InteractiveLineChartBucketKind bucketKind) => bucketKind switch
	{
		InteractiveLineChartBucketKind.Second => dateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
		InteractiveLineChartBucketKind.Minute => dateTime.ToString("yyyy-MM-dd HH:mm", CultureInfo.InvariantCulture),
		InteractiveLineChartBucketKind.Hour => dateTime.ToString("yyyy-MM-dd HH:00", CultureInfo.InvariantCulture),
		InteractiveLineChartBucketKind.Day => dateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
		InteractiveLineChartBucketKind.Week => dateTime.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture),
		InteractiveLineChartBucketKind.Month => dateTime.ToString("yyyy-MM", CultureInfo.InvariantCulture),
		InteractiveLineChartBucketKind.Quarter => dateTime.ToString("yyyy-MM", CultureInfo.InvariantCulture),
		InteractiveLineChartBucketKind.Year => dateTime.ToString("yyyy", CultureInfo.InvariantCulture),
		_ => dateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture)
	};

	private void UpdatePlotArea()
	{
		double width = GetSafeDimension(ChartCanvas.ActualWidth > 0 ? ChartCanvas.ActualWidth : ChartCanvas.Width, 1);
		double height = GetSafeDimension(ChartCanvas.ActualHeight > 0 ? ChartCanvas.ActualHeight : ChartCanvas.Height, 1);
		double left = Math.Clamp(width * 0.10, 46, 86);
		double right = Math.Clamp(width * 0.025, 8, 28);
		double top = Math.Clamp(height * 0.06, 10, 22);
		double bottom = Math.Clamp(height * 0.16, 34, 54);
		PlotLeft = left;
		PlotTop = top;
		PlotWidth = Math.Max(10, width - left - right);
		PlotHeight = Math.Max(10, height - top - bottom);
		PlotRight = PlotLeft + PlotWidth;
		PlotBottom = PlotTop + PlotHeight;
		TooltipWidth = ComputeTooltipWidth(useTwoSectionTooltip: false);
	}

	private static double GetSafeDimension(double value, double fallback) => double.IsFinite(value) && value > 0 ? value : fallback;

	private void UpdateLegendVisibility()
	{
		Series1LegendVisibility = ShouldShowSeries1() ? Visibility.Visible : Visibility.Collapsed;
		Series2LegendVisibility = ShouldShowSeries2() ? Visibility.Visible : Visibility.Collapsed;
	}

	private bool ShouldShowSeries1() => _displayMode is InteractiveLineChartDisplayMode.Both or InteractiveLineChartDisplayMode.Series1Only;

	private bool ShouldShowSeries2() => _displayMode is InteractiveLineChartDisplayMode.Both or InteractiveLineChartDisplayMode.Series2Only;

	private void ClearRenderedChart()
	{
		Series1PathData = "M 0,0";
		Series2PathData = "M 0,0";
		Series1PathVisibility = Visibility.Collapsed;
		Series2PathVisibility = Visibility.Collapsed;
		_renderedSeries1.Clear();
		_renderedSeries2.Clear();
		_visibleSeries1.Clear();
		_visibleSeries2.Clear();
		XAxisLabels.Clear();
		YAxisLabels.Clear();
		HorizontalGridLines.Clear();
		VerticalGridLines.Clear();
		HideInteractiveOverlays();
		HideRangeSelectionVisualsPreservingState();
	}

	private void HideInteractiveOverlays()
	{
		CrosshairVisibility = Visibility.Collapsed;
		Series1MarkerVisibility = Visibility.Collapsed;
		Series2MarkerVisibility = Visibility.Collapsed;
		TooltipBothVisibility = Visibility.Collapsed;
		TooltipSingleVisibility = Visibility.Collapsed;
	}

	private bool TryGetFullXRange(out double minX, out double maxX)
	{
		minX = double.MaxValue;
		maxX = double.MinValue;
		UpdateMinMaxFromSeries(Series1Items, ref minX, ref maxX);
		UpdateMinMaxFromSeries(Series2Items, ref minX, ref maxX);
		if (minX == double.MaxValue || maxX == double.MinValue)
		{
			return false;
		}

		if (Math.Abs(maxX - minX) < double.Epsilon)
		{
			maxX = minX + 1;
		}
		return true;
	}

	private static void UpdateMinMaxFromSeries(List<InteractiveLineChartPoint>? series, ref double minX, ref double maxX)
	{
		if (series is null)
		{
			return;
		}

		foreach (InteractiveLineChartPoint point in CollectionsMarshal.AsSpan(series))
		{
			if (point.X < minX)
			{
				minX = point.X;
			}

			if (point.X > maxX)
			{
				maxX = point.X;
			}
		}
	}

	private void UpdateVisibleYRange()
	{
		double minY = double.MaxValue;
		double maxY = double.MinValue;
		if (ShouldShowSeries1())
		{
			UpdateVisibleYRangeFromSeries(_visibleSeries1, ref minY, ref maxY);
		}

		if (ShouldShowSeries2())
		{
			UpdateVisibleYRangeFromSeries(_visibleSeries2, ref minY, ref maxY);
		}

		if (minY == double.MaxValue || maxY == double.MinValue)
		{
			minY = 0;
			maxY = 1;
		}

		if (minY > 0)
		{
			minY = 0;
		}

		double range = maxY - minY;
		if (range < 1)
		{
			range = 1;
		}
		_visibleMinY = minY;
		_visibleMaxY = maxY + (range * 0.08);
	}

	private static void UpdateVisibleYRangeFromSeries(List<InteractiveLineChartPoint> series, ref double minY, ref double maxY)
	{
		foreach (InteractiveLineChartPoint point in CollectionsMarshal.AsSpan(series))
		{
			if (point.Y < minY)
			{
				minY = point.Y;
			}

			if (point.Y > maxY)
			{
				maxY = point.Y;
			}
		}
	}

	private bool BuildPath(List<InteractiveLineChartPoint> source, List<RenderedPoint> renderedPoints, out string pathData)
	{
		renderedPoints.Clear();
		if (source.Count < 2)
		{
			pathData = "M 0,0";
			return false;
		}

		ReadOnlySpan<InteractiveLineChartPoint> sourceSpan = CollectionsMarshal.AsSpan(source);
		StringBuilder builder = new(sourceSpan.Length * 22);
		for (int index = 0; index < sourceSpan.Length; index++)
		{
			InteractiveLineChartPoint point = sourceSpan[index];
			double screenX = MapX(point.X);
			double screenY = MapY(point.Y);
			if (!IsFiniteScreenPoint(screenX, screenY))
			{
				continue;
			}

			_ = index == 0
				? builder.Append(string.Create(CultureInfo.InvariantCulture, $"M {screenX:0.##},{screenY:0.##}"))
				: builder.Append(string.Create(CultureInfo.InvariantCulture, $" L {screenX:0.##},{screenY:0.##}"));

			if (IsInsidePlot(screenX, screenY))
			{
				renderedPoints.Add(new RenderedPoint(point, screenX, screenY));
			}
		}

		pathData = renderedPoints.Count > 0 ? builder.ToString() : "M 0,0";
		return renderedPoints.Count > 1;
	}

	private bool IsInsidePlot(double screenX, double screenY) => IsFiniteScreenPoint(screenX, screenY) && screenX >= PlotLeft && screenX <= PlotRight && screenY >= PlotTop && screenY <= PlotBottom;

	private static bool IsFiniteScreenPoint(double screenX, double screenY) => double.IsFinite(screenX) && double.IsFinite(screenY);

	private void BuildAxisLabelsAndGridLines()
	{
		XAxisLabels.Clear();
		YAxisLabels.Clear();
		HorizontalGridLines.Clear();
		VerticalGridLines.Clear();
		double canvasWidth = GetSafeDimension(ChartCanvas.ActualWidth > 0 ? ChartCanvas.ActualWidth : ChartCanvas.Width, 1);
		double canvasHeight = GetSafeDimension(ChartCanvas.ActualHeight > 0 ? ChartCanvas.ActualHeight : ChartCanvas.Height, 1);
		double fontSize = GetAdaptiveFontSize(canvasWidth, canvasHeight);

		for (int index = 0; index <= 5; index++)
		{
			double ratio = index / 5.0;
			double value = _visibleMaxY - ((_visibleMaxY - _visibleMinY) * ratio);
			double y = PlotTop + (PlotHeight * ratio);
			HorizontalGridLines.Add(new InteractiveLineChartLineVisual(PlotLeft, y, PlotRight, y));
			YAxisLabels.Add(new InteractiveLineChartAxisLabel(FormatNumber(value), 0, y - (fontSize * 0.7), PlotLeft - 8, fontSize));
		}

		int xIntervals = GetXLabelCount(PlotWidth);
		for (int index = 0; index < xIntervals; index++)
		{
			double ratio = xIntervals == 1 ? 0 : index / (double)(xIntervals - 1);
			double value = _viewMinX + ((_viewMaxX - _viewMinX) * ratio);
			double x = PlotLeft + (PlotWidth * ratio);
			double labelWidth = Math.Clamp(PlotWidth / Math.Max(1, xIntervals), 48, 120);
			VerticalGridLines.Add(new InteractiveLineChartLineVisual(x, PlotTop, x, PlotBottom));
			XAxisLabels.Add(new InteractiveLineChartAxisLabel(FormatXValue(value), x - (labelWidth / 2), PlotBottom + 8, labelWidth, fontSize));
		}
	}

	private static int GetXLabelCount(double plotWidth)
	{
		if (plotWidth < 260)
		{
			return 2;
		}
		if (plotWidth < 420)
		{
			return 3;
		}
		if (plotWidth < 620)
		{
			return 4;
		}
		if (plotWidth < 900)
		{
			return 6;
		}
		return 8;
	}

	private static double GetAdaptiveFontSize(double width, double height)
	{
		double raw = Math.Min(GetSafeDimension(width, 1), GetSafeDimension(height, 1)) / 34;
		return Math.Clamp(raw, 9, 13);
	}

	private double MapX(double value)
	{
		double denominator = _viewMaxX - _viewMinX;
		return denominator <= 0 ? PlotLeft : PlotLeft + ((value - _viewMinX) / denominator * PlotWidth);
	}

	private double MapY(double value)
	{
		double denominator = _visibleMaxY - _visibleMinY;
		return denominator <= 0 ? PlotBottom : PlotBottom - ((value - _visibleMinY) / denominator * PlotHeight);
	}

	private double MapExportX(double value, double plotLeft, double plotWidth)
	{
		double denominator = _viewMaxX - _viewMinX;
		return denominator <= 0 ? plotLeft : plotLeft + ((value - _viewMinX) / denominator * plotWidth);
	}

	private double MapExportY(double value, double plotTop, double plotHeight)
	{
		double denominator = _visibleMaxY - _visibleMinY;
		return denominator <= 0 ? plotTop + plotHeight : plotTop + plotHeight - ((value - _visibleMinY) / denominator * plotHeight);
	}

	private string BuildSvgPath(List<InteractiveLineChartPoint> source, double plotLeft, double plotTop, double plotWidth, double plotHeight)
	{
		ReadOnlySpan<InteractiveLineChartPoint> sourceSpan = CollectionsMarshal.AsSpan(source);
		StringBuilder builder = new(sourceSpan.Length * 22);
		for (int index = 0; index < sourceSpan.Length; index++)
		{
			InteractiveLineChartPoint point = sourceSpan[index];
			double x = MapExportX(point.X, plotLeft, plotWidth);
			double y = MapExportY(point.Y, plotTop, plotHeight);
			_ = index == 0
				? builder.Append(string.Create(CultureInfo.InvariantCulture, $"M {x:0.##},{y:0.##}"))
				: builder.Append(string.Create(CultureInfo.InvariantCulture, $" L {x:0.##},{y:0.##}"));
		}
		return builder.ToString();
	}

	private void UpdateCrosshair(double pointerX, double pointerY)
	{
		if (!_viewInitialized || pointerX < PlotLeft || pointerX > PlotRight || pointerY < PlotTop || pointerY > PlotBottom)
		{
			HideInteractiveOverlays();
			return;
		}

		CrosshairX = pointerX;
		CrosshairY = pointerY;
		CrosshairVisibility = Visibility.Visible;
		double xValue = _viewMinX + ((pointerX - PlotLeft) / PlotWidth * (_viewMaxX - _viewMinX));
		RenderedPoint? nearest1 = FindNearestPoint(_renderedSeries1, xValue);
		RenderedPoint? nearest2 = FindNearestPoint(_renderedSeries2, xValue);
		bool showBlockedMarker = Series1PathVisibility == Visibility.Visible && nearest1.HasValue && IsInsidePlot(nearest1.Value.ScreenX, nearest1.Value.ScreenY);
		bool showAllowedMarker = Series2PathVisibility == Visibility.Visible && nearest2.HasValue && IsInsidePlot(nearest2.Value.ScreenX, nearest2.Value.ScreenY);
		Series1MarkerVisibility = showBlockedMarker ? Visibility.Visible : Visibility.Collapsed;
		Series2MarkerVisibility = showAllowedMarker ? Visibility.Visible : Visibility.Collapsed;

		if (showBlockedMarker && nearest1.HasValue)
		{
			Series1MarkerX = nearest1.Value.ScreenX - 6;
			Series1MarkerY = nearest1.Value.ScreenY - 6;
			TooltipSeries1Text = nearest1.Value.Point.DetailsText ?? nearest1.Value.Point.YText;
			TooltipBlockedText = TooltipSeries1Text;
			SplitTooltipText(TooltipBlockedText, Series1Name, out string blockedHeaderText, out string blockedDetailsText);
			TooltipBlockedHeaderText = blockedHeaderText;
			TooltipBlockedDetailsText = blockedDetailsText;
		}
		else
		{
			TooltipSeries1Text = string.Empty;
			TooltipBlockedText = string.Empty;
			TooltipBlockedHeaderText = string.Empty;
			TooltipBlockedDetailsText = string.Empty;
		}

		if (showAllowedMarker && nearest2.HasValue)
		{
			Series2MarkerX = nearest2.Value.ScreenX - 6;
			Series2MarkerY = nearest2.Value.ScreenY - 6;
			TooltipSeries2Text = nearest2.Value.Point.DetailsText ?? nearest2.Value.Point.YText;
			TooltipAllowedText = TooltipSeries2Text;
			SplitTooltipText(TooltipAllowedText, Series2Name, out string allowedHeaderText, out string allowedDetailsText);
			TooltipAllowedHeaderText = allowedHeaderText;
			TooltipAllowedDetailsText = allowedDetailsText;
		}
		else
		{
			TooltipSeries2Text = string.Empty;
			TooltipAllowedText = string.Empty;
			TooltipAllowedHeaderText = string.Empty;
			TooltipAllowedDetailsText = string.Empty;
		}

		TooltipHeaderText = FormatTooltipXValue(xValue);
		if (showBlockedMarker && showAllowedMarker)
		{
			TooltipBothVisibility = Visibility.Visible;
			TooltipSingleVisibility = Visibility.Collapsed;
			TooltipWidth = ComputeTooltipWidth(useTwoSectionTooltip: true);
		}
		else if (showBlockedMarker)
		{
			TooltipBothVisibility = Visibility.Collapsed;
			TooltipSingleVisibility = Visibility.Visible;
			TooltipSingleTitleText = Series1Name;
			TooltipSingleBodyText = TooltipBlockedText;
			TooltipSingleHeaderText = TooltipBlockedHeaderText;
			TooltipSingleDetailsText = TooltipBlockedDetailsText;
			TooltipSingleBrush = Series1Brush;
			TooltipWidth = ComputeTooltipWidth(useTwoSectionTooltip: false);
		}
		else if (showAllowedMarker)
		{
			TooltipBothVisibility = Visibility.Collapsed;
			TooltipSingleVisibility = Visibility.Visible;
			TooltipSingleTitleText = Series2Name;
			TooltipSingleBodyText = TooltipAllowedText;
			TooltipSingleHeaderText = TooltipAllowedHeaderText;
			TooltipSingleDetailsText = TooltipAllowedDetailsText;
			TooltipSingleBrush = Series2Brush;
			TooltipWidth = ComputeTooltipWidth(useTwoSectionTooltip: false);
		}
		else
		{
			TooltipBothVisibility = Visibility.Collapsed;
			TooltipSingleVisibility = Visibility.Collapsed;
			return;
		}

		double tooltipHeightEstimate = TooltipBothVisibility == Visibility.Visible ? 245 : 180;
		PositionTooltipBesidePointer(pointerX, pointerY, tooltipHeightEstimate);
		BringVisibleTooltipAboveRangeSelection();
		_ = DispatcherQueue.TryEnqueue(BringVisibleTooltipAboveRangeSelection);
	}

	private void BringVisibleTooltipAboveRangeSelection()
	{
		const int tooltipZIndex = 5000;
		for (int index = 0; index < ChartCanvas.Children.Count; index++)
		{
			UIElement child = ChartCanvas.Children[index];
			if (ElementContainsVisibleTooltipContent(child))
			{
				Canvas.SetZIndex(child, tooltipZIndex);
			}
		}
	}

	private bool ElementContainsVisibleTooltipContent(DependencyObject element)
	{
		if (element is TextBlock textBlock && TextMatchesVisibleTooltipContent(textBlock.Text))
		{
			return true;
		}
		int childCount = VisualTreeHelper.GetChildrenCount(element);
		for (int index = 0; index < childCount; index++)
		{
			DependencyObject child = VisualTreeHelper.GetChild(element, index);
			if (ElementContainsVisibleTooltipContent(child))
			{
				return true;
			}
		}
		return false;
	}

	private bool TextMatchesVisibleTooltipContent(string value)
	{
		if (string.IsNullOrWhiteSpace(value))
		{
			return false;
		}
		if (TooltipBothVisibility == Visibility.Visible)
		{
			return string.Equals(value, TooltipBlockedHeaderText, StringComparison.OrdinalIgnoreCase) ||
				string.Equals(value, TooltipAllowedHeaderText, StringComparison.OrdinalIgnoreCase) ||
				string.Equals(value, TooltipBlockedDetailsText, StringComparison.OrdinalIgnoreCase) ||
				string.Equals(value, TooltipAllowedDetailsText, StringComparison.OrdinalIgnoreCase);
		}
		if (TooltipSingleVisibility == Visibility.Visible)
		{
			return string.Equals(value, TooltipSingleHeaderText, StringComparison.OrdinalIgnoreCase) ||
				string.Equals(value, TooltipSingleDetailsText, StringComparison.OrdinalIgnoreCase);
		}
		return false;
	}

	private static void SplitTooltipText(string tooltipText, string fallbackHeaderText, out string headerText, out string detailsText)
	{
		if (string.IsNullOrWhiteSpace(tooltipText))
		{
			headerText = fallbackHeaderText;
			detailsText = string.Empty;
			return;
		}
		int lineBreakIndex = tooltipText.IndexOf('\n');
		if (lineBreakIndex < 0)
		{
			headerText = tooltipText.Trim();
			detailsText = string.Empty;
			return;
		}
		headerText = tooltipText[..lineBreakIndex].Trim();
		detailsText = tooltipText[(lineBreakIndex + 1)..].Trim();
	}

	private void PositionTooltipBesidePointer(double pointerX, double pointerY, double tooltipHeightEstimate)
	{
		const double tooltipGap = 18;
		double rightX = pointerX + tooltipGap;
		double leftX = pointerX - TooltipWidth - tooltipGap;
		bool canUseRightSide = rightX + TooltipWidth <= PlotRight;
		bool canUseLeftSide = leftX >= PlotLeft;
		double tooltipX;

		if (canUseRightSide)
		{
			tooltipX = rightX;
		}
		else if (canUseLeftSide)
		{
			tooltipX = leftX;
		}
		else if (pointerX < PlotLeft + (PlotWidth / 2))
		{
			// Keep the tooltip to the right of the pointer even in very tight widths.
			tooltipX = rightX;
		}
		else
		{
			// Keep the tooltip to the left of the pointer even in very tight widths.
			tooltipX = leftX;
		}

		double tooltipY = pointerY - (tooltipHeightEstimate / 2);
		TooltipX = tooltipX;
		TooltipY = Math.Clamp(tooltipY, PlotTop, Math.Max(PlotTop, PlotBottom - tooltipHeightEstimate));
	}

	private static RenderedPoint? FindNearestPoint(List<RenderedPoint> points, double xValue)
	{
		ReadOnlySpan<RenderedPoint> pointsSpan = CollectionsMarshal.AsSpan(points);
		if (pointsSpan.Length == 0)
		{
			return null;
		}

		int low = 0;
		int high = pointsSpan.Length - 1;
		while (high - low > 1)
		{
			int middle = low + ((high - low) / 2);
			if (pointsSpan[middle].Point.X < xValue)
			{
				low = middle;
			}
			else
			{
				high = middle;
			}
		}

		double lowDistance = Math.Abs(pointsSpan[low].Point.X - xValue);
		double highDistance = Math.Abs(pointsSpan[high].Point.X - xValue);
		return lowDistance <= highDistance ? pointsSpan[low] : pointsSpan[high];
	}

	private void ZoomAt(double pointerX, double factor)
	{
		if (!_viewInitialized || PlotWidth <= 1)
		{
			return;
		}

		bool keepRangeSelectionVisualSize = _rangeSelectionActive && _viewMaxX > _viewMinX;
		double preservedMinimumRatio = 0;
		double preservedMaximumRatio = 0;
		if (keepRangeSelectionVisualSize)
		{
			EnsureRangeSelectionRatios();
			NormalizeRangeSelectionRatios();
			preservedMinimumRatio = _rangeSelectionMinimumRatio;
			preservedMaximumRatio = _rangeSelectionMaximumRatio;
		}

		double anchorRatio = Math.Clamp((pointerX - PlotLeft) / PlotWidth, 0, 1);
		double anchorValue = _viewMinX + ((_viewMaxX - _viewMinX) * anchorRatio);
		double currentRange = _viewMaxX - _viewMinX;
		double fullRange = _fullMaxX - _fullMinX;
		double newRange = Math.Clamp(currentRange * factor, Math.Max(fullRange / 500, 1), fullRange);
		double newMin = anchorValue - (newRange * anchorRatio);
		double newMax = newMin + newRange;

		if (newMin < _fullMinX)
		{
			newMin = _fullMinX;
			newMax = newMin + newRange;
		}

		if (newMax > _fullMaxX)
		{
			newMax = _fullMaxX;
			newMin = newMax - newRange;
		}

		_viewMinX = Math.Max(_fullMinX, newMin);
		_viewMaxX = Math.Min(_fullMaxX, newMax);
		if (keepRangeSelectionVisualSize)
		{
			_rangeSelectionMinimumRatio = preservedMinimumRatio;
			_rangeSelectionMaximumRatio = preservedMaximumRatio;
			_rangeSelectionRatiosInitialized = true;
			UpdateRangeSelectionValuesFromRatios();
		}
		SaveCurrentChartState();
		RenderChart();
	}

	private void PanView(double deltaPixels)
	{
		if (!_viewInitialized || PlotWidth <= 1)
		{
			return;
		}

		double range = _dragStartViewMaxX - _dragStartViewMinX;
		double deltaValue = -(deltaPixels / PlotWidth) * range;
		double newMin = _dragStartViewMinX + deltaValue;
		double newMax = _dragStartViewMaxX + deltaValue;

		if (newMin < _fullMinX)
		{
			newMin = _fullMinX;
			newMax = newMin + range;
		}

		if (newMax > _fullMaxX)
		{
			newMax = _fullMaxX;
			newMin = newMax - range;
		}

		_viewMinX = newMin;
		_viewMaxX = newMax;
		SaveCurrentChartState();
		RenderChart();
	}

	private void UpdateZoomStatusText()
	{
		double fullRange = _fullMaxX - _fullMinX;
		double visibleRange = _viewMaxX - _viewMinX;
		if (fullRange <= 0 || visibleRange <= 0)
		{
			ZoomStatusText = "100%";
			return;
		}

		double zoom = fullRange / visibleRange;
		ZoomStatusText = zoom <= 1.02 ? "100%" : string.Create(CultureInfo.InvariantCulture, $"{zoom:0.#}x zoom");
	}

	private string FormatXValue(double value)
	{
		if (UseDateTimeAxis)
		{
			long ticks = (long)Math.Clamp(value, DateTime.MinValue.Ticks, DateTime.MaxValue.Ticks);
			DateTime dateTime = new(ticks);
			double visibleRangeTicks = _viewMaxX - _viewMinX;
			if (visibleRangeTicks <= TimeSpan.FromDays(2).Ticks)
			{
				return dateTime.ToString("MM/dd HH:mm", CultureInfo.InvariantCulture);
			}
			if (visibleRangeTicks <= TimeSpan.FromDays(90).Ticks)
			{
				return dateTime.ToString("MM/dd", CultureInfo.InvariantCulture);
			}
			return dateTime.ToString("yyyy/MM", CultureInfo.InvariantCulture);
		}
		return FormatNumber(value);
	}

	private string FormatTooltipXValue(double value)
	{
		if (UseDateTimeAxis)
		{
			long ticks = (long)Math.Clamp(value, DateTime.MinValue.Ticks, DateTime.MaxValue.Ticks);
			DateTime dateTime = new(ticks);
			return dateTime.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture);
		}
		return FormatNumber(value);
	}

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

	private static string BrushToHex(SolidColorBrush brush)
	{
		Color color = brush.Color;
		return string.Create(CultureInfo.InvariantCulture, $"#{color.R:X2}{color.G:X2}{color.B:X2}");
	}

	private static string EscapeSvgText(string value) => value.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;").Replace("'", "&apos;");

}
