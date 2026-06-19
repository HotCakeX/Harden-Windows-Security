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
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using CommonCore.IntelGathering;
using CommonCore.ToolKits;
using Microsoft.UI;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.Foundation;
using Windows.UI;

namespace AppControlManager.Analysis;

internal sealed partial class AnalysisResultItem(string name, string displayName, int count, Color itemColor) : ViewModelBase
{
	internal string Name => name;
	internal string DisplayName => displayName;

	internal int Count => count;

	// Color property for charts, bound to the ColorPicker
	internal Color ItemColor
	{
		get; set
		{
			if (SP(ref field, value))
			{
				ColorBrush = new SolidColorBrush(value);
				OnPropertyChanged(nameof(ColorBrush));
				ColorChanged?.Invoke(this, EventArgs.Empty);
			}
		}
	} = itemColor;

	internal SolidColorBrush ColorBrush { get; private set; } = new SolidColorBrush(itemColor);

	internal event EventHandler? ColorChanged;
}

internal sealed class ColorPalette(string name, SolidColorBrush brush1, SolidColorBrush brush2, SolidColorBrush brush3)
{
	internal string Name => name;
	internal SolidColorBrush Brush1 => brush1;
	internal SolidColorBrush Brush2 => brush2;
	internal SolidColorBrush Brush3 => brush3;
}

internal sealed partial class AnalysisCategory : ViewModelBase
{
	internal string Title { get; init; } = string.Empty;
	internal string IconGlyph { get; init; } = string.Empty;

	internal readonly ObservableCollection<AnalysisResultItem> Items = [];

	internal bool IsPieChartVisible
	{
		get; set
		{
			// Prevent unchecking if the other one isn't checked
			if (!value && !IsBarChartVisible) return;

			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(PieChartVisibility));
				if (value) IsBarChartVisible = false;
			}
		}
	} = true;

	internal bool IsBarChartVisible
	{
		get; set
		{
			// Prevent unchecking if the other one isn't checked
			if (!value && !IsPieChartVisible) return;

			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(BarChartVisibility));
				if (value) IsPieChartVisible = false;
			}
		}
	}

	internal Visibility PieChartVisibility => IsPieChartVisible ? Visibility.Visible : Visibility.Collapsed;
	internal Visibility BarChartVisibility => IsBarChartVisible ? Visibility.Visible : Visibility.Collapsed;

	internal readonly ObservableCollection<PieSliceData> PieSlices = [];
	internal readonly ObservableCollection<ColumnBarData> ColumnBars = [];

	internal void AddItems(IEnumerable<AnalysisResultItem> newItems)
	{
		Items.Clear();

		// Setting default color palette
		ColorPalette defaultPalette = FileIdentityAnalysis.AvailablePalettes[6];

		// Since all categories are limited to a maximum of 3 items, we only need the 3 palette colors.
		Color[] defaultColors = [
			defaultPalette.Brush1.Color,
			defaultPalette.Brush2.Color,
			defaultPalette.Brush3.Color
		];

		int colorIndex = 0;

		foreach (AnalysisResultItem item in newItems)
		{
			item.ItemColor = defaultColors[colorIndex % defaultColors.Length];
			item.ColorChanged += (s, e) => UpdateCharts();
			Items.Add(item);
			colorIndex++;
		}
		UpdateCharts();
	}

	internal void UpdateCharts()
	{
		double total = Items.Sum(x => x.Count);
		if (total == 0) return;

		// Update Pie Slices
		PieSlices.Clear();
		double currentAngle = 0;
		double radius = 70;
		double cx = 75;
		double cy = 75;
		int sliceIndex = 0;

		foreach (AnalysisResultItem item in Items)
		{
			if (item.Count == 0) continue;

			double pct = Math.Round(item.Count / total * 100, 1);
			double sweepAngle = item.Count / total * 360;

			if (sweepAngle >= 359.99)
			{
				string fullCirclePath = $"M {cx} {cy - radius} a {radius},{radius} 0 1,0 0,{radius * 2} a {radius},{radius} 0 1,0 0,-{radius * 2}";
				PieSlices.Add(new PieSliceData
				(
					pathData: fullCirclePath,
					fill: item.ColorBrush,
					toolTip: $"{item.DisplayName}: {item.Count} (100%)",
					percentageText: "100%",
					labelX: cx - 15,
					labelY: cy - 10,
					centerX: cx,
					centerY: cy,
					hoverOffsetX: 0,
					hoverOffsetY: 0
				));
				continue;
			}

			double startRad = (currentAngle - 90) * Math.PI / 180.0;
			double endRad = (currentAngle + sweepAngle - 90) * Math.PI / 180.0;

			double startX = cx + radius * Math.Cos(startRad);
			double startY = cy + radius * Math.Sin(startRad);
			double endX = cx + radius * Math.Cos(endRad);
			double endY = cy + radius * Math.Sin(endRad);

			int largeArcFlag = sweepAngle > 180 ? 1 : 0;
			string pathData = $"M {cx},{cy} L {startX:0.00},{startY:0.00} A {radius},{radius} 0 {largeArcFlag},1 {endX:0.00},{endY:0.00} Z";

			double midAngle = currentAngle + (sweepAngle / 2);
			double midRad = (midAngle - 90) * Math.PI / 180.0;

			// Adjust label radius for very narrow slices to prevent text overlapping
			double labelRadius = radius * 0.65;
			if (sweepAngle < 15)
			{
				// Stagger the labels outwards alternating by index
				labelRadius = radius * (0.65 + (sliceIndex % 2 == 0 ? 0.3 : 0.6));
			}

			double labelX = cx + labelRadius * Math.Cos(midRad) - 15;
			double labelY = cy + labelRadius * Math.Sin(midRad) - 10;

			double popOutDistance = 8.0;

			PieSlices.Add(new PieSliceData
			(
				pathData: pathData,
				fill: item.ColorBrush,
				toolTip: $"{item.DisplayName}: {item.Count} ({pct}%)",
				percentageText: $"{pct}%",
				labelX: labelX,
				labelY: labelY,
				centerX: cx,
				centerY: cy,
				hoverOffsetX: popOutDistance * Math.Cos(midRad),
				hoverOffsetY: popOutDistance * Math.Sin(midRad)
			));

			currentAngle += sweepAngle;
			sliceIndex++;
		}

		// Update Column Bars
		ColumnBars.Clear();
		double maxVal = Items.Max(x => x.Count);
		double maxHeightPx = 100;

		foreach (AnalysisResultItem item in Items)
		{
			double h = item.Count / maxVal * maxHeightPx;
			double pct = Math.Round(item.Count / total * 100, 1);
			ColumnBars.Add(new ColumnBarData(height: h, maxHeight: maxHeightPx, label: item.DisplayName, toolTip: $"{item.DisplayName}: {item.Count}", fill: item.ColorBrush, percentageText: $"{pct}%"));
		}
	}
}

internal sealed class PieSliceData(string pathData, SolidColorBrush fill, string toolTip, string percentageText, double labelX, double labelY, double centerX, double centerY, double hoverOffsetX, double hoverOffsetY)

{
	internal string PathData => pathData;
	internal SolidColorBrush Fill => fill;
	internal string Tooltip => toolTip;
	internal string PercentageText => percentageText;
	internal double LabelX => labelX;
	internal double LabelY => labelY;
	internal double CenterX => centerX;
	internal double CenterY => centerY;
	internal double HoverOffsetX => hoverOffsetX;
	internal double HoverOffsetY => hoverOffsetY;
}

internal sealed class ColumnBarData(double height, double maxHeight, SolidColorBrush fill, string toolTip, string label, string percentageText)
{
	internal double Height => height;
	internal double MaxHeight => maxHeight;
	internal SolidColorBrush Fill => fill;
	internal string Tooltip => toolTip;
	internal string Label => label;
	internal string PercentageText => percentageText;
}

internal sealed class LinePointData(double x, double y, SolidColorBrush fill, string dateText, string countText)
{
	internal double X => x;
	internal double Y => y;
	internal SolidColorBrush Fill => fill;
	internal string DateText => dateText;
	internal string CountText => countText;
}

internal sealed class AxisLabel(string text, double offset)
{
	internal string Text => text;
	internal double Offset => offset;
}

internal readonly struct ChartGridLine(double offset)
{
	internal double Offset => offset;
}

internal enum AnalysisTimeRangeKind
{
	AllTime,
	Past1Hour,
	Past12Hours,
	Past24Hours,
	PastWeek,
	PastMonth,
	Past6Months,
	PastYear
}

internal sealed class TimeRangeFilterOption(string displayName, AnalysisTimeRangeKind kind)
{
	internal string DisplayName => displayName;
	internal AnalysisTimeRangeKind Kind => kind;
	public override string ToString() => DisplayName;
}

internal sealed partial class FileIdentityAnalysis : ViewModelBase
{
	private List<FileIdentity> _allFileIdentities = [];
	private bool _suppressTimeRangeRefresh;

	internal FileIdentityAnalysis()
	{
		_suppressTimeRangeRefresh = true;
		Analysis_SelectedTimeRange = Analysis_TimeRangeOptions[0];
		_suppressTimeRangeRefresh = false;
	}

	internal readonly List<TimeRangeFilterOption> Analysis_TimeRangeOptions =
	[
		new("All time (entire range)", AnalysisTimeRangeKind.AllTime),
		new("Past 1 hour", AnalysisTimeRangeKind.Past1Hour),
		new("Past 12 hours", AnalysisTimeRangeKind.Past12Hours),
		new("Past 24 hours", AnalysisTimeRangeKind.Past24Hours),
		new("Past week", AnalysisTimeRangeKind.PastWeek),
		new("Past month", AnalysisTimeRangeKind.PastMonth),
		new("Past 6 months", AnalysisTimeRangeKind.Past6Months),
		new("Past year", AnalysisTimeRangeKind.PastYear)
	];

	internal TimeRangeFilterOption? Analysis_SelectedTimeRange { get; set => SP(ref field, value); }

	internal bool Analysis_IsRecalculating
	{
		get; set
		{
			if (SP(ref field, value))
			{
				OnPropertyChanged(nameof(Analysis_RecalculationProgressVisibility));
				OnPropertyChanged(nameof(Analysis_ContentOpacity));
				OnPropertyChanged(nameof(Analysis_ContentIsHitTestVisible));
			}
		}
	}

	internal Visibility Analysis_RecalculationProgressVisibility => Analysis_IsRecalculating ? Visibility.Visible : Visibility.Collapsed;
	internal double Analysis_ContentOpacity => Analysis_IsRecalculating ? 0.45 : 1.0;
	internal bool Analysis_ContentIsHitTestVisible => !Analysis_IsRecalculating;

	internal string? Analysis_TotalAllowed { get; set => SP(ref field, value); }
	internal string? Analysis_TotalBlocked { get; set => SP(ref field, value); }

	internal string? Analysis_Global_TotalSigned { get; set => SP(ref field, value); }
	internal string? Analysis_Global_TotalUnsigned { get; set => SP(ref field, value); }
	internal string? Analysis_Global_TotalECCSigned { get; set => SP(ref field, value); }
	internal string? Analysis_Global_TotalUserWriteable { get; set => SP(ref field, value); }
	internal string? Analysis_Global_TotalWHQL { get; set => SP(ref field, value); }
	internal string? Analysis_Global_TotalSigningLevelMismatches { get; set => SP(ref field, value); }

	internal readonly ObservableCollection<AnalysisCategory> BlockedCategories = [];
	internal readonly ObservableCollection<AnalysisCategory> AllowedCategories = [];

	internal string? Analysis_SummaryText { get; set => SP(ref field, value); }
	internal readonly ObservableCollection<string> Analysis_ActionableRecommendations = [];

	internal static readonly List<ColorPalette> AvailablePalettes = [
		new(name: "Default", brush1: new (Colors.DodgerBlue), brush2: new(Colors.OrangeRed), brush3: new(Colors.LimeGreen)),
		new(name: "Pastel Dream", brush1: new(Color.FromArgb(255, 255, 182, 193)), brush2: new(Color.FromArgb(255, 253, 253, 150)), brush3: new(Color.FromArgb(255, 174, 198, 207))),
		new(name: "Neon Cyber", brush1: new(Colors.Cyan), brush2: new(Colors.Magenta), brush3: new(Colors.Yellow)),
		new(name: "Lavender Meadow", brush1: new(Color.FromArgb(255, 230, 230, 250)), brush2: new(Color.FromArgb(255, 216, 191, 216)), brush3: new(Color.FromArgb(255, 221, 160, 221))),
		new(name: "Racker", brush1: new(Color.FromArgb(255, 235, 0, 0)), brush2: new(Color.FromArgb(255, 149, 0, 138)), brush3: new(Color.FromArgb(255, 51, 0, 252))),
		new(name: "Flower", brush1: new(Color.FromArgb(255, 139, 222, 218)), brush2: new(Color.FromArgb(255, 153, 142, 224)), brush3: new(Color.FromArgb(255, 239, 147, 147))),
		new(name: "Magic", brush1: new(Color.FromArgb(255, 89, 193, 115)), brush2: new(Color.FromArgb(255, 161, 127, 224)), brush3: new(Color.FromArgb(255, 93, 38, 193))),
		new(name: "After the rain", brush1: new(Color.FromArgb(255, 255, 117, 195)), brush2: new(Color.FromArgb(255, 166, 71, 71)), brush3: new(Color.FromArgb(255, 159, 255, 91))),
		new(name: "Beloko", brush1: new(Color.FromArgb(255, 255, 30, 86)), brush2: new(Color.FromArgb(255, 249, 201, 66)), brush3: new(Color.FromArgb(255, 30, 144, 255))),
		new(name: "Megatron", brush1: new(Color.FromArgb(255, 198, 255, 221)), brush2: new(Color.FromArgb(255, 251, 215, 134)), brush3: new(Color.FromArgb(255, 247, 121, 125))),
		new(name: "Wiretap", brush1: new(Color.FromArgb(255, 138, 35, 135)), brush2: new(Color.FromArgb(255, 233, 64, 87)), brush3: new(Color.FromArgb(255, 242, 113, 33)))
	];

	internal void ApplyColorPalette(ColorPalette palette)
	{
		foreach (AnalysisCategory cat in BlockedCategories.Concat(AllowedCategories))
		{
			if (cat.Items.Count > 0)
				cat.Items[0].ItemColor = palette.Brush1.Color;

			if (cat.Items.Count > 1)
				cat.Items[1].ItemColor = palette.Brush2.Color;

			if (cat.Items.Count > 2)
				cat.Items[2].ItemColor = palette.Brush3.Color;
		}
	}

	// Path.Data cannot bind to an empty string because WinUI must convert the value to Geometry.
	// A zero-length path keeps empty charts blank while still providing valid geometry.
	private const string EmptyLineChartPathData = "M 0,0 L 0,0";

	// Chart Properties
	internal List<PieSliceData> Chart_PieSlices { get; set => SP(ref field, value); } = [];

	// Blocked Line Chart Properties
	internal List<LinePointData> BlockedChart_LinePoints { get; set => SP(ref field, value); } = [];
	internal string BlockedChart_LinePathData { get; set => SP(ref field, value); } = EmptyLineChartPathData;
	internal List<AxisLabel> BlockedChart_YAxisLabels { get; set => SP(ref field, value); } = [];
	internal List<AxisLabel> BlockedChart_XAxisLabels { get; set => SP(ref field, value); } = [];
	internal List<ChartGridLine> BlockedChart_YGridLines { get; set => SP(ref field, value); } = [];

	// Allowed Line Chart Properties
	internal List<LinePointData> AllowedChart_LinePoints { get; set => SP(ref field, value); } = [];
	internal string AllowedChart_LinePathData { get; set => SP(ref field, value); } = EmptyLineChartPathData;
	internal List<AxisLabel> AllowedChart_YAxisLabels { get; set => SP(ref field, value); } = [];
	internal List<AxisLabel> AllowedChart_XAxisLabels { get; set => SP(ref field, value); } = [];
	internal List<ChartGridLine> AllowedChart_YGridLines { get; set => SP(ref field, value); } = [];

	// Main method called from ViewModels.
	internal async Task PrepareAnalysis(List<FileIdentity> AllFileIdentities)
	{
		_allFileIdentities = AllFileIdentities;
		await RecalculateAnalysisForSelectedTimeRangeAsync();
	}

	internal async void TimeRangeComboBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
	{
		if (_suppressTimeRangeRefresh || _allFileIdentities.Count == 0)
		{
			return;
		}

		await RecalculateAnalysisForSelectedTimeRangeAsync();
	}

	private async Task RecalculateAnalysisForSelectedTimeRangeAsync()
	{
		TimeRangeFilterOption? selectedTimeRange = Analysis_SelectedTimeRange;

		Analysis_IsRecalculating = true;

		try
		{
			List<FileIdentity> filteredFileIdentities = await Task.Run(() => GetFileIdentitiesForTimeRange(selectedTimeRange));
			await PrepareAnalysisCore(filteredFileIdentities);
		}
		finally
		{
			Analysis_IsRecalculating = false;
		}
	}

	private List<FileIdentity> GetFileIdentitiesForTimeRange(TimeRangeFilterOption? selectedTimeRange)
	{
		if (selectedTimeRange is null || selectedTimeRange.Kind == AnalysisTimeRangeKind.AllTime)
		{
			return new List<FileIdentity>(_allFileIdentities);
		}

		DateTime now = DateTime.Now;
		DateTime threshold = GetThresholdForTimeRange(selectedTimeRange.Kind, now);
		List<FileIdentity> filteredFileIdentities = new(_allFileIdentities.Count);

		foreach (FileIdentity item in CollectionsMarshal.AsSpan(_allFileIdentities))
		{
			if (item.TimeCreated.HasValue && item.TimeCreated.Value >= threshold && item.TimeCreated.Value <= now)
			{
				filteredFileIdentities.Add(item);
			}
		}

		return filteredFileIdentities;
	}

	private static DateTime GetThresholdForTimeRange(AnalysisTimeRangeKind timeRangeKind, DateTime now) => timeRangeKind switch
	{
		AnalysisTimeRangeKind.Past1Hour => now.AddHours(-1),
		AnalysisTimeRangeKind.Past12Hours => now.AddHours(-12),
		AnalysisTimeRangeKind.Past24Hours => now.AddHours(-24),
		AnalysisTimeRangeKind.PastWeek => now.AddDays(-7),
		AnalysisTimeRangeKind.PastMonth => now.AddMonths(-1),
		AnalysisTimeRangeKind.Past6Months => now.AddMonths(-6),
		AnalysisTimeRangeKind.PastYear => now.AddYears(-1),
		_ => DateTime.MinValue
	};

	private async Task PrepareAnalysisCore(List<FileIdentity> AllFileIdentities)
	{
		await Task.Run(async () =>
		{
			int totalAllowedCount = 0;
			int totalBlockedCount = 0;
			int globalSignedCount = 0;
			int globalUnsignedCount = 0;
			int globalEccSignedCount = 0;
			int globalUserWriteableCount = 0;
			int globalWhqlCount = 0;
			int globalSigningLevelMismatchesCount = 0;

			Dictionary<string, int> blockedFileExtensions = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> blockedTimeFrames = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> blockedPoliciesCount = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> blockedComputersCount = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> blockedFiles = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> blockedPublishers = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> blockedInitiatingProcesses = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> blockedPackagedAppsCount = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> blockedSigningScenariosCount = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> blockedDirectories = new(StringComparer.OrdinalIgnoreCase);

			Dictionary<string, int> allowedFileExtensions = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> allowedTimeFrames = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> allowedPoliciesCount = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> allowedComputersCount = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> allowedFiles = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> allowedPublishers = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> allowedInitiatingProcesses = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> allowedPackagedAppsCount = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> allowedSigningScenariosCount = new(StringComparer.OrdinalIgnoreCase);
			Dictionary<string, int> allowedDirectories = new(StringComparer.OrdinalIgnoreCase);

			foreach (FileIdentity item in CollectionsMarshal.AsSpan(AllFileIdentities))
			{
				if (item.SignatureStatus == SignatureStatus.IsSigned) globalSignedCount++;
				else if (item.SignatureStatus == SignatureStatus.IsUnsigned) globalUnsignedCount++;

				if (item.IsECCSigned == true) globalEccSignedCount++;
				if (item.UserWriteable == true) globalUserWriteableCount++;
				if (item.HasWHQLSigner == true) globalWhqlCount++;

				if (!string.IsNullOrWhiteSpace(item.RequestedSigningLevel) && !string.IsNullOrWhiteSpace(item.ValidatedSigningLevel) && !string.Equals(item.RequestedSigningLevel, item.ValidatedSigningLevel, StringComparison.OrdinalIgnoreCase))
				{
					globalSigningLevelMismatchesCount++;
				}

				if (item.Action == EventAction.Audit)
				{
					totalAllowedCount++;
					ProcessEventForDictionaries(item, allowedFileExtensions, allowedTimeFrames, allowedPoliciesCount, allowedComputersCount, allowedFiles, allowedPublishers, allowedInitiatingProcesses, allowedPackagedAppsCount, allowedSigningScenariosCount, allowedDirectories);
				}
				else
				{
					totalBlockedCount++;
					ProcessEventForDictionaries(item, blockedFileExtensions, blockedTimeFrames, blockedPoliciesCount, blockedComputersCount, blockedFiles, blockedPublishers, blockedInitiatingProcesses, blockedPackagedAppsCount, blockedSigningScenariosCount, blockedDirectories);
				}
			}

			Analysis_TotalAllowed = totalAllowedCount.ToString();
			Analysis_TotalBlocked = totalBlockedCount.ToString();
			Analysis_Global_TotalSigned = globalSignedCount.ToString();
			Analysis_Global_TotalUnsigned = globalUnsignedCount.ToString();
			Analysis_Global_TotalECCSigned = globalEccSignedCount.ToString();
			Analysis_Global_TotalUserWriteable = globalUserWriteableCount.ToString();
			Analysis_Global_TotalWHQL = globalWhqlCount.ToString();
			Analysis_Global_TotalSigningLevelMismatches = globalSigningLevelMismatchesCount.ToString();

			#region Summary Text Generation

			StringBuilder summaryBuilder = new();
			_ = summaryBuilder.Append(string.Format(Atlas.GetStr("AnalysisCompleteSummary"), totalAllowedCount + totalBlockedCount, totalAllowedCount, totalBlockedCount));

			_ = totalBlockedCount > totalAllowedCount
				? summaryBuilder.Append(Atlas.GetStr("SignificantBlockedEventsSummary"))
				: summaryBuilder.Append(Atlas.GetStr("MajorityAllowedEventsSummary"));

			if (globalUnsignedCount > 0)
				_ = summaryBuilder.Append(string.Format(Atlas.GetStr("UnsignedFilesDetectedSummary"), globalUnsignedCount));

			HashSet<string> allComputers = new(allowedComputersCount.Keys, StringComparer.OrdinalIgnoreCase);
			allComputers.UnionWith(blockedComputersCount.Keys);
			if (allComputers.Count > 0)
				_ = summaryBuilder.Append(string.Format(Atlas.GetStr("UniqueComputersSummary"), allComputers.Count));

			int userModeCount = allowedSigningScenariosCount.Where(x => x.Key.Contains("User", StringComparison.OrdinalIgnoreCase)).Sum(x => x.Value) + blockedSigningScenariosCount.Where(x => x.Key.Contains("User", StringComparison.OrdinalIgnoreCase)).Sum(x => x.Value);
			int kernelModeCount = allowedSigningScenariosCount.Where(x => x.Key.Contains("Kernel", StringComparison.OrdinalIgnoreCase)).Sum(x => x.Value) + blockedSigningScenariosCount.Where(x => x.Key.Contains("Kernel", StringComparison.OrdinalIgnoreCase)).Sum(x => x.Value);

			if (userModeCount > kernelModeCount)
				_ = summaryBuilder.Append(Atlas.GetStr("UserModeMajoritySummary"));
			else if (kernelModeCount > userModeCount)
				_ = summaryBuilder.Append(Atlas.GetStr("KernelModeMajoritySummary"));
			else if (userModeCount > 0)
				_ = summaryBuilder.Append(Atlas.GetStr("EvenModeDistributionSummary"));

			Dictionary<string, int> allPublishers = new(StringComparer.OrdinalIgnoreCase);
			foreach (KeyValuePair<string, int> kv in allowedPublishers) { allPublishers[kv.Key] = kv.Value; }
			foreach (KeyValuePair<string, int> kv in blockedPublishers)
			{
				ref int publisherCount = ref CollectionsMarshal.GetValueRefOrAddDefault(allPublishers, kv.Key, out bool exists);
				publisherCount = exists ? publisherCount + kv.Value : kv.Value;
			}

			if (allPublishers.Count > 0)
			{
				KeyValuePair<string, int> topPub = allPublishers.OrderByDescending(x => x.Value).First();
				_ = summaryBuilder.Append(string.Format(Atlas.GetStr("TopPublisherSummary"), topPub.Key, topPub.Value));
			}

			Analysis_SummaryText = summaryBuilder.ToString().TrimEnd();

			#endregion

			#region Actionable Recommendations Generation

			List<string> recommendations = [];
			if (totalBlockedCount > 0)
			{
				if (blockedPublishers.Count > 0)
				{
					KeyValuePair<string, int> topPub = blockedPublishers.OrderByDescending(x => x.Value).First();
					double pct = Math.Round((double)topPub.Value / totalBlockedCount * 100, 1);
					if (pct > 5) // Only recommend if it's somewhat significant
						recommendations.Add(string.Format(Atlas.GetStr("AllowPublisherRecommendation"), topPub.Key, pct, topPub.Value));
				}

				if (blockedDirectories.Count > 0)
				{
					KeyValuePair<string, int> topDir = blockedDirectories.OrderByDescending(x => x.Value).First();
					double pct = Math.Round((double)topDir.Value / totalBlockedCount * 100, 1);
					if (pct > 5)
						recommendations.Add(string.Format(Atlas.GetStr("CreatePathRuleRecommendation"), topDir.Key, pct, topDir.Value));
				}

				if (globalUserWriteableCount > 0)
				{
					recommendations.Add(string.Format(Atlas.GetStr("UserWriteableLocationsRecommendation"), globalUserWriteableCount));
				}

				if (blockedFileExtensions.Count > 0)
				{
					KeyValuePair<string, int> topExt = blockedFileExtensions.OrderByDescending(x => x.Value).First();
					double pct = Math.Round((double)topExt.Value / totalBlockedCount * 100, 1);
					if (pct > 10)
						recommendations.Add(string.Format(Atlas.GetStr("FileTypeRecommendation"), topExt.Key, pct));
				}
			}

			if (recommendations.Count == 0)
			{
				recommendations.Add(Atlas.GetStr("NoImmediateRecommendations"));
			}

			#endregion

			// Generate Charts Data on the UI thread to create Brushes etc.
			await Atlas.AppDispatcher.EnqueueAsync(() =>
			{
				GeneratePieChartData(totalAllowedCount, totalBlockedCount);
				GenerateLineChartData(blockedTimeFrames, isAllowed: false);
				GenerateLineChartData(allowedTimeFrames, isAllowed: true);

				Analysis_ActionableRecommendations.Clear();
				foreach (string rec in CollectionsMarshal.AsSpan(recommendations))
				{
					Analysis_ActionableRecommendations.Add(rec);
				}

				// Rebuild Categories Collections for DataBinding
				BlockedCategories.Clear();
				BlockedCategories.Add(CreateCategory("Top File Extensions", "\uE8D2", blockedFileExtensions, 3));
				BlockedCategories.Add(CreateCategory("Peak Block Times (Hourly)", "\uE823", blockedTimeFrames, 3));
				BlockedCategories.Add(CreateCategory("Most Active Policies", "\uE8F1", blockedPoliciesCount, 3));
				BlockedCategories.Add(CreateCategory("Top Directories", "\uE8B7", blockedDirectories, 3));
				BlockedCategories.Add(CreateCategory("Top Computers", "\uE7F8", blockedComputersCount, 3));
				BlockedCategories.Add(CreateCategory("Top Files", "\uE8D2", blockedFiles, 3));
				BlockedCategories.Add(CreateCategory("Top Blocked Publishers", "\uE8D4", blockedPublishers, 3));
				BlockedCategories.Add(CreateCategory("Top Initiating Processes", "\uE9F5", blockedInitiatingProcesses, 3, true));
				BlockedCategories.Add(CreateCategory("Top Packaged Apps", "\uE718", blockedPackagedAppsCount, 3));
				BlockedCategories.Add(CreateCategory("Signing Scenarios", "\uE8B3", blockedSigningScenariosCount, 3)); // Technically only 2, usermode and kernel mode

				AllowedCategories.Clear();
				AllowedCategories.Add(CreateCategory("Top File Extensions", "\uE8D2", allowedFileExtensions, 3));
				AllowedCategories.Add(CreateCategory("Peak Audit Times (Hourly)", "\uE823", allowedTimeFrames, 3));
				AllowedCategories.Add(CreateCategory("Most Active Policies", "\uE8F1", allowedPoliciesCount, 3));
				AllowedCategories.Add(CreateCategory("Top Directories", "\uE8B7", allowedDirectories, 3));
				AllowedCategories.Add(CreateCategory("Top Computers", "\uE7F8", allowedComputersCount, 3));
				AllowedCategories.Add(CreateCategory("Top Files", "\uE8D2", allowedFiles, 3));
				AllowedCategories.Add(CreateCategory("Top Allowed Publishers", "\uE8D4", allowedPublishers, 3));
				AllowedCategories.Add(CreateCategory("Top Initiating Processes", "\uE9F5", allowedInitiatingProcesses, 3, true));
				AllowedCategories.Add(CreateCategory("Top Packaged Apps", "\uE718", allowedPackagedAppsCount, 3));
				AllowedCategories.Add(CreateCategory("Signing Scenarios", "\uE8B3", allowedSigningScenariosCount, 3)); // Technically only 2, usermode and kernel mode
			});
		});
	}

	private static AnalysisCategory CreateCategory(string title, string iconGlyph, Dictionary<string, int> dict, int take, bool fileNameOnly = false)
	{
		AnalysisCategory category = new() { Title = title, IconGlyph = iconGlyph };
		List<AnalysisResultItem> extracted = ExtractTopItems(dict, take, fileNameOnly);
		category.AddItems(extracted);
		return category;
	}

	private void GeneratePieChartData(int allowed, int blocked)
	{
		double total = allowed + blocked;
		if (total == 0)
		{
			Chart_PieSlices = [];
			return;
		}

		List<PieSliceData> slices = [];
		double currentAngle = 0;
		double radius = 100;
		double cx = 100;
		double cy = 100;

		(string Name, int Value, Color Color)[] items =
		[
			("Allowed", allowed, Colors.LimeGreen),
			("Blocked", blocked, Colors.OrangeRed)
		];

		foreach ((string Name, int Value, Color Color) item in items)
		{
			if (item.Value == 0) continue;

			double pct = Math.Round(item.Value / total * 100, 1);
			double sweepAngle = item.Value / total * 360;

			// Handle full circle edge case
			if (sweepAngle >= 359.99)
			{
				string fullCirclePath = $"M {cx} {cy - radius} a {radius},{radius} 0 1,0 0,{radius * 2} a {radius},{radius} 0 1,0 0,-{radius * 2}";
				slices.Add(new PieSliceData
				(
					pathData: fullCirclePath,
					fill: new SolidColorBrush(item.Color),
					toolTip: $"{item.Name}: {item.Value} (100%)",
					percentageText: "100%",
					labelX: cx - 15,
					labelY: cy - 10,
					centerX: cx,
					centerY: cy,
					hoverOffsetX: 0,
					hoverOffsetY: 0
				));
				continue;
			}

			double startRad = (currentAngle - 90) * Math.PI / 180.0;
			double endRad = (currentAngle + sweepAngle - 90) * Math.PI / 180.0;

			double startX = cx + radius * Math.Cos(startRad);
			double startY = cy + radius * Math.Sin(startRad);
			double endX = cx + radius * Math.Cos(endRad);
			double endY = cy + radius * Math.Sin(endRad);

			int largeArcFlag = sweepAngle > 180 ? 1 : 0;

			// SVG Path: M cx cy L startX startY A rx ry x-axis-rotation large-arc-flag sweep-flag endX endY Z
			string pathData = $"M {cx},{cy} L {startX:0.00},{startY:0.00} A {radius},{radius} 0 {largeArcFlag},1 {endX:0.00},{endY:0.00} Z";

			// Determine center of slice for the label (65% from the center)
			double midAngle = currentAngle + (sweepAngle / 2);
			double midRad = (midAngle - 90) * Math.PI / 180.0;
			double labelRadius = radius * 0.65;

			// Adjusting X/Y slightly to center the text roughly based on font width/height
			double labelX = cx + labelRadius * Math.Cos(midRad) - 15;
			double labelY = cy + labelRadius * Math.Sin(midRad) - 10;

			double popOutDistance = 10.0;

			slices.Add(new PieSliceData
			(
				pathData: pathData,
				fill: new SolidColorBrush(item.Color),
				toolTip: $"{item.Name}: {item.Value} ({pct}%)",
				percentageText: $"{pct}%",
				labelX: labelX,
				labelY: labelY,
				centerX: cx,
				centerY: cy,
				hoverOffsetX: popOutDistance * Math.Cos(midRad),
				hoverOffsetY: popOutDistance * Math.Sin(midRad)
			));

			currentAngle += sweepAngle;
		}

		Chart_PieSlices = slices;
	}

	private void GenerateLineChartData(Dictionary<string, int> timeFrames, bool isAllowed)
	{
		if (timeFrames.Count == 0)
		{
			if (isAllowed)
			{
				AllowedChart_LinePoints = [];
				AllowedChart_LinePathData = EmptyLineChartPathData;
				AllowedChart_YAxisLabels = [];
				AllowedChart_XAxisLabels = [];
				AllowedChart_YGridLines = [];
			}
			else
			{
				BlockedChart_LinePoints = [];
				BlockedChart_LinePathData = EmptyLineChartPathData;
				BlockedChart_YAxisLabels = [];
				BlockedChart_XAxisLabels = [];
				BlockedChart_YGridLines = [];
			}
			return;
		}

		// Sort chronological
		List<KeyValuePair<string, int>> sorted = timeFrames.OrderBy(x => DateTime.Parse(x.Key)).ToList();
		double maxVal = sorted.Max(x => x.Value);
		if (maxVal == 0) maxVal = 1;

		double canvasWidth = 800;
		// Leaving top and bottom padding so points don't clip at borders (e.g. 10px each)
		double renderHeight = 230;
		double yPadding = 10;

		// 40px padding on left and right ensures 70px wide labels centered on the final point never clip out of bounds
		double xPadding = 40;
		double renderWidth = canvasWidth - (xPadding * 2);

		List<LinePointData> points = [];
		StringBuilder pathBuilder = new();

		double xStep = sorted.Count > 1 ? renderWidth / (sorted.Count - 1) : renderWidth / 2;
		Color accent = isAllowed ? Colors.LimeGreen : Colors.OrangeRed;
		SolidColorBrush brush = new(accent);

		for (int i = 0; i < sorted.Count; i++)
		{
			double x = xPadding + (i * xStep);
			// Invert Y because Canvas Y grows downwards. We apply padding to prevent clipping.
			double y = yPadding + renderHeight - (sorted[i].Value / maxVal * renderHeight);

			string formattedDate = DateTime.TryParse(sorted[i].Key, out DateTime parsedDate)
				? parsedDate.ToString("MM/dd HH:mm")
				: sorted[i].Key;

			points.Add(new LinePointData
			(
				x: x,
				y: y,
				dateText: formattedDate,
				countText: sorted[i].Value.ToString(),
				fill: brush
			));

			_ = i == 0 ? pathBuilder.Append($"M {x:0.00},{y:0.00} ") : pathBuilder.Append($"L {x:0.00},{y:0.00} ");
		}

		// Generate Y-Axis Labels & Grid Lines matching the padded height
		int yIntervals = 5;
		List<AxisLabel> yLabels = [];
		List<ChartGridLine> yGridLines = [];
		for (int i = 0; i <= yIntervals; i++)
		{
			double val = maxVal - (maxVal / yIntervals * i);
			double offset = yPadding + renderHeight / yIntervals * i;
			yLabels.Add(new AxisLabel(text: val.ToString("0.#"), offset: offset));
			yGridLines.Add(new ChartGridLine(offset: offset));
		}

		// Generate accurate X-Axis Labels (Horizontally aligned, up to 6 items to prevent overlaps on 800px width)
		List<AxisLabel> xLabels = [];
		int maxXLabels = 6;
		int step = Math.Max(1, (int)Math.Ceiling((double)sorted.Count / maxXLabels));

		for (int i = 0; i < sorted.Count; i += step)
		{
			double x = xPadding + (i * xStep);
			string formattedDate = DateTime.TryParse(sorted[i].Key, out DateTime parsedDate)
				? parsedDate.ToString("MM/dd HH:mm")
				: sorted[i].Key;
			xLabels.Add(new AxisLabel(text: formattedDate, offset: x));
		}

		// Ensure the absolute last point is labeled if the step skipped it, and it isn't too close to the previous label
		if (sorted.Count > 1 && (sorted.Count - 1) % step != 0)
		{
			double lastX = xPadding + ((sorted.Count - 1) * xStep);
			if (lastX - xLabels.Last().Offset > 100) // Ensure at least 100px space for the new string
			{
				string formattedDate = DateTime.TryParse(sorted.Last().Key, out DateTime parsedDate)
					? parsedDate.ToString("MM/dd HH:mm")
					: sorted.Last().Key;
				xLabels.Add(new AxisLabel(text: formattedDate, offset: lastX));
			}
		}

		if (isAllowed)
		{
			AllowedChart_LinePoints = points;
			AllowedChart_LinePathData = pathBuilder.ToString();
			AllowedChart_YAxisLabels = yLabels;
			AllowedChart_YGridLines = yGridLines;
			AllowedChart_XAxisLabels = xLabels;
		}
		else
		{
			BlockedChart_LinePoints = points;
			BlockedChart_LinePathData = pathBuilder.ToString();
			BlockedChart_YAxisLabels = yLabels;
			BlockedChart_YGridLines = yGridLines;
			BlockedChart_XAxisLabels = xLabels;
		}
	}

	private static void ProcessEventForDictionaries(
		FileIdentity item, Dictionary<string, int> extensions, Dictionary<string, int> timeFrames,
		Dictionary<string, int> policies, Dictionary<string, int> computers, Dictionary<string, int> files,
		Dictionary<string, int> publishers, Dictionary<string, int> processes, Dictionary<string, int> packagedApps,
		Dictionary<string, int> scenarios, Dictionary<string, int> directories)
	{
		if (!string.IsNullOrWhiteSpace(item.PolicyName)) { ref int count = ref CollectionsMarshal.GetValueRefOrAddDefault(policies, item.PolicyName, out bool exists); count = exists ? count + 1 : 1; }
		if (!string.IsNullOrWhiteSpace(item.ComputerName)) { ref int count = ref CollectionsMarshal.GetValueRefOrAddDefault(computers, item.ComputerName, out bool exists); count = exists ? count + 1 : 1; }
		if (!string.IsNullOrWhiteSpace(item.FileName)) { string? ext = Path.GetExtension(item.FileName); if (!string.IsNullOrWhiteSpace(ext)) { ref int count = ref CollectionsMarshal.GetValueRefOrAddDefault(extensions, ext, out bool exists); count = exists ? count + 1 : 1; } }
		if (item.TimeCreated.HasValue) { string timeFrame = item.TimeCreated.Value.ToString("yyyy-MM-dd HH:00"); ref int count = ref CollectionsMarshal.GetValueRefOrAddDefault(timeFrames, timeFrame, out bool exists); count = exists ? count + 1 : 1; }
		if (!string.IsNullOrWhiteSpace(item.FileName)) { ref int count = ref CollectionsMarshal.GetValueRefOrAddDefault(files, item.FileName, out bool exists); count = exists ? count + 1 : 1; }
		foreach (string pub in item.FilePublishers) { if (!string.IsNullOrWhiteSpace(pub)) { ref int count = ref CollectionsMarshal.GetValueRefOrAddDefault(publishers, pub, out bool exists); count = exists ? count + 1 : 1; } }
		if (!string.IsNullOrWhiteSpace(item.ProcessName)) { ref int count = ref CollectionsMarshal.GetValueRefOrAddDefault(processes, item.ProcessName, out bool exists); count = exists ? count + 1 : 1; }
		if (!string.IsNullOrWhiteSpace(item.PackageFamilyName)) { ref int count = ref CollectionsMarshal.GetValueRefOrAddDefault(packagedApps, item.PackageFamilyName, out bool exists); count = exists ? count + 1 : 1; }

		string scenarioStr = item.SISigningScenario.ToString();
		ref int scCount = ref CollectionsMarshal.GetValueRefOrAddDefault(scenarios, scenarioStr, out bool scExists);
		scCount = scExists ? scCount + 1 : 1;

		if (!string.IsNullOrWhiteSpace(item.FilePath))
		{
			try
			{
				string? dir = Path.GetDirectoryName(item.FilePath);
				if (!string.IsNullOrWhiteSpace(dir))
				{
					ref int count = ref CollectionsMarshal.GetValueRefOrAddDefault(directories, dir, out bool exists);
					count = exists ? count + 1 : 1;
				}
			}
			catch { } // Handle potential invalid path character exceptions silently
		}
	}

	private static List<AnalysisResultItem> ExtractTopItems(Dictionary<string, int> dict, int take, bool fileNameOnly = false)
	{
		List<AnalysisResultItem> result = new(take > 100 ? dict.Count : take);
		foreach (KeyValuePair<string, int> kvp in dict.OrderByDescending(x => x.Value).Take(take))
		{
			string? display = kvp.Key;
			if (fileNameOnly)
			{
				display = Path.GetFileName(kvp.Key);
			}

			result.Add(new AnalysisResultItem(name: kvp.Key, displayName: display ?? kvp.Key, count: kvp.Value, itemColor: Colors.Gray));
		}
		return result;
	}

	/// <summary>
	/// Generates and prompts the user to download an SVG rendering of the specified chart.
	/// </summary>
	internal async void ExportChart_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button btn && btn.Tag is string chartType)
		{
			string svgContent = "";
			string defaultFileName = "";

			Color accentColor = (Color)Application.Current.Resources["SystemAccentColor"];
			string accentHex = $"#{accentColor.R:X2}{accentColor.G:X2}{accentColor.B:X2}";

			if (chartType == "Pie")
			{
				StringBuilder sb = new();

				// Shifting the viewBox further up (-40) to make room for the title
				_ = sb.AppendLine("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"-20 -40 240 290\">");
				_ = sb.AppendLine("<style>");
				_ = sb.AppendLine(".text { font-family: 'Segoe UI', sans-serif; font-size: 12px; font-weight: bold; fill: #FFFFFF; }");
				_ = sb.AppendLine($".title {{ font-family: 'Segoe UI', sans-serif; font-size: 14px; font-weight: bold; fill: {accentHex}; text-anchor: middle; }}");
				_ = sb.AppendLine(".legend-text { font-family: 'Segoe UI', sans-serif; font-size: 12px; fill: #A0A0A0; }");
				_ = sb.AppendLine("</style>");

				// Chart Title
				_ = sb.AppendLine($"<text x=\"100\" y=\"-15\" class=\"title\">{Atlas.GetStr("DistributionOverview/Text")}</text>");

				foreach (PieSliceData slice in Chart_PieSlices)
				{
					string colorHex = $"#{slice.Fill.Color.R:X2}{slice.Fill.Color.G:X2}{slice.Fill.Color.B:X2}";
					_ = sb.AppendLine($"<path d=\"{slice.PathData}\" fill=\"{colorHex}\" stroke=\"#1C1C1C\" stroke-width=\"2\" stroke-linejoin=\"round\" />");
					_ = sb.AppendLine($"<text x=\"{slice.LabelX}\" y=\"{slice.LabelY + 10}\" class=\"text\">{slice.PercentageText}</text>");
				}

				// Legend Items (Centered at the bottom)
				_ = sb.AppendLine("<circle cx=\"35\" cy=\"230\" r=\"5\" fill=\"#32CD32\" />");
				_ = sb.AppendLine($"<text x=\"45\" y=\"234\" class=\"legend-text\">{Atlas.GetStr("Allowed/Text")}</text>");

				_ = sb.AppendLine("<circle cx=\"115\" cy=\"230\" r=\"5\" fill=\"#FF4500\" />");
				_ = sb.AppendLine($"<text x=\"125\" y=\"234\" class=\"legend-text\">{Atlas.GetStr("Blocked/Text")}</text>");

				_ = sb.AppendLine("</svg>");
				svgContent = sb.ToString();
				defaultFileName = "Distribution_Overview.svg";
			}
			else if (string.Equals(chartType, "BlockedLine", StringComparison.OrdinalIgnoreCase) || string.Equals(chartType, "AllowedLine", StringComparison.OrdinalIgnoreCase))
			{
				bool isAllowed = string.Equals(chartType, "AllowedLine", StringComparison.OrdinalIgnoreCase);
				List<LinePointData> points = isAllowed ? AllowedChart_LinePoints : BlockedChart_LinePoints;
				string pathData = isAllowed ? AllowedChart_LinePathData : BlockedChart_LinePathData;
				List<AxisLabel> yLabels = isAllowed ? AllowedChart_YAxisLabels : BlockedChart_YAxisLabels;
				List<AxisLabel> xLabels = isAllowed ? AllowedChart_XAxisLabels : BlockedChart_XAxisLabels;
				List<ChartGridLine> gridLines = isAllowed ? AllowedChart_YGridLines : BlockedChart_YGridLines;
				string strokeColor = isAllowed ? "#32CD32" : "#FF4500";
				string chartTitle = isAllowed ? Atlas.GetStr("AllowedOrAuditedEventsTrend/Text") : Atlas.GetStr("BlockedEventsTrend/Text");

				StringBuilder sb = new();

				// Shifting the viewBox up (-40) to make room for the title
				_ = sb.AppendLine("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 -40 860 320\">");
				_ = sb.AppendLine("<style>");
				_ = sb.AppendLine(".text { font-family: 'Segoe UI', sans-serif; font-size: 11px; fill: #A0A0A0; }");
				_ = sb.AppendLine(".title { font-family: 'Segoe UI', sans-serif; font-size: 16px; font-weight: bold; text-anchor: middle; }");
				_ = sb.AppendLine("</style>");

				// Chart Title
				_ = sb.AppendLine($"<text x=\"430\" y=\"-15\" class=\"title\" fill=\"{strokeColor}\">{chartTitle}</text>");

				foreach (ChartGridLine line in CollectionsMarshal.AsSpan(gridLines))
				{
					_ = sb.AppendLine($"<line x1=\"60\" x2=\"860\" y1=\"{line.Offset}\" y2=\"{line.Offset}\" stroke=\"#404040\" stroke-width=\"1\" stroke-dasharray=\"4 4\" />");
				}
				foreach (AxisLabel lbl in CollectionsMarshal.AsSpan(yLabels))
				{
					_ = sb.AppendLine($"<text x=\"50\" y=\"{lbl.Offset + 4}\" class=\"text\" text-anchor=\"end\">{lbl.Text}</text>");
				}
				foreach (AxisLabel lbl in CollectionsMarshal.AsSpan(xLabels))
				{
					_ = sb.AppendLine($"<text x=\"{lbl.Offset + 60}\" y=\"265\" class=\"text\" text-anchor=\"middle\">{lbl.Text}</text>");
				}
				_ = sb.AppendLine($"<path d=\"{pathData}\" fill=\"none\" stroke=\"{strokeColor}\" stroke-width=\"3\" stroke-linejoin=\"round\" transform=\"translate(60, 0)\" />");
				foreach (LinePointData pt in CollectionsMarshal.AsSpan(points))
				{
					_ = sb.AppendLine($"<circle cx=\"{pt.X + 60}\" cy=\"{pt.Y}\" r=\"7\" fill=\"{strokeColor}\" stroke=\"#1C1C1C\" stroke-width=\"2\" />");
				}
				_ = sb.AppendLine("</svg>");
				svgContent = sb.ToString();
				defaultFileName = isAllowed ? "Allowed_Events_Trend.svg" : "Blocked_Events_Trend.svg";
			}

			if (!string.IsNullOrWhiteSpace(svgContent))
			{
				string? savePath = FileDialogHelper.ShowSaveFileDialog("SVG Image (*.svg)|*.svg", defaultFileName);
				if (!string.IsNullOrWhiteSpace(savePath))
				{
					if (!savePath.EndsWith(".svg", StringComparison.OrdinalIgnoreCase))
					{
						savePath += ".svg";
					}
					await File.WriteAllTextAsync(savePath, svgContent);
				}
			}
		}
	}

	/// <summary>
	/// Used to hold the currently open Popup instance to close it before opening a new one.
	/// </summary>
	private Popup? _currentlyOpenPopup;

	/// <summary>
	/// Opens the popup with an animated popout effect when hovering over the item.
	/// </summary>
	internal void AnalysisItem_PointerEntered(object sender, PointerRoutedEventArgs e)
	{
		if (sender is Grid containerGrid)
		{
			Popup? popup = FindVisualChildByName<Popup>(containerGrid, "HoverPopup");
			Border? baseBorder = FindVisualChildByName<Border>(containerGrid, "BaseBorder");

			if (popup != null && baseBorder != null)
			{
				if (_currentlyOpenPopup != null && _currentlyOpenPopup != popup)
				{
					_currentlyOpenPopup.IsOpen = false;
				}

				if (popup.Child is FrameworkElement popupChild)
				{
					// Tag the popup to its child so we can retrieve it later on exit
					popupChild.Tag = popup;
				}

				// Align the popup perfectly over the base border
				popup.HorizontalOffset = baseBorder.Margin.Left;
				popup.VerticalOffset = baseBorder.Margin.Top;
				popup.IsOpen = true;

				_currentlyOpenPopup = popup;
			}
		}
	}

	/// <summary>
	/// Manages the state when leaving the base grid.
	/// If the pointer moved over the popup, we intentionally ignore the closing command.
	/// </summary>
	internal void AnalysisItem_PointerExited(object sender, PointerRoutedEventArgs e)
	{
		if (sender is Grid containerGrid)
		{
			Popup? popup = FindVisualChildByName<Popup>(containerGrid, "HoverPopup");

			if (popup != null && popup.IsOpen && popup.Child is FrameworkElement popupChild)
			{
				// We check if the pointer is currently inside the bounds of the Popup Child
				Point pointerPosition = e.GetCurrentPoint(popupChild).Position;

				if (pointerPosition.X >= 0 && pointerPosition.Y >= 0 &&
					pointerPosition.X <= popupChild.ActualWidth &&
					pointerPosition.Y <= popupChild.ActualHeight)
				{
					// The pointer successfully moved directly into the popup. Avoid closing it to prevent flickering.
					return;
				}

				popup.IsOpen = false;

				if (_currentlyOpenPopup == popup)
				{
					_currentlyOpenPopup = null;
				}
			}
		}
	}

	/// <summary>
	/// Safely closes the popup only when the cursor actually leaves the boundaries of the Popup itself.
	/// </summary>
	internal void PopupBorder_PointerExited(object sender, PointerRoutedEventArgs e)
	{
		if (sender is FrameworkElement popupBorder && popupBorder.Tag is Popup popup)
		{
			// Validate if the pointer actually left the border, mitigating random internal route exiting
			Point pointerPosition = e.GetCurrentPoint(popupBorder).Position;

			if (pointerPosition.X < 0 || pointerPosition.Y < 0 ||
				pointerPosition.X >= popupBorder.ActualWidth ||
				pointerPosition.Y >= popupBorder.ActualHeight)
			{
				popup.IsOpen = false;

				if (_currentlyOpenPopup == popup)
				{
					_currentlyOpenPopup = null;
				}
			}
		}
	}

	/// <summary>
	/// Handles the click event for the small Copy button inside the popup item.
	/// </summary>
	internal void CopyItemText_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button btn && btn.Tag is string textToCopy)
		{
			ClipboardManagement.CopyText(textToCopy);
		}
	}

	/// <summary>
	/// Handles click event for palette buttons to apply a specific palette scheme.
	/// </summary>
	internal void PaletteButton_Click(object sender, RoutedEventArgs e)
	{
		if (sender is Button btn && btn.Tag is ColorPalette palette)
		{
			ApplyColorPalette(palette);
		}
	}

	/// <summary>
	/// Interactive Hover for the Line Chart Hotspots.
	/// Expands the ellipse uniformly and displays a floating layout seamlessly without pointer loops.
	/// </summary>
	internal void Hotspot_PointerEntered(object sender, PointerRoutedEventArgs e)
	{
		if (sender is Grid hotspotGrid)
		{
			Microsoft.UI.Xaml.Shapes.Ellipse? ellipse = FindVisualChildByName<Microsoft.UI.Xaml.Shapes.Ellipse>(hotspotGrid, "PointEllipse");
			if (ellipse?.RenderTransform is ScaleTransform scale)
			{
				scale.ScaleX = 1.6;
				scale.ScaleY = 1.6;
			}

			Popup? popup = FindVisualChildByName<Popup>(hotspotGrid, "DataPopup");
			if (popup != null)
			{
				popup.IsOpen = true;
				Canvas.SetZIndex(hotspotGrid, 100);
			}
		}
	}

	/// <summary>
	/// Interactive Hover Exit for the Line Chart Hotspots.
	/// Shrinks the ellipse uniformly back and closes the popup.
	/// </summary>
	internal void Hotspot_PointerExited(object sender, PointerRoutedEventArgs e)
	{
		if (sender is Grid hotspotGrid)
		{
			Microsoft.UI.Xaml.Shapes.Ellipse? ellipse = FindVisualChildByName<Microsoft.UI.Xaml.Shapes.Ellipse>(hotspotGrid, "PointEllipse");
			if (ellipse?.RenderTransform is ScaleTransform scale)
			{
				scale.ScaleX = 1.0;
				scale.ScaleY = 1.0;
			}

			Popup? popup = FindVisualChildByName<Popup>(hotspotGrid, "DataPopup");
			if (popup != null)
			{
				popup.IsOpen = false;
				Canvas.SetZIndex(hotspotGrid, 0);
			}
		}
	}

	/// <summary>
	/// Smooth composition animation for hovering into a Pie Slice
	/// </summary>
	internal void PieSlice_PointerEntered(object sender, PointerRoutedEventArgs e)
	{
		if (sender is FrameworkElement element && element.Tag is PieSliceData data)
		{
			Visual visual = Microsoft.UI.Xaml.Hosting.ElementCompositionPreview.GetElementVisual(element);
			Compositor compositor = visual.Compositor;

			Vector3KeyFrameAnimation offsetAnimation = compositor.CreateVector3KeyFrameAnimation();
			offsetAnimation.InsertKeyFrame(1f, new System.Numerics.Vector3((float)data.HoverOffsetX, (float)data.HoverOffsetY, 0));
			offsetAnimation.Duration = TimeSpan.FromMilliseconds(200);

			Vector3KeyFrameAnimation scaleAnimation = compositor.CreateVector3KeyFrameAnimation();
			scaleAnimation.InsertKeyFrame(1f, new System.Numerics.Vector3(1.05f, 1.05f, 1f));
			scaleAnimation.Duration = TimeSpan.FromMilliseconds(200);

			visual.CenterPoint = new System.Numerics.Vector3((float)data.CenterX, (float)data.CenterY, 0f);

			visual.StartAnimation("Offset", offsetAnimation);
			visual.StartAnimation("Scale", scaleAnimation);

			Canvas.SetZIndex(element, 10); // Bring visual to forefront
		}
	}

	/// <summary>
	/// Smooth composition animation returning the Pie Slice back to idle state.
	/// </summary>
	internal void PieSlice_PointerExited(object sender, PointerRoutedEventArgs e)
	{
		if (sender is FrameworkElement element && element.Tag is PieSliceData)
		{
			Visual visual = Microsoft.UI.Xaml.Hosting.ElementCompositionPreview.GetElementVisual(element);
			Compositor compositor = visual.Compositor;

			Vector3KeyFrameAnimation offsetAnimation = compositor.CreateVector3KeyFrameAnimation();
			offsetAnimation.InsertKeyFrame(1f, new System.Numerics.Vector3(0f, 0f, 0f));
			offsetAnimation.Duration = TimeSpan.FromMilliseconds(300);

			Vector3KeyFrameAnimation scaleAnimation = compositor.CreateVector3KeyFrameAnimation();
			scaleAnimation.InsertKeyFrame(1f, new System.Numerics.Vector3(1f, 1f, 1f));
			scaleAnimation.Duration = TimeSpan.FromMilliseconds(300);

			visual.StartAnimation("Offset", offsetAnimation);
			visual.StartAnimation("Scale", scaleAnimation);

			Canvas.SetZIndex(element, 0); // Restore hierarchy depth
		}
	}

	/// <summary>
	/// Helper method to find a specific element type by Name in the visual tree.
	/// </summary>
	private static T? FindVisualChildByName<T>(DependencyObject parent, string name) where T : FrameworkElement
	{
		if (parent == null) return null;

		int count = VisualTreeHelper.GetChildrenCount(parent);
		for (int i = 0; i < count; i++)
		{
			DependencyObject child = VisualTreeHelper.GetChild(parent, i);

			if (child is T t && t.Name == name)
			{
				return t;
			}

			T? result = FindVisualChildByName<T>(child, name);
			if (result != null)
			{
				return result;
			}
		}
		return null;
	}

}
