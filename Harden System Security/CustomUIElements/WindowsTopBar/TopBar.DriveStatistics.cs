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

using System.Globalization;
using System.IO;
using System.IO.Pipes;
using System.Numerics;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Input;
using WinRT;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Animation;
using Windows.Foundation;

namespace HardenSystemSecurity.CustomUIElements.WindowsTopBar;

internal sealed partial class TopBar
{
	private Flyout? _statisticsFlyout;
	private CancellationTokenSource? _statisticsCancellation;
	private static readonly string[] StatisticsLabels =
		["Pictures", "Audio", "Video", "DLL", "EXE", "Documents", "Archives", "Source and data", "No extension", "Other"];
	private static readonly uint[] StatisticsColors =
		[0xFF59C173, 0xFFA17FE0, 0xFF5D26C1, 0xFF1E90FF, 0xFFFF7553,
		 0xFFF9C942, 0xFF8BDEDA, 0xFFFF75C3, 0xFF9A9AA5, 0xFFB9CE74];

	private void OnDriveStatisticsClick()
	{
		if (_isClosed || _activeView != TopBarView.Search || _statisticsFlyout is not null) return;
		ComboBox driveBox = new() { Header = "Drive", MinWidth = 100.0 };
		string? osRoot = Path.GetPathRoot(Environment.SystemDirectory);
		foreach (string drive in Environment.GetLogicalDrives())
		{
			driveBox.Items.Add(drive);
			if (string.Equals(drive, osRoot, StringComparison.OrdinalIgnoreCase)) driveBox.SelectedItem = drive;
		}
		if (driveBox.SelectedIndex < 0 && driveBox.Items.Count > 0) driveBox.SelectedIndex = 0;
		Button refresh = new() { Content = "Load statistics", VerticalAlignment = VerticalAlignment.Bottom };
		TextBlock status = new() { Text = "Counts by extension, not disk space. Select a drive and load.", TextWrapping = TextWrapping.Wrap };
		Grid chart = new() { Width = 260.0, Height = 260.0, HorizontalAlignment = HorizontalAlignment.Center };
		StackPanel legend = new() { Spacing = 5.0 };
		StackPanel content = new()
		{
			Width = Math.Max(280.0, Math.Min(420.0, GetDisplayWidthDips() - 64.0)),
			Spacing = 12.0,
			Children =
			{
				new TextBlock { Text = "Drive Statistics", FontSize = 20.0, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold },
				new StackPanel { Orientation = Orientation.Horizontal, Spacing = 12.0, Children = { driveBox, refresh } },
				status, chart, legend
			}
		};
		Flyout flyout = new()
		{
			ShouldConstrainToRootBounds = false,
			Content = new ScrollViewer
			{
				MaxHeight = Math.Max(120.0, Math.Min(720.0, _displayHeight / _rasterizationScale - 64.0)),
				VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
				HorizontalScrollBarVisibility = ScrollBarVisibility.Disabled,
				Content = content
			}
		};
		_statisticsFlyout = flyout;
		TrackFlyout(flyout);
		refresh.Click += async (_, _) =>
		{
			if (driveBox.SelectedItem is not string drive || _statisticsCancellation is not null) return;
			using CancellationTokenSource cancellation = new(TimeSpan.FromMinutes(5));
			_statisticsCancellation = cancellation;
			refresh.IsEnabled = false;
			driveBox.IsEnabled = false;
			ClearStatisticsChart(chart);
			legend.Children.Clear();
			status.Text = "Counting files on " + drive + "...";
			try
			{
				(long[] counts, int skipped) = await Task.Run(() => ReadDriveStatisticsAsync(drive, cancellation.Token));
				cancellation.Token.ThrowIfCancellationRequested();
				if (_isClosed || !ReferenceEquals(_statisticsFlyout, flyout)) return;
				RenderDriveStatistics(chart, legend, counts);
				long total = 0;
				foreach (long count in counts) total = checked(total + count);
				status.Text = drive + " " + total.ToString("N0", CultureInfo.CurrentCulture) + " files counted. " +
					(skipped == 0 ? "Hard links are not counted separately." :
					"Partial snapshot: " + skipped.ToString("N0", CultureInfo.CurrentCulture) + " inaccessible directories.");
			}
			catch (OperationCanceledException)
			{
				if (!_isClosed && ReferenceEquals(_statisticsFlyout, flyout)) status.Text = "Statistics request canceled or timed out.";
			}
			catch (Exception exception)
			{
				Logger.Write(exception);
				if (!_isClosed && ReferenceEquals(_statisticsFlyout, flyout))
					status.Text = "Statistics unavailable. The updated service requires an NTFS or ReFS drive with an existing USN journal.";
			}
			finally
			{
				if (ReferenceEquals(_statisticsCancellation, cancellation)) _statisticsCancellation = null;
				if (!_isClosed && ReferenceEquals(_statisticsFlyout, flyout))
				{
					refresh.IsEnabled = true;
					driveBox.IsEnabled = true;
				}
			}
		};
		flyout.Closed += (_, _) =>
		{
			if (ReferenceEquals(_statisticsFlyout, flyout))
			{
				_statisticsCancellation?.Cancel();
				_statisticsFlyout = null;
			}
			// Release detached content even while a canceled request is finishing.
			ClearStatisticsChart(chart);
			legend.Children.Clear();
			flyout.Content = null;
			flyout.Opened -= OnFlyoutOpened;
			flyout.Closed -= OnFlyoutClosed;
			if (!_isClosed && !_isPinned && _openFlyoutCount == 0 && !IsCursorOverBar()) _retractionTimer.Start();
		};
		flyout.ShowAt(DriveStatisticsButton);
	}

	private static async Task<(long[] Counts, int Skipped)> ReadDriveStatisticsAsync(string drive, CancellationToken token)
	{
		using NamedPipeClientStream pipe = new(".", "GlobalSearchHSS_FileStatisticsPipe",
			PipeAccessRights.ReadData | PipeAccessRights.WriteData | PipeAccessRights.ReadAttributes | PipeAccessRights.Synchronize,
			PipeOptions.Asynchronous, TokenImpersonationLevel.Impersonation, HandleInheritability.None);
		await pipe.ConnectAsync(15000, token).ConfigureAwait(false);
		using CancellationTokenRegistration registration = token.Register(pipe.Dispose);
		try
		{
			byte[] request = [1, 1, (byte)char.ToUpperInvariant(drive[0])];
			await pipe.WriteAsync(request, token).ConfigureAwait(false);
			using BinaryReader reader = new(pipe, Encoding.UTF8, leaveOpen: true);
			if (reader.ReadByte() != 1 || reader.ReadByte() != 0) throw new InvalidDataException("Statistics request failed.");
			int skipped = reader.ReadInt32();
			if (skipped < 0) throw new InvalidDataException("Invalid partial snapshot metadata.");
			long[] counts = new long[10];
			long total = 0;
			for (int i = 0; i < counts.Length; i++)
			{
				counts[i] = reader.ReadInt64();
				if (counts[i] < 0) throw new InvalidDataException("Invalid category count.");
				total = checked(total + counts[i]);
			}
			return (counts, skipped);
		}
		catch (Exception) when (token.IsCancellationRequested)
		{
			throw new OperationCanceledException(token);
		}
	}

	private static void RenderDriveStatistics(Grid chart, StackPanel legend, long[] counts)
	{
		long total = 0;
		foreach (long count in counts) total = checked(total + count);
		double angle = -Math.PI / 2.0;
		const double Center = 130.0;
		const double Radius = 110.0;
		for (int i = 0; i < counts.Length; i++)
		{
			SolidColorBrush brush = new(ToColor(StatisticsColors[i]));
			double fraction = total == 0 ? 0.0 : counts[i] / (double)total;
			string percentage = (fraction * 100.0).ToString("0.0", CultureInfo.CurrentCulture) + "%";
			string tooltip = StatisticsLabels[i] + ": " + counts[i].ToString("N0", CultureInfo.CurrentCulture) + " (" + percentage + ")";
			legend.Children.Add(new StackPanel
			{
				Orientation = Orientation.Horizontal,
				Spacing = 8.0,
				Children = { new Microsoft.UI.Xaml.Shapes.Ellipse { Width = 12.0, Height = 12.0, Fill = brush },
					new TextBlock { Text = tooltip, TextWrapping = TextWrapping.Wrap } }
			});
			if (counts[i] == 0) continue;
			double sweep = fraction * Math.PI * 2.0;
			double middle = angle + sweep / 2.0;
			Geometry geometry;
			if (counts[i] == total)
				geometry = new EllipseGeometry { Center = new Point(Center, Center), RadiusX = Radius, RadiusY = Radius };
			else
			{
				PathFigure figure = new() { StartPoint = new Point(Center, Center), IsClosed = true, IsFilled = true };
				figure.Segments.Add(new LineSegment { Point = new Point(Center + Radius * Math.Cos(angle), Center + Radius * Math.Sin(angle)) });
				figure.Segments.Add(new ArcSegment
				{
					Point = new Point(Center + Radius * Math.Cos(angle + sweep), Center + Radius * Math.Sin(angle + sweep)),
					Size = new Size(Radius, Radius),
					IsLargeArc = sweep > Math.PI,
					SweepDirection = SweepDirection.Clockwise
				});
				PathGeometry path = new();
				path.Figures.Add(figure);
				geometry = path;
			}
			Grid slice = new() { Width = 260.0, Height = 260.0 };
			Microsoft.UI.Xaml.Shapes.Path shape = new()
			{
				Data = geometry,
				Fill = brush,
				StrokeThickness = 2.0,
				// Rounded joins prevent sharp slice tips from producing stroke spikes at the center.
				StrokeLineJoin = PenLineJoin.Round,
				Stroke = new SolidColorBrush(chart.ActualTheme == ElementTheme.Light ? Microsoft.UI.Colors.White : Microsoft.UI.Colors.Black),
				Transitions = new TransitionCollection { new EntranceThemeTransition() }
			};
			ToolTipService.SetToolTip(shape, tooltip);
			slice.Children.Add(shape);
			// Tiny slices retain their counts in the legend and tooltip without overlapping labels.
			if (fraction >= 0.04)
				slice.Children.Add(new TextBlock
				{
					Text = percentage,
					FontWeight = Microsoft.UI.Text.FontWeights.SemiBold,
					FontSize = 12.0,
					HorizontalAlignment = HorizontalAlignment.Left,
					VerticalAlignment = VerticalAlignment.Top,
					IsHitTestVisible = false,
					RenderTransform = new TranslateTransform
					{
						X = Center + Radius * 0.65 * Math.Cos(middle) - 15.0,
						Y = Center + Radius * 0.65 * Math.Sin(middle) - 10.0
					}
				});
			Vector3 offset = counts[i] == total ? Vector3.Zero : new((float)(10.0 * Math.Cos(middle)), (float)(10.0 * Math.Sin(middle)), 0.0f);
			slice.Tag = offset;
			slice.PointerEntered += OnStatisticsSliceEntered;
			slice.PointerExited += OnStatisticsSliceExited;
			chart.Children.Add(slice);
			angle += sweep;
		}
	}

	[DynamicWindowsRuntimeCast(typeof(Grid))]
	private static void OnStatisticsSliceEntered(object sender, PointerRoutedEventArgs e)
	{
		if (sender is Grid { Tag: Vector3 offset } slice)
			AnimateStatisticsSlice(slice, offset, 1.05f, 200, 10);
	}

	[DynamicWindowsRuntimeCast(typeof(Grid))]
	private static void OnStatisticsSliceExited(object sender, PointerRoutedEventArgs e)
	{
		if (sender is Grid slice)
			AnimateStatisticsSlice(slice, Vector3.Zero, 1.0f, 300, 0);
	}

	[DynamicWindowsRuntimeCast(typeof(Grid))]
	[DynamicWindowsRuntimeCast(typeof(Microsoft.UI.Xaml.Shapes.Path))]
	private static void ClearStatisticsChart(Grid chart)
	{
		// The visual and compositor belong to XAML. Stop our animations, but do not dispose them.
		foreach (UIElement child in chart.Children)
		{
			if (child is not Grid slice) continue;
			slice.PointerEntered -= OnStatisticsSliceEntered;
			slice.PointerExited -= OnStatisticsSliceExited;
			Visual visual = ElementCompositionPreview.GetElementVisual(slice);
			visual.StopAnimation("Offset");
			visual.StopAnimation("Scale");
			slice.Tag = null;
			foreach (UIElement item in slice.Children)
			{
				if (item is not Microsoft.UI.Xaml.Shapes.Path shape) continue;
				ToolTipService.SetToolTip(shape, null);
				shape.Transitions = null;
				shape.Data = null;
				shape.Fill = null;
				shape.Stroke = null;
			}
			slice.Children.Clear();
		}
		chart.Children.Clear();
	}

	private static void AnimateStatisticsSlice(FrameworkElement element, Vector3 offset, float scale, int milliseconds, int zIndex)
	{
		Visual visual = ElementCompositionPreview.GetElementVisual(element);
		Compositor compositor = visual.Compositor;
		// Release owned animation templates after starting their compositor animations.
		using Vector3KeyFrameAnimation offsetAnimation = compositor.CreateVector3KeyFrameAnimation();
		offsetAnimation.InsertKeyFrame(1.0f, offset);
		offsetAnimation.Duration = TimeSpan.FromMilliseconds(milliseconds);
		using Vector3KeyFrameAnimation scaleAnimation = compositor.CreateVector3KeyFrameAnimation();
		scaleAnimation.InsertKeyFrame(1.0f, new Vector3(scale, scale, 1.0f));
		scaleAnimation.Duration = TimeSpan.FromMilliseconds(milliseconds);
		visual.CenterPoint = new Vector3(130.0f, 130.0f, 0.0f);
		visual.StartAnimation("Offset", offsetAnimation);
		visual.StartAnimation("Scale", scaleAnimation);
		Canvas.SetZIndex(element, zIndex);
	}
}
