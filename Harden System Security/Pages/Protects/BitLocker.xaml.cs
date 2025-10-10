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

using CommunityToolkit.WinUI;
using CommunityToolkit.WinUI.Media;
using HardenSystemSecurity.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;
using Windows.UI;

namespace HardenSystemSecurity.Pages.Protects;

internal sealed partial class BitLocker : Page
{
	private BitLockerVM ViewModel => ViewModelProvider.BitLockerVM;

	internal BitLocker()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
		ViewModel.ExportJsonButtonHighlightRequested += OnExportJsonButtonHighlightRequested;
	}

	/// <summary>
	/// OnNavigatedFrom indicates real page navigation (not transient Unloaded under TabView).
	/// We explicitly dispose the special controls that were prevented from auto-disposal.
	/// </summary>
	/// <param name="e"></param>
	protected override void OnNavigatedFrom(NavigationEventArgs e)
	{
		base.OnNavigatedFrom(e);

		// Dispose all descendants that explicitly opted out of automatic disposal.
		AppControlManager.ViewModels.ViewModelBase.DisposeExplicitOptInDescendants(SecurityMeasuresList);

		// Finally dispose the list control itself.
		SecurityMeasuresList.Dispose();

		ViewModel.ExportJsonButtonHighlightRequested -= OnExportJsonButtonHighlightRequested;
		StopExportButtonAnimation();
	}

	private void OnExportJsonButtonHighlightRequested()
	{
		if (ExportToJsonButton == null)
		{
			return;
		}
		StopExportButtonAnimation();
		StartExportButtonAnimation();
	}

	#region Animations For Export Button

	private DispatcherTimer? _exportBtnAnimTimer;
	private TimeSpan _elapsed = TimeSpan.Zero;

	private static readonly TimeSpan TotalFadeDuration = TimeSpan.FromMilliseconds(3000);
	private static readonly TimeSpan TickInterval = TimeSpan.FromMilliseconds(30);

	private const Double BlurMax = 28.0;
	private const Double OpacityStart = 1.0;

	private static readonly Color HighlightColor = Color.FromArgb(255, 255, 105, 180);

	private AttachedCardShadow? _exportBtnShadow;

	private void StartExportButtonAnimation()
	{
		if (ExportToJsonButton == null)
		{
			return;
		}

		_elapsed = TimeSpan.Zero;

		if (_exportBtnShadow == null)
		{
			_exportBtnShadow = new AttachedCardShadow
			{
				Color = HighlightColor,
				BlurRadius = BlurMax,
				Opacity = OpacityStart,
				Offset = "0",
				CornerRadius = 5.0
			};
			Effects.SetShadow(ExportToJsonButton, _exportBtnShadow);
		}
		else
		{
			_exportBtnShadow.Color = HighlightColor;
			_exportBtnShadow.BlurRadius = BlurMax;
			_exportBtnShadow.Opacity = OpacityStart;
			_exportBtnShadow.Offset = "0";
			_exportBtnShadow.CornerRadius = 5.0;
			Effects.SetShadow(ExportToJsonButton, _exportBtnShadow);
		}

		if (_exportBtnAnimTimer == null)
		{
			_exportBtnAnimTimer = new DispatcherTimer
			{
				Interval = TickInterval
			};
			_exportBtnAnimTimer.Tick += ExportBtnAnimTimer_Tick;
		}
		_exportBtnAnimTimer.Start();
	}

	private void StopExportButtonAnimation()
	{
		if (_exportBtnAnimTimer != null)
		{
			_exportBtnAnimTimer.Tick -= ExportBtnAnimTimer_Tick;
			_exportBtnAnimTimer.Stop();
			_exportBtnAnimTimer = null;
		}

		if (_exportBtnShadow != null && ExportToJsonButton != null)
		{
			try
			{
				Effects.SetShadow(ExportToJsonButton, new AttachedCardShadow
				{
					Color = Color.FromArgb(0, 0, 0, 0),
					BlurRadius = 0.0,
					Opacity = 0.0,
					Offset = "0",
					CornerRadius = 0.0
				});
			}
			catch (Exception)
			{
			}
		}

		_exportBtnShadow = null;
		_elapsed = TimeSpan.Zero;
	}

	private void ExportBtnAnimTimer_Tick(object? sender, object e)
	{
		if (_exportBtnShadow == null || ExportToJsonButton == null)
		{
			StopExportButtonAnimation();
			return;
		}

		_elapsed += TickInterval;

		Double progress = _elapsed.TotalMilliseconds / TotalFadeDuration.TotalMilliseconds;
		if (progress >= 1.0)
		{
			StopExportButtonAnimation();
			return;
		}

		Double remaining = 1.0 - progress;

		try
		{
			_exportBtnShadow.BlurRadius = BlurMax * remaining;
			_exportBtnShadow.Opacity = OpacityStart * remaining;
			_exportBtnShadow.Color = HighlightColor;
		}
		catch (Exception)
		{
			StopExportButtonAnimation();
		}
	}

	#endregion

}
