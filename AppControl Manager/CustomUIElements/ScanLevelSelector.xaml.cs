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
using System.Text;
using CommonCore.IntelGathering;
using Microsoft.UI.Composition;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Hosting;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using Windows.UI;
using WinRT;

namespace AppControlManager.CustomUIElements;

internal sealed partial class ScanLevelSelector : UserControl
{
	internal ScanLevelSelector() => InitializeComponent();

	public static readonly DependencyProperty ItemsSourceProperty = DependencyProperty.Register(
		nameof(ItemsSource),
		typeof(object),
		typeof(ScanLevelSelector),
		new PropertyMetadata(null, ItemsSourceChanged));

	public static readonly DependencyProperty SelectedItemProperty = DependencyProperty.Register(
		nameof(SelectedItem),
		typeof(object),
		typeof(ScanLevelSelector),
		new PropertyMetadata(null, SelectionInputChanged));

	public object? ItemsSource
	{
		get => GetValue(ItemsSourceProperty);
		set => SetValue(ItemsSourceProperty, value);
	}

	public object? SelectedItem
	{
		get => GetValue(SelectedItemProperty);
		set => SetValue(SelectedItemProperty, value);
	}

	[DynamicWindowsRuntimeCast(typeof(ScanLevelSelector))]
	private static void SelectionInputChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e) =>
		((ScanLevelSelector)sender).UpdateSelectionIndicators();

	// Runs when the source is bound by any page that hosts the selector. It first re-applies the user's
	// persisted fallback selection/order onto the freshly created source, then refreshes the selection indicators.
	[DynamicWindowsRuntimeCast(typeof(ScanLevelSelector))]
	private static void ItemsSourceChanged(DependencyObject sender, DependencyPropertyChangedEventArgs e)
	{
		ScanLevelSelector selector = (ScanLevelSelector)sender;
		selector.ApplySavedFallbackOrder();
		selector.UpdateSelectionIndicators();
	}

	private void UpdateSelectionIndicators()
	{
		if (ItemsSource is not IEnumerable<ScanLevelsComboBoxType> items)
			return;

		foreach (ScanLevelsComboBoxType item in items)
			item.IsSelected = ReferenceEquals(item, SelectedItem);
	}

	// Re-applies the persisted selection/order onto the current source.
	private void ApplySavedFallbackOrder()
	{
		if (ItemsSource is not IEnumerable<ScanLevelsComboBoxType> items)
			return;

		if (string.IsNullOrEmpty(Atlas.Settings.CustomizableScanLevelsFallbackOrder))
			return;

		Dictionary<ScanLevels, List<ScanLevels>> parsed = ParseSavedState(Atlas.Settings.CustomizableScanLevelsFallbackOrder);
		if (parsed.Count is 0)
			return;

		foreach (ScanLevelsComboBoxType level in items)
		{
			if (parsed.TryGetValue(level.Level, out List<ScanLevels>? orderedSelected))
			{
				level.RestoreFallbackState(orderedSelected);
			}
		}
	}

	// Parses the compact persisted format: "levelId:selId,selId,...;levelId:...".
	// The value part can be empty which means the user removed every fallback for that level.
	// Any malformed or unknown token is ignored so a bad/imported value can never break restoration.
	private static Dictionary<ScanLevels, List<ScanLevels>> ParseSavedState(string saved)
	{
		Dictionary<ScanLevels, List<ScanLevels>> result = new();

		string[] entries = saved.Split(';', StringSplitOptions.RemoveEmptyEntries);
		foreach (string entry in entries)
		{
			int colon = entry.IndexOf(':');
			if (colon < 0)
				continue;

			if (!int.TryParse(entry.AsSpan(0, colon), out int levelId))
				continue;

			ScanLevels levelKey = (ScanLevels)levelId;

			List<ScanLevels> selected = [];
			string valuePart = entry[(colon + 1)..];
			if (valuePart.Length > 0)
			{
				string[] tokens = valuePart.Split(',', StringSplitOptions.RemoveEmptyEntries);
				foreach (string token in tokens)
				{
					if (int.TryParse(token, out int fallbackId))
					{
						selected.Add((ScanLevels)fallbackId);
					}
				}
			}

			result[levelKey] = selected;
		}

		return result;
	}

	// Serializes the current selection/order of every scan level that owns fallbacks and persists it.
	private void PersistScanLevels()
	{
		if (ItemsSource is not IEnumerable<ScanLevelsComboBoxType> items)
			return;

		StringBuilder builder = new();
		foreach (ScanLevelsComboBoxType level in items)
		{
			// Levels without fallbacks (such as: Hash, File Path, Wildcard Folder Path) have nothing to persist.
			if (level.AvailableFallbacks.Count is 0)
				continue;

			if (builder.Length > 0)
			{
				_ = builder.Append(';');
			}

			_ = builder.Append((int)level.Level).Append(':');

			List<ScanLevels> selected = level.SelectedFallbackLevels;
			for (int i = 0; i < selected.Count; i++)
			{
				if (i > 0)
				{
					_ = builder.Append(',');
				}
				_ = builder.Append((int)selected[i]);
			}
		}

		Atlas.Settings.CustomizableScanLevelsFallbackOrder = builder.ToString();
	}

	[DynamicWindowsRuntimeCast(typeof(Border))]
	[DynamicWindowsRuntimeCast(typeof(DependencyObject))]
	private void Option_Tapped(object sender, TappedRoutedEventArgs e)
	{
		if (IsInteractiveDescendant(e.OriginalSource as DependencyObject, (Border)sender))
			return;

		if (((Border)sender).Tag is not ScanLevelsComboBoxType scanLevel)
			return;

		e.Handled = true;
		SelectedItem = scanLevel;
		EditorFlyout.Hide();
	}

	[DynamicWindowsRuntimeCast(typeof(Button))]
	private static bool IsInteractiveDescendant(DependencyObject? source, DependencyObject optionRoot)
	{
		DependencyObject? current = source;
		while (current is not null && current != optionRoot)
		{
			if (current is Button or Border { Tag: FallbackItem })
				return true;

			current = VisualTreeHelper.GetParent(current);
		}

		return false;
	}

	[DynamicWindowsRuntimeCast(typeof(Border))]
	private void Option_PointerEntered(object sender, PointerRoutedEventArgs e)
	{
		Border option = (Border)sender;
		Color color = option.ActualTheme is ElementTheme.Dark
			? Color.FromArgb(20, 255, 255, 255)
			: Color.FromArgb(14, 0, 0, 0);
		option.Background = new SolidColorBrush(color);
	}

	[DynamicWindowsRuntimeCast(typeof(Border))]
	private void Option_PointerExited(object sender, PointerRoutedEventArgs e) =>
		((Border)sender).Background = new SolidColorBrush(Color.FromArgb(0, 0, 0, 0));

	[DynamicWindowsRuntimeCast(typeof(Border))]
	private void FallbackChip_Tapped(object sender, TappedRoutedEventArgs e)
	{
		Border border = (Border)sender;
		if (border.Tag is not FallbackItem { CanEdit: true })
			return;

		e.Handled = true;
		FlyoutBase.ShowAttachedFlyout(border);
	}

	[DynamicWindowsRuntimeCast(typeof(Button))]
	private void AddFallback_Click(object sender, RoutedEventArgs e)
	{

		Button button = (Button)sender;
		if (button.Tag is not ScanLevelsComboBoxType scanLevel)
			return;

		MenuFlyout flyout = new();
		foreach (ScanLevelFallbackOption option in scanLevel.AvailableFallbacks)
		{
			if (option.IsSelected)
				continue;

			MenuFlyoutItem menuItem = new()
			{
				Text = option.FriendlyName,
				Tag = option
			};
			menuItem.Click += AddFallbackMenuItem_Click;
			flyout.Items.Add(menuItem);
		}

		if (flyout.Items.Count is 0)
		{
			flyout.Items.Add(new MenuFlyoutItem
			{
				Text = "All available fallbacks are already added",
				IsEnabled = false
			});
		}

		flyout.ShowAt(button);
	}

	[DynamicWindowsRuntimeCast(typeof(MenuFlyoutItem))]
	private void AddFallbackMenuItem_Click(object sender, RoutedEventArgs e)
	{
		if (((MenuFlyoutItem)sender).Tag is ScanLevelFallbackOption option)
		{
			option.IsSelected = true;
			PersistScanLevels();
		}
	}

	[DynamicWindowsRuntimeCast(typeof(Button))]
	private void MoveFallbackLeft_Click(object sender, RoutedEventArgs e)
	{
		MoveFallback((Button)sender, -1);
		PersistScanLevels();
	}

	[DynamicWindowsRuntimeCast(typeof(Button))]
	private void MoveFallbackRight_Click(object sender, RoutedEventArgs e)
	{
		MoveFallback((Button)sender, 1);
		PersistScanLevels();
	}

	[DynamicWindowsRuntimeCast(typeof(Button))]
	private void RemoveFallback_Click(object sender, RoutedEventArgs e)
	{
		if (((Button)sender).Tag is FallbackItem { Option: ScanLevelFallbackOption option })
		{
			option.IsSelected = false;
			PersistScanLevels();
		}
	}

	[DynamicWindowsRuntimeCast(typeof(Border))]
	private void FallbackChip_PointerEntered(object sender, PointerRoutedEventArgs e) => AnimateChip((Border)sender, 1.04f);

	[DynamicWindowsRuntimeCast(typeof(Border))]
	private void FallbackChip_PointerExited(object sender, PointerRoutedEventArgs e) => AnimateChip((Border)sender, 1.0f);

	private static void AnimateChip(FrameworkElement element, float scale)
	{
		Visual visual = ElementCompositionPreview.GetElementVisual(element);
		visual.CenterPoint = new System.Numerics.Vector3(
			(float)element.ActualWidth / 2.0f,
			(float)element.ActualHeight / 2.0f,
			0.0f);

		Vector3KeyFrameAnimation animation = visual.Compositor.CreateVector3KeyFrameAnimation();
		animation.InsertKeyFrame(1.0f, new System.Numerics.Vector3(scale, scale, 1.0f));
		animation.Duration = TimeSpan.FromMilliseconds(120);
		visual.StartAnimation(nameof(Visual.Scale), animation);
	}

	private static void MoveFallback(Button button, int offset)
	{
		if (button.Tag is not FallbackItem item || item.Owner is null || item.Option is null)
			return;

		int oldIndex = item.Owner.AvailableFallbacks.IndexOf(item.Option);
		item.Owner.MoveFallback(oldIndex, oldIndex + offset);
	}
}
