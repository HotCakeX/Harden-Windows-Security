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

using AppControlManager.IntelGathering;
using AppControlManager.Others;
using AppControlManager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media.Animation;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// MDEAHPolicyCreation is a page for managing MDE Advanced Hunting policies, including scanning logs, filtering data,
/// and creating policies.
/// </summary>
internal sealed partial class MDEAHPolicyCreation : Page
{

	private MDEAHPolicyCreationVM ViewModel { get; } = ViewModelProvider.MDEAHPolicyCreationVM;

	internal MDEAHPolicyCreation()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;

		// Perform initial selected item assignment for the SelectorBar
		InitSelectorBar();

		// Setting it in XAML would fire it unnecessarily initially
		MenuSelectorBar.SelectionChanged += ViewModel.MenuSelectorBar_SelectionChanged;
	}

	#region For the toolbar menu's Selector Bar - The rest in the ViewModel class.

	private void InitSelectorBar()
	{
		foreach (SelectorBarItem item in MenuSelectorBar.Items)
		{
			item.IsSelected = ((string)item.Tag).Equals(ViewModel.SelectedBarItemTag, StringComparison.OrdinalIgnoreCase);
		}
	}

	#endregion

	/// <summary>
	/// Click event handler for copy
	/// </summary>
	/// <param name="sender"></param>
	/// <param name="e"></param>
	private void CopyToClipboard_Click(object sender, RoutedEventArgs e)
	{
		// Attempt to retrieve the property mapping using the Tag as the key.
		if (ListViewHelper.FileIdentityPropertyMappings.TryGetValue((string)((MenuFlyoutItem)sender).Tag, out var mapping))
		{
			ListViewHelper.CopyToClipboard<FileIdentity>(fi => mapping.Getter(fi)?.ToString(), FileIdentitiesListView);
		}
	}


	/// <summary>
	/// Handles the Copy button click.
	/// Copies the associated query text to the clipboard and plays an animation
	/// that changes the button's text from "Copy" to "Copied" and then back.
	/// </summary>
	private void CopyButton_Click(object sender, RoutedEventArgs e)
	{
		Button copyButton = (Button)sender;
		MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage queryItem = (MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage)copyButton.DataContext;

		// Copy the query text to the clipboard.
		ClipboardManagement.CopyText(queryItem.Query);

		// Retrieve the Grid that is the button's content.
		if (copyButton.Content is Grid grid)
		{
			// Find the two TextBlocks
			TextBlock normalTextBlock = (TextBlock)grid.FindName("NormalText");
			TextBlock copiedTextBlock = (TextBlock)grid.FindName("CopiedText");

			// Create a storyboard to hold both keyframe animations.
			Storyboard sb = new();

			// Create a keyframe animation for the "NormalText" (Copy)
			// Timeline:
			// 0ms: Opacity = 1
			// 200ms: fade out to 0
			// 1200ms: remain at 0
			// 1400ms: fade back in to 1
			DoubleAnimationUsingKeyFrames normalAnimation = new();
			normalAnimation.KeyFrames.Add(new DiscreteDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(0), Value = 1 });
			normalAnimation.KeyFrames.Add(new LinearDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(200), Value = 0 });
			normalAnimation.KeyFrames.Add(new DiscreteDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(1200), Value = 0 });
			normalAnimation.KeyFrames.Add(new LinearDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(1400), Value = 1 });
			Storyboard.SetTarget(normalAnimation, normalTextBlock);
			Storyboard.SetTargetProperty(normalAnimation, "Opacity");

			// Create a keyframe animation for the "CopiedText" (Copied)
			// Timeline:
			// 0ms: Opacity = 0
			// 200ms: fade in to 1
			// 1200ms: remain at 1
			// 1400ms: fade out to 0
			DoubleAnimationUsingKeyFrames copiedAnimation = new();
			copiedAnimation.KeyFrames.Add(new DiscreteDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(0), Value = 0 });
			copiedAnimation.KeyFrames.Add(new LinearDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(200), Value = 1 });
			copiedAnimation.KeyFrames.Add(new DiscreteDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(1200), Value = 1 });
			copiedAnimation.KeyFrames.Add(new LinearDoubleKeyFrame { KeyTime = TimeSpan.FromMilliseconds(1400), Value = 0 });
			Storyboard.SetTarget(copiedAnimation, copiedTextBlock);
			Storyboard.SetTargetProperty(copiedAnimation, "Opacity");

			// Add animations to the storyboard.
			sb.Children.Add(normalAnimation);
			sb.Children.Add(copiedAnimation);

			// Start the storyboard.
			sb.Begin();
		}
	}
}

internal sealed class MDEAdvancedHuntingQueriesForMDEAHPolicyCreationPage
{
	internal string? QueryTitle { get; init; }
	internal string? Query { get; init; }
}
