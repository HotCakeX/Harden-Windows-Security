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
using AppControlManager.Others;
using HardenSystemSecurity.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Navigation;

namespace HardenSystemSecurity.Pages.Protects;

internal sealed partial class BitLocker : Page
{
	private BitLockerVM ViewModel => ViewModelProvider.BitLockerVM;

	internal BitLocker()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
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
		DisposeExplicitOptInDescendants(SecurityMeasuresList);

		// Finally dispose the list control itself.
		SecurityMeasuresList.Dispose();
	}

	/// <summary>
	/// Traverses the visual tree breadth-first and disposes any descendant control that:
	///  - Implements IExplicitDisposalOptIn (meaning it skipped disposal on Unloaded)
	///  - Implements IDisposable
	/// This keeps the logic generic (works for AnimatedCancellableButton, LinkButtonV2, StatusIndicatorV2, etc.).
	/// </summary>
	private static void DisposeExplicitOptInDescendants(FrameworkElement root)
	{
		if (root == null)
		{
			return;
		}

		Queue<DependencyObject> queue = new();
		queue.Enqueue(root);

		while (queue.Count > 0)
		{
			DependencyObject current = queue.Dequeue();
			int childCount = VisualTreeHelper.GetChildrenCount(current);
			for (int i = 0; i < childCount; i++)
			{
				DependencyObject child = VisualTreeHelper.GetChild(current, i);

				// If it opted in and is disposable, dispose it.
				if (child is IExplicitDisposalOptIn explicitOptIn &&
					child is IDisposable disposable &&
					explicitOptIn.DisposeOnlyOnExplicitCall)
				{
					try
					{
						disposable.Dispose();
					}
					catch
					{
						// Swallow: disposal errors should not block the rest.
					}
				}

				queue.Enqueue(child);
			}
		}
	}
}
