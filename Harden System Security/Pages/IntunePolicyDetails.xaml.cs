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

using HardenSystemSecurity.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;

namespace HardenSystemSecurity.Pages;

internal sealed partial class IntunePolicyDetails : Page, CommonCore.UI.IPageHeaderProvider
{
	/// <summary>
	/// The assignment table remains active at or above this page-content width. Below the threshold,
	/// the compact card layout is loaded instead so labels and values remain readable.
	/// </summary>
	private const double WideAssignmentLayoutMinimumWidth = 900D;

	private IntuneVM ViewModel => ViewModelProvider.IntuneVM;

	internal IntunePolicyDetails() => InitializeComponent();

	string CommonCore.UI.IPageHeaderProvider.HeaderTitle => "View and Manage the Intune Policy Assignments";

	Uri? CommonCore.UI.IPageHeaderProvider.HeaderGuideUri => new("https://github.com/HotCakeX/Harden-Windows-Security/wiki/Intune-%7C-Harden-System-Security");

	/// <summary>
	/// Uses the details page's available content width rather than the outer window width, because
	/// navigation chrome can reduce the actual space available to the assignment ListView.
	/// </summary>
	private void LayoutRoot_SizeChanged(object sender, SizeChangedEventArgs e) =>
		ViewModel.SetPolicyDetailsLayout(e.NewSize.Width >= WideAssignmentLayoutMinimumWidth);

	private void BackButton_Click(object sender, RoutedEventArgs e)
	{
		if (Frame.CanGoBack)
		{
			Frame.GoBack();
		}
	}

	/// <summary>
	/// Handles Back button through the same navigation path as the visible Back button.
	/// </summary>
	private void BackKeyboardAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		args.Handled = true;

		if (Frame.CanGoBack)
		{
			Frame.GoBack();
		}
	}

	/// <summary>
	/// Routes F5 through the same view-model refresh operation as the visible Refresh button.
	/// Marking the accelerator handled prevents the key press from being processed again upstream.
	/// </summary>
	private void RefreshKeyboardAccelerator_Invoked(KeyboardAccelerator sender, KeyboardAcceleratorInvokedEventArgs args)
	{
		args.Handled = true;
		ViewModel.RefreshPolicyDetails_Click();
	}
}
