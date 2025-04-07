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
using AppControlManager.ViewModels;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Input;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Represents a page for managing merge policies with a view model for data binding. It handles user interactions for
/// selecting files and displaying flyouts.
/// </summary>
internal sealed partial class MergePolicies : Page
{

#pragma warning disable CA1822
	private MergePoliciesVM ViewModel { get; } = App.AppHost.Services.GetRequiredService<MergePoliciesVM>();
	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();
#pragma warning restore CA1822

	/// <summary>
	/// Initializes a new instance of the MergePolicies class. Sets up the navigation cache mode and binds the data context
	/// to the ViewModel.
	/// </summary>
	internal MergePolicies()
	{
		this.InitializeComponent();

		// Make sure navigating to/from this page maintains its state
		this.NavigationCacheMode = NavigationCacheMode.Required;

		this.DataContext = ViewModel;
	}


	private void MainPolicySettingsCard_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!MainPolicy_Flyout.IsOpen)
				MainPolicy_Flyout.ShowAt(MainPolicySettingsCard);
	}

	private void MainPolicySettingsCard_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!MainPolicy_Flyout.IsOpen)
			MainPolicy_Flyout.ShowAt(MainPolicySettingsCard);
	}

	private void MainPolicyBrowseButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!MainPolicy_Flyout.IsOpen)
			MainPolicy_Flyout.ShowAt(MainPolicyBrowseButton);
	}

	private void OtherPoliciesSettingsCard_Holding(object sender, HoldingRoutedEventArgs e)
	{
		if (e.HoldingState is HoldingState.Started)
			if (!OtherPolicies_Flyout.IsOpen)
				OtherPolicies_Flyout.ShowAt(OtherPoliciesSettingsCard);
	}

	private void OtherPoliciesSettingsCard_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!OtherPolicies_Flyout.IsOpen)
			OtherPolicies_Flyout.ShowAt(OtherPoliciesSettingsCard);
	}

	private void OtherPoliciesBrowseButton_RightTapped(object sender, RightTappedRoutedEventArgs e)
	{
		if (!OtherPolicies_Flyout.IsOpen)
			OtherPolicies_Flyout.ShowAt(OtherPoliciesBrowseButton);
	}


	private void MainPolicySettingsCard_Click(object sender, RoutedEventArgs e)
	{

		string? selectedFile = FileDialogHelper.ShowFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (!string.IsNullOrEmpty(selectedFile))
		{
			// Store the selected XML file path
			ViewModel.MainPolicy = selectedFile;

			// Add the selected main XML policy file path to the flyout's TextBox
			ViewModel.MainPolicy = selectedFile;

			// Manually display the Flyout since user clicked/tapped on the Settings card and not the button itself
			MainPolicy_Flyout.ShowAt(MainPolicySettingsCard);
		}
	}


	private void OtherPoliciesSettingsCard_Click(object sender, RoutedEventArgs e)
	{

		List<string>? selectedFiles = FileDialogHelper.ShowMultipleFilePickerDialog(GlobalVars.XMLFilePickerFilter);

		if (selectedFiles is { Count: > 0 })
		{
			foreach (string file in selectedFiles)
			{
				if (ViewModel.OtherPolicies.Add(file))
				{
					// Append the new file to the TextBox, followed by a newline
					ViewModel.OtherPoliciesString += file + Environment.NewLine;
				}
			}

			// Manually display the Flyout since user clicked/tapped on the Settings card and not the button itself
			OtherPolicies_Flyout.ShowAt(OtherPoliciesSettingsCard);
		}
	}

}
