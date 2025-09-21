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

using AppControlManager.ViewModels;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Navigation;

namespace AppControlManager.Pages;

/// <summary>
/// Represents a page for managing merge policies with a view model for data binding. It handles user interactions for
/// selecting files and displaying flyouts.
/// </summary>
internal sealed partial class MergePolicies : Page
{
	private MergePoliciesVM ViewModel { get; } = ViewModelProvider.MergePoliciesVM;

	/// <summary>
	/// Initializes a new instance of the MergePolicies class. Sets up the navigation cache mode and binds the data context
	/// to the ViewModel.
	/// </summary>
	internal MergePolicies()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
	}
}
