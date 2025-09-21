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
/// The PolicyEditor class manages the UI for editing policies.
/// </summary>
internal sealed partial class PolicyEditor : Page
{

	private PolicyEditorVM ViewModel { get; } = ViewModelProvider.PolicyEditorVM;

	internal static Flyout? _DiamondButtonFlyout { get; private set; }
	internal static Button? _DiamondButton { get; private set; }

	/// <summary>
	/// Initializes a new instance of the PolicyEditor class.
	/// </summary>
	internal PolicyEditor()
	{
		InitializeComponent();
		NavigationCacheMode = NavigationCacheMode.Disabled;
		DataContext = ViewModel;
		_DiamondButtonFlyout = DiamondButtonFlyout;
		_DiamondButton = DiamondButton;
	}
}
