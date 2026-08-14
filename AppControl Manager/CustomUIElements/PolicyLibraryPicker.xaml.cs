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

using AppControlManager.SiPolicy;
using AppControlManager.ViewModels;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements;

/// <summary>
/// Lightweight, selection-only view of the shared Policies Library collection.
/// </summary>
internal sealed partial class PolicyLibraryPicker : UserControl
{
	internal UniquePolicyFileRepresentObservableCollection Policies => ViewModelProvider.MainWindowVM.SidebarPoliciesLibrary;
	internal event Action<PolicyFileRepresent>? PolicySelected;
	internal Visibility GetEmptyStateVisibility(int count) => count is 0 ? Visibility.Visible : Visibility.Collapsed;

	internal PolicyLibraryPicker() => InitializeComponent();

	private void OnPolicyItemClick(object sender, ItemClickEventArgs e)
	{
		if (e.ClickedItem is PolicyFileRepresent policy)
			PolicySelected?.Invoke(policy);
	}
}
