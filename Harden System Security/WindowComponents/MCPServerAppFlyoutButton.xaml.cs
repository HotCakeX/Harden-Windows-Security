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
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Windows.System;

namespace HardenSystemSecurity.WindowComponents;

/// <summary>
/// Provides a title-bar access point whose flyout displays the MCP Server companion app in the Microsoft Store.
/// </summary>
internal sealed partial class MCPServerAppFlyoutButton : UserControl
{
	private static readonly Uri MCPServerStoreUri = new("https://apps.microsoft.com/detail/9P3BDTHKR7KS");

	internal MCPServerAppFlyoutButton() => InitializeComponent();

	/// <summary>
	/// Opens the MCP Server companion app listing using the default handler for the HTTPS URI.
	/// </summary>
	private async void OpenApp_Click(object sender, RoutedEventArgs args) => _ = await Launcher.LaunchUriAsync(MCPServerStoreUri);
}
