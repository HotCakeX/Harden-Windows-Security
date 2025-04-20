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
using System.Collections.ObjectModel;
using AppControlManager.Others;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements;

// https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.controls.contentdialog
internal sealed partial class CustomPatternBasedFilePath : ContentDialog
{

	private AppSettings.Main AppSettings { get; } = App.AppHost.Services.GetRequiredService<AppSettings.Main>();

	internal static readonly ObservableCollection<FilePathPatternExample> FilePathPatternExamplesCollection = [

		new()
		{
			Example = "C:\\Windows\\*",
			Description = GlobalVars.Rizz.GetString("CustomPatternBasedFilePathExampleDescription1")
		},
		new()
		{
			Example = "D:\\EnterpriseApps\\MyApp\\*",
			Description = GlobalVars.Rizz.GetString("CustomPatternBasedFilePathExampleDescription2")
		},
		new()
		{
			Example = "*\\Bing.exe",
			Description = GlobalVars.Rizz.GetString("CustomPatternBasedFilePathExampleDescription3")
		},
		new()
		{
			Example = "C:\\*\\CCMCACHE\\*\\7z????-x64.exe",
			Description = GlobalVars.Rizz.GetString("CustomPatternBasedFilePathExampleDescription4")
		},
		new()
		{
			Example = "C:\\Users\\UserName\\AppData\\Local\\Temp\\????????-????-????-????-????????????.tmp.node\"",
			Description = GlobalVars.Rizz.GetString("CustomPatternBasedFilePathExampleDescription5")
		}
	];

	internal CustomPatternBasedFilePath()
	{
		this.InitializeComponent();

		XamlRoot = App.MainWindow?.Content.XamlRoot;

		CustomPatternBasedFilePathListView.ItemsSource = FilePathPatternExamplesCollection;

		this.RequestedTheme = string.Equals(AppSettings.AppTheme, "Light", StringComparison.OrdinalIgnoreCase) ? ElementTheme.Light : (string.Equals(AppSettings.AppTheme, "Dark", StringComparison.OrdinalIgnoreCase) ? ElementTheme.Dark : ElementTheme.Default);
	}
}

internal sealed class FilePathPatternExample
{
	internal string? Example;
	internal string? Description;
}
