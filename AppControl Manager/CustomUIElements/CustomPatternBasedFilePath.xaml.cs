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

using System.Collections.ObjectModel;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;

namespace AppControlManager.CustomUIElements;

// https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.controls.contentdialog
internal sealed partial class CustomPatternBasedFilePath : ContentDialog
{
	private AppSettings.Main AppSettings => App.Settings;

	internal static readonly ObservableCollection<FilePathPatternExample> FilePathPatternExamplesCollection = [];

	internal static void PopulateFilePathPatternExamplesCollection()
	{
		FilePathPatternExamplesCollection.Clear();

		FilePathPatternExamplesCollection.Add(new FilePathPatternExample
		{
			Example = "C:\\Windows\\*",
			Description = GlobalVars.GetStr("CustomPatternBasedFilePathExampleDescription1")
		});

		FilePathPatternExamplesCollection.Add(new FilePathPatternExample
		{
			Example = "D:\\EnterpriseApps\\MyApp\\*",
			Description = GlobalVars.GetStr("CustomPatternBasedFilePathExampleDescription2")
		});

		FilePathPatternExamplesCollection.Add(new FilePathPatternExample
		{
			Example = "*\\Bing.exe",
			Description = GlobalVars.GetStr("CustomPatternBasedFilePathExampleDescription3")
		});

		FilePathPatternExamplesCollection.Add(new FilePathPatternExample
		{
			Example = "C:\\*\\CCMCACHE\\*\\7z????-x64.exe",
			Description = GlobalVars.GetStr("CustomPatternBasedFilePathExampleDescription4")
		});

		FilePathPatternExamplesCollection.Add(new FilePathPatternExample
		{
			Example = "C:\\Users\\UserName\\AppData\\Local\\Temp\\????????-????-????-????-????????????.tmp.node",
			Description = GlobalVars.GetStr("CustomPatternBasedFilePathExampleDescription5")
		});
	}

	internal CustomPatternBasedFilePath()
	{
		PopulateFilePathPatternExamplesCollection();

		InitializeComponent();

		XamlRoot = App.MainWindow?.Content.XamlRoot;

		CustomPatternBasedFilePathListView.ItemsSource = FilePathPatternExamplesCollection;

		RequestedTheme = string.Equals(AppSettings.AppTheme, "Light", StringComparison.OrdinalIgnoreCase) ? ElementTheme.Light : (string.Equals(AppSettings.AppTheme, "Dark", StringComparison.OrdinalIgnoreCase) ? ElementTheme.Dark : ElementTheme.Default);
	}
}

internal sealed class FilePathPatternExample
{
	internal string? Example;
	internal string? Description;
}
