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

namespace AppControlManager.CustomUIElements;

// https://learn.microsoft.com/windows/windows-app-sdk/api/winrt/microsoft.ui.xaml.controls.contentdialog
internal sealed partial class CustomPatternBasedFilePath : ContentDialogV2
{
	internal static readonly ObservableCollection<FilePathPatternExample> FilePathPatternExamplesCollection = [];

	internal static void PopulateFilePathPatternExamplesCollection()
	{
		FilePathPatternExamplesCollection.Clear();

		FilePathPatternExamplesCollection.Add(new FilePathPatternExample
		(
			example: "C:\\Windows\\*",
			description: Atlas.GetStr("CustomPatternBasedFilePathExampleDescription1")
		));

		FilePathPatternExamplesCollection.Add(new FilePathPatternExample
		(
			example: "D:\\EnterpriseApps\\MyApp\\*",
			description: Atlas.GetStr("CustomPatternBasedFilePathExampleDescription2")
		));

		FilePathPatternExamplesCollection.Add(new FilePathPatternExample
		(
			example: "*\\Bing.exe",
			description: Atlas.GetStr("CustomPatternBasedFilePathExampleDescription3")
		));

		FilePathPatternExamplesCollection.Add(new FilePathPatternExample
		(
			example: "C:\\*\\CCMCACHE\\*\\7z????-x64.exe",
			description: Atlas.GetStr("CustomPatternBasedFilePathExampleDescription4")
		));

		FilePathPatternExamplesCollection.Add(new FilePathPatternExample
		(
			example: "C:\\Users\\UserName\\AppData\\Local\\Temp\\????????-????-????-????-????????????.tmp.node",
			description: Atlas.GetStr("CustomPatternBasedFilePathExampleDescription5")
		));
	}

	internal CustomPatternBasedFilePath()
	{
		PopulateFilePathPatternExamplesCollection();
		InitializeComponent();
		CustomPatternBasedFilePathListView.ItemsSource = FilePathPatternExamplesCollection;
	}
}

internal sealed class FilePathPatternExample(string example, string description)
{
	internal string Example => example;
	internal string Description => description;
}
