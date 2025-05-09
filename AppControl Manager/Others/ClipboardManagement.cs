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

using Windows.ApplicationModel.DataTransfer;

namespace AppControlManager.Others;

internal static class ClipboardManagement
{
	/// <summary>
	/// Takes a text and copies it to the OS clipboard.
	/// </summary>
	/// <param name="text">The text to be copied.</param>
	internal static void CopyText(string? text)
	{
		// Create a DataPackage to hold the text data
		DataPackage dataPackage = new();

		// Set the text as the content of the DataPackage
		dataPackage.SetText(text);

		// Copy the DataPackage content to the clipboard
		Clipboard.SetContent(dataPackage);
	}
}
