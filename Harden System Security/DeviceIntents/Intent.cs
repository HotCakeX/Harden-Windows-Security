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

namespace HardenSystemSecurity.DeviceIntents;

/// <summary>
/// Specifies the intent or purpose of the device.
/// This enumeration is used to apply policies and configurations based on usage intent.
/// </summary>
internal enum Intent : int
{
	Development = 0,
	Gaming = 1,
	School = 2,
	Business = 3,
	SpecializedAccessWorkstation = 4,
	PrivilegedAccessWorkstation = 5,
	All = 99
}

/// <summary>
/// Defiens an intent item with associated metadata to display it in the UI.
/// </summary>
/// <param name="intent"></param>
/// <param name="title"></param>
/// <param name="description"></param>
/// <param name="image"></param>
internal sealed class IntentItem(Intent intent, string title, string description, Uri image)
{
	internal Intent Intent => intent;
	internal string Title => title;
	internal string Description => description;
	internal Uri Image => image;
}
