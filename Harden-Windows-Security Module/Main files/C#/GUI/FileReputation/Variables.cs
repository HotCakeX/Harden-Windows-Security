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
using System.Runtime.InteropServices;
using System.Windows.Controls;

namespace HardenWindowsSecurity;

internal static class GUIFileReputation
{
	internal static UserControl? View;

	internal static Grid? ParentGrid;

	internal static string? selectedFilePath;

	// Enum representing different trust levels of a file
	internal enum TrustScore
	{
		PotentiallyUnwantedApplication = -3,
		Malicious = -2,
		Unknown = -1,
		Good = 0,
		HighTrust = 1
	}

	// Structure to hold extra info about the file trust
	[StructLayout(LayoutKind.Sequential)]
	internal struct MpFileTrustExtraInfo
	{
		internal uint First;             // First extra info field
		internal uint Second;            // Second extra info field
		internal uint DataSize;          // Size of the data
		internal uint AlignmentPadding;  // Padding for memory alignment
		internal IntPtr Data;            // Pointer to extra data
	}

}
