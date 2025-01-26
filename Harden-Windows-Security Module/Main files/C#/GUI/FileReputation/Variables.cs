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
