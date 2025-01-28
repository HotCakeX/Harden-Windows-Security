﻿namespace HardenWindowsSecurity;

internal static class GUIExclusions
{
	// Stores the file paths selected by the user after using the browse button
	internal static string[]? selectedFiles;

	// Defining this variables in an accessible scope, updated through the dispatcher, used from event handlers
	internal static bool MicrosoftDefenderToggleButtonStatus;
	internal static bool ControlledFolderAccessToggleButtonStatus;
	internal static bool AttackSurfaceReductionRulesToggleButtonStatus;
}
