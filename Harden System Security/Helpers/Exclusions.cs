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

namespace HardenSystemSecurity.Helpers;

internal sealed class Exclusions(string target, ExclusionSource source)
{
	internal string Target => target;
	internal ExclusionSource Source => source;
	internal string SourceFriendlyName => ExclusionSourceToString(source);

	private static string ExclusionSourceToString(ExclusionSource s) => s switch
	{
		ExclusionSource.Antivirus_Path => "Antivirus - Path",
		ExclusionSource.Antivirus_Extension => "Antivirus - Extension",
		ExclusionSource.Antivirus_Process => "Antivirus - Process",
		ExclusionSource.ControlledFolderAccess => "Controlled Folder Access",
		ExclusionSource.AttackSurfaceReduction => "Attack Surface Reduction",
		_ => "Unknown Exclusion Source"
	};
}

internal enum ExclusionSource
{
	Antivirus_Path = 0,
	Antivirus_Extension = 1,
	Antivirus_Process = 2,
	ControlledFolderAccess = 3,
	AttackSurfaceReduction = 4
}
