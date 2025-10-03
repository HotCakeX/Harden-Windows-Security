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

namespace AppControlManager.Others;

internal static class VersionIncrementer
{
	/// <summary>
	/// This can recursively increment an input version by one, and is aware of the max limit
	/// </summary>
	/// <param name="version"></param>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static Version AddVersion(Version version)
	{
		// Ensure all 4 components are present
		if (version.Build == -1 || version.Revision == -1)
		{
			throw new InvalidOperationException("Expected a 4-part version (major.minor.build.revision).");
		}

		// Validate segment bounds according to the CI schema.
		if (version.Major > ushort.MaxValue || version.Minor > ushort.MaxValue ||
			version.Build > ushort.MaxValue || version.Revision > ushort.MaxValue)
		{
			throw new InvalidOperationException($"Each version segment must be within [0, {ushort.MaxValue}].");
		}

		if (version.Major == ushort.MaxValue &&
			version.Minor == ushort.MaxValue &&
			version.Build == ushort.MaxValue &&
			version.Revision == ushort.MaxValue)
		{
			throw new InvalidOperationException("Version has reached its maximum value.");
		}

		// Increment with carry from least significant segment
		if (version.Revision < ushort.MaxValue)
		{
			return new Version(version.Major, version.Minor, version.Build, version.Revision + 1);
		}

		if (version.Build < ushort.MaxValue)
		{
			return new Version(version.Major, version.Minor, version.Build + 1, 0);
		}

		if (version.Minor < ushort.MaxValue)
		{
			return new Version(version.Major, version.Minor + 1, 0, 0);
		}

		// By this point Major < ushort.MaxValue is guaranteed by the all-max check above
		return new Version(version.Major + 1, 0, 0, 0);
	}
}
