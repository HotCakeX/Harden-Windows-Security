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

internal sealed class ExFileInfo(
	string? originalFileName,
	string? internalName,
	string? productName,
	Version? version,
	string? fileDescription)
{
	/// <summary>
	/// Holds the original name of the file. It can be null if no name is provided.
	/// </summary>
	internal string? OriginalFileName => originalFileName;

	/// <summary>
	/// Represents the internal name of an entity, which can be null. It is a string property that can be accessed and
	/// modified.
	/// </summary>
	internal string? InternalName => internalName;

	/// <summary>
	/// Represents the name of a product. It can be null, indicating that the product name is not specified.
	/// </summary>
	internal string? ProductName => productName;

	/// <summary>
	/// Represents the version of an object, allowing for nullable values. It can be used to track or specify the
	/// versioning of data.
	/// </summary>
	internal Version? Version => version;

	/// <summary>
	/// Represents an optional description of a file. It can hold a string value or be null.
	/// </summary>
	internal string? FileDescription => fileDescription;
}
