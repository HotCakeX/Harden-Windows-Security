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

using System.Collections.Generic;

namespace HardenSystemSecurity.GroupPolicy;

/// <summary>
/// A class representing the result of a merge operation on registry policy files.
/// </summary>
/// <param name="mergedFile">The main object that is the result of the merge operation.</param>
/// <param name="operations">Details of the merge operation.</param>
internal sealed class MergeResult(
	RegistryPolicyFile mergedFile,
	List<MergeOperation> operations)
{
	internal RegistryPolicyFile MergedFile => mergedFile;
	internal List<MergeOperation> Operations => operations;
}
