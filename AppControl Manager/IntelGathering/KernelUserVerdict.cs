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
using AppControlManager.SiPolicyIntel;

namespace AppControlManager.IntelGathering;

internal sealed class KernelUserVerdict(
	SSType verdict,
	bool isPE,
	bool hasSIP,
	List<string> imports
	)
{
	internal SSType Verdict => verdict;
	internal bool IsPE => isPE;
	internal bool HasSIP => hasSIP;
	internal List<string> Imports => imports;
}
