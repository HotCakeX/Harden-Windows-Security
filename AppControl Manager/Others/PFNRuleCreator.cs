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

using AppControlManager.SiPolicyIntel;

namespace AppControlManager.Others;

/// <summary>
/// Defines a class for creating rules based on package family name.
/// </summary>
/// <param name="packageFamilyName">Specifies the name of the package family for which the rule is created.</param>
/// <param name="minimumFileVersion">Indicates the minimum file version required for the rule to apply.</param>
/// <param name="siSigningScenario">Represents the signing scenario associated with the rule.</param>
internal sealed class PFNRuleCreator(string packageFamilyName, string minimumFileVersion, SSType siSigningScenario)
{
	internal string PackageFamilyName => packageFamilyName;
	internal string MinimumFileVersion => minimumFileVersion;
	internal SSType SiSigningScenario => siSigningScenario;
}

