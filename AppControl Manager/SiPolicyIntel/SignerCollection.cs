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

namespace AppControlManager.SiPolicyIntel;

/// <summary>
/// This is the output of the method that collects all types of signers from SiPolicies
/// </summary>
internal sealed class SignerCollection(
	HashSet<FilePublisherSignerRule> filePublisherSigners,
	HashSet<SignerRule> signerRules,
	HashSet<WHQLPublisher> wHQLPublishers,
	HashSet<WHQLFilePublisher> wHQLFilePublishers,
	HashSet<UpdatePolicySignerRule> updatePolicySigners,
	HashSet<SupplementalPolicySignerRule> supplementalPolicySigners
	)
{
	internal HashSet<FilePublisherSignerRule> FilePublisherSigners => filePublisherSigners;
	internal HashSet<SignerRule> SignerRules => signerRules;
	internal HashSet<WHQLPublisher> WHQLPublishers => wHQLPublishers;
	internal HashSet<WHQLFilePublisher> WHQLFilePublishers => wHQLFilePublishers;
	internal HashSet<UpdatePolicySignerRule> UpdatePolicySigners => updatePolicySigners;
	internal HashSet<SupplementalPolicySignerRule> SupplementalPolicySigners => supplementalPolicySigners;
}
