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

namespace AppControlManager.Others;

internal sealed class PublisherSignerCreator
{
	internal List<CertificateDetailsCreator> CertificateDetails { get; set; }
	internal string? FileName { get; set; }
	internal string? AuthenticodeSHA256 { get; set; }
	internal string? AuthenticodeSHA1 { get; set; }
	internal int SiSigningScenario { get; set; }

	internal PublisherSignerCreator(List<CertificateDetailsCreator> certificateDetails, string fileName, string authenticodeSHA256, string authenticodeSHA1, int siSigningScenario)
	{
		CertificateDetails = certificateDetails;
		FileName = fileName;
		AuthenticodeSHA256 = authenticodeSHA256;
		AuthenticodeSHA1 = authenticodeSHA1;
		SiSigningScenario = siSigningScenario;
	}

	internal PublisherSignerCreator()
	{
		// Initialize CertificateDetails to an empty list to avoid null reference issues
		CertificateDetails = [];
	}
}
