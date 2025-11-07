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
using System.Linq;
using System.Xml;
using AppControlManager.SiPolicy;

namespace AppControlManager.SimulationMethods;

internal static partial class GetFileHashes
{
	/// <summary>
	/// Takes an App Control XML policy and returns all of the Hashes in the Hash rules.
	/// The method is intentionally not made to handle Allow all rules since checking for their existence happens in the main method.
	/// </summary>
	/// <param name="xml"></param>
	/// <returns></returns>
	internal static HashSet<string> Get(XmlDocument xml)
	{
		// Create an empty HashSet to store the output
		HashSet<string> outputHashInfoProcessingString = [];

		SiPolicy.SiPolicy policyObj = Management.Initialize(null, xml);

		IEnumerable<Allow>? allowRules = policyObj.FileRules?.OfType<Allow>();

		if (allowRules is not null)
		{
			// Get the hash from the Allow rules
			IEnumerable<byte[]> hashesInBytes = allowRules.Select(x => x.Hash);

			// Convert each hash byte array to string
			foreach (byte[] hash in hashesInBytes)
			{
				_ = outputHashInfoProcessingString.Add(CustomSerialization.ConvertByteArrayToHex(hash));
			}
		}

		Logger.Write(string.Format(GlobalVars.GetStr("ReturningNFileRulesBasedOnHashes"), outputHashInfoProcessingString.Count));
		// Return the output HashSet
		return outputHashInfoProcessingString;
	}
}
