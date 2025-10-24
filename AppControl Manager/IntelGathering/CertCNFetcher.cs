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
using System.Security.Cryptography.X509Certificates;
using AppControlManager.Others;

namespace AppControlManager.IntelGathering;

internal static class CertCNFetcher
{
	/// <summary>
	/// Gets the common names (CN) of the certificates in the Personal certificate store of the Current User.
	/// </summary>
	/// <returns></returns>
	/// <exception cref="InvalidOperationException"></exception>
	internal static IEnumerable<string> GetCertCNs()
	{

		// Output collection
		HashSet<string> output = [];

		// Open the current user's personal store
		using (X509Store store = new(StoreName.My, StoreLocation.CurrentUser))
		{
			store.Open(OpenFlags.ReadOnly);

			// Loop through each certificate in the current user's personal store
			foreach (X509Certificate2 cert in store.Certificates)
			{
				// Make sure it uses the RSA algorithm (Because ECDSA is not supported for signing App Control policies)
				if (string.Equals(cert.PublicKey.Oid.FriendlyName, "RSA", StringComparison.OrdinalIgnoreCase))
				{
					// Get its Subject Common Name (CN) using the GetNameString method from CryptoAPI
					string cn = CryptoAPI.GetNameString(cert.Handle, CryptoAPI.CERT_NAME_SIMPLE_DISPLAY_TYPE, null, false);

					// Add the CN to the output set and warn if there is already CN with the same name in the HashSet
					if (!output.Add(cn))
					{
						Logger.Write(string.Format(
							GlobalVars.GetStr("DuplicateCertCommonNameWarning"),
							cn));

						_ = output.Remove(cn);
					}
				}
			}
		}

		return output;
	}
}
