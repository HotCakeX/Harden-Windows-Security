using System.Collections.Generic;
using System.Linq;
using System.Xml;
using AppControlManager.Others;
using AppControlManager.SiPolicy;

namespace AppControlManager.SimulationMethods;

internal static partial class GetFileHashes
{
	/// <summary>
	/// Takes an App Control XML policy and returns all of the Hashes in the Hash rules.
	/// The method is intentionally not made to handle Allow all rules since checking for their existence happens in the main cmdlet.
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

		Logger.Write($"Returning {outputHashInfoProcessingString.Count} file rules that are based on hashes");
		// Return the output HashSet
		return outputHashInfoProcessingString;
	}
}
