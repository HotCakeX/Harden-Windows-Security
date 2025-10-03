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

using System.Xml;

namespace AppControlManager.XMLOps;

internal static class CloseEmptyXmlNodesSemantic
{

	/// <summary>
	/// Closes all empty XML nodes and removes empty nodes that are neither base nodes nor 'ProductSigners' nodes
	/// According to the CI Schema
	/// </summary>

	/*

          For example, it converts this

          <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="Auto generated policy on 03-13-2024">
            <ProductSigners>
              <AllowedSigners>
              </AllowedSigners>
            </ProductSigners>
          </SigningScenario>

          Or this

          <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="Auto generated policy on 03-13-2024">
            <ProductSigners>
              <AllowedSigners />
            </ProductSigners>
          </SigningScenario>

          to this

          <SigningScenario Value="12" ID="ID_SIGNINGSCENARIO_WINDOWS" FriendlyName="Auto generated policy on 03-13-2024">
            <ProductSigners />
          </SigningScenario>

          */

	// Defining the base node names that should not be removed even if empty
	private static readonly string[] baseNodeNames = [ "SiPolicy", "Rules", "EKUs", "FileRules", "Signers", "SigningScenarios",
						"UpdatePolicySigners", "CiSigners", "HvciOptions", "BasePolicyID", "PolicyID" ];

	internal static void Close(string xmlFilePath)
	{

		// Load the XML file
		XmlDocument xmlDoc = new();
		xmlDoc.Load(xmlFilePath);

		// Start the recursive method from the root element
		CloseEmptyNodesRecursively(xmlDoc.DocumentElement!, baseNodeNames);

		// Save the changes back to the XML file
		xmlDoc.Save(xmlFilePath);
	}


	/// <summary>
	/// Helper method to recursively close empty XML nodes
	/// </summary>
	/// <param name="xmlNode"></param>
	/// <param name="baseNodeNames"></param>
	private static void CloseEmptyNodesRecursively(XmlElement xmlNode, string[] baseNodeNames)
	{
		// Iterate through child nodes in reverse to avoid modifying collection while iterating
		for (int i = xmlNode.ChildNodes.Count - 1; i >= 0; i--)
		{
			if (xmlNode.ChildNodes[i] is XmlElement childElement)
			{
				// Recursively close empty child nodes first
				CloseEmptyNodesRecursively(childElement, baseNodeNames);

				// Check if the node is empty (no children, no attributes, no inner text)
				bool isEmpty = !childElement.HasChildNodes && !childElement.HasAttributes && string.IsNullOrWhiteSpace(childElement.InnerText);

				if (isEmpty)
				{
					// Check if it's a base node or the special case "ProductSigners"
					if (Array.Exists(baseNodeNames, baseNodeName => baseNodeName.Equals(childElement.LocalName, StringComparison.OrdinalIgnoreCase)) ||
						childElement.LocalName.Equals("ProductSigners", StringComparison.OrdinalIgnoreCase))
					{
						// Self-close it
						childElement.IsEmpty = true;
					}
					else
					{
						// If it's not a base node, remove it
						_ = xmlNode.RemoveChild(childElement);
					}
				}
			}
		}
	}
}
