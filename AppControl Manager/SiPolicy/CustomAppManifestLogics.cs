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
using System.IO;
using System.Xml;

namespace AppControlManager.SiPolicy;

internal static class CustomAppManifestLogics
{
	private const string NamespaceUri = "urn:schemas-microsoft-com:windows-defender-application-control";

	/// <summary>
	/// Deserializes an Application Manifest from either a file path or a MemoryStream into an AppManifest object.
	/// </summary>
	/// <param name="filePath">The path to the XML file containing the Application Manifest.</param>
	/// <param name="stream">The MemoryStream containing the Application Manifest XML.</param>
	/// <returns>An AppManifest object populated with data from the provided XML.</returns>
	/// <exception cref="InvalidOperationException">Thrown when neither a valid file path nor a stream is provided, or if the XML does not conform to the schema.</exception>
	internal static AppManifest DeserializeAppManifest(string? filePath, MemoryStream? stream)
	{
		XmlElement? root;

		if (!string.IsNullOrEmpty(filePath))
		{
			XmlDocument xmlDoc = new();
			xmlDoc.Load(filePath);
			root = xmlDoc.DocumentElement ?? throw new InvalidOperationException(GlobalVars.GetStr("InvalidXmlMissingRootElementValidationError"));
		}
		else if (stream != null)
		{
			XmlDocument xmlDoc = new();
			xmlDoc.Load(stream);
			root = xmlDoc.DocumentElement ?? throw new InvalidOperationException(GlobalVars.GetStr("InvalidXmlMissingRootElementValidationError"));
		}
		else
		{
			throw new InvalidOperationException(GlobalVars.GetStr("NoFilePathOrStreamProvidedValidationError"));
		}

		if (!string.Equals(root.LocalName, "AppManifest", StringComparison.OrdinalIgnoreCase) ||
			!string.Equals(root.NamespaceURI, NamespaceUri, StringComparison.OrdinalIgnoreCase))
		{
			throw new InvalidOperationException(GlobalVars.GetStr("InvalidXmlRootElementNamespaceValidationError"));
		}

		if (!root.HasAttribute("Id"))
		{
			throw new InvalidOperationException(GlobalVars.GetStr("AppManifestMissingIdAttributeValidationError"));
		}
		string id = root.GetAttribute("Id");
		if (string.IsNullOrEmpty(id))
		{
			throw new InvalidOperationException(GlobalVars.GetStr("AppManifestEmptyIdAttributeValidationError"));
		}

		List<SettingDefinition> settings = [];
		XmlNodeList settingNodes = root.GetElementsByTagName("SettingDefinition", NamespaceUri);
		foreach (XmlElement settingElem in settingNodes)
		{
			SettingDefinition setting = DeserializeSettingDefinition(settingElem);
			settings.Add(setting);
		}

		return new AppManifest
		{
			Id = id,
			SettingDefinition = settings.ToArray()
		};
	}

	private static SettingDefinition DeserializeSettingDefinition(XmlElement elem)
	{
		if (!elem.HasAttribute("Name"))
		{
			throw new InvalidOperationException(GlobalVars.GetStr("SettingDefinitionMissingNameAttributeValidationError"));
		}
		string name = elem.GetAttribute("Name");
		if (string.IsNullOrEmpty(name))
		{
			throw new InvalidOperationException(GlobalVars.GetStr("SettingDefinitionEmptyNameAttributeValidationError"));
		}

		if (!elem.HasAttribute("Type"))
		{
			throw new InvalidOperationException(GlobalVars.GetStr("SettingDefinitionMissingTypeAttributeValidationError"));
		}
		string typeStr = elem.GetAttribute("Type");
		if (!Enum.TryParse(typeStr, out SettingType type))
		{
			throw new InvalidOperationException($"Invalid 'Type' value '{typeStr}' in SettingDefinition. Must be 'Bool', 'StringList', or 'StringSet'.");
		}

		if (!elem.HasAttribute("IgnoreAuditPolicies"))
		{
			throw new InvalidOperationException(GlobalVars.GetStr("SettingDefinitionMissingIgnoreAuditPoliciesAttributeValidationError"));
		}
		string ignoreAuditPoliciesStr = elem.GetAttribute("IgnoreAuditPolicies");
		if (!bool.TryParse(ignoreAuditPoliciesStr, out bool ignoreAuditPolicies))
		{
			throw new InvalidOperationException($"Invalid 'IgnoreAuditPolicies' value '{ignoreAuditPoliciesStr}' in SettingDefinition. Must be 'true' or 'false'.");
		}

		return new SettingDefinition
		{
			Name = name,
			Type = type,
			IgnoreAuditPolicies = ignoreAuditPolicies
		};
	}

	/// <summary>
	/// Serializes an AppManifest object into an XML document.
	/// </summary>
	/// <param name="manifest">The AppManifest object to serialize.</param>
	/// <returns>An XmlDocument representing the Application Manifest.</returns>
	/// <exception cref="ArgumentNullException">Thrown when the manifest or its required properties are null.</exception>
	/// <exception cref="InvalidOperationException">Thrown when the manifest contains invalid data per the schema.</exception>
	internal static XmlDocument CreateXmlFromAppManifest(AppManifest manifest)
	{
		if (manifest is null)
		{
			throw new ArgumentNullException(nameof(manifest), GlobalVars.GetStr("AppManifestObjectNullValidationError"));
		}

		if (string.IsNullOrEmpty(manifest.Id))
		{
			throw new InvalidOperationException(GlobalVars.GetStr("AppManifestPropertyIdNullOrEmptyValidationError"));
		}

		XmlDocument xmlDoc = new();
		XmlDeclaration xmlDecl = xmlDoc.CreateXmlDeclaration("1.0", "utf-8", null);
		_ = xmlDoc.AppendChild(xmlDecl);

		XmlElement root = xmlDoc.CreateElement("AppManifest", NamespaceUri);
		_ = xmlDoc.AppendChild(root);

		root.SetAttribute("Id", manifest.Id);

		if (manifest.SettingDefinition != null)
		{
			foreach (SettingDefinition setting in manifest.SettingDefinition)
			{
				if (setting is null)
				{
					throw new InvalidOperationException(GlobalVars.GetStr("SettingDefinitionArrayNullElementValidationError"));
				}
				if (string.IsNullOrEmpty(setting.Name))
				{
					throw new InvalidOperationException(GlobalVars.GetStr("SettingDefinitionPropertyNameNullOrEmptyValidationError"));
				}

				XmlElement settingElem = xmlDoc.CreateElement("SettingDefinition", NamespaceUri);
				settingElem.SetAttribute("Name", setting.Name);
				settingElem.SetAttribute("Type", setting.Type.ToString());
				settingElem.SetAttribute("IgnoreAuditPolicies", setting.IgnoreAuditPolicies.ToString().ToLowerInvariant());
				_ = root.AppendChild(settingElem);
			}
		}

		return xmlDoc;
	}
}
