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

using System;
using System.IO;
using System.Xml;
using System.Xml.Schema;
using AppControlManager.Others;

namespace AppControlManager.Main;

internal static class CiPolicyTest
{
	/// <summary>
	/// Gets the path to an App Control XML file and validates it against the schema
	/// </summary>
	/// <param name="xmlFilePath"></param>
	/// <returns></returns>
	/// <exception cref="FileNotFoundException"></exception>
	/// <exception cref="InvalidOperationException"></exception>
	internal static bool TestCiPolicy(string xmlFilePath)
	{

		// Get the Code Integrity Schema file path
		string schemaPath = GlobalVars.CISchemaPath;

		// Make sure the schema file exists
		if (!File.Exists(schemaPath))
		{
			throw new FileNotFoundException("The Code Integrity Schema file could not be found", schemaPath);
		}

		// Make sure the input XML file exists
		if (!File.Exists(xmlFilePath))
		{
			throw new FileNotFoundException("The file does not exist.", xmlFilePath);
		}

		// Validate XML file against schema
		try
		{
			// Create the XmlReaderSettings object
			XmlReaderSettings settings = new();

			// Add schema to settings
			_ = settings.Schemas.Add(null, schemaPath);

			// Set the validation settings
			settings.ValidationType = ValidationType.Schema;

			// Set the validation flags to report warnings
			settings.ValidationFlags |= XmlSchemaValidationFlags.ReportValidationWarnings;

			// Set the validation event handler
			settings.ValidationEventHandler += (sender, args) =>
			{
				throw new XmlSchemaValidationException($"Validation error in {xmlFilePath}: {args.Message}");
			};

			// Create an XmlDocument object
			XmlDocument xmlDoc = new();

			// Load the input XML document
			xmlDoc.Load(xmlFilePath);

			using XmlReader reader = XmlReader.Create(new StringReader(xmlDoc.OuterXml), settings);
			// Validate the XML document
			while (reader.Read()) { }

			return true;
		}
		catch (XmlSchemaValidationException ex)
		{
			throw new InvalidOperationException($"Validation error in {xmlFilePath}: {ex.Message}");
		}
	}
}
