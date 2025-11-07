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
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading.Tasks;
using System.Xml;

namespace AppControlManager.IntelGathering;

internal static class GetEventLogsData
{
	// Code Integrity event path
	private const string CodeIntegrityLogPath = "Microsoft-Windows-CodeIntegrity/Operational";

	// AppLocker event path
	private const string AppLockerLogPath = "Microsoft-Windows-AppLocker/MSI and Script";

	// Get the drive letter mappings
	private static readonly List<DriveLetterMapper.DriveMapping> DriveLettersGlobalRootFix = DriveLetterMapper.GetGlobalRootDrives();

	// Get "OSDrive:\Windows\System32" string
	private static readonly string FullSystem32Path = Environment.SystemDirectory;


	/// <summary>
	/// Retrieves the Code Integrity events from the local and EVTX files
	/// </summary>
	/// <returns></returns>
	private static HashSet<FileIdentity> CodeIntegrityEventsRetriever(string? EvtxFilePath = null)
	{

		// HashSet to store the output, ensures the data are unique and are time-prioritized
		FileIdentityTimeBasedHashSet fileIdentities = new();

		// query xPath for the following Code Integrity event IDs:
		// 3076 - Audit
		// 3077 - Block
		// 3089 - Correlated
		const string query = "*[System[(EventID=3076 or EventID=3077 or EventID=3089)]]";

		EventLogQuery eventQuery;


		if (EvtxFilePath is null)
		{
			// Initialize the EventLogQuery with the log path and query
			eventQuery = new(CodeIntegrityLogPath, PathType.LogName, query);
		}
		else
		{
			// Initialize the EventLogQuery with the input evtx log path and query
			eventQuery = new(EvtxFilePath, PathType.FilePath, query);
		}


		// Use EventLogReader to read the events
		List<EventRecord> rawEvents = [];

		try
		{

			// Read the events from the system based on the query
			using (EventLogReader logReader = new(eventQuery))
			{
				EventRecord eventRecord;

				// Read each event that matches the query
				while ((eventRecord = logReader.ReadEvent()) is not null)
				{
					// Add the event to the list
					rawEvents.Add(eventRecord);
				}
			}

			// Make sure there are events to process
			if (rawEvents.Count is 0)
			{
				Logger.Write(GlobalVars.GetStr("NoCodeIntegrityLogsFoundMessage"));
				return fileIdentities.FileIdentitiesInternal;
			}

			// Group all events based on their ActivityId property
			IEnumerable<IGrouping<Guid?, EventRecord>> groupedEvents = rawEvents.GroupBy(e => e.ActivityId);

			// Iterate over each group of events
			foreach (IGrouping<Guid?, EventRecord> group in groupedEvents)
			{
				// Access the ActivityId for the group (key)
				Guid? activityId = group.Key;

				if (activityId is null)
				{
					continue;
				}

				// There are either blocked or audit events in each group
				// If there are more than 1 of either block or audit events, selecting the first one because that means the same event was triggered by multiple deployed policies

				// Get the possible audit event in the group
				EventRecord? possibleAuditEvent = group.FirstOrDefault(g => g.Id == 3076);
				// Get the possible blocked event
				EventRecord? possibleBlockEvent = group.FirstOrDefault(g => g.Id == 3077);
				// Get the possible correlated data
				IEnumerable<EventRecord> correlatedEvents = group.Where(g => g.Id == 3089);


				// If the current group belongs to an Audit event
				if (possibleAuditEvent is not null)
				{
					// Use the ToXml method of the EventRecord to convert the entire event to XML but as string
					string xmlString = possibleAuditEvent.ToXml();

					// Create an XmlDocument and load the XML string, convert it to XML document
					XmlDocument xmlDocument = new();
					xmlDocument.LoadXml(xmlString);

					// Create a namespace manager for the XML document
					XmlNamespaceManager namespaceManager = new(xmlDocument.NameTable);
					namespaceManager.AddNamespace("evt", "http://schemas.microsoft.com/win/2004/08/events/event");

					#region Get File name and fix file path
					string? FilePath = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='File Name']");

					string? FileName = null;

					if (FilePath is not null)
					{

						// Sometimes the file name begins with System32 so we prepend the Windows directory to create a full resolvable path
						if (FilePath.StartsWith("System32", StringComparison.OrdinalIgnoreCase))
						{
							FilePath = FilePath.Replace("System32", FullSystem32Path, StringComparison.OrdinalIgnoreCase);
						}
						else
						{
							// Only attempt to resolve path using current system's drives if EVTX files are not being used since they can be from other systems
							if (EvtxFilePath is null)
							{
								FilePath = ResolvePath(FilePath);
							}
						}

						// Doesn't matter if the file exists or not
						FileName = Path.GetFileName(FilePath);
					}
					#endregion


					// This increases the processing time a LOT
					/*
						#region Resolve UserID
						string? UserIDString = null;

						if (possibleAuditEvent.UserId is not null)
						{
							try
							{
								// If the user account SID doesn't exist on the system it'll throw error
								UserIDString = possibleAuditEvent.UserId.Translate(typeof(NTAccount)).Value;
							}
							catch
							{
								UserIDString = possibleAuditEvent.UserId?.ToString();
							}
						}
						#endregion
						*/


					// Make sure the file has SHA256 Hash
					string? SHA256Hash = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='SHA256 Hash']");

					if (SHA256Hash is null)
					{
						continue;
					}

					// Extract values using XPath
					FileIdentity eventData = new()
					{
						// These don't require to be retrieved from XML, they are part of the <System> node/section
						Origin = FileIdentityOrigin.EventLog,
						Action = EventAction.Audit,
						EventID = possibleAuditEvent.Id,
						TimeCreated = possibleAuditEvent.TimeCreated,
						ComputerName = possibleAuditEvent.MachineName,
						UserID = possibleAuditEvent.UserId?.ToString(),

						// Need to be retrieved from the XML because they are part of the <EventData> node of the Event, otherwise their property names wouldn't be available
						FilePath = FilePath,
						FileName = FileName,
						ProcessName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='Process Name']"),
						RequestedSigningLevel = CILogIntel.GetValidatedRequestedSigningLevel(GetIntValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='Requested Signing Level']")),
						ValidatedSigningLevel = CILogIntel.GetValidatedRequestedSigningLevel(GetIntValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='Validated Signing Level']")),
						Status = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='Status']"),
						SHA1Hash = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='SHA1 Hash']"),
						SHA256Hash = SHA256Hash,
						SHA1FlatHash = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='SHA1 Flat Hash']"),
						SHA256FlatHash = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='SHA256 Flat Hash']"),
						USN = GetLongValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='USN']"),
						SISigningScenario = (SiPolicyIntel.SSType)(GetIntValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='SI Signing Scenario']") ?? 1),
						PolicyName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='PolicyName']"),
						PolicyID = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='PolicyID']"),
						PolicyHash = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='PolicyHash']"),
						OriginalFileName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='OriginalFileName']"),
						InternalName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='InternalName']"),
						FileDescription = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='FileDescription']"),
						ProductName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='ProductName']"),
						PolicyGUID = GetGuidValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='PolicyGUID']"),
						UserWriteable = GetBooleanValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='UserWriteable']"),
						PackageFamilyName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='PackageFamilyName']")
					};

					// Safely set the FileVersion using helper method
					string? fileVersionString = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='FileVersion']");
					eventData.FileVersion = SetFileVersion(fileVersionString);

					// Iterate over each correlated event (if any) - files can have multiple signers
					foreach (EventRecord correlatedEvent in correlatedEvents)
					{
						// Use the ToXml method of the EventRecord to convert the entire event to XML but as string
						string xmlStringCore = correlatedEvent.ToXml();

						// Create an XmlDocument and load the XML string, convert it to XML document
						XmlDocument xmlDocumentCore = new();
						xmlDocumentCore.LoadXml(xmlStringCore);

						// Create a namespace manager for the XML document
						XmlNamespaceManager namespaceManagerCore = new(xmlDocumentCore.NameTable);
						namespaceManagerCore.AddNamespace("evt", "http://schemas.microsoft.com/win/2004/08/events/event");


						// Skip signers that don't have PublisherTBSHash (aka LeafCertificate TBS Hash) or PublisherName
						// They have "Unknown" as their IssuerName and PublisherName too
						// Leaf certificate is a must have for signed files
						string? PublisherTBSHash = GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='PublisherTBSHash']");

						string? PublisherName = GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='PublisherName']");

						if (PublisherTBSHash is null || PublisherName is null)
						{
							continue;
						}

						// Extract values using XPath
						FileSignerInfo signerInfo = new(
							totalSignatureCount: GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='TotalSignatureCount']"),
							signature: GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='Signature']"),
							hash: GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='Hash']"),
							pageHash: GetBooleanValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='PageHash']"),
							signatureType: CILogIntel.GetSignatureType(GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='SignatureType']")),
							validatedSigningLevel: CILogIntel.GetValidatedRequestedSigningLevel(GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='ValidatedSigningLevel']")),
							verificationError: CILogIntel.GetVerificationError(GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='VerificationError']")),
							flags: GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='Flags']"),
							notValidBefore: GetEventDataDateTimeValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='NotValidBefore']"),
							notValidAfter: GetEventDataDateTimeValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='NotValidAfter']"),
							publisherName: PublisherName,
							issuerName: GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='IssuerName']"),
							publisherTBSHash: PublisherTBSHash,
							issuerTBSHash: GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='IssuerTBSHash']"),
							oPUSInfo: GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='OPUSInfo']"),
							eKUs: GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='EKUs']"),
							knownRoot: GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='KnownRoot']")
						);


						// Add the CN of the current signer to the FilePublishers HashSet of the FileIdentity
						_ = eventData.FilePublishers.Add(PublisherName);


						// Add the current signer info/correlated event data to the main event package
						_ = eventData.FileSignerInfos.Add(signerInfo);
					}

					// Set the SignatureStatus based on the number of signers
					eventData.SignatureStatus = eventData.FileSignerInfos.Count > 0 ? SignatureStatus.IsSigned : SignatureStatus.IsUnsigned;


					// Add the entire event package to the output list
					_ = fileIdentities.Add(eventData);


					continue;
				}

				// If the current group belongs to a blocked event
				if (possibleBlockEvent is not null)
				{

					// Use the ToXml method of the EventRecord to convert the entire event to XML but as string
					string xmlString = possibleBlockEvent.ToXml();

					// Create an XmlDocument and load the XML string, convert it to XML document
					XmlDocument xmlDocument = new();
					xmlDocument.LoadXml(xmlString);

					// Create a namespace manager for the XML document
					XmlNamespaceManager namespaceManager = new(xmlDocument.NameTable);
					namespaceManager.AddNamespace("evt", "http://schemas.microsoft.com/win/2004/08/events/event");

					#region Get File name and fix file path
					string? FilePath = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='File Name']");

					string? FileName = null;

					if (FilePath is not null)
					{

						// Sometimes the file name begins with System32 so we prepend the Windows directory to create a full resolvable path
						if (FilePath.StartsWith("System32", StringComparison.OrdinalIgnoreCase))
						{
							FilePath = FilePath.Replace("System32", FullSystem32Path, StringComparison.OrdinalIgnoreCase);
						}
						else
						{
							// Only attempt to resolve path using current system's drives if EVTX files are not being used since they can be from other systems
							if (EvtxFilePath is null)
							{
								FilePath = ResolvePath(FilePath);
							}
						}

						// Doesn't matter if the file exists or not
						FileName = Path.GetFileName(FilePath);
					}
					#endregion


					/*
						#region Resolve UserID
						string? UserIDString = null;

						if (possibleBlockEvent.UserId is not null)
						{
							try
							{
								// If the user account SID doesn't exist on the system it'll throw error
								UserIDString = possibleBlockEvent.UserId.Translate(typeof(NTAccount)).Value;
							}
							catch
							{
								UserIDString = possibleBlockEvent.UserId?.ToString();
							}
						}
						#endregion
						*/


					// Make sure the file has SHA256 Hash
					string? SHA256Hash = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='SHA256 Hash']");

					if (SHA256Hash is null)
					{
						continue;
					}


					// Extract values using XPath
					FileIdentity eventData = new()
					{
						// These don't require to be retrieved from XML, they are part of the <System> node/section
						Origin = FileIdentityOrigin.EventLog,
						Action = EventAction.Block,
						EventID = possibleBlockEvent.Id,
						TimeCreated = possibleBlockEvent.TimeCreated,
						ComputerName = possibleBlockEvent.MachineName,
						UserID = possibleBlockEvent.UserId?.ToString(),

						// Need to be retrieved from the XML because they are part of the <EventData> node of the Event, otherwise their property names wouldn't be available
						FilePath = FilePath,
						FileName = FileName,
						ProcessName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='Process Name']"),
						RequestedSigningLevel = CILogIntel.GetValidatedRequestedSigningLevel(GetIntValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='Requested Signing Level']")),
						ValidatedSigningLevel = CILogIntel.GetValidatedRequestedSigningLevel(GetIntValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='Validated Signing Level']")),
						Status = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='Status']"),
						SHA1Hash = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='SHA1 Hash']"),
						SHA256Hash = SHA256Hash,
						SHA1FlatHash = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='SHA1 Flat Hash']"),
						SHA256FlatHash = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='SHA256 Flat Hash']"),
						USN = GetLongValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='USN']"),
						SISigningScenario = (SiPolicyIntel.SSType)(GetIntValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='SI Signing Scenario']") ?? 1),
						PolicyName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='PolicyName']"),
						PolicyID = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='PolicyID']"),
						PolicyHash = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='PolicyHash']"),
						OriginalFileName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='OriginalFileName']"),
						InternalName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='InternalName']"),
						FileDescription = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='FileDescription']"),
						ProductName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='ProductName']"),
						PolicyGUID = GetGuidValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='PolicyGUID']"),
						UserWriteable = GetBooleanValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='UserWriteable']"),
						PackageFamilyName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='PackageFamilyName']")
					};

					// Safely set the FileVersion using helper method
					string? fileVersionString = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='FileVersion']");
					eventData.FileVersion = SetFileVersion(fileVersionString);

					// Iterate over each correlated event (if any) - files can have multiple signers
					foreach (EventRecord correlatedEvent in correlatedEvents)
					{
						// Use the ToXml method of the EventRecord to convert the entire event to XML but as string
						string xmlStringCore = correlatedEvent.ToXml();

						// Create an XmlDocument and load the XML string, convert it to XML document
						XmlDocument xmlDocumentCore = new();
						xmlDocumentCore.LoadXml(xmlStringCore);

						// Create a namespace manager for the XML document
						XmlNamespaceManager namespaceManagerCore = new(xmlDocumentCore.NameTable);
						namespaceManagerCore.AddNamespace("evt", "http://schemas.microsoft.com/win/2004/08/events/event");


						// Skip signers that don't have PublisherTBSHash (aka LeafCertificate TBS Hash)
						// They have "Unknown" as their IssuerName and PublisherName too
						// Leaf certificate is a must have for signed files
						string? PublisherTBSHash = GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='PublisherTBSHash']");

						string? PublisherName = GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='PublisherName']");

						if (PublisherTBSHash is null || PublisherName is null)
						{
							continue;
						}


						// Extract values using XPath
						FileSignerInfo signerInfo = new(
							totalSignatureCount: GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='TotalSignatureCount']"),
							signature: GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='Signature']"),
							hash: GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='Hash']"),
							pageHash: GetBooleanValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='PageHash']"),
							signatureType: CILogIntel.GetSignatureType(GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='SignatureType']")),
							validatedSigningLevel: CILogIntel.GetValidatedRequestedSigningLevel(GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='ValidatedSigningLevel']")),
							verificationError: CILogIntel.GetVerificationError(GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='VerificationError']")),
							flags: GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='Flags']"),
							notValidBefore: GetEventDataDateTimeValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='NotValidBefore']"),
							notValidAfter: GetEventDataDateTimeValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='NotValidAfter']"),
							publisherName: PublisherName,
							issuerName: GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='IssuerName']"),
							publisherTBSHash: PublisherTBSHash,
							issuerTBSHash: GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='IssuerTBSHash']"),
							oPUSInfo: GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='OPUSInfo']"),
							eKUs: GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='EKUs']"),
							knownRoot: GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='KnownRoot']")
						);


						// Add the CN of the current signer to the FilePublishers HashSet of the FileIdentity
						_ = eventData.FilePublishers.Add(PublisherName);


						// Add the current signer info/correlated event data to the main event package
						_ = eventData.FileSignerInfos.Add(signerInfo);

					}

					// Set the SignatureStatus based on the number of signers
					eventData.SignatureStatus = eventData.FileSignerInfos.Count > 0 ? SignatureStatus.IsSigned : SignatureStatus.IsUnsigned;

					// Add the populated EventData instance to the list
					_ = fileIdentities.Add(eventData);


					continue;
				}
			}

			Logger.Write(string.Format(
				GlobalVars.GetStr("TotalCodeIntegrityLogsMessage"),
				fileIdentities.Count));

			// Return the output
			return fileIdentities.FileIdentitiesInternal;
		}
		finally
		{
			foreach (EventRecord item in rawEvents)
			{
				item.Dispose();
			}
		}
	}


	/// <summary>
	/// Retrieves the AppLocker events from the local and EVTX files
	/// </summary>
	/// <returns></returns>
	private static HashSet<FileIdentity> AppLockerEventsRetriever(string? EvtxFilePath = null)
	{

		// HashSet to store the output, ensures the data are unique
		FileIdentityTimeBasedHashSet fileIdentities = new();

		// query xPath for the following AppLocker event IDs:
		// 8028 - Audit
		// 8029 - Block
		// 8038 - Correlated
		const string query = "*[System[(EventID=8028 or EventID=8029 or EventID=8038)]]";


		EventLogQuery eventQuery;


		if (EvtxFilePath is null)
		{
			// Initialize the EventLogQuery with the log path and query
			eventQuery = new(AppLockerLogPath, PathType.LogName, query);
		}
		else
		{
			// Initialize the EventLogQuery with the input EVTX log path and query
			eventQuery = new(EvtxFilePath, PathType.FilePath, query);
		}


		// Use EventLogReader to read the events
		List<EventRecord> rawEvents = [];

		try
		{

			// Read the events from the system based on the query
			using (EventLogReader logReader = new(eventQuery))
			{
				EventRecord eventRecord;

				// Read each event that matches the query
				while ((eventRecord = logReader.ReadEvent()) is not null)
				{
					// Add the event to the list
					rawEvents.Add(eventRecord);
				}
			}

			// Make sure there are events to process
			if (rawEvents.Count == 0)
			{
				Logger.Write(GlobalVars.GetStr("NoAppLockerEventsFoundMessage"));
				return fileIdentities.FileIdentitiesInternal;
			}

			// Group all events based on their ActivityId property
			IEnumerable<IGrouping<Guid?, EventRecord>> groupedEvents = rawEvents.GroupBy(e => e.ActivityId);

			// Iterate over each group of events
			foreach (IGrouping<Guid?, EventRecord> group in groupedEvents)
			{
				// Access the ActivityId for the group (key)
				Guid? activityId = group.Key;

				if (activityId is null)
				{
					continue;
				}

				// There are either blocked or audit events in each group
				// If there are more than 1 of either block or audit events, selecting the first one because that means the same event was triggered by multiple deployed policies

				// Get the possible audit event in the group
				EventRecord? possibleAuditEvent = group.FirstOrDefault(g => g.Id == 8028);
				// Get the possible blocked event
				EventRecord? possibleBlockEvent = group.FirstOrDefault(g => g.Id == 8029);
				// Get the possible correlated data
				IEnumerable<EventRecord> correlatedEvents = group.Where(g => g.Id == 8038);


				// If the current group belongs to an Audit event
				if (possibleAuditEvent is not null)
				{
					// Use the ToXml method of the EventRecord to convert the entire event to XML but as string
					string xmlString = possibleAuditEvent.ToXml();

					// Create an XmlDocument and load the XML string, convert it to XML document
					XmlDocument xmlDocument = new();
					xmlDocument.LoadXml(xmlString);

					// Create a namespace manager for the XML document
					XmlNamespaceManager namespaceManager = new(xmlDocument.NameTable);
					namespaceManager.AddNamespace("evt", "http://schemas.microsoft.com/win/2004/08/events/event");


					#region Get File name - the file path doesn't need fixing like Code integrity ones
					string? FilePath = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='FilePath']");

					string? FileName = null;

					if (FilePath is not null)
					{

						// Sometimes the file name begins with System32 so we prepend the Windows directory to create a full resolvable path
						if (FilePath.StartsWith("System32", StringComparison.OrdinalIgnoreCase))
						{
							FilePath = FilePath.Replace("System32", FullSystem32Path, StringComparison.OrdinalIgnoreCase);
						}

						// Doesn't matter if the file exists or not
						FileName = Path.GetFileName(FilePath);
					}
					#endregion


					/*
						#region Resolve UserID
						string? UserIDString = null;

						if (possibleAuditEvent.UserId is not null)
						{
							try
							{
								// If the user account SID doesn't exist on the system it'll throw error
								UserIDString = possibleAuditEvent.UserId.Translate(typeof(NTAccount)).Value;
							}
							catch
							{
								UserIDString = possibleAuditEvent.UserId?.ToString();
							}
						}
						#endregion
						*/


					// Make sure the file has SHA256 Hash
					string? SHA256Hash = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='SHA256 Hash']");

					if (SHA256Hash is null)
					{
						continue;
					}


					// Extract values using XPath
					FileIdentity eventData = new()
					{
						// These don't require to be retrieved from XML, they are part of the <System> node/section
						Origin = FileIdentityOrigin.EventLog,
						Action = EventAction.Audit,
						EventID = possibleAuditEvent.Id,
						TimeCreated = possibleAuditEvent.TimeCreated,
						ComputerName = possibleAuditEvent.MachineName,
						UserID = possibleAuditEvent.UserId?.ToString(),

						// Need to be retrieved from the XML because they are part of the <EventData> node of the Event, otherwise their property names wouldn't be available
						FilePath = FilePath,
						FileName = FileName,
						SHA1Hash = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='Sha1Hash']"),
						SHA256Hash = SHA256Hash,
						USN = GetLongValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='USN']"),
						SISigningScenario = SiPolicyIntel.SSType.UserMode, // AppLocker doesn't apply to Kernel mode files, so all of these logs have User-Mode Signing Scenario
						OriginalFileName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='OriginalFilename']"),
						InternalName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='InternalName']"),
						FileDescription = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='FileDescription']"),
						ProductName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='ProductName']"),
						UserWriteable = GetBooleanValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='UserWriteable']")
					};

					// Safely set the FileVersion using helper method
					string? fileVersionString = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='FileVersion']");
					eventData.FileVersion = SetFileVersion(fileVersionString);

					// Iterate over each correlated event (if any) - files can have multiple signers
					foreach (EventRecord correlatedEvent in correlatedEvents)
					{
						// Use the ToXml method of the EventRecord to convert the entire event to XML but as string
						string xmlStringCore = correlatedEvent.ToXml();

						// Create an XmlDocument and load the XML string, convert it to XML document
						XmlDocument xmlDocumentCore = new();
						xmlDocumentCore.LoadXml(xmlStringCore);

						// Create a namespace manager for the XML document
						XmlNamespaceManager namespaceManagerCore = new(xmlDocumentCore.NameTable);
						namespaceManagerCore.AddNamespace("evt", "http://schemas.microsoft.com/win/2004/08/events/event");


						// Skip signers that don't have PublisherTBSHash (aka LeafCertificate TBS Hash)
						// They have "Unknown" as their IssuerName and PublisherName too
						// Leaf certificate is a must have for signed files
						string? PublisherTBSHash = GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='PublisherTBSHash']");

						string? PublisherName = GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='PublisherName']");

						if (PublisherTBSHash is null || PublisherName is null)
						{
							continue;
						}

						// Extract values using XPath
						FileSignerInfo signerInfo = new(
							totalSignatureCount: GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='TotalSignatureCount']"),
							signature: GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='Signature']"),
							publisherName: PublisherName,
							issuerName: GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='IssuerName']"),
							publisherTBSHash: PublisherTBSHash,
							issuerTBSHash: GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='IssuerTBSHash']")
						);

						// Add the CN of the current signer to the FilePublishers HashSet of the FileIdentity
						_ = eventData.FilePublishers.Add(PublisherName);

						// Add the current signer info/correlated event data to the main event package
						_ = eventData.FileSignerInfos.Add(signerInfo);

					}

					// Set the SignatureStatus based on the number of signers
					eventData.SignatureStatus = eventData.FileSignerInfos.Count > 0 ? SignatureStatus.IsSigned : SignatureStatus.IsUnsigned;


					// Add the entire event package to the output list
					_ = fileIdentities.Add(eventData);


					continue;
				}

				// If the current group belongs to a blocked event
				if (possibleBlockEvent is not null)
				{

					// Use the ToXml method of the EventRecord to convert the entire event to XML but as string
					string xmlString = possibleBlockEvent.ToXml();

					// Create an XmlDocument and load the XML string, convert it to XML document
					XmlDocument xmlDocument = new();
					xmlDocument.LoadXml(xmlString);

					// Create a namespace manager for the XML document
					XmlNamespaceManager namespaceManager = new(xmlDocument.NameTable);
					namespaceManager.AddNamespace("evt", "http://schemas.microsoft.com/win/2004/08/events/event");


					#region Get File name - the file path doesn't need fixing like Code integrity ones
					string? FilePath = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='FilePath']");

					string? FileName = null;

					if (FilePath is not null)
					{

						// Sometimes the file name begins with System32 so we prepend the Windows directory to create a full resolvable path
						if (FilePath.StartsWith("System32", StringComparison.OrdinalIgnoreCase))
						{
							FilePath = FilePath.Replace("System32", FullSystem32Path, StringComparison.OrdinalIgnoreCase);
						}

						// Doesn't matter if the file exists or not
						FileName = Path.GetFileName(FilePath);
					}
					#endregion


					/*
						#region Resolve UserID
						string? UserIDString = null;

						if (possibleBlockEvent.UserId is not null)
						{
							try
							{
								// If the user account SID doesn't exist on the system it'll throw error
								UserIDString = possibleBlockEvent.UserId.Translate(typeof(NTAccount)).Value;
							}
							catch
							{
								UserIDString = possibleBlockEvent.UserId?.ToString();
							}
						}
						#endregion
						*/


					// Make sure the file has SHA256 Hash
					string? SHA256Hash = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='SHA256 Hash']");

					if (SHA256Hash is null)
					{
						continue;
					}


					// Extract values using XPath
					FileIdentity eventData = new()
					{
						// These don't require to be retrieved from XML, they are part of the <System> node/section
						Origin = FileIdentityOrigin.EventLog,
						Action = EventAction.Block,
						EventID = possibleBlockEvent.Id,
						TimeCreated = possibleBlockEvent.TimeCreated,
						ComputerName = possibleBlockEvent.MachineName,
						UserID = possibleBlockEvent.UserId?.ToString(),

						// Need to be retrieved from the XML because they are part of the <EventData> node of the Event, otherwise their property names wouldn't be available
						FilePath = FilePath,
						FileName = FileName,
						SHA1Hash = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='Sha1Hash']"),
						SHA256Hash = SHA256Hash,
						USN = GetLongValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='USN']"),
						SISigningScenario = SiPolicyIntel.SSType.UserMode, // AppLocker doesn't apply to Kernel mode files, so all of these logs have User-Mode Signing Scenario
						OriginalFileName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='OriginalFilename']"),
						InternalName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='InternalName']"),
						FileDescription = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='FileDescription']"),
						ProductName = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='ProductName']"),
						UserWriteable = GetBooleanValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='UserWriteable']")
					};

					// Safely set the FileVersion using helper method
					string? fileVersionString = GetStringValue(xmlDocument, namespaceManager, "//evt:EventData/evt:Data[@Name='FileVersion']");
					eventData.FileVersion = SetFileVersion(fileVersionString);

					// Iterate over each correlated event (if any) - files can have multiple signers
					foreach (EventRecord correlatedEvent in correlatedEvents)
					{
						// Use the ToXml method of the EventRecord to convert the entire event to XML but as string
						string xmlStringCore = correlatedEvent.ToXml();

						// Create an XmlDocument and load the XML string, convert it to XML document
						XmlDocument xmlDocumentCore = new();
						xmlDocumentCore.LoadXml(xmlStringCore);

						// Create a namespace manager for the XML document
						XmlNamespaceManager namespaceManagerCore = new(xmlDocumentCore.NameTable);
						namespaceManagerCore.AddNamespace("evt", "http://schemas.microsoft.com/win/2004/08/events/event");


						// Skip signers that don't have PublisherTBSHash (aka LeafCertificate TBS Hash)
						// They have "Unknown" as their IssuerName and PublisherName too
						// Leaf certificate is a must have for signed files
						string? PublisherTBSHash = GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='PublisherTBSHash']");

						string? PublisherName = GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='PublisherName']");

						if (PublisherTBSHash is null || PublisherName is null)
						{
							continue;
						}

						// Extract values using XPath
						FileSignerInfo signerInfo = new(
							totalSignatureCount: GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='TotalSignatureCount']"),
							signature: GetIntValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='Signature']"),
							publisherName: PublisherName,
							issuerName: GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='IssuerName']"),
							publisherTBSHash: PublisherTBSHash,
							issuerTBSHash: GetStringValue(xmlDocumentCore, namespaceManagerCore, "//evt:EventData/evt:Data[@Name='IssuerTBSHash']")
						);


						// Add the CN of the current signer to the FilePublishers HashSet of the FileIdentity
						_ = eventData.FilePublishers.Add(PublisherName);


						// Add the current signer info/correlated event data to the main event package
						_ = eventData.FileSignerInfos.Add(signerInfo);

					}

					// Set the SignatureStatus based on the number of signers
					eventData.SignatureStatus = eventData.FileSignerInfos.Count > 0 ? SignatureStatus.IsSigned : SignatureStatus.IsUnsigned;

					// Add the populated EventData instance to the list
					_ = fileIdentities.Add(eventData);


					continue;
				}
			}

			Logger.Write(string.Format(
				GlobalVars.GetStr("TotalAppLockerLogsMessage"),
				fileIdentities.Count));

			// Return the output
			return fileIdentities.FileIdentitiesInternal;
		}
		finally
		{
			foreach (EventRecord item in rawEvents)
			{
				item.Dispose();
			}
		}
	}


	#region Helper methods to extract values

	/// <summary>
	/// Method to safely set FileVersion from a nullable string
	/// </summary>
	/// <param name="versionString"></param>
	/// <returns></returns>
	private static Version? SetFileVersion(string? versionString)
	{
		if (!string.IsNullOrWhiteSpace(versionString) && Version.TryParse(versionString, out Version? version))
		{
			return version;
		}
		return null;
	}

	/// <summary>
	/// Method to safely get an integer value from the XML document
	/// </summary>
	/// <param name="xmlDoc"></param>
	/// <param name="nsManager"></param>
	/// <param name="xpath"></param>
	/// <returns></returns>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int? GetIntValue(XmlDocument xmlDoc, XmlNamespaceManager nsManager, string xpath)
	{
		XmlNode? node = xmlDoc.SelectSingleNode(xpath, nsManager);
		return node is not null && int.TryParse(node.InnerText, NumberStyles.Integer, CultureInfo.InvariantCulture, out int result) ? result : null;
	}


	/// <summary>
	/// Only works for the "EventData" node of the Event
	/// </summary>
	private static DateTime? GetEventDataDateTimeValue(XmlDocument xmlDoc, XmlNamespaceManager nsManager, string xpath)
	{
		XmlNode? node = xmlDoc.SelectSingleNode(xpath, nsManager);
		return node is not null && DateTime.TryParse(node.InnerText, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTime result) ? result : null;
	}


	/// <summary>
	/// Returns null if the string is null, empty or whitespaces
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static string? GetStringValue(XmlDocument xmlDoc, XmlNamespaceManager nsManager, string xpath)
	{
		XmlNode? node = xmlDoc.SelectSingleNode(xpath, nsManager);
		return string.IsNullOrWhiteSpace(node?.InnerText) ? null : node?.InnerText;
	}

	/// <summary>
	/// Retrieves a long integer value from an XML document based on a specified XPath expression.
	/// </summary>
	/// <param name="xmlDoc">The XML document from which the value is extracted.</param>
	/// <param name="nsManager">Manages the namespaces used in the XPath query.</param>
	/// <param name="xpath">The XPath expression used to locate the desired node in the XML document.</param>
	/// <returns>Returns the long integer value if found and valid, otherwise returns null.</returns>
	private static long? GetLongValue(XmlDocument xmlDoc, XmlNamespaceManager nsManager, string xpath)
	{
		XmlNode? node = xmlDoc.SelectSingleNode(xpath, nsManager);
		return node is not null && long.TryParse(node.InnerText, NumberStyles.Integer, CultureInfo.InvariantCulture, out long result) ? result : null;
	}

	/// <summary>
	/// Retrieves a GUID value from an XML document based on a specified XPath expression.
	/// </summary>
	/// <param name="xmlDoc">The XML document from which the GUID value is extracted.</param>
	/// <param name="nsManager">Manages the namespaces used in the XPath query.</param>
	/// <param name="xpath">The XPath expression used to locate the desired node in the XML document.</param>
	/// <returns>Returns the extracted GUID if found and valid, otherwise returns null.</returns>
	private static Guid? GetGuidValue(XmlDocument xmlDoc, XmlNamespaceManager nsManager, string xpath)
	{
		XmlNode? node = xmlDoc.SelectSingleNode(xpath, nsManager);
		return node is not null && Guid.TryParse(node.InnerText, out Guid guid) ? guid : null;
	}

	/// <summary>
	/// Retrieves a boolean value from an XML document based on a specified XPath expression.
	/// </summary>
	/// <param name="xmlDoc">The XML document from which the boolean value is extracted.</param>
	/// <param name="nsManager">Manages the namespaces used in the XPath expression for accurate node selection.</param>
	/// <param name="xpath">The XPath expression used to locate the desired node within the XML document.</param>
	/// <returns>Returns the boolean value found at the specified node or null if not found or not a valid boolean.</returns>
	private static bool? GetBooleanValue(XmlDocument xmlDoc, XmlNamespaceManager nsManager, string xpath)
	{
		XmlNode? node = xmlDoc.SelectSingleNode(xpath, nsManager);
		return node is not null && bool.TryParse(node.InnerText, out bool result) ? result : null;
	}

	/// <summary>
	/// Replaces global root NT paths to the normal paths
	/// </summary>
	/// <param name="path"></param>
	/// <returns></returns>
	private static string ResolvePath(string path)
	{
		// Find the matching DriveMapping for the device path prefix
		foreach (DriveLetterMapper.DriveMapping mapping in DriveLettersGlobalRootFix)
		{
			if (mapping.DevicePath is not null && path.StartsWith(mapping.DevicePath, StringComparison.OrdinalIgnoreCase))
			{
				// Replace the device path with the corresponding drive letter
				return path.Replace(mapping.DevicePath, mapping.DriveLetter, StringComparison.OrdinalIgnoreCase);
			}
		}

		// If no mapping was found, return the original path
		return path;
	}

	#endregion


	#region Async processing

	/// <summary>
	/// Gets Code Integrity and AppLocker event logs Asynchronously
	/// </summary>
	/// <returns></returns>
	internal static async Task<HashSet<FileIdentity>> GetAppControlEvents(string? CodeIntegrityEvtxFilePath = null, string? AppLockerEvtxFilePath = null, int EventsToCapture = 0)
	{
		// Output
		HashSet<FileIdentity> combinedResult = [];


		if (EventsToCapture == 0)
		{

			// Start both tasks in parallel
			Task<HashSet<FileIdentity>> codeIntegrityTask = Task.Run(() => CodeIntegrityEventsRetriever(CodeIntegrityEvtxFilePath));
			Task<HashSet<FileIdentity>> appLockerTask = Task.Run(() => AppLockerEventsRetriever(AppLockerEvtxFilePath));

			// Await both tasks to complete
			HashSet<FileIdentity>[] results = await Task.WhenAll(codeIntegrityTask, appLockerTask);

			// Assign the Code Integrity task's HashSet output since it's the main category and will have the majority of the events
			combinedResult = results[0];

			// If there are AppLocker logs
			if (results[1].Count > 0)
			{

				// Add elements from the AppLocker task's result, using Add to preserve uniqueness since the HashSet has its custom comparer
				foreach (FileIdentity item in results[1])
				{
					_ = combinedResult.Add(item);
				}
			}

		}

		else if (EventsToCapture == 1)
		{
			// Only starts the Code integrity events capture task
			combinedResult = await Task.Run(() => CodeIntegrityEventsRetriever(CodeIntegrityEvtxFilePath));
		}

		else if (EventsToCapture == 2)
		{
			// Only starts the AppLocker events capture task
			combinedResult = await Task.Run(() => AppLockerEventsRetriever(AppLockerEvtxFilePath));
		}


		Logger.Write(string.Format(
			GlobalVars.GetStr("TotalLogsCountMessage"),
			combinedResult.Count));

		// Return the combined set
		return combinedResult;
	}


	#endregion


}
