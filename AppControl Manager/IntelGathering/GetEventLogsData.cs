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
using System.Net;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading.Tasks;

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
				// There are either blocked or audit events in each group
				// If there are more than 1 of either block or audit events, selecting the first one because that means the same event was triggered by multiple deployed policies

				EventRecord? possibleAuditEvent = null;
				EventRecord? possibleBlockEvent = null;
				List<EventRecord> correlatedEvents = [];

				foreach (EventRecord rec in group)
				{
					// Get the possible audit event in the group
					if (rec.Id == 3076)
					{
						possibleAuditEvent ??= rec;
					}
					// Get the possible blocked event
					else if (rec.Id == 3077)
					{
						possibleBlockEvent ??= rec;
					}
					// Get the possible correlated data
					else if (rec.Id == 3089)
					{
						correlatedEvents.Add(rec);
					}
				}


				// If the current group belongs to an Audit event
				if (possibleAuditEvent is not null)
				{
					// Get the XML string directly
					string xmlString = possibleAuditEvent.ToXml();
					ReadOnlySpan<char> xmlSpan = xmlString.AsSpan();

					#region Get File name and fix file path
					string? FilePath = GetStringValue(xmlSpan, "File Name");

					string? FileName = null;

					if (FilePath is not null)
					{
						// Sometimes the file name begins with System32 so we prepend the Windows directory to create a full resolvable path
						if (FilePath.AsSpan().StartsWith("System32", StringComparison.OrdinalIgnoreCase))
						{
							// Concat the FullSystem32Path with the rest of the string
							FilePath = string.Concat(FullSystem32Path, FilePath.AsSpan(8));
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
					string? SHA256Hash = GetStringValue(xmlSpan, "SHA256 Hash");

					if (SHA256Hash is null)
						continue;

					// Extract values using Span-based methods
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
						ProcessName = GetStringValue(xmlSpan, "Process Name"),
						RequestedSigningLevel = CILogIntel.GetValidatedRequestedSigningLevel(GetIntValue(xmlSpan, "Requested Signing Level")),
						ValidatedSigningLevel = CILogIntel.GetValidatedRequestedSigningLevel(GetIntValue(xmlSpan, "Validated Signing Level")),
						Status = GetStringValue(xmlSpan, "Status"),
						SHA1Hash = GetStringValue(xmlSpan, "SHA1 Hash"),
						SHA256Hash = SHA256Hash,
						SHA1FlatHash = GetStringValue(xmlSpan, "SHA1 Flat Hash"),
						SHA256FlatHash = GetStringValue(xmlSpan, "SHA256 Flat Hash"),
						USN = GetLongValue(xmlSpan, "USN"),
						SISigningScenario = (SiPolicyIntel.SSType)(GetIntValue(xmlSpan, "SI Signing Scenario") ?? 1),
						PolicyName = GetStringValue(xmlSpan, "PolicyName"),
						PolicyID = GetStringValue(xmlSpan, "PolicyID"),
						PolicyHash = GetStringValue(xmlSpan, "PolicyHash"),
						OriginalFileName = GetStringValue(xmlSpan, "OriginalFileName"),
						InternalName = GetStringValue(xmlSpan, "InternalName"),
						FileDescription = GetStringValue(xmlSpan, "FileDescription"),
						ProductName = GetStringValue(xmlSpan, "ProductName"),
						PolicyGUID = GetStringValue(xmlSpan, "PolicyGUID"),
						UserWriteable = GetBooleanValue(xmlSpan, "UserWriteable"),
						PackageFamilyName = GetStringValue(xmlSpan, "PackageFamilyName")
					};

					// Safely set the FileVersion using helper method
					string? fileVersionString = GetStringValue(xmlSpan, "FileVersion");
					eventData.FileVersion = SetFileVersion(fileVersionString);

					// Iterate over each correlated event (if any) - files can have multiple signers
					foreach (EventRecord correlatedEvent in CollectionsMarshal.AsSpan(correlatedEvents))
					{
						// Get the XML string directly
						string xmlStringCore = correlatedEvent.ToXml();
						ReadOnlySpan<char> xmlSpanCore = xmlStringCore.AsSpan();

						// Skip signers that don't have PublisherTBSHash (aka LeafCertificate TBS Hash) or PublisherName
						// They have "Unknown" as their IssuerName and PublisherName too
						// Leaf certificate is a must have for signed files
						string? PublisherTBSHash = GetStringValue(xmlSpanCore, "PublisherTBSHash");

						string? PublisherName = GetStringValue(xmlSpanCore, "PublisherName");

						if (PublisherTBSHash is null || PublisherName is null)
							continue;

						// Extract values using Span-based methods
						FileSignerInfo signerInfo = new(
							totalSignatureCount: GetIntValue(xmlSpanCore, "TotalSignatureCount"),
							signature: GetIntValue(xmlSpanCore, "Signature"),
							hash: GetStringValue(xmlSpanCore, "Hash"),
							pageHash: GetBooleanValue(xmlSpanCore, "PageHash"),
							signatureType: CILogIntel.GetSignatureType(GetIntValue(xmlSpanCore, "SignatureType")),
							validatedSigningLevel: CILogIntel.GetValidatedRequestedSigningLevel(GetIntValue(xmlSpanCore, "ValidatedSigningLevel")),
							verificationError: CILogIntel.GetVerificationError(GetIntValue(xmlSpanCore, "VerificationError")),
							flags: GetIntValue(xmlSpanCore, "Flags"),
							notValidBefore: GetEventDataDateTimeValue(xmlSpanCore, "NotValidBefore"),
							notValidAfter: GetEventDataDateTimeValue(xmlSpanCore, "NotValidAfter"),
							publisherName: PublisherName,
							issuerName: GetStringValue(xmlSpanCore, "IssuerName"),
							publisherTBSHash: PublisherTBSHash,
							issuerTBSHash: GetStringValue(xmlSpanCore, "IssuerTBSHash"),
							oPUSInfo: GetStringValue(xmlSpanCore, "OPUSInfo"),
							eKUs: GetStringValue(xmlSpanCore, "EKUs"),
							knownRoot: GetIntValue(xmlSpanCore, "KnownRoot")
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
					// Get the XML string directly
					string xmlString = possibleBlockEvent.ToXml();
					ReadOnlySpan<char> xmlSpan = xmlString.AsSpan();

					#region Get File name and fix file path
					string? FilePath = GetStringValue(xmlSpan, "File Name");

					string? FileName = null;

					if (FilePath is not null)
					{

						// Sometimes the file name begins with System32 so we prepend the Windows directory to create a full resolvable path
						if (FilePath.AsSpan().StartsWith("System32", StringComparison.OrdinalIgnoreCase))
						{
							FilePath = string.Concat(FullSystem32Path, FilePath.AsSpan(8));
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

					// Make sure the file has SHA256 Hash
					string? SHA256Hash = GetStringValue(xmlSpan, "SHA256 Hash");

					if (SHA256Hash is null)
						continue;

					// Extract values using Span-based methods
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
						ProcessName = GetStringValue(xmlSpan, "Process Name"),
						RequestedSigningLevel = CILogIntel.GetValidatedRequestedSigningLevel(GetIntValue(xmlSpan, "Requested Signing Level")),
						ValidatedSigningLevel = CILogIntel.GetValidatedRequestedSigningLevel(GetIntValue(xmlSpan, "Validated Signing Level")),
						Status = GetStringValue(xmlSpan, "Status"),
						SHA1Hash = GetStringValue(xmlSpan, "SHA1 Hash"),
						SHA256Hash = SHA256Hash,
						SHA1FlatHash = GetStringValue(xmlSpan, "SHA1 Flat Hash"),
						SHA256FlatHash = GetStringValue(xmlSpan, "SHA256 Flat Hash"),
						USN = GetLongValue(xmlSpan, "USN"),
						SISigningScenario = (SiPolicyIntel.SSType)(GetIntValue(xmlSpan, "SI Signing Scenario") ?? 1),
						PolicyName = GetStringValue(xmlSpan, "PolicyName"),
						PolicyID = GetStringValue(xmlSpan, "PolicyID"),
						PolicyHash = GetStringValue(xmlSpan, "PolicyHash"),
						OriginalFileName = GetStringValue(xmlSpan, "OriginalFileName"),
						InternalName = GetStringValue(xmlSpan, "InternalName"),
						FileDescription = GetStringValue(xmlSpan, "FileDescription"),
						ProductName = GetStringValue(xmlSpan, "ProductName"),
						PolicyGUID = GetStringValue(xmlSpan, "PolicyGUID"),
						UserWriteable = GetBooleanValue(xmlSpan, "UserWriteable"),
						PackageFamilyName = GetStringValue(xmlSpan, "PackageFamilyName")
					};

					// Safely set the FileVersion using helper method
					string? fileVersionString = GetStringValue(xmlSpan, "FileVersion");
					eventData.FileVersion = SetFileVersion(fileVersionString);

					// Iterate over each correlated event (if any) - files can have multiple signers
					foreach (EventRecord correlatedEvent in CollectionsMarshal.AsSpan(correlatedEvents))
					{
						// Get the XML string directly
						string xmlStringCore = correlatedEvent.ToXml();
						ReadOnlySpan<char> xmlSpanCore = xmlStringCore.AsSpan();

						// Skip signers that don't have PublisherTBSHash (aka LeafCertificate TBS Hash)
						// They have "Unknown" as their IssuerName and PublisherName too
						// Leaf certificate is a must have for signed files
						string? PublisherTBSHash = GetStringValue(xmlSpanCore, "PublisherTBSHash");

						string? PublisherName = GetStringValue(xmlSpanCore, "PublisherName");

						if (PublisherTBSHash is null || PublisherName is null)
							continue;

						// Extract values using Span-based methods
						FileSignerInfo signerInfo = new(
							totalSignatureCount: GetIntValue(xmlSpanCore, "TotalSignatureCount"),
							signature: GetIntValue(xmlSpanCore, "Signature"),
							hash: GetStringValue(xmlSpanCore, "Hash"),
							pageHash: GetBooleanValue(xmlSpanCore, "PageHash"),
							signatureType: CILogIntel.GetSignatureType(GetIntValue(xmlSpanCore, "SignatureType")),
							validatedSigningLevel: CILogIntel.GetValidatedRequestedSigningLevel(GetIntValue(xmlSpanCore, "ValidatedSigningLevel")),
							verificationError: CILogIntel.GetVerificationError(GetIntValue(xmlSpanCore, "VerificationError")),
							flags: GetIntValue(xmlSpanCore, "Flags"),
							notValidBefore: GetEventDataDateTimeValue(xmlSpanCore, "NotValidBefore"),
							notValidAfter: GetEventDataDateTimeValue(xmlSpanCore, "NotValidAfter"),
							publisherName: PublisherName,
							issuerName: GetStringValue(xmlSpanCore, "IssuerName"),
							publisherTBSHash: PublisherTBSHash,
							issuerTBSHash: GetStringValue(xmlSpanCore, "IssuerTBSHash"),
							oPUSInfo: GetStringValue(xmlSpanCore, "OPUSInfo"),
							eKUs: GetStringValue(xmlSpanCore, "EKUs"),
							knownRoot: GetIntValue(xmlSpanCore, "KnownRoot")
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
			foreach (EventRecord item in CollectionsMarshal.AsSpan(rawEvents))
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
				// There are either blocked or audit events in each group
				// If there are more than 1 of either block or audit events, selecting the first one because that means the same event was triggered by multiple deployed policies

				EventRecord? possibleAuditEvent = null;
				EventRecord? possibleBlockEvent = null;
				List<EventRecord> correlatedEvents = [];

				foreach (EventRecord rec in group)
				{
					// Get the possible audit event in the group
					if (rec.Id == 8028)
					{
						possibleAuditEvent ??= rec;
					}
					// Get the possible blocked event
					else if (rec.Id == 8029)
					{
						possibleBlockEvent ??= rec;
					}
					// Get the possible correlated data
					else if (rec.Id == 8038)
					{
						correlatedEvents.Add(rec);
					}
				}

				// If the current group belongs to an Audit event
				if (possibleAuditEvent is not null)
				{
					// Get the XML string directly
					string xmlString = possibleAuditEvent.ToXml();
					ReadOnlySpan<char> xmlSpan = xmlString.AsSpan();


					#region Get File name - the file path doesn't need fixing like Code integrity ones
					string? FilePath = GetStringValue(xmlSpan, "FilePath");

					string? FileName = null;

					if (FilePath is not null)
					{

						// Sometimes the file name begins with System32 so we prepend the Windows directory to create a full resolvable path
						if (FilePath.AsSpan().StartsWith("System32", StringComparison.OrdinalIgnoreCase))
						{
							FilePath = string.Concat(FullSystem32Path, FilePath.AsSpan(8));
						}

						// Doesn't matter if the file exists or not
						FileName = Path.GetFileName(FilePath);
					}
					#endregion

					// Make sure the file has Sha256Hash
					string? SHA256Hash = GetStringValue(xmlSpan, "Sha256Hash");

					if (SHA256Hash is null)
						continue;

					// Extract values using Span-based methods
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
						SHA1Hash = GetStringValue(xmlSpan, "Sha1Hash"),
						SHA256Hash = SHA256Hash,
						USN = GetLongValue(xmlSpan, "USN"),
						SISigningScenario = SiPolicyIntel.SSType.UserMode, // AppLocker doesn't apply to Kernel mode files, so all of these logs have User-Mode Signing Scenario
						OriginalFileName = GetStringValue(xmlSpan, "OriginalFilename"),
						InternalName = GetStringValue(xmlSpan, "InternalName"),
						FileDescription = GetStringValue(xmlSpan, "FileDescription"),
						ProductName = GetStringValue(xmlSpan, "ProductName"),
						UserWriteable = GetBooleanValue(xmlSpan, "UserWriteable")
					};

					// Safely set the FileVersion using helper method
					string? fileVersionString = GetStringValue(xmlSpan, "FileVersion");
					eventData.FileVersion = SetFileVersion(fileVersionString);

					// Iterate over each correlated event (if any) - files can have multiple signers
					foreach (EventRecord correlatedEvent in CollectionsMarshal.AsSpan(correlatedEvents))
					{
						// Get the XML string directly
						string xmlStringCore = correlatedEvent.ToXml();
						ReadOnlySpan<char> xmlSpanCore = xmlStringCore.AsSpan();

						// Skip signers that don't have PublisherTBSHash (aka LeafCertificate TBS Hash)
						// They have "Unknown" as their IssuerName and PublisherName too
						// Leaf certificate is a must have for signed files
						string? PublisherTBSHash = GetStringValue(xmlSpanCore, "PublisherTBSHash");

						string? PublisherName = GetStringValue(xmlSpanCore, "PublisherName");

						if (PublisherTBSHash is null || PublisherName is null)
						{
							continue;
						}

						// Extract values using Span-based methods
						FileSignerInfo signerInfo = new(
							totalSignatureCount: GetIntValue(xmlSpanCore, "TotalSignatureCount"),
							signature: GetIntValue(xmlSpanCore, "Signature"),
							publisherName: PublisherName,
							issuerName: GetStringValue(xmlSpanCore, "IssuerName"),
							publisherTBSHash: PublisherTBSHash,
							issuerTBSHash: GetStringValue(xmlSpanCore, "IssuerTBSHash")
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
					// Get the XML string directly
					string xmlString = possibleBlockEvent.ToXml();
					ReadOnlySpan<char> xmlSpan = xmlString.AsSpan();


					#region Get File name - the file path doesn't need fixing like Code integrity ones
					string? FilePath = GetStringValue(xmlSpan, "FilePath");

					string? FileName = null;

					if (FilePath is not null)
					{

						// Sometimes the file name begins with System32 so we prepend the Windows directory to create a full resolvable path
						if (FilePath.AsSpan().StartsWith("System32", StringComparison.OrdinalIgnoreCase))
						{
							FilePath = string.Concat(FullSystem32Path, FilePath.AsSpan(8));
						}

						// Doesn't matter if the file exists or not
						FileName = Path.GetFileName(FilePath);
					}
					#endregion

					// Make sure the file has Sha256Hash
					string? SHA256Hash = GetStringValue(xmlSpan, "Sha256Hash");

					if (SHA256Hash is null)
						continue;

					// Extract values using Span-based methods
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
						SHA1Hash = GetStringValue(xmlSpan, "Sha1Hash"),
						SHA256Hash = SHA256Hash,
						USN = GetLongValue(xmlSpan, "USN"),
						SISigningScenario = SiPolicyIntel.SSType.UserMode, // AppLocker doesn't apply to Kernel mode files, so all of these logs have User-Mode Signing Scenario
						OriginalFileName = GetStringValue(xmlSpan, "OriginalFilename"),
						InternalName = GetStringValue(xmlSpan, "InternalName"),
						FileDescription = GetStringValue(xmlSpan, "FileDescription"),
						ProductName = GetStringValue(xmlSpan, "ProductName"),
						UserWriteable = GetBooleanValue(xmlSpan, "UserWriteable")
					};

					// Safely set the FileVersion using helper method
					string? fileVersionString = GetStringValue(xmlSpan, "FileVersion");
					eventData.FileVersion = SetFileVersion(fileVersionString);

					// Iterate over each correlated event (if any) - files can have multiple signers
					foreach (EventRecord correlatedEvent in CollectionsMarshal.AsSpan(correlatedEvents))
					{
						// Get the XML string directly
						string xmlStringCore = correlatedEvent.ToXml();
						ReadOnlySpan<char> xmlSpanCore = xmlStringCore.AsSpan();

						// Skip signers that don't have PublisherTBSHash (aka LeafCertificate TBS Hash)
						// They have "Unknown" as their IssuerName and PublisherName too
						// Leaf certificate is a must have for signed files
						string? PublisherTBSHash = GetStringValue(xmlSpanCore, "PublisherTBSHash");

						string? PublisherName = GetStringValue(xmlSpanCore, "PublisherName");

						if (PublisherTBSHash is null || PublisherName is null)
							continue;

						// Extract values using Span-based methods
						FileSignerInfo signerInfo = new(
							totalSignatureCount: GetIntValue(xmlSpanCore, "TotalSignatureCount"),
							signature: GetIntValue(xmlSpanCore, "Signature"),
							publisherName: PublisherName,
							issuerName: GetStringValue(xmlSpanCore, "IssuerName"),
							publisherTBSHash: PublisherTBSHash,
							issuerTBSHash: GetStringValue(xmlSpanCore, "IssuerTBSHash")
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
			foreach (EventRecord item in CollectionsMarshal.AsSpan(rawEvents))
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
	/// Core helper to extract the content of a Data node by its Name attribute from raw XML span.
	/// Handles finding Name='AttributeName' or Name="AttributeName" and extracting the inner text.
	/// </summary>
	/// <param name="xml">The XML content as a ReadOnlySpan</param>
	/// <param name="attributeName">The value of the Name attribute to look for</param>
	/// <returns>The inner content of the node as a ReadOnlySpan, or an empty span if not found</returns>
	private static ReadOnlySpan<char> GetRawXmlValue(ReadOnlySpan<char> xml, string attributeName)
	{
		// Try single quote first
		// "Name='AttributeName'"
		int index = xml.IndexOf(string.Concat("Name='", attributeName, "'"), StringComparison.OrdinalIgnoreCase);

		if (index < 0)
		{
			// Try double quote
			// "Name="AttributeName""
			index = xml.IndexOf(string.Concat("Name=\"", attributeName, "\""), StringComparison.OrdinalIgnoreCase);
		}

		if (index < 0)
		{
			return default; // Not found
		}

		// index points to the start of "Name=...", we need to find the end of the opening tag '>'
		// We can search for '>' starting from the match index
		int closingTagIndex = xml[index..].IndexOf('>');

		if (closingTagIndex < 0)
		{
			return default; // Malformed XML or not found
		}

		// Calculate the absolute index of the '>' character
		int absoluteClosingTagIndex = index + closingTagIndex;

		// Check for self-closing tag "/>"
		// If the character before '>' is '/', it's an empty element
		if (absoluteClosingTagIndex > 0 && xml[absoluteClosingTagIndex - 1] == '/')
		{
			return default; // Empty value
		}

		// The value starts right after the '>'
		int valueStartIndex = absoluteClosingTagIndex + 1;

		// Find the start of the closing tag "</"
		int valueEndIndex = xml[valueStartIndex..].IndexOf("</", StringComparison.OrdinalIgnoreCase);

		if (valueEndIndex < 0)
		{
			return default; // Closing tag not found
		}

		// Return the slice containing the value
		return xml.Slice(valueStartIndex, valueEndIndex);
	}

	/// <summary>
	/// Safely get an integer value from the XML using Span.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int? GetIntValue(ReadOnlySpan<char> xml, string attributeName)
	{
		ReadOnlySpan<char> valueSpan = GetRawXmlValue(xml, attributeName);
		return !valueSpan.IsEmpty && int.TryParse(valueSpan, NumberStyles.Integer, CultureInfo.InvariantCulture, out int result) ? result : null;
	}

	/// <summary>
	/// Safely get a DateTime value from the XML using Span.
	/// </summary>
	private static DateTime? GetEventDataDateTimeValue(ReadOnlySpan<char> xml, string attributeName)
	{
		ReadOnlySpan<char> valueSpan = GetRawXmlValue(xml, attributeName);
		return !valueSpan.IsEmpty && DateTime.TryParse(valueSpan, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTime result) ? result : null;
	}

	/// <summary>
	/// Safely get a string value from the XML using Span.
	/// Performs XML decoding to ensure 100% compatibility with XmlDocument.
	/// </summary>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static string? GetStringValue(ReadOnlySpan<char> xml, string attributeName)
	{
		ReadOnlySpan<char> valueSpan = GetRawXmlValue(xml, attributeName);

		if (valueSpan.IsEmpty)
		{
			return null;
		}

		string value = valueSpan.ToString();

		// If the string is just whitespace, return null to match the original behavior of string.IsNullOrWhiteSpace check on InnerText.
		if (string.IsNullOrWhiteSpace(value))
		{
			return null;
		}

		// Decode XML entities (e.g., &amp; -> &) to ensure parity with XmlDocument
		return WebUtility.HtmlDecode(value);
	}

	/// <summary>
	/// Safely get a long value from the XML using Span.
	/// </summary>
	private static long? GetLongValue(ReadOnlySpan<char> xml, string attributeName)
	{
		ReadOnlySpan<char> valueSpan = GetRawXmlValue(xml, attributeName);
		return !valueSpan.IsEmpty && long.TryParse(valueSpan, NumberStyles.Integer, CultureInfo.InvariantCulture, out long result) ? result : null;
	}

	/// <summary>
	/// Safely get a boolean value from the XML using Span.
	/// </summary>
	private static bool? GetBooleanValue(ReadOnlySpan<char> xml, string attributeName)
	{
		ReadOnlySpan<char> valueSpan = GetRawXmlValue(xml, attributeName);
		return !valueSpan.IsEmpty && bool.TryParse(valueSpan, out bool result) ? result : null;
	}

	/// <summary>
	/// Replaces global root NT paths to the normal paths
	/// </summary>
	/// <param name="path"></param>
	/// <returns></returns>
	internal static string ResolvePath(string path)
	{
		// Find the matching DriveMapping for the device path prefix
		foreach (ref readonly DriveLetterMapper.DriveMapping mapping in CollectionsMarshal.AsSpan(DriveLettersGlobalRootFix))
		{
			if (mapping.DevicePath is not null && path.AsSpan().StartsWith(mapping.DevicePath, StringComparison.OrdinalIgnoreCase))
			{
				// Replace the device path with the corresponding drive letter by concatenation
				return string.Concat(mapping.DriveLetter, path.AsSpan(mapping.DevicePath.Length));
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
		using IDisposable taskTracker = TaskTracking.RegisterOperation();

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
