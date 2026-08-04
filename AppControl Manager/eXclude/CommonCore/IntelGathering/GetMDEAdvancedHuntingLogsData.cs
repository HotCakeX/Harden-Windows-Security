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
using System.Globalization;
using System.Linq;
using System.Runtime.InteropServices;

namespace CommonCore.IntelGathering;

internal static class GetMDEAdvancedHuntingLogsData
{

	/// <summary>
	/// Finds the correlated events in the CSV data and groups them together based on the EtwActivityId.
	/// Ensures that each Audit or Blocked event has its correlated Signing information events grouped together.
	/// CodeIntegrity and AppLocker logs are considered separately in each group of EtwActivityId.
	/// </summary>
	internal static HashSet<FileIdentity> Retrieve(List<MDEAdvancedHuntingData> data)
	{

		// HashSet to store the output, ensures the data are unique and signed data are prioritized over unsigned data
		FileIdentitySignatureBasedHashSet fileIdentities = new();

		// Group the events based on the EtwActivityId, which is the unique identifier for each group of correlated events
		IEnumerable<IGrouping<string?, MDEAdvancedHuntingData>> groupedEvents = data.GroupBy(e => e.EtwActivityId);

		// Iterate over each group of logs
		foreach (IGrouping<string?, MDEAdvancedHuntingData> group in groupedEvents)
		{

			// There are either blocked or audit type events in each group and they can be CodeIntegrity and AppLocker type at the same time
			// If there are more than 1 of either block or audit events, selecting the first one because that means the same event was triggered by multiple deployed policies

			// Get the possible CodeIntegrity audit event in the group
			MDEAdvancedHuntingData? possibleCodeIntegrityAuditEvent = group.FirstOrDefault(g => string.Equals(g.ActionType, "AppControlCodeIntegrityPolicyAudited", StringComparison.OrdinalIgnoreCase));
			// Get the possible CodeIntegrity blocked event in the group
			MDEAdvancedHuntingData? possibleCodeIntegrityBlockEvent = group.FirstOrDefault(g => string.Equals(g.ActionType, "AppControlCodeIntegrityPolicyBlocked", StringComparison.OrdinalIgnoreCase));

			// Get the possible AppLocker audit event in the group
			MDEAdvancedHuntingData? possibleAppLockerAuditEvent = group.FirstOrDefault(g => string.Equals(g.ActionType, "AppControlCIScriptAudited", StringComparison.OrdinalIgnoreCase));
			// Get the possible AppLocker blocked event in the group
			MDEAdvancedHuntingData? possibleAppLockerBlockEvent = group.FirstOrDefault(g => string.Equals(g.ActionType, "AppControlCIScriptBlocked", StringComparison.OrdinalIgnoreCase));

			// Get the possible correlated data
			List<MDEAdvancedHuntingData> correlatedEvents = group.Where(g => string.Equals(g.ActionType, "AppControlCodeIntegritySigningInformation", StringComparison.OrdinalIgnoreCase)).ToList();

			// If the current group has Code Integrity Audit log
			if (possibleCodeIntegrityAuditEvent is not null)
			{
				if (!ProcessEvent(possibleCodeIntegrityAuditEvent, EventAction.Audit, correlatedEvents, fileIdentities))
					continue;
			}

			// If the current group has Code Integrity Blocked log
			else if (possibleCodeIntegrityBlockEvent is not null)
			{
				if (!ProcessEvent(possibleCodeIntegrityBlockEvent, EventAction.Block, correlatedEvents, fileIdentities))
					continue;
			}

			// If the current group has AppLocker Audit log
			if (possibleAppLockerAuditEvent is not null)
			{
				if (!ProcessEvent(possibleAppLockerAuditEvent, EventAction.Audit, correlatedEvents, fileIdentities))
					continue;
			}

			// If the current group has AppLocker Blocked log
			else if (possibleAppLockerBlockEvent is not null)
			{
				if (!ProcessEvent(possibleAppLockerBlockEvent, EventAction.Block, correlatedEvents, fileIdentities))
					continue;
			}
		}

		// Return the internal data which is the right return type
		return fileIdentities.FileIdentitiesInternal;
	}

	/// <summary>
	/// Creates a FileIdentity out of an Audit/Block event of a group, attaches the signer information from the
	/// correlated events of the same group to it and adds the complete event package to the output collection.
	/// The exact same logic is shared by the CodeIntegrity and AppLocker Audit/Block events.
	/// </summary>
	/// <param name="mainEvent">The Audit or Blocked event of the current group.</param>
	/// <param name="action">The action type of the main event, Audit or Block.</param>
	/// <param name="correlatedEvents">The correlated Signing Information events of the current group.</param>
	/// <param name="fileIdentities">The output collection that the complete event package is added to.</param>
	/// <returns>False if the main event lacks the required SHA256 hash, in which case the caller must skip the rest of the current group, true otherwise.</returns>
	private static bool ProcessEvent(MDEAdvancedHuntingData mainEvent, EventAction action, List<MDEAdvancedHuntingData> correlatedEvents, FileIdentitySignatureBasedHashSet fileIdentities)
	{

		// The SHA256 must be available in Audit/Block type of events for either Code Integrity or AppLocker
		// It doesn't need to exist in the correlated SigningInformation event for MDE Advanced Hunting
		if (mainEvent.SHA256 is null)
			return false;

		// Assign fields from MDE Advanced Hunting record properties
		FileIdentity eventData = new()
		{
			Origin = FileIdentityOrigin.MDEAdvancedHunting,
			Action = action,
			TimeCreated = GetEventDataDateTimeValue(mainEvent.Timestamp),
			ComputerName = mainEvent.DeviceName,
			UserID = mainEvent.InitiatingProcessAccountName,

			FilePath = mainEvent.FolderPath,
			FileName = mainEvent.FileName,
			ProcessName = mainEvent.ProcessName,
			RequestedSigningLevel = CILogIntel.GetValidatedRequestedSigningLevel(GetIntValue(mainEvent.RequestedSigningLevel)),
			ValidatedSigningLevel = CILogIntel.GetValidatedRequestedSigningLevel(GetIntValue(mainEvent.ValidatedSigningLevel)),
			Status = mainEvent.StatusCode,
			SHA1Hash = mainEvent.SHA1,
			SHA256Hash = mainEvent.SHA256,
			SHA1FlatHash = mainEvent.Sha1FlatHash,
			SHA256FlatHash = mainEvent.Sha256FlatHash,
			USN = mainEvent.USN,
			SISigningScenario = (SSType)(mainEvent.SiSigningScenario ?? 1),
			PolicyName = mainEvent.PolicyName,
			PolicyID = mainEvent.PolicyID,
			PolicyHash = mainEvent.PolicyHash,
			OriginalFileName = mainEvent.OriginalFileName,
			InternalName = mainEvent.InternalName,
			FileDescription = mainEvent.FileDescription,
			PolicyGUID = mainEvent.PolicyGuid,
			UserWriteable = mainEvent.UserWriteable,
			FileVersion = SetFileVersion(mainEvent.FileVersion)
		};

		// If there are correlated events - for signer information of the file
		// Iterate over each correlated event - files can have multiple signers
		foreach (MDEAdvancedHuntingData correlatedEvent in CollectionsMarshal.AsSpan(correlatedEvents))
		{

			// Skip signers that don't have PublisherTBSHash (aka LeafCertificate TBS Hash) or PublisherName
			// They have "Unknown" as their IssuerName and PublisherName too
			// Leaf certificate is a must have for signed files
			if (correlatedEvent.PublisherTBSHash is null || correlatedEvent.PublisherName is null)
				continue;

			// Assign fields from MDE Advanced Hunting record properties
			FileSignerInfo signerInfo = new(
				totalSignatureCount: correlatedEvent.TotalSignatureCount,
				signature: correlatedEvent.Signature,
				hash: correlatedEvent.Hash,
				signatureType: CILogIntel.GetSignatureType(GetIntValue(correlatedEvent.SignatureType)),
				validatedSigningLevel: CILogIntel.GetValidatedRequestedSigningLevel(GetIntValue(correlatedEvent.ValidatedSigningLevel)),
				verificationError: CILogIntel.GetVerificationError(GetIntValue(correlatedEvent.VerificationError)),
				flags: correlatedEvent.Flags,
				notValidBefore: GetEventDataDateTimeValue(correlatedEvent.NotValidBefore),
				notValidAfter: GetEventDataDateTimeValue(correlatedEvent.NotValidAfter),
				publisherName: correlatedEvent.PublisherName,
				issuerName: correlatedEvent.IssuerName,
				publisherTBSHash: correlatedEvent.PublisherTBSHash,
				issuerTBSHash: correlatedEvent.IssuerTBSHash
			);

			// Add the CN of the current signer to the FilePublishers HashSet of the FileIdentity
			_ = eventData.FilePublishers.Add(correlatedEvent.PublisherName);

			// Add the current signer info/correlated event data to the main event package
			_ = eventData.FileSignerInfos.Add(signerInfo);
		}

		// Set the SignatureStatus based on the number of signers
		eventData.SignatureStatus = eventData.FileSignerInfos.Count > 0 ? SignatureStatus.IsSigned : SignatureStatus.IsUnsigned;

		// Add the entire event package to the output list
		_ = fileIdentities.Add(eventData);

		return true;
	}

	#region Helper methods to extract values

	/// <summary>
	/// Method to safely set FileVersion from a nullable string
	/// </summary>
	private static Version? SetFileVersion(string? versionString)
	{
		_ = Version.TryParse(versionString, out Version? version);
		return version;
	}

	/// <summary>
	/// Method to safely get an integer value from string
	/// </summary>
	private static int? GetIntValue(string? data) =>
		 int.TryParse(data, NumberStyles.Integer, CultureInfo.InvariantCulture, out int result) ? result : null;

	/// <summary>
	/// Safely converts string to DateTime
	/// </summary>
	private static DateTime? GetEventDataDateTimeValue(string? data) =>
		 DateTime.TryParse(data, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTime result) ? result : null;

	#endregion
}
