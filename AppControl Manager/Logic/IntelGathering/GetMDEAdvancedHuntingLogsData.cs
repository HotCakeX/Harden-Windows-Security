﻿using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;

namespace WDACConfig.IntelGathering
{
    internal static class GetMDEAdvancedHuntingLogsData
    {

        /// <summary>
        /// Finds the correlated events in the CSV data and groups them together based on the EtwActivityId.
        /// Ensures that each Audit or Blocked event has its correlated Signing information events grouped together.
        /// CodeIntegrity and AppLocker logs are considered separately in each group of EtwActivityId.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        internal static HashSet<FileIdentity> Retrieve(List<MDEAdvancedHuntingData> data)
        {


            // HashSet to store the output, ensures the data are unique and signed data are prioritized over unsigned data
            FileIdentitySignatureBasedHashSet fileIdentities = new();


            // Group the events based on the EtwActivityId, which is the unique identifier for each group of correlated events
            IEnumerable<IGrouping<string, MDEAdvancedHuntingData>> groupedEvents = data.GroupBy(e => e.EtwActivityId!);


            // Iterate over each group of logs
            foreach (IGrouping<string, MDEAdvancedHuntingData> group in groupedEvents)
            {
                // Access the EtwActivityId for the group (key)
                string? EtwActivityId = group.Key;

                if (EtwActivityId is null)
                {
                    continue;
                }

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


                // The SHA256 must be available in Audit/Block type of events for either Code Integrity or AppLocker
                // It doesn't need to exist in the correlated SigningInformation event for MDE Advanced Hunting


                // If the current group has Code Integrity Audit log
                if (possibleCodeIntegrityAuditEvent is not null)
                {

                    if (possibleCodeIntegrityAuditEvent.SHA256 is null)
                    {
                        continue;
                    }


                    // Extract values using XPath
                    FileIdentity eventData = new()
                    {

                        Origin = FileIdentityOrigin.MDEAdvancedHunting,
                        Action = EventAction.Audit,
                        TimeCreated = GetEventDataDateTimeValue(possibleCodeIntegrityAuditEvent.Timestamp),
                        ComputerName = possibleCodeIntegrityAuditEvent.DeviceName,
                        UserID = possibleCodeIntegrityAuditEvent.InitiatingProcessAccountName,

                        FilePath = possibleCodeIntegrityAuditEvent.FolderPath,
                        FileName = possibleCodeIntegrityAuditEvent.FileName,
                        ProcessName = possibleCodeIntegrityAuditEvent.ProcessName,
                        RequestedSigningLevel = GetValidatedRequestedSigningLevel(GetIntValue(possibleCodeIntegrityAuditEvent.RequestedSigningLevel)),
                        ValidatedSigningLevel = GetValidatedRequestedSigningLevel(GetIntValue(possibleCodeIntegrityAuditEvent.ValidatedSigningLevel)),
                        Status = possibleCodeIntegrityAuditEvent.StatusCode,
                        SHA1Hash = possibleCodeIntegrityAuditEvent.SHA1,
                        SHA256Hash = possibleCodeIntegrityAuditEvent.SHA256,
                        SHA1FlatHash = possibleCodeIntegrityAuditEvent.Sha1FlatHash,
                        SHA256FlatHash = possibleCodeIntegrityAuditEvent.Sha256FlatHash,
                        USN = GetLongValue(possibleCodeIntegrityAuditEvent.USN),
                        SISigningScenario = GetIntValue(possibleCodeIntegrityAuditEvent.SiSigningScenario) ?? 1,
                        PolicyName = possibleCodeIntegrityAuditEvent.PolicyName,
                        PolicyID = possibleCodeIntegrityAuditEvent.PolicyID,
                        PolicyHash = possibleCodeIntegrityAuditEvent.PolicyHash,
                        OriginalFileName = possibleCodeIntegrityAuditEvent.OriginalFileName,
                        InternalName = possibleCodeIntegrityAuditEvent.InternalName,
                        FileDescription = possibleCodeIntegrityAuditEvent.FileDescription,
                        PolicyGUID = GetGuidValue(possibleCodeIntegrityAuditEvent.PolicyGuid),
                        UserWriteable = possibleCodeIntegrityAuditEvent.UserWriteable
                    };

                    // Set the FileVersion using helper method
                    string? fileVersionString = possibleCodeIntegrityAuditEvent.FileVersion;
                    eventData.FileVersion = SetFileVersion(fileVersionString);


                    // If there are correlated events - for signer information of the file
                    if (correlatedEvents.Count > 0)
                    {

                        // Iterate over each correlated event - files can have multiple signers
                        foreach (MDEAdvancedHuntingData correlatedEvent in correlatedEvents)
                        {

                            // Skip signers that don't have PublisherTBSHash (aka LeafCertificate TBS Hash) or PublisherName
                            // They have "Unknown" as their IssuerName and PublisherName too
                            // Leaf certificate is a must have for signed files
                            string? PublisherTBSHash = correlatedEvent.PublisherTBSHash;

                            string? PublisherName = correlatedEvent.PublisherName;

                            if (PublisherTBSHash is null || PublisherName is null)
                            {
                                continue;
                            }

                            // Extract values using XPath
                            FileSignerInfo signerInfo = new()
                            {

                                TotalSignatureCount = GetIntValue(correlatedEvent.TotalSignatureCount),
                                Signature = GetIntValue(correlatedEvent.Signature),
                                Hash = correlatedEvent.Hash,
                                SignatureType = GetSignatureType(GetIntValue(correlatedEvent.SignatureType)),
                                ValidatedSigningLevel = GetValidatedRequestedSigningLevel(GetIntValue(correlatedEvent.ValidatedSigningLevel)),
                                VerificationError = GetVerificationError(GetIntValue(correlatedEvent.VerificationError)),
                                Flags = GetIntValue(correlatedEvent.Flags),
                                NotValidBefore = GetEventDataDateTimeValue(correlatedEvent.NotValidBefore),
                                NotValidAfter = GetEventDataDateTimeValue(correlatedEvent.NotValidAfter),
                                PublisherName = PublisherName,
                                IssuerName = correlatedEvent.IssuerName,
                                PublisherTBSHash = PublisherTBSHash,
                                IssuerTBSHash = correlatedEvent.IssuerTBSHash
                            };

                            // Add the CN of the current signer to the FilePublishers HashSet of the FileIdentity
                            _ = eventData.FilePublishers.Add(PublisherName);

                            // Add the current signer info/correlated event data to the main event package
                            _ = eventData.FileSignerInfos.Add(signerInfo);
                        }
                    }


                    // Set the SignatureStatus based on the number of signers
                    eventData.SignatureStatus = eventData.FileSignerInfos.Count > 0 ? SignatureStatus.Signed : SignatureStatus.Unsigned;


                    // Add the entire event package to the output list
                    _ = fileIdentities.Add(eventData);


                }






                // If the current group has Code Integrity Blocked log
                else if (possibleCodeIntegrityBlockEvent is not null)
                {

                    if (possibleCodeIntegrityBlockEvent.SHA256 is null)
                    {
                        continue;
                    }


                    // Extract values using XPath
                    FileIdentity eventData = new()
                    {

                        Origin = FileIdentityOrigin.MDEAdvancedHunting,
                        Action = EventAction.Audit,
                        TimeCreated = GetEventDataDateTimeValue(possibleCodeIntegrityBlockEvent.Timestamp),
                        ComputerName = possibleCodeIntegrityBlockEvent.DeviceName,
                        UserID = possibleCodeIntegrityBlockEvent.InitiatingProcessAccountName,

                        FilePath = possibleCodeIntegrityBlockEvent.FolderPath,
                        FileName = possibleCodeIntegrityBlockEvent.FileName,
                        ProcessName = possibleCodeIntegrityBlockEvent.ProcessName,
                        RequestedSigningLevel = GetValidatedRequestedSigningLevel(GetIntValue(possibleCodeIntegrityBlockEvent.RequestedSigningLevel)),
                        ValidatedSigningLevel = GetValidatedRequestedSigningLevel(GetIntValue(possibleCodeIntegrityBlockEvent.ValidatedSigningLevel)),
                        Status = possibleCodeIntegrityBlockEvent.StatusCode,
                        SHA1Hash = possibleCodeIntegrityBlockEvent.SHA1,
                        SHA256Hash = possibleCodeIntegrityBlockEvent.SHA256,
                        SHA1FlatHash = possibleCodeIntegrityBlockEvent.Sha1FlatHash,
                        SHA256FlatHash = possibleCodeIntegrityBlockEvent.Sha256FlatHash,
                        USN = GetLongValue(possibleCodeIntegrityBlockEvent.USN),
                        SISigningScenario = GetIntValue(possibleCodeIntegrityBlockEvent.SiSigningScenario) ?? 1,
                        PolicyName = possibleCodeIntegrityBlockEvent.PolicyName,
                        PolicyID = possibleCodeIntegrityBlockEvent.PolicyID,
                        PolicyHash = possibleCodeIntegrityBlockEvent.PolicyHash,
                        OriginalFileName = possibleCodeIntegrityBlockEvent.OriginalFileName,
                        InternalName = possibleCodeIntegrityBlockEvent.InternalName,
                        FileDescription = possibleCodeIntegrityBlockEvent.FileDescription,
                        PolicyGUID = GetGuidValue(possibleCodeIntegrityBlockEvent.PolicyGuid),
                        UserWriteable = possibleCodeIntegrityBlockEvent.UserWriteable
                    };

                    // Set the FileVersion using helper method
                    string? fileVersionString = possibleCodeIntegrityBlockEvent.FileVersion;
                    eventData.FileVersion = SetFileVersion(fileVersionString);


                    // If there are correlated events - for signer information of the file
                    if (correlatedEvents.Count > 0)
                    {

                        // Iterate over each correlated event - files can have multiple signers
                        foreach (MDEAdvancedHuntingData correlatedEvent in correlatedEvents)
                        {

                            // Skip signers that don't have PublisherTBSHash (aka LeafCertificate TBS Hash) or PublisherName
                            // They have "Unknown" as their IssuerName and PublisherName too
                            // Leaf certificate is a must have for signed files
                            string? PublisherTBSHash = correlatedEvent.PublisherTBSHash;

                            string? PublisherName = correlatedEvent.PublisherName;

                            if (PublisherTBSHash is null || PublisherName is null)
                            {
                                continue;
                            }

                            // Extract values using XPath
                            FileSignerInfo signerInfo = new()
                            {

                                TotalSignatureCount = GetIntValue(correlatedEvent.TotalSignatureCount),
                                Signature = GetIntValue(correlatedEvent.Signature),
                                Hash = correlatedEvent.Hash,
                                SignatureType = GetSignatureType(GetIntValue(correlatedEvent.SignatureType)),
                                ValidatedSigningLevel = GetValidatedRequestedSigningLevel(GetIntValue(correlatedEvent.ValidatedSigningLevel)),
                                VerificationError = GetVerificationError(GetIntValue(correlatedEvent.VerificationError)),
                                Flags = GetIntValue(correlatedEvent.Flags),
                                NotValidBefore = GetEventDataDateTimeValue(correlatedEvent.NotValidBefore),
                                NotValidAfter = GetEventDataDateTimeValue(correlatedEvent.NotValidAfter),
                                PublisherName = PublisherName,
                                IssuerName = correlatedEvent.IssuerName,
                                PublisherTBSHash = PublisherTBSHash,
                                IssuerTBSHash = correlatedEvent.IssuerTBSHash
                            };

                            // Add the CN of the current signer to the FilePublishers HashSet of the FileIdentity
                            _ = eventData.FilePublishers.Add(PublisherName);

                            // Add the current signer info/correlated event data to the main event package
                            _ = eventData.FileSignerInfos.Add(signerInfo);
                        }
                    }


                    // Set the SignatureStatus based on the number of signers
                    eventData.SignatureStatus = eventData.FileSignerInfos.Count > 0 ? SignatureStatus.Signed : SignatureStatus.Unsigned;


                    // Add the entire event package to the output list
                    _ = fileIdentities.Add(eventData);


                }


                // If the current group has AppLocker Audit log
                if (possibleAppLockerAuditEvent is not null)
                {


                    if (possibleAppLockerAuditEvent.SHA256 is null)
                    {
                        continue;
                    }


                    // Extract values using XPath
                    FileIdentity eventData = new()
                    {

                        Origin = FileIdentityOrigin.MDEAdvancedHunting,
                        Action = EventAction.Audit,
                        TimeCreated = GetEventDataDateTimeValue(possibleAppLockerAuditEvent.Timestamp),
                        ComputerName = possibleAppLockerAuditEvent.DeviceName,
                        UserID = possibleAppLockerAuditEvent.InitiatingProcessAccountName,

                        FilePath = possibleAppLockerAuditEvent.FolderPath,
                        FileName = possibleAppLockerAuditEvent.FileName,
                        ProcessName = possibleAppLockerAuditEvent.ProcessName,
                        RequestedSigningLevel = GetValidatedRequestedSigningLevel(GetIntValue(possibleAppLockerAuditEvent.RequestedSigningLevel)),
                        ValidatedSigningLevel = GetValidatedRequestedSigningLevel(GetIntValue(possibleAppLockerAuditEvent.ValidatedSigningLevel)),
                        Status = possibleAppLockerAuditEvent.StatusCode,
                        SHA1Hash = possibleAppLockerAuditEvent.SHA1,
                        SHA256Hash = possibleAppLockerAuditEvent.SHA256,
                        SHA1FlatHash = possibleAppLockerAuditEvent.Sha1FlatHash,
                        SHA256FlatHash = possibleAppLockerAuditEvent.Sha256FlatHash,
                        USN = GetLongValue(possibleAppLockerAuditEvent.USN),
                        SISigningScenario = GetIntValue(possibleAppLockerAuditEvent.SiSigningScenario) ?? 1,
                        PolicyName = possibleAppLockerAuditEvent.PolicyName,
                        PolicyID = possibleAppLockerAuditEvent.PolicyID,
                        PolicyHash = possibleAppLockerAuditEvent.PolicyHash,
                        OriginalFileName = possibleAppLockerAuditEvent.OriginalFileName,
                        InternalName = possibleAppLockerAuditEvent.InternalName,
                        FileDescription = possibleAppLockerAuditEvent.FileDescription,
                        PolicyGUID = GetGuidValue(possibleAppLockerAuditEvent.PolicyGuid),
                        UserWriteable = possibleAppLockerAuditEvent.UserWriteable
                    };

                    // Set the FileVersion using helper method
                    string? fileVersionString = possibleAppLockerAuditEvent.FileVersion;
                    eventData.FileVersion = SetFileVersion(fileVersionString);


                    // If there are correlated events - for signer information of the file
                    if (correlatedEvents.Count > 0)
                    {

                        // Iterate over each correlated event - files can have multiple signers
                        foreach (MDEAdvancedHuntingData correlatedEvent in correlatedEvents)
                        {

                            // Skip signers that don't have PublisherTBSHash (aka LeafCertificate TBS Hash) or PublisherName
                            // They have "Unknown" as their IssuerName and PublisherName too
                            // Leaf certificate is a must have for signed files
                            string? PublisherTBSHash = correlatedEvent.PublisherTBSHash;

                            string? PublisherName = correlatedEvent.PublisherName;

                            if (PublisherTBSHash is null || PublisherName is null)
                            {
                                continue;
                            }

                            // Extract values using XPath
                            FileSignerInfo signerInfo = new()
                            {

                                TotalSignatureCount = GetIntValue(correlatedEvent.TotalSignatureCount),
                                Signature = GetIntValue(correlatedEvent.Signature),
                                Hash = correlatedEvent.Hash,
                                SignatureType = GetSignatureType(GetIntValue(correlatedEvent.SignatureType)),
                                ValidatedSigningLevel = GetValidatedRequestedSigningLevel(GetIntValue(correlatedEvent.ValidatedSigningLevel)),
                                VerificationError = GetVerificationError(GetIntValue(correlatedEvent.VerificationError)),
                                Flags = GetIntValue(correlatedEvent.Flags),
                                NotValidBefore = GetEventDataDateTimeValue(correlatedEvent.NotValidBefore),
                                NotValidAfter = GetEventDataDateTimeValue(correlatedEvent.NotValidAfter),
                                PublisherName = PublisherName,
                                IssuerName = correlatedEvent.IssuerName,
                                PublisherTBSHash = PublisherTBSHash,
                                IssuerTBSHash = correlatedEvent.IssuerTBSHash
                            };

                            // Add the CN of the current signer to the FilePublishers HashSet of the FileIdentity
                            _ = eventData.FilePublishers.Add(PublisherName);

                            // Add the current signer info/correlated event data to the main event package
                            _ = eventData.FileSignerInfos.Add(signerInfo);
                        }
                    }


                    // Set the SignatureStatus based on the number of signers
                    eventData.SignatureStatus = eventData.FileSignerInfos.Count > 0 ? SignatureStatus.Signed : SignatureStatus.Unsigned;


                    // Add the entire event package to the output list
                    _ = fileIdentities.Add(eventData);

                }

                // If the current group has AppLocker Blocked log
                else if (possibleAppLockerBlockEvent is not null)
                {


                    if (possibleAppLockerBlockEvent.SHA256 is null)
                    {
                        continue;
                    }


                    // Extract values using XPath
                    FileIdentity eventData = new()
                    {

                        Origin = FileIdentityOrigin.MDEAdvancedHunting,
                        Action = EventAction.Audit,
                        TimeCreated = GetEventDataDateTimeValue(possibleAppLockerBlockEvent.Timestamp),
                        ComputerName = possibleAppLockerBlockEvent.DeviceName,
                        UserID = possibleAppLockerBlockEvent.InitiatingProcessAccountName,

                        FilePath = possibleAppLockerBlockEvent.FolderPath,
                        FileName = possibleAppLockerBlockEvent.FileName,
                        ProcessName = possibleAppLockerBlockEvent.ProcessName,
                        RequestedSigningLevel = GetValidatedRequestedSigningLevel(GetIntValue(possibleAppLockerBlockEvent.RequestedSigningLevel)),
                        ValidatedSigningLevel = GetValidatedRequestedSigningLevel(GetIntValue(possibleAppLockerBlockEvent.ValidatedSigningLevel)),
                        Status = possibleAppLockerBlockEvent.StatusCode,
                        SHA1Hash = possibleAppLockerBlockEvent.SHA1,
                        SHA256Hash = possibleAppLockerBlockEvent.SHA256,
                        SHA1FlatHash = possibleAppLockerBlockEvent.Sha1FlatHash,
                        SHA256FlatHash = possibleAppLockerBlockEvent.Sha256FlatHash,
                        USN = GetLongValue(possibleAppLockerBlockEvent.USN),
                        SISigningScenario = GetIntValue(possibleAppLockerBlockEvent.SiSigningScenario) ?? 1,
                        PolicyName = possibleAppLockerBlockEvent.PolicyName,
                        PolicyID = possibleAppLockerBlockEvent.PolicyID,
                        PolicyHash = possibleAppLockerBlockEvent.PolicyHash,
                        OriginalFileName = possibleAppLockerBlockEvent.OriginalFileName,
                        InternalName = possibleAppLockerBlockEvent.InternalName,
                        FileDescription = possibleAppLockerBlockEvent.FileDescription,
                        PolicyGUID = GetGuidValue(possibleAppLockerBlockEvent.PolicyGuid),
                        UserWriteable = possibleAppLockerBlockEvent.UserWriteable
                    };

                    // Set the FileVersion using helper method
                    string? fileVersionString = possibleAppLockerBlockEvent.FileVersion;
                    eventData.FileVersion = SetFileVersion(fileVersionString);


                    // If there are correlated events - for signer information of the file
                    if (correlatedEvents.Count > 0)
                    {

                        // Iterate over each correlated event - files can have multiple signers
                        foreach (MDEAdvancedHuntingData correlatedEvent in correlatedEvents)
                        {

                            // Skip signers that don't have PublisherTBSHash (aka LeafCertificate TBS Hash) or PublisherName
                            // They have "Unknown" as their IssuerName and PublisherName too
                            // Leaf certificate is a must have for signed files
                            string? PublisherTBSHash = correlatedEvent.PublisherTBSHash;

                            string? PublisherName = correlatedEvent.PublisherName;

                            if (PublisherTBSHash is null || PublisherName is null)
                            {
                                continue;
                            }

                            // Extract values using XPath
                            FileSignerInfo signerInfo = new()
                            {

                                TotalSignatureCount = GetIntValue(correlatedEvent.TotalSignatureCount),
                                Signature = GetIntValue(correlatedEvent.Signature),
                                Hash = correlatedEvent.Hash,
                                SignatureType = GetSignatureType(GetIntValue(correlatedEvent.SignatureType)),
                                ValidatedSigningLevel = GetValidatedRequestedSigningLevel(GetIntValue(correlatedEvent.ValidatedSigningLevel)),
                                VerificationError = GetVerificationError(GetIntValue(correlatedEvent.VerificationError)),
                                Flags = GetIntValue(correlatedEvent.Flags),
                                NotValidBefore = GetEventDataDateTimeValue(correlatedEvent.NotValidBefore),
                                NotValidAfter = GetEventDataDateTimeValue(correlatedEvent.NotValidAfter),
                                PublisherName = PublisherName,
                                IssuerName = correlatedEvent.IssuerName,
                                PublisherTBSHash = PublisherTBSHash,
                                IssuerTBSHash = correlatedEvent.IssuerTBSHash
                            };

                            // Add the CN of the current signer to the FilePublishers HashSet of the FileIdentity
                            _ = eventData.FilePublishers.Add(PublisherName);

                            // Add the current signer info/correlated event data to the main event package
                            _ = eventData.FileSignerInfos.Add(signerInfo);
                        }
                    }


                    // Set the SignatureStatus based on the number of signers
                    eventData.SignatureStatus = eventData.FileSignerInfos.Count > 0 ? SignatureStatus.Signed : SignatureStatus.Unsigned;


                    // Add the entire event package to the output list
                    _ = fileIdentities.Add(eventData);


                }

            }


            // Return the internal data which is the right return type
            return fileIdentities.FileIdentitiesInternal;
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
        /// Method to safely get an integer value from string
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        private static int? GetIntValue(string? data)
        {
            return data is not null && int.TryParse(data, NumberStyles.Integer, CultureInfo.InvariantCulture, out int result) ? result : null;
        }



        /// <summary>
        /// Converts string to DateTime
        /// </summary>
        private static DateTime? GetEventDataDateTimeValue(string? data)
        {
            return data is not null && DateTime.TryParse(data, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out DateTime result) ? result : null;
        }



        private static long? GetLongValue(string? data)
        {
            return data is not null && long.TryParse(data, NumberStyles.Integer, CultureInfo.InvariantCulture, out long result) ? result : null;
        }

        private static Guid? GetGuidValue(string? data)
        {
            return data is not null && Guid.TryParse(data, out Guid guid) ? guid : null;
        }



        /// <summary>
        /// Resolves the Validated/Requested Signing Level int to friendly string
        /// </summary>
        /// <param name="SigningLevelInt"></param>
        /// <returns></returns>
        private static string? GetValidatedRequestedSigningLevel(int? SigningLevelInt)
        {
            if (SigningLevelInt.HasValue)
            {
                _ = CILogIntel.ReqValSigningLevels.TryGetValue(SigningLevelInt.Value, out string? SigningLevel);

                return SigningLevel;
            }
            else
            {
                return null;
            }
        }


        /// <summary>
        /// Resolves the VerificationError int to a friendly string
        /// </summary>
        /// <param name="VerificationError"></param>
        /// <returns></returns>
        private static string? GetVerificationError(int? VerificationError)
        {
            if (VerificationError.HasValue)
            {
                _ = CILogIntel.VerificationErrorTable.TryGetValue(VerificationError.Value, out string? VerificationErrorString);
                return VerificationErrorString;
            }
            else
            {
                return null;
            }
        }


        /// <summary>
        /// Resolves the SignatureType int to a friendly string
        /// </summary>
        /// <param name="SignatureType"></param>
        /// <returns></returns>
        private static string? GetSignatureType(int? SignatureType)
        {
            if (SignatureType.HasValue)
            {
                _ = CILogIntel.SignatureTypeTable.TryGetValue(SignatureType.Value, out string? SignatureTypeString);
                return SignatureTypeString;
            }
            else
            {
                return null;
            }
        }


        #endregion


    }
}