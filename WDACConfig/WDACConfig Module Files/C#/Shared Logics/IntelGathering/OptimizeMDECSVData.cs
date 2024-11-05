using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

#nullable enable

namespace WDACConfig.IntelGathering
{

    internal sealed partial class OptimizeMDECSVData
    {


        /// <summary>
        /// Public method of this class.
        /// Optimizes the MDE CSV data by adding the nested properties in the "AdditionalFields" property to the parent record as first-level properties, all in one class
        /// </summary>
        /// <param name="CSVFilePath"></param>
        /// <returns></returns>
        public static List<MDEAdvancedHuntingData> Optimize(string CSVFilePath)
        {
            List<MDEAdvancedHuntingData> csvRecords = ReadCsv(CSVFilePath);

            return csvRecords;
        }



        /// <summary>
        /// Converts an entire MDE Advanced Hunting CSV file into a list of classes
        /// </summary>
        /// <param name="filePath"></param>
        /// <returns></returns>
        /// <exception cref="InvalidDataException"></exception>
        private static List<MDEAdvancedHuntingData> ReadCsv(string filePath)
        {
            // Create a list to store each CSV row record
            List<MDEAdvancedHuntingData> records = [];

            // Read the CSV file line by line
            using StreamReader reader = new(filePath);

            // Read the header line
            string? header = reader.ReadLine() ?? throw new InvalidDataException("CSV file is empty or header is missing.");

            // Read the remaining lines of the CSV file until the end of the stream is reached (EOF)
            while (!reader.EndOfStream)
            {
                // Read the next line
                string? line = reader.ReadLine();
                if (line is null) continue;

                // Split the line by commas
                string[] values = ParseCsvLine(line);

                // Initialize a new CsvRecord instance
                // P.S not all rows have the same properties
                MDEAdvancedHuntingData record = new()
                {
                    Timestamp = values.Length > 0 ? values[0] : null,
                    DeviceId = values.Length > 1 ? values[1] : null,
                    DeviceName = values.Length > 2 ? values[2] : null,
                    ActionType = values.Length > 3 ? values[3] : null,
                    FileName = values.Length > 4 ? values[4] : null,
                    FolderPath = values.Length > 5 ? values[5] : null,
                    SHA1 = values.Length > 6 ? values[6] : null,
                    SHA256 = values.Length > 7 ? values[7] : null,
                    InitiatingProcessSHA1 = values.Length > 8 ? values[8] : null,
                    InitiatingProcessSHA256 = values.Length > 9 ? values[9] : null,
                    InitiatingProcessMD5 = values.Length > 10 ? values[10] : null,
                    InitiatingProcessFileName = values.Length > 11 ? values[11] : null,
                    InitiatingProcessFileSize = values.Length > 12 ? values[12] : null,
                    InitiatingProcessFolderPath = values.Length > 13 ? values[13] : null,
                    InitiatingProcessId = values.Length > 14 ? values[14] : null,
                    InitiatingProcessCommandLine = values.Length > 15 ? values[15] : null,
                    InitiatingProcessCreationTime = values.Length > 16 ? values[16] : null,
                    InitiatingProcessAccountDomain = values.Length > 17 ? values[17] : null,
                    InitiatingProcessAccountName = values.Length > 18 ? values[18] : null,
                    InitiatingProcessAccountSid = values.Length > 19 ? values[19] : null,
                    InitiatingProcessVersionInfoCompanyName = values.Length > 20 ? values[20] : null,
                    InitiatingProcessVersionInfoProductName = values.Length > 21 ? values[21] : null,
                    InitiatingProcessVersionInfoProductVersion = values.Length > 22 ? values[22] : null,
                    InitiatingProcessVersionInfoInternalFileName = values.Length > 23 ? values[23] : null,
                    InitiatingProcessVersionInfoOriginalFileName = values.Length > 24 ? values[24] : null,
                    InitiatingProcessVersionInfoFileDescription = values.Length > 25 ? values[25] : null,
                    InitiatingProcessParentId = values.Length > 26 ? values[26] : null,
                    InitiatingProcessParentFileName = values.Length > 27 ? values[27] : null,
                    InitiatingProcessParentCreationTime = values.Length > 28 ? values[28] : null,
                    InitiatingProcessLogonId = values.Length > 29 ? values[29] : null,
                    ReportId = values.Length > 30 ? values[30] : null
                };

                // Parse the AdditionalFields JSON if it exists
                if (values.Length > 31 && !string.IsNullOrWhiteSpace(values[31]))
                {
                    // Get the JSON string from the CSV which is in the AdditionalFields property
                    string additionalFieldsString = values[31];

                    // Format the JSON string so the next method won't throw error
                    string FormattedJSONString = EnsureAllValuesAreQuoted(additionalFieldsString);

                    // Deserialize the JSON content into a dictionary
                    Dictionary<string, string>? additionalFields = JsonSerializer.Deserialize<Dictionary<string, string>>(FormattedJSONString);


                    if (additionalFields is not null)
                    {
                        // Populate the new properties from the JSON
                        record.PolicyID = additionalFields.TryGetValue("PolicyID", out string? PolicyID) ? PolicyID : null;
                        record.PolicyName = additionalFields.TryGetValue("PolicyName", out string? PolicyName) ? PolicyName : null;
                        record.RequestedSigningLevel = additionalFields.TryGetValue("Requested Signing Level", out string? RequestedSigningLevel) ? RequestedSigningLevel : null;
                        record.ValidatedSigningLevel = additionalFields.TryGetValue("Validated Signing Level", out string? ValidatedSigningLevel) ? ValidatedSigningLevel : null;
                        record.ProcessName = additionalFields.TryGetValue("ProcessName", out string? ProcessName) ? ProcessName : null;
                        record.StatusCode = additionalFields.TryGetValue("StatusCode", out string? StatusCode) ? StatusCode : null;
                        record.Sha1FlatHash = additionalFields.TryGetValue("Sha1FlatHash", out string? Sha1FlatHash) ? Sha1FlatHash : null;
                        record.Sha256FlatHash = additionalFields.TryGetValue("Sha256FlatHash", out string? Sha256FlatHash) ? Sha256FlatHash : null;
                        record.USN = additionalFields.TryGetValue("USN", out string? USN) ? USN : null;
                        record.SiSigningScenario = additionalFields.TryGetValue("SiSigningScenario", out string? SiSigningScenario) ? SiSigningScenario : null;
                        record.PolicyHash = additionalFields.TryGetValue("PolicyHash", out string? PolicyHash) ? PolicyHash : null;
                        record.PolicyGuid = additionalFields.TryGetValue("PolicyGuid", out string? PolicyGuid) ? PolicyGuid : null;
                        record.UserWriteable = additionalFields.TryGetValue("UserWriteable", out string? UserWriteable) ? bool.Parse(UserWriteable) : null;
                        record.OriginalFileName = additionalFields.TryGetValue("OriginalFileName", out string? OriginalFileName) ? OriginalFileName : null;
                        record.InternalName = additionalFields.TryGetValue("InternalName", out string? InternalName) ? InternalName : null;
                        record.FileDescription = additionalFields.TryGetValue("FileDescription", out string? FileDescription) ? FileDescription : null;
                        record.FileVersion = additionalFields.TryGetValue("FileVersion", out string? FileVersion) ? FileVersion : null;
                        record.EtwActivityId = additionalFields.TryGetValue("EtwActivityId", out string? EtwActivityId) ? EtwActivityId : null;
                        record.IssuerName = additionalFields.TryGetValue("IssuerName", out string? IssuerName) ? IssuerName : null;
                        record.IssuerTBSHash = additionalFields.TryGetValue("IssuerTBSHash", out string? IssuerTBSHash) ? IssuerTBSHash : null;
                        record.NotValidAfter = additionalFields.TryGetValue("NotValidAfter", out string? NotValidAfter) ? NotValidAfter : null;
                        record.NotValidBefore = additionalFields.TryGetValue("NotValidBefore", out string? NotValidBefore) ? NotValidBefore : null;
                        record.PublisherName = additionalFields.TryGetValue("PublisherName", out string? PublisherName) ? PublisherName : null;
                        record.PublisherTBSHash = additionalFields.TryGetValue("PublisherTBSHash", out string? PublisherTBSHash) ? PublisherTBSHash : null;
                        record.SignatureType = additionalFields.TryGetValue("SignatureType", out string? SignatureType) ? SignatureType : null;
                        record.TotalSignatureCount = additionalFields.TryGetValue("TotalSignatureCount", out string? TotalSignatureCount) ? TotalSignatureCount : null;
                        record.VerificationError = additionalFields.TryGetValue("VerificationError", out string? VerificationError) ? VerificationError : null;
                        record.Signature = additionalFields.TryGetValue("Signature", out string? Signature) ? Signature : null;
                        record.Hash = additionalFields.TryGetValue("Hash", out string? Hash) ? Hash : null;
                        record.Flags = additionalFields.TryGetValue("Flags", out string? Flags) ? Flags : null;
                        record.PolicyBits = additionalFields.TryGetValue("PolicyBits", out string? PolicyBits) ? PolicyBits : null;
                    }
                }

                // Add the populated record to the list
                records.Add(record);
            }

            return records;
        }


        /// <summary>
        /// Ensures the JSON string is well formatted. If a field has no double quotes, it will add them around it.
        /// </summary>
        /// <param name="jsonString"></param>
        /// <returns></returns>
        private static string EnsureAllValuesAreQuoted(string jsonString)
        {
            // Regex to match unquoted values that are not inside quotes
            Regex regex = JsonFixerRegex();

            // Replace the matched unquoted values with the same value wrapped in double quotes
            string result = regex.Replace(jsonString, match => $"\"{match.Value.Trim()}\"");

            return result;
        }



        /// <summary>
        /// Parses each line/row of the CSV file
        /// </summary>
        /// <param name="line"></param>
        /// <returns></returns>
        private static string[] ParseCsvLine(string line)
        {
            List<string> fields = [];
            StringBuilder currentField = new();
            bool inQuotes = false;

            // Iterate through each character in the line
            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];

                // Handle quotes
                if (c == '"')
                {
                    // Handle escaped quotes ("")
                    if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                    {
                        _ = currentField.Append('"'); // Append a single quote if it's an escape sequence
                        i++; // Skip the next quote
                    }
                    else
                    {
                        inQuotes = !inQuotes; // Toggle the inQuotes flag
                    }
                }

                // Handle commas
                else if (c == ',' && !inQuotes)
                {
                    // When we hit a comma outside of quotes, the field is complete
                    fields.Add(currentField.ToString());
                    _ = currentField.Clear();
                }

                else
                {
                    // Add characters to the current field
                    _ = currentField.Append(c);
                }
            }

            // Add the last field to the list
            fields.Add(currentField.ToString());

            // Clean up: Remove the outermost quotes for non-JSON fields
            // If a field has more than one set/pair of double quotes around it, only one pair will be removed
            for (int i = 0; i < fields.Count; i++)
            {
                string field = fields[i];

                // If the field is a JSON field, we don't want to remove quotes
                if (field.StartsWith("{", StringComparison.OrdinalIgnoreCase) && field.EndsWith("}", StringComparison.OrdinalIgnoreCase))
                {
                    continue; // Skip JSON fields
                }

                // Remove leading and trailing quotes if they exist (for non-JSON fields)
                if (field.StartsWith("\"", StringComparison.OrdinalIgnoreCase) && field.EndsWith("\"", StringComparison.OrdinalIgnoreCase) && field.Length > 1)
                {
                    fields[i] = field[1..^1];
                }
            }

            return [.. fields];
        }




        // 1. (?<=:)
        //    Positive Lookbehind: Asserts that the match must be preceded by a colon `:`.
        //    Ensures that we're matching a value that appears immediately after a key-value colon.
        //
        // 2. \s*
        //    Matches zero or more whitespace characters following the colon.
        //    Allows for optional spaces between the colon and the value.
        //
        // 3. (?!\"\")
        //    Negative Lookahead: Ensures that the match is NOT followed by a double quote `"`.
        //    This prevents already quoted values from being matched.
        //
        // 4. ([^\"",\s]+)
        //    Capturing Group: Matches one or more characters that are not a double quote `"`,
        //    comma `,`, or whitespace. This captures unquoted strings up to a comma, closing
        //    brace, or space, allowing only unquoted single-word values to be matched.
        //
        // 5. (?=\s*,|\s*})
        //    Positive Lookahead: Asserts that the match must be followed by either a comma `,`
        //    (indicating another key-value pair) or a closing brace `}`, with optional whitespace.
        //    This confirms the end of the unquoted value within the JSON structure.
        //
        // Summary:
        // Some MDE AH AdditionalFields JSON content have unquoted fields, this takes care of them.
        // The regex Will Fail if the field that is not quoted contains a comma(s), space(s) or double quote(s) in it, before the comma that marks the end of the field.
        // This is because the regex is designed to match unquoted fields that are single words/digits.
        //
        [GeneratedRegex(@"(?<=:)\s*(?!\"")([^\"",\s]+)(?=\s*,|\s*})", RegexOptions.Compiled)]
        private static partial Regex JsonFixerRegex();

    }
}
