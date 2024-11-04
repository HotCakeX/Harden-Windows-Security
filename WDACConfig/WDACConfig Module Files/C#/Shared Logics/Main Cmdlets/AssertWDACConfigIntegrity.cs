using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;

#nullable enable

namespace WDACConfig
{
    // This class defines Hash entries for each file in the WDACConfig PowerShell module based on the cloud CSV
    public sealed class WDACConfigHashEntry(string? relativePath, string? fileName, string? fileHash)
    {
        public string? RelativePath { get; set; } = relativePath;
        public string? FileName { get; set; } = fileName;
        public string? FileHash { get; set; } = fileHash;
    }


    public static class AssertWDACConfigIntegrity
    {
        /// <summary>
        /// Hashes all of the files in the WDACConfig, download the cloud hashes, compares them with each other and report back hash mismatches
        /// </summary>
        /// <param name="SaveLocally"></param>
        /// <param name="path">Location where new hash results will be saved</param>
        public static List<WDACConfigHashEntry>? Invoke(bool SaveLocally, string? path)
        {

            // Defining the output file name and the URL of the cloud CSV file
            string OutputFileName = "Hashes.csv";
            string url = "https://raw.githubusercontent.com/HotCakeX/Harden-Windows-Security/main/WDACConfig/Utilities/Hashes.csv";

            // Hash details of the current PowerShell files
            List<WDACConfigHashEntry> CurrentFileHashes = [];

            using HttpClient client = new();

            // Download CSV content synchronously
            string csvData = client.GetStringAsync(url).Result;

            // Parse the CSV content
            List<WDACConfigHashEntry> ParsedCSVList = ParseCSV(csvData);

            // Get all of the files in the PowerShell module directory
            List<FileInfo> files = FileUtility.GetFilesFast([new DirectoryInfo(WDACConfig.GlobalVars.ModuleRootPath!)], null, ["*"]);

            // Loop over each file
            foreach (FileInfo file in files)
            {

                // Making sure the PowerShell Gallery file in the WDACConfig module's folder is skipped
                if (string.Equals(file.Name, "PSGetModuleInfo.xml", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                // Read the file as a byte array - This way we can get hashes of a file in use by another process where Get-FileHash would fail
                byte[] Bytes = File.ReadAllBytes(file.FullName);

                // Compute the hash of the byte array
                Byte[] HashBytes = SHA512.HashData(Bytes);

                // Convert the hash bytes to a hexadecimal string to make it look like the output of the Get-FileHash which produces hexadecimals (0-9 and A-F)
                // If [System.Convert]::ToBase64String was used, it'd return the hash in base64 format, which uses 64 symbols (A-Z, a-z, 0-9, + and /) to represent each byte
                String HashString = BitConverter.ToString(HashBytes);

                // Remove the dashes from the hexadecimal string
                HashString = HashString.Replace("-", "", StringComparison.OrdinalIgnoreCase);

                // Add the file details to the list
                CurrentFileHashes.Add(new WDACConfigHashEntry(
                    Path.GetRelativePath(GlobalVars.ModuleRootPath!, file.FullName),
                    file.Name,
                    HashString));
            }

            // Save the current files' hashes to a CSV in the user defined directory path
            if (SaveLocally)
            {
                if (path is null || !Path.Exists(path))
                {
                    throw new InvalidOperationException("path parameter does not exist");
                }

                ExportToCsv(Path.Combine(path, OutputFileName), CurrentFileHashes);
            }

            // A list to store mismatches
            List<WDACConfigHashEntry> MismatchedEntries = [];

            // Compare the two lists
            foreach (WDACConfigHashEntry currentFileHash in CurrentFileHashes)
            {
                // Find the corresponding entry in ParsedCSVList
                WDACConfigHashEntry? matchingParsedEntry = ParsedCSVList.FirstOrDefault(
                    p => RemoveQuotes(p.RelativePath) == RemoveQuotes(currentFileHash.RelativePath) &&
                         RemoveQuotes(p.FileName) == RemoveQuotes(currentFileHash.FileName) &&
                         RemoveQuotes(p.FileHash) == RemoveQuotes(currentFileHash.FileHash)
                );

                // If there's no matching entry or the hashes are different, add to the mismatch list
                if (matchingParsedEntry is null)
                {
                    MismatchedEntries.Add(currentFileHash);
                }
            }

            if (MismatchedEntries.Count > 0)
            {
                Logger.Write("The following files are different from the ones in the cloud:");
                return MismatchedEntries;
            }
            else
            {
                Logger.Write("All of your local WDACConfig files are genuine.");
                return null;
            }
        }

        /// <summary>
        /// Parses the CSV content and returns a list of WDACConfigHashEntry objects
        /// </summary>
        /// <param name="csvData"></param>
        /// <returns></returns>
        private static List<WDACConfigHashEntry> ParseCSV(string csvData)
        {
            List<WDACConfigHashEntry> entries = [];

            using (StringReader reader = new(csvData))
            {
                string? line;
                bool isHeader = true;

                while ((line = reader.ReadLine()) != null)
                {
                    // Skip the header
                    if (isHeader)
                    {
                        isHeader = false;
                        continue;
                    }

                    // Split the CSV line by commas
                    var fields = line.Split(',');

                    if (fields.Length == 3)
                    {
                        entries.Add(new WDACConfigHashEntry
                        (
                            fields[0],
                            fields[1],
                            fields[2]
                        ));
                    }
                }
            }

            return entries;
        }


        /// <summary>
        /// Exports the list of WDACConfigHashEntry objects to a CSV file
        /// </summary>
        /// <param name="outputPath"></param>
        /// <param name="entries"></param>
        private static void ExportToCsv(string outputPath, List<WDACConfigHashEntry> entries)
        {
            // Ensure we create a new file or overwrite an existing one
            using StreamWriter writer = new(outputPath, false, Encoding.UTF8);
            // Write the CSV header
            writer.WriteLine("""
"RelativePath","FileName","FileHash"
""");

            // Write each entry in the list
            foreach (var entry in entries)
            {
                string relativePath = EscapeCsv(entry.RelativePath);
                string fileName = EscapeCsv(entry.FileName);
                string fileHash = EscapeCsv(entry.FileHash);

                // Write the CSV row
                writer.WriteLine($"{relativePath},{fileName},{fileHash}");
            }
        }


        /// <summary>
        /// Escapes the content of a field for CSV (quotes any value with commas).
        /// </summary>
        /// <param name="field">The string to escape.</param>
        /// <returns>Escaped CSV string</returns>
        private static string EscapeCsv(string? field)
        {
            // If the field is null or empty, return an empty string
            if (string.IsNullOrWhiteSpace(field)) return "";

            // Add quotes around each field regardless of whether they already include comma, quotes etc.
            return $"\"{field.Replace("\"", "\"\"", StringComparison.OrdinalIgnoreCase)}\"";

        }


        /// <summary>
        /// Helper function to remove double quotes from the strings
        /// </summary>
        /// <param name="input"></param>
        /// <returns></returns>
        private static string? RemoveQuotes(string? input)
        {
            return input?.Trim('"');
        }
    }
}
