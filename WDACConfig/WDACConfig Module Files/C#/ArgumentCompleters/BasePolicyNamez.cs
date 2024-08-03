using System;
using System.Diagnostics;
using System.Text.Json;
using System.Collections.Generic;
using System.Management.Automation;

namespace WDACConfig
{
    public class BasePolicyNamez : IValidateSetValuesGenerator
    {
        // Argument tab auto-completion and ValidateSet for Non-System Policy names
        public string[] GetValidValues()
        {
            // Run CiTool.exe and capture the output
            ProcessStartInfo startInfo = new ProcessStartInfo
            {
                FileName = @"C:\Windows\System32\CiTool.exe",
                Arguments = "-lp -json",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            Process process = new Process { StartInfo = startInfo };
            process.Start();

            string jsonOutput = process.StandardOutput.ReadToEnd();
            process.WaitForExit();

            // Parse the JSON output
            JsonDocument jsonDoc = JsonDocument.Parse(jsonOutput);
            JsonElement policiesElement = jsonDoc.RootElement.GetProperty("Policies");

            List<string> validValues = new List<string>();

            foreach (JsonElement policyElement in policiesElement.EnumerateArray())
            {
                bool isSystemPolicy = policyElement.GetProperty("IsSystemPolicy").GetBoolean();
                string policyId = policyElement.GetProperty("PolicyID").GetString();
                string basePolicyId = policyElement.GetProperty("BasePolicyID").GetString();
                string friendlyName = policyElement.GetProperty("FriendlyName").GetString();

                // Use ordinal, case-insensitive comparison for the policy IDs
                if (!isSystemPolicy && string.Equals(policyId, basePolicyId, StringComparison.OrdinalIgnoreCase))
                {
                    validValues.Add(friendlyName);
                }
            }

            return validValues.ToArray();
        }
    }
}
