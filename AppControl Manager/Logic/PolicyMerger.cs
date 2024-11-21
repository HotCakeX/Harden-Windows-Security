using System.Linq;

namespace WDACConfig
{
    public static class PolicyMerger
    {
        /// <summary>
        /// Merges multiple policies into a single policy using the PowerShell cmdlet of the ConfigCI module
        /// </summary>
        /// <param name="inputPolicies">path(s) of the policies to be merged together</param>
        /// <param name="outputPolicy">path of the output file</param>
        public static void Merge(string[] inputPolicies, string outputPolicy)
        {
            // Wrap each policy path in double quotes, escape for PowerShell
            string policiesArray = $"@({string.Join(", ", inputPolicies.Select(path => $"\\\"{path}\\\""))})";

            // Escape the output policy path for PowerShell
            string escapedOutputPolicy = $"\\\"{outputPolicy}\\\"";

            // Construct the PowerShell script
            string script = $"Merge-CIPolicy -PolicyPaths {policiesArray} -OutputFilePath {escapedOutputPolicy}";

            Logger.Write($"PowerShell code that will be executed: {script}");

            // Execute the command
            ProcessStarter.RunCommand("powershell.exe", $"-Command \"{script}\"");
        }
    }
}
