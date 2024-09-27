#nullable enable

using System.Linq;

namespace WDACConfig
{
    public class PolicyMerger
    {
        /// <summary>
        /// Merges multiple policies into a single policy using the PowerShell cmdlet of the ConfigCI module
        /// </summary>
        /// <param name="inputPolicies">path(s) of the policies to be merged together</param>
        /// <param name="outputPolicy">path of the output file</param>
        public static void Merge(string[] inputPolicies, string outputPolicy)
        {
            // Wrap each policy path in quotes and join them into a single comma-separated string
            string policiesList = string.Join(", ", inputPolicies.Select(path => $"\"{path}\""));

            // Use the policiesList in the script
            string script = $"Merge-CIPolicy -PolicyPaths {policiesList} -OutputFilePath \"{outputPolicy}\"";

            _ = PowerShellExecutor.ExecuteScript(script);
        }
    }
}
