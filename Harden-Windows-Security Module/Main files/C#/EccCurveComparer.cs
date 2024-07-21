using System;
using System.Linq;
using System.Management.Automation;
using System.Collections.Generic;

namespace HardeningModule
{
    public class EccCurveComparisonResult
    {
        public bool AreCurvesCompliant { get; set; }
        public List<string> CurrentEccCurves { get; set; }
    }

    public static class EccCurveComparer
    {
        public static EccCurveComparisonResult GetEccCurveComparison()
        {
            // Get current ECC curves from PowerShell and store them in a list
            List<string> currentEccCurves = GetCurrentEccCurves();

            // List of compliant ECC curves to compare against
            List<string> compliantEccCurves = new List<string> { "nistP521", "curve25519", "NistP384", "NistP256" };

            // Compare both arrays for equality in terms of members and their exact position
            bool areCurvesCompliant = currentEccCurves.SequenceEqual(compliantEccCurves, StringComparer.OrdinalIgnoreCase);

            // Create and return the result object
            return new EccCurveComparisonResult
            {
                AreCurvesCompliant = areCurvesCompliant,
                CurrentEccCurves = currentEccCurves
            };
        }

        // Get the current ECC curves from the system
        private static List<string> GetCurrentEccCurves()
        {
            // List to store the current ECC curves
            List<string> currentEccCurvesToOutput = new List<string>();

            // Initialize PowerShell instance
            using (PowerShell powerShell = PowerShell.Create())
            {
                // Add the PowerShell command to get ECC curves
                powerShell.AddCommand("Get-TlsEccCurve");

                // Execute the command and get the result
                var results = powerShell.Invoke();

                // Extract the ECC curves from the results
                foreach (var result in results)
                {
                    // Make sure the result is not null
                    if (result != null)
                    {
                        // Split the result string into an array of substrings based on specified delimiters
                        // new[] { ' ', '\r', '\n' } - An array of characters to use as delimiters: space, carriage return, and newline
                        // StringSplitOptions.RemoveEmptyEntries - An option to remove empty entries from the result array
                        var curves = result.ToString().Split(new[] { ' ', '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                        currentEccCurvesToOutput.AddRange(curves);
                    }
                }
            }

            return currentEccCurvesToOutput;
        }
    }
}
