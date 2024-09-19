using System;
using System.IO;
using System.Net.Http;

#nullable enable

namespace WDACConfig
{
    public class DriversBlockRulesFetcher
    {

        /// <summary>
        /// A method to fetch the Vulnerable Driver Block List from the Microsoft servers and deploy it to the system
        /// </summary>
        /// <param name="StagingArea">The directory to use for temporary files</param>
        /// <exception cref="Exception"></exception>
        public static void Fetch(string StagingArea)
        {
            // The location where the downloaded zip file will be saved
            string DownloadSaveLocation = System.IO.Path.Combine(StagingArea, "VulnerableDriverBlockList.zip");

            // The location where the zip file will be extracted
            string ZipExtractionDir = System.IO.Path.Combine(StagingArea, "VulnerableDriverBlockList");

            // The link to download the zip file
            string DriversBlockListZipDownloadLink = "https://aka.ms/VulnerableDriverBlockList";

            // Get the system drive
            string? systemDrive = Environment.GetEnvironmentVariable("SystemDrive");

            // Initialize the final destination of the SiPolicy file
            string SiPolicyFinalDestination;
            if (systemDrive != null)
            {
                // Construct the final destination of the SiPolicy file
                SiPolicyFinalDestination = System.IO.Path.Combine(systemDrive, "Windows", "System32", "CodeIntegrity", "SiPolicy.p7b");
            }
            else
            {
                throw new InvalidOperationException("SystemDrive environment variable is null");
            }

            // Download the zip file
            using (HttpClient client = new())
            {
                // Download the file synchronously
                byte[] fileBytes = client.GetByteArrayAsync(DriversBlockListZipDownloadLink).GetAwaiter().GetResult();
                File.WriteAllBytes(DownloadSaveLocation, fileBytes);
            }

            // Extract the contents of the zip file, overwriting any existing files
            System.IO.Compression.ZipFile.ExtractToDirectory(DownloadSaveLocation, ZipExtractionDir, true);

            // Get the path of the SiPolicy file
            string[] SiPolicyPaths = System.IO.Directory.GetFiles(ZipExtractionDir, "SiPolicy_Enforced.p7b", System.IO.SearchOption.AllDirectories);

            // Make sure to get only one file is there is more than one (which is unexpected)
            string SiPolicyPath = SiPolicyPaths[0];

            // If the SiPolicy file already exists, delete it
            if (File.Exists(SiPolicyFinalDestination))
            {
                File.Delete(SiPolicyFinalDestination);
            }

            // Move the SiPolicy file to the final destination, renaming it in the process
            File.Move(SiPolicyPath, SiPolicyFinalDestination);
        }
    }
}
