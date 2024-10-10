using System;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

#nullable enable

namespace WDACConfig
{

    // This is to ensure the Serialize method works when trimming is enabled

    /*
    [JsonSerializable(typeof(UserConfiguration))]
    public partial class UserConfigurationContext : JsonSerializerContext
    {
    }
    */


    // Represents an instance of the User configurations JSON settings file
    // Maintains the order of the properties when writing to the JSON file
    // Includes the methods for interacting with user configurations JSON file
    public partial class UserConfiguration(
            string? signedPolicyPath,
            string? unsignedPolicyPath,
            string? signToolCustomPath,
            string? certificateCommonName,
            string? certificatePath,
            Guid? strictKernelPolicyGUID,
            Guid? strictKernelNoFlightRootsPolicyGUID,
            DateTime? lastUpdateCheck,
            DateTime? strictKernelModePolicyTimeOfDeployment
        )
    {
        [JsonPropertyOrder(1)]
        public string? SignedPolicyPath { get; set; } = signedPolicyPath;

        [JsonPropertyOrder(2)]
        public string? UnsignedPolicyPath { get; set; } = unsignedPolicyPath;

        [JsonPropertyOrder(3)]
        public string? SignToolCustomPath { get; set; } = signToolCustomPath;

        [JsonPropertyOrder(4)]
        public string? CertificateCommonName { get; set; } = certificateCommonName;

        [JsonPropertyOrder(5)]
        public string? CertificatePath { get; set; } = certificatePath;

        [JsonPropertyOrder(6)]
        public Guid? StrictKernelPolicyGUID { get; set; } = strictKernelPolicyGUID;

        [JsonPropertyOrder(7)]
        public Guid? StrictKernelNoFlightRootsPolicyGUID { get; set; } = strictKernelNoFlightRootsPolicyGUID;

        [JsonPropertyOrder(8)]
        public DateTime? LastUpdateCheck { get; set; } = lastUpdateCheck;

        [JsonPropertyOrder(9)]
        public DateTime? StrictKernelModePolicyTimeOfDeployment { get; set; } = strictKernelModePolicyTimeOfDeployment;



        // Used by the static methods, when trimming is not enabled
        private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };



        /// <summary>
        /// Sets user configuration settings to the JSON file
        /// By default all params are null, so use named parameters when calling this method for easy invocation
        /// </summary>
        /// <param name="SignedPolicyPath"></param>
        /// <param name="UnsignedPolicyPath"></param>
        /// <param name="SignToolCustomPath"></param>
        /// <param name="CertificateCommonName"></param>
        /// <param name="CertificatePath"></param>
        /// <param name="StrictKernelPolicyGUID"></param>
        /// <param name="StrictKernelNoFlightRootsPolicyGUID"></param>
        /// <param name="LastUpdateCheck"></param>
        /// <param name="StrictKernelModePolicyTimeOfDeployment"></param>
        /// <returns></returns>
        /// <exception cref="InvalidOperationException"></exception>
        public static UserConfiguration Set(
            string? SignedPolicyPath = null,
            string? UnsignedPolicyPath = null,
            string? SignToolCustomPath = null,
            string? CertificateCommonName = null,
            string? CertificatePath = null,
            Guid? StrictKernelPolicyGUID = null,
            Guid? StrictKernelNoFlightRootsPolicyGUID = null,
            DateTime? LastUpdateCheck = null,
            DateTime? StrictKernelModePolicyTimeOfDeployment = null
            )
        {
            // Validate certificateCommonName
            if (!string.IsNullOrWhiteSpace(CertificateCommonName))
            {
                CertCNz certCNz = new();
                string[] certCommonNames = certCNz.GetValidValues();

                if (!certCommonNames.Contains(CertificateCommonName))
                {
                    throw new InvalidOperationException($"{CertificateCommonName} does not belong to a subject CN of any of the deployed certificates");
                }
            }

            // Validate the SignedPolicyPath parameter
            if (!string.IsNullOrWhiteSpace(SignedPolicyPath))
            {
                if (PolicyFileSigningStatusDetection.Check(SignedPolicyPath) is not PolicyFileSigningStatusDetection.SigningStatus.Signed)
                {
                    throw new InvalidOperationException($"The specified policy file '{SignedPolicyPath}' is not signed. Please provide a signed policy file.");
                }
            }

            // Validate the UnsignedPolicyPath parameter
            if (!string.IsNullOrWhiteSpace(UnsignedPolicyPath))
            {
                if (PolicyFileSigningStatusDetection.Check(UnsignedPolicyPath) is PolicyFileSigningStatusDetection.SigningStatus.Signed)
                {
                    throw new InvalidOperationException($"The specified policy file '{UnsignedPolicyPath}' is signed. Please provide an Unsigned policy file.");
                }
            }



            Logger.Write("Trying to parse and read the current user configurations file");
            UserConfiguration UserConfiguration = ReadUserConfiguration();

            // Modify the properties based on the input
            if (!string.IsNullOrWhiteSpace(SignedPolicyPath)) UserConfiguration.SignedPolicyPath = SignedPolicyPath;
            if (!string.IsNullOrWhiteSpace(UnsignedPolicyPath)) UserConfiguration.UnsignedPolicyPath = UnsignedPolicyPath;
            if (!string.IsNullOrWhiteSpace(SignToolCustomPath)) UserConfiguration.SignToolCustomPath = SignToolCustomPath;
            if (!string.IsNullOrWhiteSpace(CertificateCommonName)) UserConfiguration.CertificateCommonName = CertificateCommonName;
            if (!string.IsNullOrWhiteSpace(CertificatePath)) UserConfiguration.CertificatePath = CertificatePath;
            if (StrictKernelPolicyGUID.HasValue) UserConfiguration.StrictKernelPolicyGUID = StrictKernelPolicyGUID;
            if (StrictKernelNoFlightRootsPolicyGUID.HasValue) UserConfiguration.StrictKernelNoFlightRootsPolicyGUID = StrictKernelNoFlightRootsPolicyGUID;
            if (LastUpdateCheck.HasValue) UserConfiguration.LastUpdateCheck = LastUpdateCheck;
            if (StrictKernelModePolicyTimeOfDeployment.HasValue) UserConfiguration.StrictKernelModePolicyTimeOfDeployment = StrictKernelModePolicyTimeOfDeployment;

            // Write the updated properties back to the JSON file
            WriteUserConfiguration(UserConfiguration);

            return UserConfiguration;
        }




        public static UserConfiguration Get()
        {
            // Read the current configuration
            UserConfiguration currentConfig = ReadUserConfiguration();
            return currentConfig;
        }




        public static void Remove(
        bool SignedPolicyPath = false,
        bool UnsignedPolicyPath = false,
        bool SignToolCustomPath = false,
        bool CertificateCommonName = false,
        bool CertificatePath = false,
        bool StrictKernelPolicyGUID = false,
        bool StrictKernelNoFlightRootsPolicyGUID = false,
        bool LastUpdateCheck = false,
        bool StrictKernelModePolicyTimeOfDeployment = false
        )
        {
            // Read the current configuration
            UserConfiguration currentConfig = ReadUserConfiguration();

            // Remove properties by setting them to null based on the specified flags
            if (SignedPolicyPath) currentConfig.SignedPolicyPath = null;
            if (UnsignedPolicyPath) currentConfig.UnsignedPolicyPath = null;
            if (SignToolCustomPath) currentConfig.SignToolCustomPath = null;
            if (CertificateCommonName) currentConfig.CertificateCommonName = null;
            if (CertificatePath) currentConfig.CertificatePath = null;
            if (StrictKernelPolicyGUID) currentConfig.StrictKernelPolicyGUID = null;
            if (StrictKernelNoFlightRootsPolicyGUID) currentConfig.StrictKernelNoFlightRootsPolicyGUID = null;
            if (LastUpdateCheck) currentConfig.LastUpdateCheck = null;
            if (StrictKernelModePolicyTimeOfDeployment) currentConfig.StrictKernelModePolicyTimeOfDeployment = null;

            // Write the updated configuration back to the JSON file
            WriteUserConfiguration(currentConfig);

            Logger.Write("The specified properties have been removed and set to null in the UserConfigurations.json file.");
        }


        private static UserConfiguration ReadUserConfiguration()
        {
            try
            {

                // Create the WDACConfig folder in Program Files if it doesn't exist
                if (!Directory.Exists(GlobalVars.UserConfigDir))
                {
                    _ = Directory.CreateDirectory(GlobalVars.UserConfigDir);
                    Logger.Write("The WDACConfig folder in Program Files has been created because it did not exist.");
                }

                // Create User configuration folder in the WDACConfig folder if it doesn't already exist
                string UserConfigDir = Path.Combine(GlobalVars.UserConfigDir, "UserConfigurations");
                if (!Directory.Exists(UserConfigDir))
                {
                    _ = Directory.CreateDirectory(UserConfigDir);
                    Logger.Write("The WDACConfig folder in Program Files has been created because it did not exist.");
                }

                // Read the JSON file
                string json = File.ReadAllText(GlobalVars.UserConfigJson);
                return ParseJson(json);
            }
            catch (Exception ex)
            {
                // Log the error if JSON is corrupted or any other error occurs
                Logger.Write($"Error reading or parsing the user configuration file: {ex.Message}. A new configuration with default values will be created.");

                // Create a new configuration with default values and write it to the file
                UserConfiguration defaultConfig = new(null, null, null, null, null, null, null, null, null);
                WriteUserConfiguration(defaultConfig);

                return defaultConfig;
            }
        }


        private static UserConfiguration ParseJson(string json)
        {
            using JsonDocument doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            return new UserConfiguration(
                TryGetStringProperty(root, "SignedPolicyPath"),
                TryGetStringProperty(root, "UnsignedPolicyPath"),
                TryGetStringProperty(root, "SignToolCustomPath"),
                TryGetStringProperty(root, "CertificateCommonName"),
                TryGetStringProperty(root, "CertificatePath"),

                TryGetGuidProperty(root, "StrictKernelPolicyGUID"),
                TryGetGuidProperty(root, "StrictKernelNoFlightRootsPolicyGUID"),

                TryGetDateTimeProperty(root, "LastUpdateCheck"),
                TryGetDateTimeProperty(root, "StrictKernelModePolicyTimeOfDeployment")
            );

            static string? TryGetStringProperty(JsonElement root, string propertyName)
            {
                try
                {
                    return root.TryGetProperty(propertyName, out var propertyValue) ? propertyValue.GetString() : null;
                }
                catch
                {
                    return null;
                }
            }

            static Guid? TryGetGuidProperty(JsonElement root, string propertyName)
            {
                try
                {
                    return root.TryGetProperty(propertyName, out var propertyValue) ? Guid.TryParse(propertyValue.GetString(), out var guid) ? guid : null : null;
                }
                catch
                {
                    return null;
                }
            }

            static DateTime? TryGetDateTimeProperty(JsonElement root, string propertyName)
            {
                try
                {
                    return root.TryGetProperty(propertyName, out var propertyValue) ? propertyValue.GetDateTime() : null;
                }
                catch
                {
                    return null;
                }
            }

        }

        private static void WriteUserConfiguration(UserConfiguration userConfiguration)
        {
            // Create a JSON object from the UserConfiguration properties
            var json = new
            {
                SignedPolicyPath = userConfiguration.SignedPolicyPath,
                UnsignedPolicyPath = userConfiguration.UnsignedPolicyPath,
                SignToolCustomPath = userConfiguration.SignToolCustomPath,
                CertificateCommonName = userConfiguration.CertificateCommonName,
                CertificatePath = userConfiguration.CertificatePath,
                StrictKernelPolicyGUID = userConfiguration.StrictKernelPolicyGUID?.ToString(),
                StrictKernelNoFlightRootsPolicyGUID = userConfiguration.StrictKernelNoFlightRootsPolicyGUID?.ToString(),
                LastUpdateCheck = userConfiguration.LastUpdateCheck?.ToString("o"),
                StrictKernelModePolicyTimeOfDeployment = userConfiguration.StrictKernelModePolicyTimeOfDeployment?.ToString("o")
            };

            // Serialize the object to JSON using the new context
            // Trimming enabled
            // string jsonString = JsonSerializer.Serialize(json, UserConfigurationContext.Default.UserConfiguration);


            // Serialize the object to JSON
            // Trimming disabled
            string jsonString = JsonSerializer.Serialize(json, UserConfiguration.JsonOptions);

            // Write the JSON string to the file
            File.WriteAllText(GlobalVars.UserConfigJson, jsonString);
            Logger.Write("The UserConfigurations.json file has been updated successfully.");
        }

    }
}
