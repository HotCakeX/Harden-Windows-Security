using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml;

#nullable enable

namespace WDACConfig
{
    public class CiRuleOptions
    {

        public enum PolicyTemplate
        {
            Base,
            BaseISG,
            BaseKernel,
            Supplemental
        }

        public enum PolicyRuleOptions
        {
            EnabledUMCI = 0,
            EnabledBootMenuProtection = 1,
            RequiredWHQL = 2,
            EnabledAuditMode = 3,
            DisabledFlightSigning = 4,
            EnabledInheritDefaultPolicy = 5,
            EnabledUnsignedSystemIntegrityPolicy = 6,
            RequiredEVSigners = 8,
            EnabledAdvancedBootOptionsMenu = 9,
            EnabledBootAuditOnFailure = 10,
            DisabledScriptEnforcement = 11,
            RequiredEnforceStoreApplications = 12,
            EnabledManagedInstaller = 13,
            EnabledIntelligentSecurityGraphAuthorization = 14,
            EnabledInvalidateEAsOnReboot = 15,
            EnabledUpdatePolicyNoReboot = 16,
            EnabledAllowSupplementalPolicies = 17,
            DisabledRuntimeFilePathRuleProtection = 18,
            EnabledDynamicCodeSecurity = 19,
            EnabledRevokedExpiredAsUnsigned = 20,
            EnabledDeveloperModeDynamicCodeTrust = 100,
            EnabledSecureSettingPolicy = 102,
            EnabledConditionalWindowsLockdownPolicy = 103
        }


        // Mapping enum values to custom string representations that match rule options in the policy XML file
        // Since they include colons and spaces, cannot be included in the enum
        internal readonly static Dictionary<string, int> PolicyRuleOptionsActual = new()
        {
            { "Enabled:UMCI", (int)PolicyRuleOptions.EnabledUMCI },
            { "Enabled:Boot Menu Protection", (int)PolicyRuleOptions.EnabledBootMenuProtection },
            { "Required:WHQL", (int)PolicyRuleOptions.RequiredWHQL },
            { "Enabled:Audit Mode", (int)PolicyRuleOptions.EnabledAuditMode },
            { "Disabled:Flight Signing", (int)PolicyRuleOptions.DisabledFlightSigning },
            { "Enabled:Inherit Default Policy", (int)PolicyRuleOptions.EnabledInheritDefaultPolicy },
            { "Enabled:Unsigned System Integrity Policy", (int)PolicyRuleOptions.EnabledUnsignedSystemIntegrityPolicy },
            { "Required:EV Signers", (int)PolicyRuleOptions.RequiredEVSigners },
            { "Enabled:Advanced Boot Options Menu", (int)PolicyRuleOptions.EnabledAdvancedBootOptionsMenu },
            { "Enabled:Boot Audit On Failure", (int)PolicyRuleOptions.EnabledBootAuditOnFailure },
            { "Disabled:Script Enforcement", (int)PolicyRuleOptions.DisabledScriptEnforcement },
            { "Required:Enforce Store Applications", (int)PolicyRuleOptions.RequiredEnforceStoreApplications },
            { "Enabled:Managed Installer", (int)PolicyRuleOptions.EnabledManagedInstaller },
            { "Enabled:Intelligent Security Graph Authorization", (int)PolicyRuleOptions.EnabledIntelligentSecurityGraphAuthorization },
            { "Enabled:Invalidate EAs on Reboot", (int)PolicyRuleOptions.EnabledInvalidateEAsOnReboot },
            { "Enabled:Update Policy No Reboot", (int)PolicyRuleOptions.EnabledUpdatePolicyNoReboot },
            { "Enabled:Allow Supplemental Policies", (int)PolicyRuleOptions.EnabledAllowSupplementalPolicies },
            { "Disabled:Runtime FilePath Rule Protection", (int)PolicyRuleOptions.DisabledRuntimeFilePathRuleProtection },
            { "Enabled:Dynamic Code Security", (int)PolicyRuleOptions.EnabledDynamicCodeSecurity },
            { "Enabled:Revoked Expired As Unsigned", (int)PolicyRuleOptions.EnabledRevokedExpiredAsUnsigned },
            { "Enabled:Developer Mode Dynamic Code Trust", (int)PolicyRuleOptions.EnabledDeveloperModeDynamicCodeTrust },
            { "Enabled:Secure Setting Policy", (int)PolicyRuleOptions.EnabledSecureSettingPolicy },
            { "Enabled:Conditional Windows Lockdown Policy", (int)PolicyRuleOptions.EnabledConditionalWindowsLockdownPolicy }
        };


        internal readonly static Dictionary<int, string> PolicyRuleOptionsActualInverted = new()
        {
            { (int)PolicyRuleOptions.EnabledUMCI, "Enabled:UMCI" },
            { (int)PolicyRuleOptions.EnabledBootMenuProtection, "Enabled:Boot Menu Protection" },
            { (int)PolicyRuleOptions.RequiredWHQL, "Required:WHQL" },
            { (int)PolicyRuleOptions.EnabledAuditMode, "Enabled:Audit Mode" },
            { (int)PolicyRuleOptions.DisabledFlightSigning, "Disabled:Flight Signing" },
            { (int)PolicyRuleOptions.EnabledInheritDefaultPolicy, "Enabled:Inherit Default Policy" },
            { (int)PolicyRuleOptions.EnabledUnsignedSystemIntegrityPolicy, "Enabled:Unsigned System Integrity Policy" },
            { (int)PolicyRuleOptions.RequiredEVSigners, "Required:EV Signers" },
            { (int)PolicyRuleOptions.EnabledAdvancedBootOptionsMenu, "Enabled:Advanced Boot Options Menu" },
            { (int)PolicyRuleOptions.EnabledBootAuditOnFailure, "Enabled:Boot Audit On Failure" },
            { (int)PolicyRuleOptions.DisabledScriptEnforcement, "Disabled:Script Enforcement" },
            { (int)PolicyRuleOptions.RequiredEnforceStoreApplications, "Required:Enforce Store Applications" },
            { (int)PolicyRuleOptions.EnabledManagedInstaller, "Enabled:Managed Installer" },
            { (int)PolicyRuleOptions.EnabledIntelligentSecurityGraphAuthorization, "Enabled:Intelligent Security Graph Authorization" },
            { (int)PolicyRuleOptions.EnabledInvalidateEAsOnReboot, "Enabled:Invalidate EAs on Reboot" },
            { (int)PolicyRuleOptions.EnabledUpdatePolicyNoReboot, "Enabled:Update Policy No Reboot" },
            { (int)PolicyRuleOptions.EnabledAllowSupplementalPolicies, "Enabled:Allow Supplemental Policies" },
            { (int)PolicyRuleOptions.DisabledRuntimeFilePathRuleProtection, "Disabled:Runtime FilePath Rule Protection" },
            { (int)PolicyRuleOptions.EnabledDynamicCodeSecurity, "Enabled:Dynamic Code Security" },
            { (int)PolicyRuleOptions.EnabledRevokedExpiredAsUnsigned, "Enabled:Revoked Expired As Unsigned" },
            { (int)PolicyRuleOptions.EnabledDeveloperModeDynamicCodeTrust, "Enabled:Developer Mode Dynamic Code Trust" },
            { (int)PolicyRuleOptions.EnabledSecureSettingPolicy, "Enabled:Secure Setting Policy" },
            { (int)PolicyRuleOptions.EnabledConditionalWindowsLockdownPolicy, "Enabled:Conditional Windows Lockdown Policy" }
        };


        #region
        // Defining the rule options for each policy type and scenario

        private readonly static HashSet<int> BaseRules = [
            (int)PolicyRuleOptions.EnabledUMCI,
            (int)PolicyRuleOptions.RequiredWHQL,
            (int)PolicyRuleOptions.EnabledInheritDefaultPolicy,
            (int)PolicyRuleOptions.EnabledUnsignedSystemIntegrityPolicy,
            (int)PolicyRuleOptions.DisabledScriptEnforcement,
            (int)PolicyRuleOptions.RequiredEnforceStoreApplications,
            (int)PolicyRuleOptions.EnabledUpdatePolicyNoReboot,
            (int)PolicyRuleOptions.EnabledAllowSupplementalPolicies,
            (int)PolicyRuleOptions.EnabledDynamicCodeSecurity,
            (int)PolicyRuleOptions.EnabledRevokedExpiredAsUnsigned
        ];

        private readonly static HashSet<int> BaseISGRules = [
            (int)PolicyRuleOptions.EnabledUMCI,
            (int)PolicyRuleOptions.RequiredWHQL,
            (int)PolicyRuleOptions.EnabledInheritDefaultPolicy,
            (int)PolicyRuleOptions.EnabledUnsignedSystemIntegrityPolicy,
            (int)PolicyRuleOptions.DisabledScriptEnforcement,
            (int)PolicyRuleOptions.RequiredEnforceStoreApplications,
            (int)PolicyRuleOptions.EnabledIntelligentSecurityGraphAuthorization,
            (int)PolicyRuleOptions.EnabledInvalidateEAsOnReboot,
            (int)PolicyRuleOptions.EnabledUpdatePolicyNoReboot,
            (int)PolicyRuleOptions.EnabledAllowSupplementalPolicies,
            (int)PolicyRuleOptions.EnabledDynamicCodeSecurity,
            (int)PolicyRuleOptions.EnabledRevokedExpiredAsUnsigned
        ];

        private readonly static HashSet<int> BaseKernelModeRules = [
            (int)PolicyRuleOptions.RequiredWHQL,
            (int)PolicyRuleOptions.EnabledInheritDefaultPolicy,
            (int)PolicyRuleOptions.EnabledUnsignedSystemIntegrityPolicy,
            (int)PolicyRuleOptions.EnabledUpdatePolicyNoReboot,
            (int)PolicyRuleOptions.EnabledAllowSupplementalPolicies,
            (int)PolicyRuleOptions.EnabledRevokedExpiredAsUnsigned
        ];

        private readonly static HashSet<int> SupplementalRules = [
            (int)PolicyRuleOptions.EnabledUnsignedSystemIntegrityPolicy,
            (int)PolicyRuleOptions.DisabledRuntimeFilePathRuleProtection
        ];

        private readonly static HashSet<int> RequireWHQLRules = [(int)PolicyRuleOptions.RequiredWHQL];
        private readonly static HashSet<int> EnableAuditModeRules = [(int)PolicyRuleOptions.EnabledAuditMode];
        private readonly static HashSet<int> DisableFlightSigningRules = [(int)PolicyRuleOptions.DisabledFlightSigning];
        private readonly static HashSet<int> RequireEVSignersRules = [(int)PolicyRuleOptions.RequiredEVSigners];
        private readonly static HashSet<int> ScriptEnforcementRules = [(int)PolicyRuleOptions.DisabledScriptEnforcement];
        private readonly static HashSet<int> TestModeRules = [(int)PolicyRuleOptions.EnabledAdvancedBootOptionsMenu, (int)PolicyRuleOptions.EnabledBootAuditOnFailure];
        #endregion


        /// <summary>
        /// Configures the Policy rule options in a given XML file and sets the HVCI to Strict in the output XML file.
        /// It offers many ways to configure the policy rule options in a given XML file.
        /// All of its various parameters provide the flexibility that ensures only one pass is needed to configure the policy rule options.
        /// First the template is processed, then the individual boolean parameters, and finally the individual rules to add and remove.
        /// </summary>
        /// <param name="filePath">  Specifies the path to the XML file that contains the CI policy rules </param>
        /// <param name="template"> Specifies the template to use for the CI policy rules </param>
        /// <param name="rulesToAdd"> Specifies the rule options to add to the policy XML file </param>
        /// <param name="rulesToRemove">  Specifies the rule options to remove from the policy XML file </param>
        /// <param name="RequireWHQL"> Specifies whether to require WHQL signatures for all drivers </param>
        /// <param name="EnableAuditMode"> Specifies whether to enable audit mode </param>
        /// <param name="DisableFlightSigning"> Specifies whether to disable flight signing </param>
        /// <param name="RequireEVSigners"> Specifies whether to require EV signers </param>
        /// <param name="ScriptEnforcement"> Specifies whether to disable script enforcement </param>
        /// <param name="TestMode"> Specifies whether to enable test mode </param>
        /// <param name="RemoveAll"> Removes all the existing rule options from the policy XML file </param>
        /// <exception cref="InvalidOperationException"></exception>
        public static void Set(
            string filePath,
            PolicyTemplate? template = null,
            PolicyRuleOptions[]? rulesToAdd = null,
            PolicyRuleOptions[]? rulesToRemove = null,
            bool? RequireWHQL = null,
            bool? EnableAuditMode = null,
            bool? DisableFlightSigning = null,
            bool? RequireEVSigners = null,
            bool? ScriptEnforcement = null,
            bool? TestMode = null,
            bool? RemoveAll = null
            )
        {

            Logger.Write($"Configuring the policy rule options for: {filePath}");

            XmlDocument xmlDocument = new();
            xmlDocument.Load(filePath);

            // Create namespace manager and add the default namespace with a prefix
            XmlNamespaceManager namespaceManager = new(xmlDocument.NameTable);
            namespaceManager.AddNamespace("ns", "urn:schemas-microsoft-com:sipolicy");

            // Get SiPolicy node
            XmlNode siPolicyNode = xmlDocument.SelectSingleNode("ns:SiPolicy", namespaceManager)
                ?? throw new InvalidOperationException("Invalid XML structure, SiPolicy node not found");

            // Store the type of the policy in a variable
            string PolicyType = siPolicyNode.Attributes?["PolicyType"]?.Value ?? throw new InvalidOperationException("Policy type attribute does not exist in the selected policy");

            // Find the Rules Node
            XmlNode? RulesNode = siPolicyNode.SelectSingleNode("ns:Rules", namespaceManager);

            // An empty dictionary to store the existing rule options in the XML policy file
            Dictionary<int, string> ExistingRuleOptions = [];

            // The final rule options to implement which contains only unique values
            HashSet<int> RuleOptionsToImplement = [];

            // A flag to determine whether to clear all the existing rules based on the input parameters
            bool ClearAllRules = false;

            if (template is not null || RemoveAll is not null)
            {
                ClearAllRules = true;
            }

            // To store the current policy rules nodes
            XmlNodeList? currentPolicyRules = null;

            if (RulesNode is not null)
            {
                // Get all of the current policy <Rule> nodes in the <Rules> node
                currentPolicyRules = RulesNode.SelectNodes("ns:Rule", namespaceManager);
            }

            if (currentPolicyRules is not null)
            {

                // Iterating through each <Rule> node in the supplied XML file
                foreach (XmlNode rule in currentPolicyRules)
                {
                    // Get the option text from the <Option> node
                    XmlNode? optionNode = rule.SelectSingleNode("ns:Option", namespaceManager);
                    string OptionText = optionNode!.InnerText;


                    // Check if the option text exists in the PolicyRuleOptionsActual dictionary
                    if (PolicyRuleOptionsActual.TryGetValue(OptionText, out int parsedValue))
                    {
                        // Add the option text and its corresponding int value to the dictionary
                        _ = ExistingRuleOptions.TryAdd(parsedValue, OptionText);
                    }
                }

            }

            if (!ClearAllRules && ExistingRuleOptions.Keys.Count > 0)
            {
                // Add the existing rule options to the final rule options to implement
                RuleOptionsToImplement.UnionWith(ExistingRuleOptions.Keys);
            }
            else
            {
                RuleOptionsToImplement.Clear();
            }


            // Process selected templates
            switch (template)
            {
                case PolicyTemplate.Base:
                    RuleOptionsToImplement.UnionWith(BaseRules);
                    break;
                case PolicyTemplate.BaseISG:
                    RuleOptionsToImplement.UnionWith(BaseISGRules);
                    break;
                case PolicyTemplate.BaseKernel:
                    RuleOptionsToImplement.UnionWith(BaseKernelModeRules);
                    break;
                case PolicyTemplate.Supplemental:
                    RuleOptionsToImplement.UnionWith(SupplementalRules);
                    break;
                default:
                    break;
            }



            #region Process individual boolean parameters

            // if RequireWHQL is not null and is explicitly set to true
            if (RequireWHQL == true)
            {
                RuleOptionsToImplement.UnionWith(RequireWHQLRules);
            }
            // if RequireWHQL is not null and is explicitly set to false
            if (RequireWHQL == false)
            {
                RuleOptionsToImplement.ExceptWith(RequireWHQLRules);
            }

            // Same logic for the rest, if any of these are null, they are skipped
            if (EnableAuditMode == true)
            {
                RuleOptionsToImplement.UnionWith(EnableAuditModeRules);
            }
            if (EnableAuditMode == false)
            {
                RuleOptionsToImplement.ExceptWith(EnableAuditModeRules);
            }

            if (DisableFlightSigning == true)
            {
                RuleOptionsToImplement.UnionWith(DisableFlightSigningRules);
            }
            if (DisableFlightSigning == false)
            {
                RuleOptionsToImplement.ExceptWith(DisableFlightSigningRules);
            }

            if (RequireEVSigners == true)
            {
                RuleOptionsToImplement.UnionWith(RequireEVSignersRules);
            }
            if (RequireEVSigners == false)
            {
                RuleOptionsToImplement.ExceptWith(RequireEVSignersRules);
            }

            if (ScriptEnforcement == false)
            {
                RuleOptionsToImplement.UnionWith(ScriptEnforcementRules);
            }
            if (ScriptEnforcement == true)
            {
                RuleOptionsToImplement.ExceptWith(ScriptEnforcementRules);
            }

            if (TestMode == true)
            {
                RuleOptionsToImplement.UnionWith(TestModeRules);
            }
            if (TestMode == false)
            {
                RuleOptionsToImplement.ExceptWith(TestModeRules);
            }
            #endregion


            // Process individual rules to add
            if (rulesToAdd is not null)
            {
                foreach (PolicyRuleOptions rule in rulesToAdd)
                {
                    _ = RuleOptionsToImplement.Add((int)rule);
                }
            }

            // Process individual rules to remove
            if (rulesToRemove is not null)
            {
                foreach (PolicyRuleOptions rule in rulesToRemove)
                {
                    _ = RuleOptionsToImplement.Remove((int)rule);
                }
            }


            // Make sure Supplemental policies only contain rule options that are applicable to them
            if ((template is not null && template is PolicyTemplate.Supplemental) || string.Equals(PolicyType, "Supplemental Policy", StringComparison.OrdinalIgnoreCase))
            {
                List<int> SupplementalPolicyAllowedRuleOptions = [18, 14, 13, 7, 5, 6];

                foreach (int rule in RuleOptionsToImplement)
                {
                    if (!SupplementalPolicyAllowedRuleOptions.Contains(rule))
                    {
                        _ = RuleOptionsToImplement.Remove(rule);
                    }
                }
            }


            #region Compare the existing rule options in the policy XML file with the rule options to implement

            // Get keys from the ExistingRuleOptions dictionary
            var existingRuleKeys = ExistingRuleOptions.Keys.ToArray();

            // Find elements in RuleOptionsToImplement that are not in ExistingRuleOptions.Keys
            var toAdd = RuleOptionsToImplement.Except(existingRuleKeys);

            // Find elements in ExistingRuleOptions.Keys that are not in RuleOptionsToImplement
            var toRemove = existingRuleKeys.Except(RuleOptionsToImplement);

            foreach (var option in toAdd)
            {
                _ = PolicyRuleOptionsActualInverted.TryGetValue(option, out string? parsed);

                Logger.Write($"Adding Rule Option: {parsed}");
            }

            foreach (var option in toRemove)
            {
                _ = PolicyRuleOptionsActualInverted.TryGetValue(option, out string? parsed);

                Logger.Write($"Removing Rule Option: {parsed}");
            }
            #endregion


            // Always remove any existing rule options initially. The calculations determining which
            // Rules must be included in the policy are all made in this method.
            if (RulesNode is not null)
            {
                RulesNode.RemoveAll();
            }


            // Convert the HashSet to a List and sort it
            List<int> RuleOptionsToImplementSorted = [.. RuleOptionsToImplement];
            RuleOptionsToImplementSorted.Sort();


            if (RulesNode is null)
            {
                throw new InvalidOperationException("Rules node is null!");
            }

            // Create new Rule elements
            foreach (int num in RuleOptionsToImplementSorted)
            {
                // Create a new rule element
                XmlElement NewRuleNode = xmlDocument.CreateElement("Rule", RulesNode.NamespaceURI);

                // Create the Option element inside of the rule element
                XmlElement OptionNode = xmlDocument.CreateElement("Option", RulesNode.NamespaceURI);

                _ = PolicyRuleOptionsActualInverted.TryGetValue(num, out string? innerText);

                // Set the value of the Option element
                OptionNode.InnerText = innerText!;

                // Append the Option element to the Rule element
                _ = NewRuleNode.AppendChild(OptionNode);

                // Add the new Rule element to the Rules node
                _ = RulesNode.AppendChild(NewRuleNode);

            }

            // Save the XML
            xmlDocument.Save(filePath);

            // Close the empty XML nodes
            CloseEmptyXmlNodesSemantic.Close(filePath);

            // Set the HVCI to Strict
            UpdateHvciOptions.Update(filePath);

            // Validate the XML file at the end
            if (!(bool)CiPolicyTest.TestCiPolicy(filePath, null)!)
            {
                throw new InvalidOperationException("The XML file created at the end is not compliant with the CI policy schema");
            }
        }
    }
}
