using System;
using System.Collections.Generic;

#nullable enable

namespace HardenWindowsSecurity
{
    // Class to represent a policy with various attributes
    public sealed class CiPolicyInfo
    {
        public string? PolicyID { get; set; }           // Unique identifier for the policy
        public string? BasePolicyID { get; set; }       // Identifier for the base policy
        public string? FriendlyName { get; set; }       // Human-readable name of the policy
        public Version? Version { get; set; }           // Version object representing the policy version
        public string? VersionString { get; set; }      // Original version string from the policy data
        public bool IsSystemPolicy { get; set; }        // Indicates if it's a system policy
        public bool IsSignedPolicy { get; set; }        // Indicates if the policy is signed
        public bool IsOnDisk { get; set; }              // Indicates if the policy is present on disk
        public bool IsEnforced { get; set; }            // Indicates if the policy is enforced
        public bool IsAuthorized { get; set; }          // Indicates if the policy is authorized
        public List<string>? PolicyOptions { get; set; }// List of options or settings related to the policy
    }
}
