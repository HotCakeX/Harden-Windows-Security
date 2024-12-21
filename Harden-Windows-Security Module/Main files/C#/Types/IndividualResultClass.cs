namespace HardenWindowsSecurity;

    /// <summary>
    /// A class that defines a single compliance check result
    /// </summary>
    public sealed class IndividualResult
    {
        public required string FriendlyName { get; set; }
        public required bool Compliant { get; set; }
        public string? Value { get; set; }
        public required string Name { get; set; }
        public required ComplianceCategories Category { get; set; }
        public required ConfirmSystemComplianceMethods.Method Method { get; set; }
    }
