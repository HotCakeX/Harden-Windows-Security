// Hardening Category results used by the Confirm-SystemCompliance cmdlet

#nullable enable

namespace HardenWindowsSecurity
{
    public sealed class IndividualResult
    {
        public string? FriendlyName { get; set; }
        public bool Compliant { get; set; }
        public string? Value { get; set; }
        public string? Name { get; set; }
        public string? Category { get; set; }
        public string? Method { get; set; }
    }
}
