#nullable enable

namespace HardenWindowsSecurity
{
    /// <summary>
    /// A class that defines a single compliance check result
    /// </summary>
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
