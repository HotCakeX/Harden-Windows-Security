// Hardening Category results used by the Confirm-SystemCompliance cmdlet
namespace HardeningModule
{
    public class IndividualResult
    {
        public string FriendlyName { get; set; }
        public string Compliant { get; set; }
        public string Value { get; set; }
        public string Name { get; set; }
        public string Category { get; set; }
        public string Method { get; set; }
    }
}
