using System.Collections.Generic;

#nullable enable

namespace WDACConfig
{
    public class Signer(string id, string name, string certRoot, string? certPublisher, string? certIssuer,
                  string[]? certEKU, string? certOemID, string[]? fileAttribRef,
                  Dictionary<string, Dictionary<string, string>>? fileAttrib,
                  string signerScope, bool isWHQL, bool isAllowed, bool hasEKU)
    {
        public string ID { get; set; } = id;
        public string Name { get; set; } = name;
        public string CertRoot { get; set; } = certRoot;
        public string? CertPublisher { get; set; } = certPublisher;
        public string? CertIssuer { get; set; } = certIssuer;
        public string[]? CertEKU { get; set; } = certEKU;
        public string? CertOemID { get; set; } = certOemID;
        public string[]? FileAttribRef { get; set; } = fileAttribRef;
        public Dictionary<string, Dictionary<string, string>>? FileAttrib { get; set; } = fileAttrib;
        public string SignerScope { get; set; } = signerScope;
        public bool IsWHQL { get; set; } = isWHQL;
        public bool IsAllowed { get; set; } = isAllowed;
        public bool HasEKU { get; set; } = hasEKU;
    }
}
