using System;
using System.Collections.Generic;

namespace WDACConfig
{
    public class Signer
    {
        public string ID { get; set; }
        public string Name { get; set; }
        public string CertRoot { get; set; }
        public string CertPublisher { get; set; }
        public string CertIssuer { get; set; }
        public string[] CertEKU { get; set; }
        public string CertOemID { get; set; }
        public string[] FileAttribRef { get; set; }
        public Dictionary<string, Dictionary<string, string>> FileAttrib { get; set; }
        public string SignerScope { get; set; }
        public bool IsWHQL { get; set; }
        public bool IsAllowed { get; set; }
        public bool HasEKU { get; set; }
        public Signer(string id, string name, string certRoot, string certPublisher, string certIssuer,
                      string[] certEKU, string certOemID, string[] fileAttribRef,
                      Dictionary<string, Dictionary<string, string>> fileAttrib,
                      string signerScope, bool isWHQL, bool isAllowed, bool hasEKU)
        {
            ID = id;
            Name = name;
            CertRoot = certRoot;
            CertPublisher = certPublisher;
            CertIssuer = certIssuer;
            CertEKU = certEKU;
            CertOemID = certOemID;
            FileAttribRef = fileAttribRef;
            FileAttrib = fileAttrib;
            SignerScope = signerScope;
            IsWHQL = isWHQL;
            IsAllowed = isAllowed;
            HasEKU = hasEKU;
        }
    }
}
