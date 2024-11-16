using System.Xml;

namespace WDACConfig
{
    // This class represents a <FileAttrib> node within a Code Integrity XML file
    public sealed class FileAttrib
    {
        public required XmlNode Node { get; set; }
        public required XmlNode Signer { get; set; }
        public required XmlNode AllowedSigner { get; set; }
        public required XmlNode FileAttribRef { get; set; }
        public required string Id { get; set; }
        public string? MinimumFileVersion { get; set; }
        public string? FileDescription { get; set; }
        public string? FileName { get; set; }
        public string? InternalName { get; set; }
        public string? FilePath { get; set; }
        public string? ProductName { get; set; }
    }
}
