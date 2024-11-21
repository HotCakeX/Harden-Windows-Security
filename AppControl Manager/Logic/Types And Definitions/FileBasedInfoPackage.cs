using System.Collections.Generic;

namespace WDACConfig
{
    // Used by the BuildSignerAndHashObjects method to store and return the output
    public sealed class FileBasedInfoPackage(List<FilePublisherSignerCreator> filepublishersigners, List<PublisherSignerCreator> publishersigners, List<HashCreator> completehashes)
    {
        public List<FilePublisherSignerCreator> FilePublisherSigners { get; set; } = filepublishersigners;
        public List<PublisherSignerCreator> PublisherSigners { get; set; } = publishersigners;
        public List<HashCreator> CompleteHashes { get; set; } = completehashes;
    }
}
