using System.Collections.Generic;

#nullable enable

namespace WDACConfig
{
    // Used by the BuildSignerAndHashObjects method to store and return the output
    public class FileBasedInfoPackage(List<FilePublisherSignerCreator> filepublishersigners, List<PublisherSignerCreator> publishersigners, List<HashCreator> completehashes)
    {
        public List<FilePublisherSignerCreator> FilePublisherSigners { get; set; } = filepublishersigners;
        public List<PublisherSignerCreator> PublisherSigners { get; set; } = publishersigners;
        public List<HashCreator> CompleteHashes { get; set; } = completehashes;
    }
}
