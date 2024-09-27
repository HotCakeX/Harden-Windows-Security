using System.Collections.Generic;

#nullable enable

namespace WDACConfig
{
    // Used by the BuildSignerAndHashObjects method to store and return the output
    public class FileBasedInfoPackage(List<WDACConfig.FilePublisherSignerCreator> filepublishersigners, List<WDACConfig.PublisherSignerCreator> publishersigners, List<WDACConfig.HashCreator> completehashes)
    {
        public List<WDACConfig.FilePublisherSignerCreator> FilePublisherSigners { get; set; } = filepublishersigners;
        public List<WDACConfig.PublisherSignerCreator> PublisherSigners { get; set; } = publishersigners;
        public List<WDACConfig.HashCreator> CompleteHashes { get; set; } = completehashes;
    }
}
