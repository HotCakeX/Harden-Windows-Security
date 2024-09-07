using System.Collections.Generic;

#nullable enable

namespace WDACConfig
{
    // Used by the BuildSignerAndHashObjects method to store and return the output
    public class FileBasedInfoPackage
    {
        public List<WDACConfig.FilePublisherSignerCreator> FilePublisherSigners { get; set; }
        public List<WDACConfig.PublisherSignerCreator> PublisherSigners { get; set; }
        public List<WDACConfig.HashCreator> CompleteHashes { get; set; }

        public FileBasedInfoPackage(List<WDACConfig.FilePublisherSignerCreator> filepublishersigners, List<WDACConfig.PublisherSignerCreator> publishersigners, List<WDACConfig.HashCreator> completehashes)
        {
            FilePublisherSigners = filepublishersigners;
            PublisherSigners = publishersigners;
            CompleteHashes = completehashes;
        }
    }
}
