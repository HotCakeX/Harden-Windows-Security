using System.Collections.Generic;

namespace AppControlManager.Others;

// Used by the BuildSignerAndHashObjects method to store and return the output
internal sealed class FileBasedInfoPackage(List<FilePublisherSignerCreator> filepublishersigners, List<PublisherSignerCreator> publishersigners, List<HashCreator> completehashes)
{
	internal List<FilePublisherSignerCreator> FilePublisherSigners { get; set; } = filepublishersigners;
	internal List<PublisherSignerCreator> PublisherSigners { get; set; } = publishersigners;
	internal List<HashCreator> CompleteHashes { get; set; } = completehashes;
}
