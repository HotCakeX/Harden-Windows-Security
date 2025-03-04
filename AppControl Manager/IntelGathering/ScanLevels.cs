namespace AppControlManager.IntelGathering;

// The levels used by the BuildSignerAndHashObjects method
internal enum ScanLevels
{
	FilePublisher,
	Publisher,
	Hash,
	FilePath,
	WildCardFolderPath,
	PFN,
	CustomFileRulePattern
}
