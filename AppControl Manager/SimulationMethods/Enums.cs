namespace AppControlManager.SimulationMethods;

internal static class Enums
{
	internal enum MatchLevel
	{
		AllowAllRule, // The policy is a black list, contains allow all rules
		FileHash, // The file is allowed by Authenticode/Page/Flat hash
		CatalogHash, // The file is allowed by Signer and file's signature is on the system in a security catalog
		FilePath, // The file is allowed by its path
		WHQLFilePublisher,
		WHQLPublisher,
		WHQL,
		SignedVersion,
		FilePublisher,
		Publisher,
		PcaCertificateOrRootCertificate,
		LeafCertificate,
		NoMatch // File is Not allowed

	}

	internal enum SpecificFileNamMatchLevel
	{
		OriginalFileName,
		InternalName,
		ProductName,
		FileDescription,
		PackageFamilyName,
		Version,
		NotApplicable
	}
}
