namespace AppControlManager.Others;

internal sealed class OpusSigner(string tbsHash, string subjectCN)
{
	internal string TBSHash { get; set; } = tbsHash;
	internal string SubjectCN { get; set; } = subjectCN;
}
