
#nullable enable

namespace WDACConfig
{
    public class OpusSigner(string tbsHash, string subjectCN)
    {
        public string TBSHash { get; set; } = tbsHash;
        public string SubjectCN { get; set; } = subjectCN;
    }
}
