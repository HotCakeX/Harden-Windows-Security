
#nullable enable

namespace WDACConfig
{
    public class OpusSigner
    {
        public string TBSHash { get; set; }
        public string SubjectCN { get; set; }

        public OpusSigner(string tbsHash, string subjectCN)
        {
            TBSHash = tbsHash;
            SubjectCN = subjectCN;
        }
    }
}
