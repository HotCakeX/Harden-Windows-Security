using System.Collections.Generic;

namespace WDACConfig.IntelGathering
{
    internal sealed class KernelUserVerdict
    {
        public required UserOrKernelMode Verdict { get; set; }
        public required bool IsPE { get; set; }
        public required bool HasSIP { get; set; }
        public required List<string> Imports { get; set; }
    }


    internal enum UserOrKernelMode
    {
        UserMode,
        KernelMode
    }
}
