using System.Collections.Generic;
using AppControlManager.SiPolicyIntel;

namespace AppControlManager.IntelGathering;

internal sealed class KernelUserVerdict
{
	internal required SSType Verdict { get; set; }
	internal required bool IsPE { get; set; }
	internal required bool HasSIP { get; set; }
	internal required List<string> Imports { get; set; }
}
