using System.Collections.Generic;
using AppControlManager.SiPolicyIntel;

namespace AppControlManager.IntelGathering;

internal sealed class KernelUserVerdict
{
	public required SSType Verdict { get; set; }
	public required bool IsPE { get; set; }
	public required bool HasSIP { get; set; }
	public required List<string> Imports { get; set; }
}
