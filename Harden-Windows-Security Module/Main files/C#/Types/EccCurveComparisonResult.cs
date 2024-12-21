using System.Collections.Generic;

namespace HardenWindowsSecurity;

internal sealed class EccCurveComparisonResult
{
	internal bool AreCurvesCompliant { get; set; }
	internal List<string>? CurrentEccCurves { get; set; }
}
