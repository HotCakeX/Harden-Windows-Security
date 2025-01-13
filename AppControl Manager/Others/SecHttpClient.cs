using System.Net;
using System.Net.Http;

namespace AppControlManager.Others;

/// <summary>
/// This class enforces minimum HTTP version of 2.0 and is future proof since it tries the highest available HTTP version by default
/// </summary>
internal sealed partial class SecHttpClient : HttpClient
{
	internal SecHttpClient() : base()
	{
		DefaultRequestVersion = HttpVersion.Version20;
		DefaultVersionPolicy = HttpVersionPolicy.RequestVersionOrHigher;
	}
}
