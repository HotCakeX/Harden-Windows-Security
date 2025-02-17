using System.IO;
using AppControlManager.Others;

namespace AppControlManager.IntelGathering;

public static class PrepareEmptyPolicy
{
	/// <summary>
	/// Copies the empty policy in app resources to the defined directory and returns its new path
	/// </summary>
	/// <param name="directory"></param>
	/// <returns></returns>
	public static string Prepare(string directory)
	{
		string pathToReturn = Path.Combine(directory, "EmptyPolicyFile.xml");

		File.Copy(GlobalVars.EmptyPolicyPath, pathToReturn, true);

		return pathToReturn;
	}
}
