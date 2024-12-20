namespace AppControlManager.SiPolicyIntel;

internal static class BytesArrayComparer
{
	internal static bool AreByteArraysEqual(byte[]? a, byte[]? b)
	{
		if (a is null || b is null)
			return false;

		if (a.Length != b.Length)
			return false;

		for (int i = 0; i < a.Length; i++)
		{
			if (a[i] != b[i])
				return false;
		}

		return true;
	}
}
