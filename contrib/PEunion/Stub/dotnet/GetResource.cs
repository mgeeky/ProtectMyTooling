using System;
using System.Reflection;
using System.Resources;

public partial class __Stub
{
	/// <summary>
	/// byte[] GetResource(string name)
	/// </summary>
	public static byte[] __GetResource(string __name)
	{
		Assembly assembly = Assembly.GetExecutingAssembly();
		using (ResourceReader reader = new ResourceReader(assembly.GetManifestResourceStream(assembly.GetManifestResourceNames()[/**/0])))
		{
			// Get resource
			string type;
			byte[] resourceData;
			reader.GetResourceData(__name, out type, out resourceData);

			// The first 4 bytes contain the size of resourceData and must be removed.
			byte[] data = new byte[resourceData.Length - /**/4];
			Buffer.BlockCopy(resourceData, /**/4, data, /**/0, data.Length);

			return data;
		}
	}
}