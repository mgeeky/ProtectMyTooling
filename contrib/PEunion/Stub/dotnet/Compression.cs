using System.IO;
using System.IO.Compression;

public partial class __Stub
{
	/// <summary>
	/// byte[] Decompress(byte[] data)
	/// </summary>
	public static byte[] __Decompress(byte[] __data)
	{
		// Decompress data using GZip
		using (MemoryStream memoryStream = new MemoryStream())
		{
			using (GZipStream gzipStream = new GZipStream(new MemoryStream(__data), CompressionMode.Decompress))
			{
				gzipStream.CopyTo(memoryStream);
			}

			return memoryStream.ToArray();
		}
	}
}