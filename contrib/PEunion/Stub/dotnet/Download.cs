using System.Net;

public partial class __Stub
{
	/// <summary>
	/// byte[] Download(string url)
	/// </summary>
	public static byte[] __Download(string __url)
	{
		// Disable SSL / TLS checks
		foreach (int protocol in new[]
		{
			/**/48, // SSL3
			/**/192, // TLS
			/**/768, // TLS 1.1
			/**/3072, // TLS 1.2
			/**/12288, // TLS 1.3
		})
		{
			try
			{
				ServicePointManager.SecurityProtocol |= (SecurityProtocolType)protocol;
			}
			catch
			{
			}
		}

		// Download file
		using (WebClient webClient = new WebClient())
		{
			return webClient.DownloadData(__url);
		}
	}
}