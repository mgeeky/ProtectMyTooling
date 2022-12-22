# RunPE (process hollowing)

A native executable is executed in-memory. For .NET executables, use `Invoke` in a .NET stub

A new process is created in a suspended state. The process memory is replaced with the specified file and the process is resumed. The new process is forked from the originally executed file (the stub). Additionally, the parent process ID is spoofed. Most importantly, the file is not written to disk.

If the file contains EOF data, check `Use EOF Data` to include EOF data in the stub.