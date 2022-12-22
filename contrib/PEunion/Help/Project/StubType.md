# Stub

* The native stub is written in assembly and compiled with the FASM compiler
* The .NET stub is written in C# and compiled using CodeDom, targeting either x86 or x64

**Note:** If you want to execute a .NET executable in-memory, use `Invoke` instead of `RunPE`. For this, the .NET stub is required.