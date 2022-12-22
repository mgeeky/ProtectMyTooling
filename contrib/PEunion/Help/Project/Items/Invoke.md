# Invoke (.NET)

A .NET executable is executed in-memory. This is achieved using built-in language capability:

```
byte[] dotNetExecutable = ....;
Assembly.Load(dotNetExecutable).EntryPoint.Invoke()
```

This feature is only available in a .NET stub. It is recommended to use `Invoke` for .NET executables instead of `RunPE`.