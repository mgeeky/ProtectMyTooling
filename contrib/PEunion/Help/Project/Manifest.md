# Manifest

A manifest can be included in the output binary. Two templates exist:

* `Default`: A standard manifest with a `requestedExecutionLevel` of `asInvoker`
* `Elevated`: A UAC manifest with a `requestedExecutionLevel` of `requireAdministrator`

In addition to the standard templates, a custom manifest file can be specified. It is advisable to always include a manifest.

If the output binary requires elevated privileges, a UAC manifest should be included.

## Example of mixed elevated / not elevated usage

* One executable is run in-memory (RunPE) and does not require elevated privileges
* Another executable which requires elevated privileges is dropped and executed

If a UAC manifest is included and the user cancels elevation, both executables are **not** run. By not including a UAC manifest, the in-memory execution still takes place. The dropped file will then trigger the UAC dialog.