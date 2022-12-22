# Drop file

A file is written to disk.

* `Drop Location`: The base directory to write the file in
* `Drop Filename`: The filename of the written file
* `Set File Attributes`: File attributes of the written file

Optionally, this file can be executed:

* `Do not execute`: Just write the file to disk
* `Execute`: Execute using `ShellExecute` using the `open` verb
* `Execute elevated`: Execute using `ShellExecute` using the `runas` verb

If using the `runas` verb and the user does not consent, the file will not be run, but the stub continues execution.

## Example

The stub has two items:

1. `RunPE` a small executable
2. `Drop` a large file to the temp directory and execute