# Item Source

`Source` is the file to be used.

## Embedded file

The file is embedded in the compiled binary.

### File properties

* `Compress`: The file is stored compressed. This is not recommended for large files, as decompression might exceed memory limits. Compression does not increase executable entropy as all embedded files are encrypted in addition. Use `stub padding` to decrease entropy.
* `Use EOF Data`: If the executable contains data after the end of the file, these bytes are appended to the compiled binary in unencrypted form.

## Download

The file is downloaded from the specified URL.