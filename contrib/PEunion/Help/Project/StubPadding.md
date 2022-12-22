# Stub Padding

At runtime, the stub decrypts the main shellcode that contains the the "actual" stub and all embedded files.

However, encryption results in high-entropy, which causes AV alerts. Therefore, a low-entropy packing scheme is used. The padding consists of `0x00` bytes that are intermingled with the encrypted shellcode.

`Padding` example values:

* `50`: The compiled file will be about 50% larger **(recommended)**
* `100`: The compiled file will be about twice as large
* `500`: The compiled file will be about 6 times as large

Padding can also be used to simulate a larger file, if required.

**Note:** The size differences may vary by several KB.

**Important:** It is generally advisable to set the padding to about `50` to not cause packer detection due to high entropy. **Compressing** files and applying a padding of **50** afterwards is recommendable.