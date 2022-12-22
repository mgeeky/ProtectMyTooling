# New Filename

The new filename is made of 3 parts:

1. `Filename`: The first part of the new filename
2. `Extension`: The original extension of the file, in reverse character order
3. `Spoofed Extension`: An arbitrary spoofed extension

Due to the right-to-left override character, the `Extension` part is displayed in the middle of the new filename and in reverse character order. However, the `Exact Character Representation` shows that it is still the actual extension of the new file.

Therefore, it cannot be changed. However, some extensions are interchangeable, such as `.exe` and `.scr`. This is why `rcs` appears in the DropDown list when your original file is an `.exe` file.

**Tip:** Try typing different strings into part 1, 2 and 3 and watch the changes in the `Preview` section.