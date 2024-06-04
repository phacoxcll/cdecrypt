# CDecrypt

### Description

A utility that decrypts Wii U NUS content files.

### Details

This is a fork of a fork made by [VitaSmith](https://github.com/VitaSmith/cdecrypt) of the CDecrypt originally made by [Crediar](https://code.google.com/archive/p/cdecrypt/) intended for modders who want to explore or modify the content of the Wii U applications they own.

Unlike other clones, this version of cdecrypt has **no** external dependencies such as OpenSSL libraries and whatnot: A single executable file is all you need.
It also supports international characters, does not need to reside in the same directory as the NUS content, and can be compiled for Linux or macOS.

### Usage

You can use a `keys.txt` file so you don't have to enter the common key every time.

```
cdecrypt [common key] <TMD or TIK file> <TMD or TIK file>
```

If an existing file is provided as the second parameter, it is ignored (to preserve compatibility with the previous versions of CDecrypt).

```
cdecrypt [common key] <TMD or TIK file|input directory> [output directory]
```

If only one parameter is specified, the content is extracted into the same directory where the NUS files reside. If the second parameter is not an existing file, then it is used as the target directory to extract files in, with any intermediate directories created if needed.

Note that on Windows, you can drag and drop a directory/file directly onto `cdecrypt.exe`.

```
cdecrypt [common key] <TMD or TIK file|input directory> <file to decrypt> <output filename>
```

If three parameters are specified, an attempt is made to extract only the file specified by the second parameter, the file name specified by the third parameter is used as the destination. For example: `cdecrypt "NUS files" meta\iconTex.tga icon.tga`
