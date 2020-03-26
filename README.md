# CDecrypt v3.0

Small application that allows unpack (decrypt) Wii U NUS Content.

This is a fork of a fork made by neobrain of the abandoned CDecrypt originally made by Crediar.

Internally it works almost the same as version 2.0b but it differs in these aspects:

- Remove the Wii U Common Keys from the code. Now need an external file named "keys.txt" where the first line must be the Wii U Common Key and optionally the second line must be the Wii U Common Dev Key.

- Change the command line entry. Now instead of requiring the paths to the files "title.tmd" and "title.tik", requires the path to the NUS Content to decrypt <input path> and the path where you will place the decrypted content <output path>.
  
- Now lets unpack (decrypt) a specific file, requires the path to the NUS Content to decrypt <input path>, the relative path with the name of the file to decrypt <file to decrypt> and the path where you will place the decrypted file <output filename>.
  
- Supports paths with non-ASCII characters.

- Supports paths as large as the user's system allows.
