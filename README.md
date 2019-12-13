# CDecrypt v2.1b

Small application that allows unpack (decrypt) Wii U NUS Content.

This is a fork of a fork made by neobrain of the abandoned CDecrypt originally made for crediting.

Internally it works almost the same as version 2.0b but it differs in two aspects:

- Change the command line entry. Now instead of requiring the paths to the files "title.tmd" and "title.tik", requires the path to the NUS Content to decrypt <input path> and the path where you will place the decrypted content <output path>.

- Remove the Wii U Common Keys from the code. Now need an external file named "keys.txt" where the first line must be	the Wii U Common Key and optionally the second line must be the Wii U Common Dev Key.
