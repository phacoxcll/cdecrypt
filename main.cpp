/*
	CDecrypt - Decrypt Wii U NUS content files [https://code.google.com/p/cdecrypt/]

	Copyright (c) 2013-2019 crediar, phacox.cll

	CDecrypt is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.

------------------------------------------------------------------------------------

  	CDecrypt v3.0b

	Differences with respect to v2.0b by crediar:

	- Change the command line entry. Now instead of requiring the paths
	to the files "title.tmd" and "title.tik", requires the path to the
	NUS Content to decrypt <input path> and the path where you will place
	the decrypted content <output path>.

	- Remove the Wii U Common Keys from the code. Now need an external
	file named "keys.txt" where the first line must be	the Wii U Common Key
	and optionally the second line must be the Wii U Common Dev Key.

	- Now lets unpack (decrypt) a specific file, requires the path to the
	NUS Content to decrypt <input path>, the relative path with the name of
	the file to decrypt <file to decrypt> and the path where you will place
	the decrypted file <output filename>.

	- Replaces the character type char with the wide character type wchar_t
	for all presentation and data collection variables, it also replaces all
	the presentation and modification functions of strings by its equivalent
	for the wide character type. It now supports paths with non-ASCII
	characters.
	
	- Supports paths as large as the user's system allows.
	
	- Reorganization of code and variable names.
*/

#define _CRT_SECURE_NO_WARNINGS

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl\aes.h>
#include <openssl\sha.h>
#include <openssl\md5.h>
#include <time.h>
#include <vector>
#include <direct.h>
#include <ctype.h>
#include <locale.h>

#pragma comment(lib, "libeay32.lib")

typedef unsigned __int64 u64;
typedef signed __int64   s64;
typedef unsigned int     u32;
typedef signed int       s32;
typedef unsigned short   u16;
typedef signed short     s16;
typedef unsigned char     u8;
typedef signed char       s8;

#define SRC_FILE_LEN 16
#define BLOCK_SIZE_HASH 0x10000 //Data block size for extracting file by hash
#define BLOCK_SIZE_FILE 0x8000  //Data block size for extracting file

u8 WiiUCommonKeyMD5[16] =
{
	0x35, 0xAC, 0x59, 0x94, 0x97, 0x22, 0x79, 0x33, 0x1D, 0x97, 0x09, 0x4F, 0xA2, 0xFB, 0x97, 0xFC
};

u8 WiiUCommonDevKeyMD5[16] =
{
	0xB9, 0xE2, 0xDB, 0xF1, 0xF8, 0xC5, 0x21, 0x29, 0xB7, 0xA5, 0x45, 0x6B, 0x52, 0xA3, 0x90, 0xDF
};

u8 WiiUCommonKey[16];
u8 WiiUCommonDevKey[16];

AES_KEY Key;
u8 EncTitleKey[16];
u8 DecTitleKey[16];
u8 TitleID[16];
u8 DKey[16];

u64 H0Count = 0;
u64 H0Fail = 0;

#pragma pack(1)

enum ContentType
{
	CONTENT_REQUIRED = (1 << 0), // not sure
	CONTENT_SHARED   = (1 << 15),
	CONTENT_OPTIONAL = (1 << 14),
};

typedef struct
{
	u16 IndexOffset;  //  0 0x204
	u16 CommandCount; //  2 0x206
	u8 SHA2[32];      // 12 0x208
} ContentInfo;

typedef struct
{
	u32 ID;      //  0 0xB04
	u16 Index;   //  4 0xB08
	u16 Type;    //  6 0xB0A
	u64 Size;    //  8 0xB0C
	u8 SHA2[32]; // 16 0xB14
} Content;

typedef struct
{
	u32 SignatureType;   // 0x000
	u8 Signature[0x100]; // 0x004

	u8 Padding0[0x3C];   // 0x104
	u8 Issuer[0x40];     // 0x140

	u8 Version;          // 0x180
	u8 CACRLVersion;     // 0x181
	u8 SignerCRLVersion; // 0x182
	u8 Padding1;         // 0x183

	u64 SystemVersion;   // 0x184
	u64 TitleID;         // 0x18C 
	u32 TitleType;       // 0x194 
	u16 GroupID;         // 0x198 
	u8 Reserved[62];     // 0x19A 
	u32 AccessRights;    // 0x1D8
	u16 TitleVersion;    // 0x1DC 
	u16 ContentCount;    // 0x1DE 
	u16 BootIndex;       // 0x1E0
	u8 Padding3[2];      // 0x1E2 
	u8 SHA2[32];         // 0x1E4

	ContentInfo ContentInfos[64];

	Content Contents[];  // 0x1E4 

} TitleMetaData;

struct FSTInfo
{
	u32 Unknown;
	u32 Size;
	u32 UnknownB;
	u32 UnknownC[6];
};

struct FST
{
	u32 MagicBytes;
	u32 Unknown;
	u32 EntryCount;

	u32 UnknownB[5];

	FSTInfo FSTInfos[];
};

struct FEntry
{
	union
	{
		struct
		{
			u32 Type : 8;
			u32 NameOffset : 24;
		};
		u32 TypeName;
	};
	union
	{
		struct // File Entry
		{
			u32 FileOffset;
			u32 FileLength;
		};
		struct // Dir Entry
		{
			u32 ParentOffset;
			u32 NextOffset;
		};
		u32 entry[2];
	};
	unsigned short Flags;
	unsigned short ContentID;
};


#define bs16(s) (u16)( ((s)>>8) | ((s)<<8) )

#define bs32(s) (u32)( (((s)&0xFF0000)>>8) | (((s)&0xFF00)<<8) | ((s)>>24) | ((s)<<24) )

u32 bs24(u32 i)
{
	return ((i & 0xFF0000) >> 16) | ((i & 0xFF) << 16) | (i & 0x00FF00);
}

u64 bs64(u64 i)
{
	return ((u64)(bs32(i & 0xFFFFFFFF)) << 32) | (bs32(i >> 32));
}


u8* ReadFile(const wchar_t* name, u32* length)
{
	FILE* in = _wfopen(name, L"rb");
	if (in == NULL)
	{
		//perror("");
		return NULL;
	}

	fseek(in, 0, SEEK_END);
	*length = ftell(in);

	fseek(in, 0, 0);

	u8* Data = new u8[*length];

	u32 read = fread(Data, 1, *length, in);

	fclose(in);

	return Data;
}

void FileDump(const wchar_t* name, void* data, u32 length)
{
	if (data == NULL)
	{
		wprintf(L"zero ptr");
		return;
	}

	if (length == 0)
	{
		wprintf(L"zero sz");
		return;
	}

	FILE* Out = _wfopen(name, L"wb");

	if (Out == NULL)
	{
		perror("");
		return;
	}

	if (fwrite(data, 1, length, Out) != length)
	{
		perror("");
	}

	fclose(Out);
}


char ToASCII(char c)
{
	if (c < 0x20) return '.';
	if (c > 0x7E) return '.';
	return c;
}

void PrintHexDump(void* d, s32 len)
{
	u8* data;
	s32 i, off;
	data = (u8*)d;
	for (off = 0; off < len; off += 16)
	{
		wprintf(L"%08x  ", off);
		for (i = 0; i < 16; i++)
			if ((i + off) >= len)
				wprintf(L"   ");
			else
				wprintf(L"%02x ", data[off + i]);

		wprintf(L" ");
		for (i = 0; i < 16; i++)
			if ((i + off) >= len) printf(" ");
			else wprintf(L"%hc", ToASCII(data[off + i]));
		wprintf(L"\n");
	}
}

u8 ToByte(char hex)
{
	if (hex >= '0' && hex <= '9')
		return hex - '0';
	else if (hex >= 'A' && hex <= 'F')
		return hex - 'A' + 10;
	else if (hex >= 'a' && hex <= 'f')
		return hex - 'a' + 10;
	else
		throw hex;
}

void ToByteArray(const char* str, u8* out)
{
	while (*str && str[1])
	{
		*(out++) = ToByte(*str) * 16 + ToByte(str[1]);
		str += 2;
	}
}

void PrintKeysFileHelp()
{
	wprintf(L"Create a file named \"keys.txt\" next to the executable, open it with the notepad and place the Wii U Common Key on the first line, optionally you can place a second line with the Wii U Common Dev Key.\n");
}

s32 LoadWiiUCommonKeys()
{
	u32 keysLen;
	u8* keys = ReadFile(L"keys.txt", &keysLen);

	if (keys == nullptr)
	{
		wprintf(L"The \"keys.txt\" file not exist or could not be read.\n");
		PrintKeysFileHelp();
		return EXIT_FAILURE;
	}

	if (keysLen < 32)
	{
		wprintf(L"The \"keys.txt\" file is too small to contain one key.\n");
		return EXIT_FAILURE;
	}

	if (keysLen > 68)
	{
		wprintf(L"The \"keys.txt\" file is unnecessarily large.\n");
		return EXIT_FAILURE;
	}

	if (keysLen >= 32)
	{
		char wKey[33];
		wKey[32] = '\0';
		memcpy(wKey, keys, 32);

		for (char* c = wKey; *c = toupper(*c); ++c);

		MD5_CTX context;
		u8 digest[16];
		MD5_Init(&context);
		MD5_Update(&context, wKey, strlen(wKey));
		MD5_Final(digest, &context);

		for (s32 i = 0; i < 16; ++i)
		{
			if (digest[i] != WiiUCommonKeyMD5[i])
			{
				wprintf(L"Invalid Wii U Common Key: \"%hs\"\n", wKey);
				return EXIT_FAILURE;
			}
		}

		ToByteArray(wKey, WiiUCommonKey);
		wprintf(L"Wii U Common Key found.\n");
	}

	if (keysLen >= 64)
	{
		char wDevKey[33];
		wDevKey[32] = '\0';

		if (keysLen == 64)
			memcpy(wDevKey, keys + 32, 32);
		else if (keys[32] == ' ' || keys[32] == '\n')
			memcpy(wDevKey, keys + 33, 32);
		else if (keys[32] == '\r' && keys[33] == '\n')
			memcpy(wDevKey, keys + 34, 32);
		else
			wDevKey[0] = '\0';

		for (char* c = wDevKey; *c = toupper(*c); ++c);

		MD5_CTX context;
		u8 digest[16];
		MD5_Init(&context);
		MD5_Update(&context, wDevKey, strlen(wDevKey));
		MD5_Final(digest, &context);

		for (int i = 0; i < 16; ++i)
		{
			if (digest[i] != WiiUCommonDevKeyMD5[i])
			{
				wprintf(L"Invalid Wii U Common Dev Key: \"%hs\"\n", wDevKey);
				return EXIT_FAILURE;
			}
		}

		ToByteArray(wDevKey, WiiUCommonDevKey);
		wprintf(L"Wii U Common Dev Key found.\n");
	}
	else
	{
		memset(WiiUCommonDevKey, 0, 16);
		wprintf(L"Wii U Common Dev Key not found.\n");
	}

	delete[] keys;

	return EXIT_SUCCESS;
}

wchar_t* Adjust(wchar_t*& str, s32* currentStrMaxLength, s32 sizeToFit)
{
	if (sizeToFit > *currentStrMaxLength)
	{
		wchar_t* newPtr;
		*currentStrMaxLength = (sizeToFit / 64 + 1) * 64;
		newPtr = new wchar_t[*currentStrMaxLength];
		wmemset(newPtr, 0, *currentStrMaxLength);
		wcscpy(newPtr, str);
		delete[] str;
		str = nullptr;
		return newPtr;
	}
	return str;
}


void ExtractFileHash(FILE* in, u64 partDataOffset, u64 fileOffset, u64 size, wchar_t* fileName, u16 contentID)
{
	char* encdata = new char[BLOCK_SIZE_HASH];
	char* decdata = new char[BLOCK_SIZE_HASH];
	u8 iv[16];
	u8 hash[SHA_DIGEST_LENGTH];
	u8 h0[SHA_DIGEST_LENGTH];
	u8 hashes[0x400];

	u64 wrote = 0;
	u64 writeSize = 0xFC00;	// Hash block size
	u64 block = (fileOffset / 0xFC00) & 0xF;

	FILE* out = _wfopen(fileName, L"wb");
	if (out == NULL)
	{
		wprintf(L"Could not create \"%ls\"\n", fileName);
		perror("");
		exit(0);
	}

	u64 roffset = fileOffset / 0xFC00 * BLOCK_SIZE_HASH;
	u64 soffset = fileOffset - (fileOffset / 0xFC00 * 0xFC00);

	if (soffset + size > writeSize)
		writeSize = writeSize - soffset;

	_fseeki64(in, partDataOffset + roffset, SEEK_SET);
	while (size > 0)
	{
		if (writeSize > size)
			writeSize = size;

		fread(encdata, sizeof(char), BLOCK_SIZE_HASH, in);

		memset(iv, 0, sizeof(iv));
		iv[1] = (u8)contentID;
		AES_cbc_encrypt((const u8*)(encdata), (u8*)hashes, 0x400, &Key, iv, AES_DECRYPT);

		memcpy(h0, hashes + 0x14 * block, SHA_DIGEST_LENGTH);
		memcpy(iv, hashes + 0x14 * block, sizeof(iv));
		if (block == 0)
			iv[1] ^= contentID;
		AES_cbc_encrypt((const u8*)(encdata + 0x400), (u8*)decdata, 0xFC00, &Key, iv, AES_DECRYPT);

		SHA1((const u8*)decdata, 0xFC00, hash);
		if (block == 0)
			hash[1] ^= contentID;
		H0Count++;
		if (memcmp(hash, h0, SHA_DIGEST_LENGTH) != 0)
		{
			H0Fail++;
			PrintHexDump(hash, SHA_DIGEST_LENGTH);
			PrintHexDump(hashes, 0x100);
			PrintHexDump(decdata, 0x100);
			wprintf(L"Failed to verify H0 hash\n");
			exit(0);
		}

		size -= fwrite(decdata + soffset, sizeof(char), writeSize, out);

		wrote += writeSize;

		block++;
		if (block >= 16)
			block = 0;

		if (soffset)
		{
			writeSize = 0xFC00;
			soffset = 0;
		}
	}

	fclose(out);
	delete[] encdata;
	delete[] decdata;
}

void ExtractFile(FILE* in, u64 partDataOffset, u64 fileOffset, u64 size, wchar_t* fileName, u16 contentID)
{
	char* encdata = new char[BLOCK_SIZE_FILE];
	char* decdata = new char[BLOCK_SIZE_FILE];
	u64 wrote = 0;
	//u64 block = (fileOffset / BLOCK_SIZE_FILE) & 0xF;

	//wprintf(L"PO:%08llX FO:%08llX FS:%llu\n", partDataOffset, fileOffset, size );

	//calc real offset
	u64 roffset = fileOffset / BLOCK_SIZE_FILE * BLOCK_SIZE_FILE;
	u64 soffset = fileOffset - (fileOffset / BLOCK_SIZE_FILE * BLOCK_SIZE_FILE);
	//wprintf(L"Extracting:\"%ls\" RealOffset:%08llX RealOffset:%08llX\n", fileName, roffset, soffset );

	FILE* out = _wfopen(fileName, L"wb");
	if (out == NULL)
	{
		wprintf(L"Could not create \"%ls\"\n", fileName);
		perror("");
		exit(0);
	}

	u8 iv[16];
	memset(iv, 0, sizeof(iv));
	iv[1] = (u8)contentID;

	u64 writeSize = BLOCK_SIZE_FILE;

	if (soffset + size > writeSize)
		writeSize = writeSize - soffset;

	_fseeki64(in, partDataOffset + roffset, SEEK_SET);

	while (size > 0)
	{
		if (writeSize > size)
			writeSize = size;

		fread(encdata, sizeof(char), BLOCK_SIZE_FILE, in);
		AES_cbc_encrypt((const u8*)(encdata), (u8*)decdata, BLOCK_SIZE_FILE, &Key, iv, AES_DECRYPT);
		size -= fwrite(decdata + soffset, sizeof(char), writeSize, out);

		wrote += writeSize;

		if (soffset)
		{
			writeSize = BLOCK_SIZE_FILE;
			soffset = 0;
		}
	}

	fclose(out);
	delete[] encdata;
	delete[] decdata;
}


s32 wmain(s32 argc, wchar_t* argv[])
{
	wprintf(L"CDecrypt v3.0 by crediar, phacox.cll\n");
	wprintf(L"Built: %hs %hs\n", __TIME__, __DATE__);

	if (argc != 3 && argc != 4)
	{
		printf("Use: CDecrypt <input path> <output path>\n");
		printf("Or:  CDecrypt <input path> <file to decrypt> <output filename>\n");
		return EXIT_SUCCESS;
	}

	if (LoadWiiUCommonKeys())
		return EXIT_FAILURE;

	wchar_t* inputPath;
	wchar_t* outputPath;
	wchar_t* fileToDecrypt;

	struct _stat info;
	if (_wstat(argv[1], &info) != 0 || (info.st_mode & S_IFDIR) != S_IFDIR)
	{
		wprintf(L"The \"%ls\" path not exist.\n", argv[1]);
		return EXIT_FAILURE;
	}

	s32 inputLen = wcslen(argv[1]) + (argv[1][wcslen(argv[1]) - 1] != L'\\' ? 1 : 0);
	inputPath = new wchar_t[inputLen + 1];
	wcscpy(inputPath, argv[1]);
	if (argv[1][wcslen(argv[1]) - 1] != L'\\')
		wcscat(inputPath, L"\\");

	if (argc == 3)
	{
		if (_wstat(argv[2], &info) != 0 || (info.st_mode & S_IFDIR) != S_IFDIR)
		{
			wprintf(L"The \"%ls\" path not exist.\n", argv[2]);
			return EXIT_FAILURE;
		}

		s32 outputLen = wcslen(argv[2]) + (argv[2][wcslen(argv[2]) - 1] != L'\\' ? 1 : 0);
		outputPath = new wchar_t[outputLen + 1];
		wcscpy(outputPath, argv[2]);
		if (argv[2][wcslen(argv[2]) - 1] != L'\\')
			wcscat(outputPath, L"\\");

		fileToDecrypt = new wchar_t[1];
		fileToDecrypt[0] = L'\0';
	}
	else //if (argc == 4)
	{
		outputPath = new wchar_t[wcslen(argv[3]) + 1];
		wcscpy(outputPath, argv[3]);

		fileToDecrypt = new wchar_t[wcslen(argv[2]) + 1];
		wcscpy(fileToDecrypt, argv[2]);
	}

	wchar_t* tmdPath = new wchar_t[inputLen + SRC_FILE_LEN];
	wcscpy(tmdPath, inputPath);
	wcscat(tmdPath, L"title.tmd");
	u32 TMDLen;
	u8* TMD = ReadFile(tmdPath, &TMDLen);
	if (TMD == nullptr)
	{
		wprintf(L"Failed to open \"%ls\"\n", tmdPath);
		return EXIT_FAILURE;
	}
	delete[] tmdPath;

	wchar_t* tikPath = new wchar_t[inputLen + SRC_FILE_LEN];
	wcscpy(tikPath, inputPath);
	wcscat(tikPath, L"title.tik");
	u32 TIKLen;
	u8* TIK = ReadFile(tikPath, &TIKLen);
	if (TIK == nullptr)
	{
		wprintf(L"Failed to open \"%ls\"\n", tikPath);
		return EXIT_FAILURE;
	}
	delete[] tikPath;

	TitleMetaData* tmd = (TitleMetaData*)TMD;

	if (tmd->Version != 1)
	{
		wprintf(L"Unsupported TMD Version: %u\n", tmd->Version);
		return EXIT_FAILURE;
	}

	wprintf(L"Title version: %u\n", bs16(tmd->TitleVersion));
	wprintf(L"Content Count: %u\n", bs16(tmd->ContentCount));

	if (strcmp((char*)TMD + 0x140, "Root-CA00000003-CP0000000b") == 0)
	{
		AES_set_decrypt_key((const u8*)WiiUCommonKey, sizeof(WiiUCommonKey) * 8, &Key);
	}
	else if (strcmp((char*)TMD + 0x140, "Root-CA00000004-CP00000010") == 0)
	{
		if (WiiUCommonDevKey[0] == 0)
		{
			wprintf(L"To decrypt this NUS Content the Wii U Common Dev Key is required.\n");
			PrintKeysFileHelp();
			return EXIT_SUCCESS;
		}
		else
			AES_set_decrypt_key((const u8*)WiiUCommonDevKey, sizeof(WiiUCommonDevKey) * 8, &Key);
	}
	else
	{
		wprintf(L"Unknown Root type: \"%hs\"\n", TMD + 0x140);
		return EXIT_FAILURE;
	}

	memset(TitleID, 0, sizeof(TitleID));

	memcpy(TitleID, TMD + 0x18C, 8);
	memcpy(EncTitleKey, TIK + 0x1BF, 16);
	delete[] TIK;

	AES_cbc_encrypt(EncTitleKey, DecTitleKey, sizeof(DecTitleKey), &Key, TitleID, AES_DECRYPT);
	AES_set_decrypt_key(DecTitleKey, sizeof(DecTitleKey) * 8, &Key);

	char iv[16];
	memset(iv, 0, sizeof(iv));

	wchar_t* sourcePath = new wchar_t[inputLen + SRC_FILE_LEN];
	wchar_t sourceFile[SRC_FILE_LEN];
	swprintf(sourceFile, SRC_FILE_LEN, L"%08X.app", bs32(tmd->Contents[0].ID));
	wcscpy(sourcePath, inputPath);
	wcscat(sourcePath, sourceFile);

	u32 CNTLen;
	u8* CNT = ReadFile(sourcePath, &CNTLen);
	if (CNT == (u8*)NULL)
	{
		swprintf(sourceFile, SRC_FILE_LEN, L"%08X", bs32(tmd->Contents[0].ID));
		wcscpy(sourcePath, inputPath);
		wcscat(sourcePath, sourceFile);
		CNT = ReadFile(sourcePath, &CNTLen);
		if (CNT == (u8*)NULL)
		{
			wprintf(L"Failed to open content: %08X\n", bs32(tmd->Contents[0].ID));
			return EXIT_FAILURE;
		}
	}

	if (bs64(tmd->Contents[0].Size) != (u64)CNTLen)
	{
		printf("Size of content: %u is wrong: %u:%I64u\n", bs32(tmd->Contents[0].ID), CNTLen, bs64(tmd->Contents[0].Size));
		return EXIT_FAILURE;
	}

	AES_cbc_encrypt((const u8*)(CNT), (u8*)(CNT), CNTLen, &Key, (u8*)(iv), AES_DECRYPT);

	if (bs32(*(u32*)CNT) != 0x46535400)
	{
		swprintf(sourceFile, SRC_FILE_LEN, L"%08X.bin", bs32(tmd->Contents[0].ID));
		FileDump(sourceFile, CNT, CNTLen);
		wprintf(L"Fail. File dumped: %ls\n", sourceFile);
		return EXIT_FAILURE;
	}

	FST* _fst = (FST*)(CNT);

	wprintf(L"FSTInfo Entries: %u\n", bs32(_fst->EntryCount));
	if (bs32(_fst->EntryCount) > 90000)
		return EXIT_FAILURE;

	FEntry* fe = (FEntry*)(CNT + 0x20 + bs32(_fst->EntryCount) * 0x20);

	u32 Entries = bs32(*(u32*)(CNT + 0x20 + bs32(_fst->EntryCount) * 0x20 + 8));
	u32 NameOff = 0x20 + bs32(_fst->EntryCount) * 0x20 + Entries * 0x10;
	u32 DirEntries = 0;

	wprintf(L"FST entries: %u\n", Entries);

	s32 Entry[16];
	s32 LEntry[16];
	s32 level = 0;
	s32 cntNameLen = 0;
	s32 relativePathLen = 128;
	s32 destPathLen = 128;
	char* cntName;
	wchar_t* relativePath = new wchar_t[relativePathLen];
	wchar_t* destPath = new wchar_t[destPathLen];
	for (u32 i = 1; i < Entries; ++i)
	{
		if (level)
		{
			while (LEntry[level - 1] == i)
			{
				//printf("[%03X]leaving :\"%s\" Level:%d\n", i, CNT + NameOff + bs24( fe[Entry[level-1]].NameOffset ), level );
				level--;
			}
		}

		if (fe[i].Type & 1)
		{
			Entry[level] = i;
			LEntry[level++] = bs32(fe[i].NextOffset);
			if (level > 15)	// something is wrong!
			{
				wprintf(L"level error: %u\n", level);
				break;
			}
		}
		else
		{
			wmemset(relativePath, 0, relativePathLen);

			for (s32 j = 0; j < level; ++j)
			{
				cntName = (char*)CNT + NameOff + bs24(fe[Entry[j]].NameOffset);
				cntNameLen = strlen((char*)CNT + NameOff + bs24(fe[Entry[j]].NameOffset));
				relativePath = Adjust(relativePath, &relativePathLen, wcslen(relativePath) + cntNameLen + 2);
				if (j)
					relativePath[wcslen(relativePath)] = L'\\';				
				mbstowcs(relativePath + wcslen(relativePath), cntName, cntNameLen);
				if (argc == 3)
				{
					destPath = Adjust(destPath, &destPathLen, wcslen(outputPath) + wcslen(relativePath) + 1);
					wcscpy(destPath, outputPath);
					wcscat(destPath, relativePath);
					s32 a = _wmkdir(destPath);
				}
			}			
			cntName = (char*)CNT + NameOff + bs24(fe[i].NameOffset);
			cntNameLen = strlen((char*)CNT + NameOff + bs24(fe[i].NameOffset));
			relativePath = Adjust(relativePath, &relativePathLen, wcslen(relativePath) + cntNameLen + 2);
			if (level)
				relativePath[wcslen(relativePath)] = L'\\';			
			mbstowcs(relativePath + wcslen(relativePath), cntName, cntNameLen);

			if (argc == 3 || (argc == 4 && wcscmp(relativePath, fileToDecrypt) == 0))
			{
				if (argc == 3)
				{
					destPath = Adjust(destPath, &destPathLen, wcslen(outputPath) + wcslen(relativePath) + 1);
					wcscpy(destPath, outputPath);
					wcscat(destPath, relativePath);
				}
				else //if (argc == 4)
				{
					destPath = Adjust(destPath, &destPathLen, wcslen(outputPath) + 1);
					wcscpy(destPath, outputPath);
				}

				u32 CNTSize = bs32(fe[i].FileLength);
				u64 CNTOff = ((u64)bs32(fe[i].FileOffset));

				if ((bs16(fe[i].Flags) & 4) == 0)
					CNTOff <<= 5;

				wprintf(L"Size:%07X Offset:%010llX CID:%02X U:%03X Output:\"%ls\"\n",
					CNTSize, CNTOff, bs16(fe[i].ContentID), bs16(fe[i].Flags), destPath);

				u32 ContFileID = bs32(tmd->Contents[bs16(fe[i].ContentID)].ID);

				swprintf(sourceFile, SRC_FILE_LEN, L"%08X.app", ContFileID);
				wcscpy(sourcePath, inputPath);
				wcscat(sourcePath, sourceFile);
				if (!(fe[i].Type & 0x80))
				{
					FILE* cnt = _wfopen(sourcePath, L"rb");
					if (cnt == NULL)
					{
						swprintf(sourceFile, SRC_FILE_LEN, L"%08X", ContFileID);
						wcscpy(sourcePath, inputPath);
						wcscat(sourcePath, sourceFile);
						cnt = _wfopen(sourcePath, L"rb");
						if (cnt == NULL)
						{
							wprintf(L"Could not open: \"%ls\"\n", sourcePath);
							perror("");
							return EXIT_FAILURE;
						}
					}
					if ((bs16(fe[i].Flags) & 0x440))
						ExtractFileHash(cnt, 0, CNTOff, bs32(fe[i].FileLength), destPath, bs16(fe[i].ContentID));
					else
						ExtractFile(cnt, 0, CNTOff, bs32(fe[i].FileLength), destPath, bs16(fe[i].ContentID));
					fclose(cnt);
				}
			}
		}
	}
	return EXIT_SUCCESS;
}
