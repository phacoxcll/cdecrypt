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
*/
/*
	CDecrypt v2.1b

	Differences with respect to v2.0b by crediar:

	- Change the command line entry. Now instead of requiring the paths
	to the files "title.tmd" and "title.tik", requires the path to the
	NUS Content to decrypt <input path> and the path where you will place
	the decrypted content <output path>.

	- Remove the Wii U Common Keys from the code. Now need an external
	file named "keys.txt" where the first line must be	the Wii U Common Key
	and optionally the second line must be the Wii U Common Dev Key.
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

#pragma comment(lib,"libeay32.lib")

typedef unsigned	__int64 u64;
typedef signed		__int64 s64;
typedef unsigned	int u32;
typedef signed		int s32;
typedef unsigned	short u16;
typedef signed		short s16;
typedef unsigned	char u8;
typedef signed		char s8;

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

AES_KEY key;
u8 enc_title_key[16];
u8 dec_title_key[16];
u8 title_id[16];
u8 dkey[16];

u64 H0Count = 0;
u64 H0Fail = 0;

#define MAXLEN 1024
#define BLOCK_SIZE_HASH 0x10000 //Data block size for extracting file by hash
#define BLOCK_SIZE_FILE 0x8000  //Data block size for extracting file

char* InputPath;
char* OutputPath;

#pragma pack(1)

enum ContentType
{
	CONTENT_REQUIRED = (1 << 0),	// not sure
	CONTENT_SHARED = (1 << 15),
	CONTENT_OPTIONAL = (1 << 14),
};

typedef struct
{
	u16 IndexOffset;	//	0	0x204
	u16 CommandCount;	//	2	0x206
	u8	SHA2[32];		//  12	0x208
} ContentInfo;

typedef struct
{
	u32 ID;				//	0	0xB04
	u16 Index;			//	4	0xB08
	u16 Type;			//	6	0xB0A
	u64 Size;			//	8	0xB0C
	u8	SHA2[32];		//  16	0xB14
} Content;

typedef struct
{
	u32 SignatureType;		// 0x000
	u8	Signature[0x100];	// 0x004

	u8	Padding0[0x3C];		// 0x104
	u8	Issuer[0x40];		// 0x140

	u8	Version;			// 0x180
	u8	CACRLVersion;		// 0x181
	u8	SignerCRLVersion;	// 0x182
	u8	Padding1;			// 0x183

	u64	SystemVersion;		// 0x184
	u64	TitleID;			// 0x18C 
	u32	TitleType;			// 0x194 
	u16	GroupID;			// 0x198 
	u8	Reserved[62];		// 0x19A 
	u32	AccessRights;		// 0x1D8
	u16	TitleVersion;		// 0x1DC 
	u16	ContentCount;		// 0x1DE 
	u16 BootIndex;			// 0x1E0
	u8	Padding3[2];		// 0x1E2 
	u8	SHA2[32];			// 0x1E4

	ContentInfo ContentInfos[64];

	Content Contents[];		// 0x1E4 

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
		struct		// File Entry
		{
			u32 FileOffset;
			u32 FileLength;
		};
		struct		// Dir Entry
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


char* ReadFile(const char* Name, u32* Length)
{
	FILE* in = fopen(Name, "rb");
	if (in == NULL)
	{
		//perror("");
		return NULL;
	}

	fseek(in, 0, SEEK_END);
	*Length = ftell(in);

	fseek(in, 0, 0);

	char* Data = new char[*Length];

	u32 read = fread(Data, 1, *Length, in);

	fclose(in);

	return Data;
}

void FileDump(const char* Name, void* Data, u32 Length)
{
	if (Data == NULL)
	{
		printf("zero ptr");
		return;
	}

	if (Length == 0)
	{
		printf("zero sz");
		return;
	}

	FILE* Out = fopen(Name, "wb");

	if (Out == NULL)
	{
		perror("");
		return;
	}

	if (fwrite(Data, 1, Length, Out) != Length)
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
		printf("%08x  ", off);
		for (i = 0; i < 16; i++)
			if ((i + off) >= len)
				printf("   ");
			else
				printf("%02x ", data[off + i]);

		printf(" ");
		for (i = 0; i < 16; i++)
			if ((i + off) >= len) printf(" ");
			else printf("%c", ToASCII(data[off + i]));
		printf("\n");
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
	printf("Create a file named \"keys.txt\" next to the executable, open it with the notepad and place the Wii U Common Key on the first line, optionally you can place a second line with the Wii U Common Dev Key.\n");
}

s32 LoadWiiUCommonKeys()
{
	u32 keysLen;
	char* keys = ReadFile("keys.txt", &keysLen);

	if (keys == nullptr)
	{
		printf("The \"keys.txt\" file not exist or could not be read.\n");
		PrintKeysFileHelp();
		return EXIT_FAILURE;
	}

	if (keysLen < 32)
	{
		printf("The \"keys.txt\" file is too small to contain one key.\n");
		return EXIT_FAILURE;
	}

	if (keysLen > 68)
	{
		printf("The \"keys.txt\" file is unnecessarily large.\n");
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
				printf("Invalid Wii U Common Key: \"%s\"\n", wKey);
				return EXIT_FAILURE;
			}
		}

		ToByteArray(wKey, WiiUCommonKey);
		printf("Wii U Common Key found.\n");
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
				printf("Invalid Wii U Common Dev Key: \"%s\"\n", wDevKey);
				return EXIT_FAILURE;
			}
		}

		ToByteArray(wDevKey, WiiUCommonDevKey);
		printf("Wii U Common Dev Key found.\n");
	}
	else
	{
		memset(WiiUCommonDevKey, 0, 16);
		printf("Wii U Common Dev Key not found.\n");
	}

	delete[] keys;

	return EXIT_SUCCESS;
}

s32 SetPaths(char* inputPath, char* outputPath)
{
	u16 inPathLen = strlen(inputPath);
	u16 outPathLen = strlen(outputPath);

	if (inPathLen + 1 > MAXLEN - 12)
	{
		printf("The input path is too long.\n");
		return EXIT_FAILURE;
	}

	if (outPathLen + 1 > MAXLEN - 128)
	{
		printf("The output path is too long.\n");
		return EXIT_FAILURE;
	}

	struct stat info;
	if (stat(inputPath, &info) != 0 || (info.st_mode & S_IFDIR) != S_IFDIR)
	{
		printf("The input folder not exist.\n");
		return EXIT_FAILURE;
	}

	if (stat(outputPath, &info) != 0 || (info.st_mode & S_IFDIR) != S_IFDIR)
	{
		printf("The output folder not exist.\n");
		return EXIT_FAILURE;
	}

	if (inputPath[inPathLen - 1] == '\\')
	{
		InputPath = new char[inPathLen];
		strcpy(inputPath, inputPath);
	}
	else
	{
		InputPath = new char[inPathLen + 1];
		strcpy(InputPath, inputPath);
		strcat(InputPath, "\\");
	}

	if (outputPath[outPathLen - 1] == '\\')
	{
		OutputPath = new char[outPathLen];
		strcpy(OutputPath, outputPath);
	}
	else
	{
		OutputPath = new char[outPathLen + 1];
		strcpy(OutputPath, outputPath);
		strcat(OutputPath, "\\");
	}

	return EXIT_SUCCESS;
}


void ExtractFileHash(FILE* in, u64 PartDataOffset, u64 FileOffset, u64 Size, char* FileName, u16 ContentID)
{
	char* encdata = new char[BLOCK_SIZE_HASH];
	char* decdata = new char[BLOCK_SIZE_HASH];
	u8 IV[16];
	u8 hash[SHA_DIGEST_LENGTH];
	u8 H0[SHA_DIGEST_LENGTH];
	u8 Hashes[0x400];

	u64 Wrote = 0;
	u64 WriteSize = 0xFC00;	// Hash block size
	u64 Block = (FileOffset / 0xFC00) & 0xF;

	FILE* out = fopen(FileName, "wb");
	if (out == NULL)
	{
		printf("Could not create \"%s\"\n", FileName);
		perror("");
		exit(0);
	}

	u64 roffset = FileOffset / 0xFC00 * BLOCK_SIZE_HASH;
	u64 soffset = FileOffset - (FileOffset / 0xFC00 * 0xFC00);

	if (soffset + Size > WriteSize)
		WriteSize = WriteSize - soffset;

	_fseeki64(in, PartDataOffset + roffset, SEEK_SET);
	while (Size > 0)
	{
		if (WriteSize > Size)
			WriteSize = Size;

		fread(encdata, sizeof(char), BLOCK_SIZE_HASH, in);

		memset(IV, 0, sizeof(IV));
		IV[1] = (u8)ContentID;
		AES_cbc_encrypt((const u8*)(encdata), (u8*)Hashes, 0x400, &key, IV, AES_DECRYPT);

		memcpy(H0, Hashes + 0x14 * Block, SHA_DIGEST_LENGTH);

		memcpy(IV, Hashes + 0x14 * Block, sizeof(IV));
		if (Block == 0)
			IV[1] ^= ContentID;
		AES_cbc_encrypt((const u8*)(encdata + 0x400), (u8*)decdata, 0xFC00, &key, IV, AES_DECRYPT);

		SHA1((const u8*)decdata, 0xFC00, hash);
		if (Block == 0)
			hash[1] ^= ContentID;
		H0Count++;
		if (memcmp(hash, H0, SHA_DIGEST_LENGTH) != 0)
		{
			H0Fail++;
			PrintHexDump(hash, SHA_DIGEST_LENGTH);
			PrintHexDump(Hashes, 0x100);
			PrintHexDump(decdata, 0x100);
			printf("Failed to verify H0 hash\n");
			exit(0);
		}

		Size -= fwrite(decdata + soffset, sizeof(char), WriteSize, out);

		Wrote += WriteSize;

		Block++;
		if (Block >= 16)
			Block = 0;

		if (soffset)
		{
			WriteSize = 0xFC00;
			soffset = 0;
		}
	}

	fclose(out);
	delete[] encdata;
	delete[] decdata;
}

void ExtractFile(FILE* in, u64 PartDataOffset, u64 FileOffset, u64 Size, char* FileName, u16 ContentID)
{
	char* encdata = new char[BLOCK_SIZE_FILE];
	char* decdata = new char[BLOCK_SIZE_FILE];
	u64 Wrote = 0;
	u64 Block = (FileOffset / BLOCK_SIZE_FILE) & 0xF;

	//printf("PO:%08llX FO:%08llX FS:%llu\n", PartDataOffset, FileOffset, Size );

	//calc real offset
	u64 roffset = FileOffset / BLOCK_SIZE_FILE * BLOCK_SIZE_FILE;
	u64 soffset = FileOffset - (FileOffset / BLOCK_SIZE_FILE * BLOCK_SIZE_FILE);
	//printf("Extracting:\"%s\" RealOffset:%08llX RealOffset:%08llX\n", FileName, roffset, soffset );

	FILE* out = fopen(FileName, "wb");
	if (out == NULL)
	{
		printf("Could not create \"%s\"\n", FileName);
		perror("");
		exit(0);
	}
	u8 IV[16];
	memset(IV, 0, sizeof(IV));
	IV[1] = (u8)ContentID;

	u64 WriteSize = BLOCK_SIZE_FILE;

	if (soffset + Size > WriteSize)
		WriteSize = WriteSize - soffset;

	_fseeki64(in, PartDataOffset + roffset, SEEK_SET);

	while (Size > 0)
	{
		if (WriteSize > Size)
			WriteSize = Size;

		fread(encdata, sizeof(char), BLOCK_SIZE_FILE, in);

		AES_cbc_encrypt((const u8*)(encdata), (u8*)decdata, BLOCK_SIZE_FILE, &key, IV, AES_DECRYPT);

		Size -= fwrite(decdata + soffset, sizeof(char), WriteSize, out);

		Wrote += WriteSize;

		if (soffset)
		{
			WriteSize = BLOCK_SIZE_FILE;
			soffset = 0;
		}
	}

	fclose(out);
	delete[] encdata;
	delete[] decdata;
}


s32 main(s32 argc, char* argv[])
{
	printf("CDecrypt v2.1b by crediar, phacox.cll\n");
	printf("Built: %s %s\n", __TIME__, __DATE__);

	if (argc != 3)
	{
		printf("Use: CDecrypt <input path> <output path>\n");
		return EXIT_SUCCESS;
	}

	if (LoadWiiUCommonKeys())
		return EXIT_FAILURE;

	if (SetPaths(argv[1], argv[2]))
		return EXIT_FAILURE;

	char tmdPath[MAXLEN];
	strcpy(tmdPath, InputPath);
	strcat(tmdPath, "title.tmd");
	u32 TMDLen;
	char* TMD = ReadFile(tmdPath, &TMDLen);
	if (TMD == nullptr)
	{
		printf("Failed to open \"%s\"\n", tmdPath);
		return EXIT_FAILURE;
	}

	char tikPath[MAXLEN];
	strcpy(tikPath, InputPath);
	strcat(tikPath, "title.tik");
	u32 TIKLen;
	char* TIK = ReadFile(tikPath, &TIKLen);
	if (TIK == nullptr)
	{
		printf("Failed to open \"%s\"\n", tikPath);
		return EXIT_FAILURE;
	}

	TitleMetaData* tmd = (TitleMetaData*)TMD;

	if (tmd->Version != 1)
	{
		printf("Unsupported TMD Version: %u\n", tmd->Version);
		return EXIT_FAILURE;
	}

	printf("Title version: %u\n", bs16(tmd->TitleVersion));
	printf("Content Count: %u\n", bs16(tmd->ContentCount));

	if (strcmp(TMD + 0x140, "Root-CA00000003-CP0000000b") == 0)
	{
		AES_set_decrypt_key((const u8*)WiiUCommonKey, sizeof(WiiUCommonKey) * 8, &key);
	}
	else if (strcmp(TMD + 0x140, "Root-CA00000004-CP00000010") == 0)
	{
		if (WiiUCommonDevKey[0] == 0)
		{
			printf("To decrypt this NUS Content the Wii U Common Dev Key is required.\n");
			PrintKeysFileHelp();
			return EXIT_SUCCESS;
		}
		else
			AES_set_decrypt_key((const u8*)WiiUCommonDevKey, sizeof(WiiUCommonDevKey) * 8, &key);
	}
	else
	{
		printf("Unknown Root type: \"%s\"\n", TMD + 0x140);
		return EXIT_FAILURE;
	}

	memset(title_id, 0, sizeof(title_id));

	memcpy(title_id, TMD + 0x18C, 8);
	memcpy(enc_title_key, TIK + 0x1BF, 16);
	delete[] TIK;

	AES_cbc_encrypt(enc_title_key, dec_title_key, sizeof(dec_title_key), &key, title_id, AES_DECRYPT);
	AES_set_decrypt_key(dec_title_key, sizeof(dec_title_key) * 8, &key);

	char iv[16];
	memset(iv, 0, sizeof(iv));

	char sourcePath[MAXLEN];
	char sourceFile[MAXLEN];
	sprintf(sourceFile, "%08X.app", bs32(tmd->Contents[0].ID));
	strcpy(sourcePath, InputPath);
	strcat(sourcePath, sourceFile);

	u32 CNTLen;
	char* CNT = ReadFile(sourcePath, &CNTLen);
	if (CNT == (char*)NULL)
	{
		sprintf(sourceFile, "%08X", bs32(tmd->Contents[0].ID));
		memset(sourcePath, 0, MAXLEN);
		strcpy(sourcePath, InputPath);
		strcat(sourcePath, sourceFile);
		CNT = ReadFile(sourcePath, &CNTLen);
		if (CNT == (char*)NULL)
		{
			printf("Failed to open content: %08X\n", bs32(tmd->Contents[0].ID));
			return EXIT_FAILURE;
		}
	}

	if (bs64(tmd->Contents[0].Size) != (u64)CNTLen)
	{
		printf("Size of content: %u is wrong: %u:%I64u\n", bs32(tmd->Contents[0].ID), CNTLen, bs64(tmd->Contents[0].Size));
		return EXIT_FAILURE;
	}

	AES_cbc_encrypt((const u8*)(CNT), (u8*)(CNT), CNTLen, &key, (u8*)(iv), AES_DECRYPT);

	if (bs32(*(u32*)CNT) != 0x46535400)
	{
		sprintf(sourceFile, "%08X.bin", bs32(tmd->Contents[0].ID));
		FileDump(sourceFile, CNT, CNTLen);
		printf("Fail. File dumped: %s\n", sourceFile);
		return EXIT_FAILURE;
	}

	FST* _fst = (FST*)(CNT);

	printf("FSTInfo Entries: %u\n", bs32(_fst->EntryCount));
	if (bs32(_fst->EntryCount) > 90000)
		return EXIT_FAILURE;

	FEntry* fe = (FEntry*)(CNT + 0x20 + bs32(_fst->EntryCount) * 0x20);

	u32 Entries = bs32(*(u32*)(CNT + 0x20 + bs32(_fst->EntryCount) * 0x20 + 8));
	u32 NameOff = 0x20 + bs32(_fst->EntryCount) * 0x20 + Entries * 0x10;
	u32 DirEntries = 0;

	printf("FST entries: %u\n", Entries);

	char destPath[MAXLEN];
	s32 Entry[16];
	s32 LEntry[16];
	s32 level = 0;
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
				printf("level error: %u\n", level);
				break;
			}
		}
		else
		{
			memset(destPath, 0, MAXLEN);
			strcpy(destPath, OutputPath);

			for (s32 j = 0; j < level; ++j)
			{
				if (j)
					destPath[strlen(destPath)] = '\\';
				memcpy(destPath + strlen(destPath), CNT + NameOff + bs24(fe[Entry[j]].NameOffset), strlen(CNT + NameOff + bs24(fe[Entry[j]].NameOffset)));
				_mkdir(destPath);
			}
			if (level)
				destPath[strlen(destPath)] = '\\';
			memcpy(destPath + strlen(destPath), CNT + NameOff + bs24(fe[i].NameOffset), strlen(CNT + NameOff + bs24(fe[i].NameOffset)));

			u32 CNTSize = bs32(fe[i].FileLength);
			u64 CNTOff = ((u64)bs32(fe[i].FileOffset));

			if ((bs16(fe[i].Flags) & 4) == 0)
				CNTOff <<= 5;

			printf("Size:%07X Offset:%010llX CID:%02X U:%03X Output:\"%s\"\n", CNTSize, CNTOff, bs16(fe[i].ContentID), bs16(fe[i].Flags), destPath);

			u32 ContFileID = bs32(tmd->Contents[bs16(fe[i].ContentID)].ID);

			sprintf(sourceFile, "%08X.app", ContFileID);
			memset(sourcePath, 0, MAXLEN);
			strcpy(sourcePath, InputPath);
			strcat(sourcePath, sourceFile);
			if (!(fe[i].Type & 0x80))
			{
				FILE* cnt = fopen(sourcePath, "rb");
				if (cnt == NULL)
				{
					sprintf(sourceFile, "%08X", ContFileID);
					memset(sourcePath, 0, MAXLEN);
					strcpy(sourcePath, InputPath);
					strcat(sourcePath, sourceFile);
					cnt = fopen(sourcePath, "rb");
					if (cnt == NULL)
					{
						printf("Could not open: \"%s\"\n", sourcePath);
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
	return EXIT_SUCCESS;
}
