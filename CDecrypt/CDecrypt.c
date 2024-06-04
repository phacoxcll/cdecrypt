/*
  cdecrypt - Decrypt Wii U NUS content files

  Copyright © 2013-2015 crediar <https://code.google.com/p/cdecrypt/>
  Copyright © 2020-2022 VitaSmith <https://github.com/VitaSmith/cdecrypt>

  This program is free software: you can redistribute it and/or modify
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

#define APP_VERSION v4.8 phacox MOD

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utf8.h"
#include "util.h"
#include "aes.h"
#include "sha1.h"
#include "md5.h"

#define MAX_ENTRIES     90000
#define MAX_LEVELS      16
#define FST_MAGIC       0x46535400              // 'FST\0'
// We use part of the root cert name used by TMD/TIK to identify them
#define TMD_MAGIC       0x4350303030303030ULL   // 'CP000000'
#define TIK_MAGIC       0x5853303030303030ULL   // 'XS000000'
#define T_MAGIC_OFFSET  0x0150
#define HASH_BLOCK_SIZE 0xFC00
#define HASHES_SIZE     0x0400

#define KEY_IN_FILE 0
#define KEY_COM_LINE 1
#define DECRYPT_ALL 3
#define DECRYPT_FILE 4

static const uint8_t WiiUCommonKeyMD5[16] =
{ 0x35, 0xAC, 0x59, 0x94, 0x97, 0x22, 0x79, 0x33, 0x1D, 0x97, 0x09, 0x4F, 0xA2, 0xFB, 0x97, 0xFC };
static const uint8_t WiiUCommonDevKeyMD5[16] =
{ 0xB9, 0xE2, 0xDB, 0xF1, 0xF8, 0xC5, 0x21, 0x29, 0xB7, 0xA5, 0x45, 0x6B, 0x52, 0xA3, 0x90, 0xDF };

uint8_t WiiUCommonKey[16];
uint8_t WiiUCommonDevKey[16];

aes_context     ctx;
uint8_t         title_id[16];
uint8_t         title_key[16];
uint64_t        h0_count = 0;
uint64_t        h0_fail  = 0;

#pragma pack(1)

enum ContentType
{
    CONTENT_REQUIRED = (1 << 0),    // Not sure
    CONTENT_SHARED   = (1 << 15),
    CONTENT_OPTIONAL = (1 << 14),
};

typedef struct
{
    uint16_t IndexOffset;           //  0  0x204
    uint16_t CommandCount;          //  2  0x206
    uint8_t  SHA2[32];              //  12 0x208
} ContentInfo;

typedef struct
{
    uint32_t ID;                    //  0  0xB04
    uint16_t Index;                 //  4  0xB08
    uint16_t Type;                  //  6  0xB0A
    uint64_t Size;                  //  8  0xB0C
    uint8_t  SHA2[32];              //  16 0xB14
} Content;

typedef struct
{
    uint32_t SignatureType;         // 0x000
    uint8_t  Signature[0x100];      // 0x004

    uint8_t  Padding0[0x3C];        // 0x104
    uint8_t  Issuer[0x40];          // 0x140

    uint8_t  Version;               // 0x180
    uint8_t  CACRLVersion;          // 0x181
    uint8_t  SignerCRLVersion;      // 0x182
    uint8_t  Padding1;              // 0x183

    uint64_t SystemVersion;         // 0x184
    uint64_t TitleID;               // 0x18C
    uint32_t TitleType;             // 0x194
    uint16_t GroupID;               // 0x198
    uint8_t  Reserved[62];          // 0x19A
    uint32_t AccessRights;          // 0x1D8
    uint16_t TitleVersion;          // 0x1DC
    uint16_t ContentCount;          // 0x1DE
    uint16_t BootIndex;             // 0x1E0
    uint8_t  Padding3[2];           // 0x1E2
    uint8_t  SHA2[32];              // 0x1E4

    ContentInfo ContentInfos[64];

    Content  Contents[];            // 0x1E4

} TitleMetaData;

struct FSTInfo
{
    uint32_t Unknown;
    uint32_t Size;
    uint32_t UnknownB;
    uint32_t UnknownC[6];
};

struct FST
{
    uint32_t MagicBytes;
    uint32_t Unknown;
    uint32_t EntryCount;

    uint32_t UnknownB[5];

    struct FSTInfo FSTInfos[];
};

struct FEntry
{
    union
    {
        struct
        {
            uint32_t Type : 8;
            uint32_t NameOffset : 24;
        };
        uint32_t TypeName;
    };
    union
    {
        struct      // File Entry
        {
            uint32_t FileOffset;
            uint32_t FileLength;
        };
        struct       // Dir Entry
        {
            uint32_t ParentOffset;
            uint32_t NextOffset;
        };
        uint32_t entry[2];
    };
    uint16_t Flags;
    uint16_t ContentID;
};

static bool to_byte(char hex, uint8_t* out)
{
    if (hex >= '0' && hex <= '9')
        *out = hex - '0';
    else if (hex >= 'A' && hex <= 'F')
        *out = hex - 'A' + 10;
    else if (hex >= 'a' && hex <= 'f')
        *out = hex - 'a' + 10;
    else
        return false;

    return true;
}

static bool to_bytearray(const char* str, uint8_t* out, size_t out_len)
{
    size_t str_len = strlen(str);

    if (str_len / 2.0 > out_len)
        return false;

    if (str_len % 2 != 0)
        return false;

    uint8_t a = 0, b = 0;
    uint8_t* out_ptr = out;

    while (*str && *(str + 1))
    {
        if (!to_byte(*str, &a) || !to_byte(*(str + 1), &b))
        {
            memset(out_ptr, 0, out_len);
            return false;
        }

        *(out++) = a * 16 + b;
        str += 2;
    }

    return true;
}

static bool is_common_key(const char* str)
{
    size_t str_len = strlen(str);

    if (str_len != 32)
        return false;

    char key[33];
    key[32] = '\0';
    memcpy(key, str, 32);

    for (char* c = key; *c = toupper(*c); ++c);

    uint8_t digest[16];
    md5(key, 32, digest);

    for (int i = 0; i < 16; ++i)
    {
        if (digest[i] != WiiUCommonKeyMD5[i])
        {
            return false;
        }
    }

    return true;
}

static bool is_common_dev_key(const char* str)
{
    size_t str_len = strlen(str);

    if (str_len != 32)
        return false;

    char key[33];
    key[32] = '\0';
    memcpy(key, str, 32);

    for (char* c = key; *c = toupper(*c); ++c);

    uint8_t digest[16];
    md5(key, 32, digest);

    for (int i = 0; i < 16; ++i)
    {
        if (digest[i] != WiiUCommonDevKeyMD5[i])
        {
            return false;
        }
    }

    return true;
}

static bool load_keys(uint8_t* common_key, uint8_t* common_dev_key)
{
    uint8_t* keys = NULL;
    uint32_t keys_len = read_file("keys.txt", &keys);

    if (keys == NULL)
    {
        printf("Create a file named 'keys.txt' next to the executable, open it with the notepad and place the Wii U Common Key on the first line, optionally you can place a second line with the Wii U Common Dev Key.\n");
        return false;
    }
    else
    {
        printf("File 'keys.txt' found!\n");
    }

    if (keys_len < 32)
    {
        printf("The 'keys.txt' file is too small to contain one key.\n");
        free(keys);
        return false;
    }

    if (keys_len > 68)
    {
        printf("The 'keys.txt' file is unnecessarily large.\n");
        free(keys);
        return false;
    }

    if (keys_len >= 32)
    {
        char key[33];
        key[32] = '\0';
        memcpy(key, keys, 32);

        if (is_common_key(key) && to_bytearray(key, common_key, 16))
        {
            printf("Wii U Common Key found.\n");
        }
        else
        {
            printf("Invalid Wii U Common Key: '%hs'\n", key);
            free(keys);
            return false;
        }
    }

    if (keys_len >= 64)
    {
        char dev_key[33];
        dev_key[32] = '\0';

        if (keys_len == 64)
            memcpy(dev_key, keys + 32, 32);
        else if (keys[32] == ' ' || keys[32] == '\n')
            memcpy(dev_key, keys + 33, 32);
        else if (keys[32] == '\r' && keys[33] == '\n')
            memcpy(dev_key, keys + 34, 32);
        else
            dev_key[0] = '\0';

        if (is_common_dev_key(dev_key) && to_bytearray(dev_key, common_dev_key, 16))
        {
            printf("Wii U Common Dev Key found.\n");
        }
        else
        {
            printf("Invalid Wii U Common Dev Key: '%hs'\n", dev_key);
            free(keys);
            return false;
        }
    }
    else
    {
        memset(WiiUCommonDevKey, 0, 16);
        printf("Wii U Common Dev Key not found.\n");
    }

    free(keys);

    return true;
}

static bool file_dump(const char* path, void* buf, size_t len)
{
    assert(buf != NULL);
    assert(len != 0);

    FILE* dst = fopen_utf8(path, "wb");
    if (dst == NULL) {
        fprintf(stderr, "ERROR: Could not dump file '%s'\n", path);
        return false;
    }

    bool r = (fwrite(buf, 1, len, dst) == len);
    if (!r)
        fprintf(stderr, "ERROR: Failed to dump file '%s'\n", path);

    fclose(dst);
    return r;
}

static __inline char ascii(char s)
{
    if (s < 0x20) return '.';
    if (s > 0x7E) return '.';
    return s;
}

static void hexdump(uint8_t* buf, size_t len)
{
    size_t i, off;
    for (off = 0; off < len; off += 16) {
        printf("%08x  ", (uint32_t)off);
        for (i = 0; i < 16; i++)
            if ((i + off) >= len)
                printf("   ");
            else
                printf("%02x ", buf[off + i]);

        printf(" ");
        for (i = 0; i < 16; i++) {
            if ((i + off) >= len)
                printf(" ");
            else
                printf("%c", ascii(buf[off + i]));
        }
        printf("\n");
    }
}

#define BLOCK_SIZE  0x10000
static bool extract_file_hash(FILE* src, uint64_t part_data_offset, uint64_t file_offset,
                              uint64_t size, const char* path, uint16_t content_id)
{
    bool r = false;
    uint8_t *enc = malloc(BLOCK_SIZE);
    uint8_t *dec = malloc(BLOCK_SIZE);
    assert(enc != NULL);
    assert(dec != NULL);
    uint8_t iv[16];
    uint8_t hash[SHA_DIGEST_LENGTH];
    uint8_t h0[SHA_DIGEST_LENGTH];
    uint8_t hashes[HASHES_SIZE];

    uint64_t write_size = HASH_BLOCK_SIZE;
    uint64_t block_number = (file_offset / HASH_BLOCK_SIZE) & 0x0F;

    FILE* dst = fopen_utf8(path, "wb");
    if (dst == NULL) {
        fprintf(stderr, "ERROR: Could not create '%s'\n", path);
        goto out;
    }

    uint64_t roffset = file_offset / HASH_BLOCK_SIZE * BLOCK_SIZE;
    uint64_t soffset = file_offset - (file_offset / HASH_BLOCK_SIZE * HASH_BLOCK_SIZE);

    if (soffset + size > write_size)
        write_size = write_size - soffset;

    fseek64(src, part_data_offset + roffset, SEEK_SET);
    while (size > 0) {
        if (write_size > size)
            write_size = size;

        if (fread(enc, sizeof(char), BLOCK_SIZE, src) != BLOCK_SIZE) {
            fprintf(stderr, "ERROR: Could not read %d bytes from '%s'\n", BLOCK_SIZE, path);
            goto out;
        }

        memset(iv, 0, sizeof(iv));
        iv[1] = (uint8_t)content_id;
        aes_crypt_cbc(&ctx, AES_DECRYPT, HASHES_SIZE, iv, enc, (uint8_t*)hashes);

        memcpy(h0, hashes + 0x14 * block_number, SHA_DIGEST_LENGTH);

        memcpy(iv, hashes + 0x14 * block_number, sizeof(iv));
        if (block_number == 0)
            iv[1] ^= content_id;
        aes_crypt_cbc(&ctx, AES_DECRYPT, HASH_BLOCK_SIZE, iv, enc + HASHES_SIZE, dec);

        sha1(dec, HASH_BLOCK_SIZE, hash);

        if (block_number == 0)
            hash[1] ^= content_id;
        h0_count++;
        if (memcmp(hash, h0, SHA_DIGEST_LENGTH) != 0) {
            h0_fail++;
            hexdump(hash, SHA_DIGEST_LENGTH);
            hexdump(hashes, 0x100);
            hexdump(dec, 0x100);
            fprintf(stderr, "ERROR: Could not verify H0 hash\n");
            goto out;
        }

        size -= fwrite(dec + soffset, sizeof(char), (size_t)write_size, dst);

        block_number++;
        if (block_number >= 16)
            block_number = 0;

        if (soffset) {
            write_size = HASH_BLOCK_SIZE;
            soffset = 0;
        }
    }
    r = true;

out:
    if (dst != NULL)
        fclose(dst);
    free(enc);
    free(dec);
    return r;
}
#undef BLOCK_SIZE

#define BLOCK_SIZE  0x8000
static bool extract_file(FILE* src, uint64_t part_data_offset, uint64_t file_offset,
                         uint64_t size, const char* path, uint16_t content_id)
{
    bool r = false;
    uint8_t* enc = malloc(BLOCK_SIZE);
    uint8_t* dec = malloc(BLOCK_SIZE);
    assert(enc != NULL);
    assert(dec != NULL);

    // Calc real offset
    uint64_t roffset = file_offset / BLOCK_SIZE * BLOCK_SIZE;
    uint64_t soffset = file_offset - (file_offset / BLOCK_SIZE * BLOCK_SIZE);

    FILE* dst = fopen_utf8(path, "wb");
    if (dst == NULL) {
        fprintf(stderr, "ERROR: Could not create '%s'\n", path);
        goto out;
    }
    uint8_t iv[16];
    memset(iv, 0, sizeof(iv));
    iv[1] = (uint8_t)content_id;

    uint64_t write_size = BLOCK_SIZE;

    if (soffset + size > write_size)
        write_size = write_size - soffset;

    fseek64(src, part_data_offset + roffset, SEEK_SET);

    while (size > 0) {
        if (write_size > size)
            write_size = size;

        if (fread(enc, sizeof(char), BLOCK_SIZE, src) != BLOCK_SIZE) {
            fprintf(stderr, "ERROR: Could not read %d bytes from '%s'\n", BLOCK_SIZE, path);
            goto out;
        }

        aes_crypt_cbc(&ctx, AES_DECRYPT, BLOCK_SIZE, iv, (const uint8_t*)(enc), (uint8_t*)dec);

        size -= fwrite(dec + soffset, sizeof(char), (size_t)write_size, dst);

        if (soffset) {
            write_size = BLOCK_SIZE;
            soffset = 0;
        }
    }

    r = true;

out:
    if (dst != NULL)
        fclose(dst);
    free(enc);
    free(dec);
    return r;
}
#undef BLOCK_SIZE

int main_utf8(int argc, char** argv)
{
    int r = EXIT_FAILURE;
    int decrypt = DECRYPT_ALL;
    int key_source = KEY_IN_FILE;
    char str[PATH_MAX], *tmd_path = NULL, *tik_path = NULL, * fdec_name = NULL;
    FILE* src = NULL;
    TitleMetaData* tmd = NULL;
    uint8_t *tik = NULL, *cnt = NULL;
    const char* pattern[] = { "%s%c%08x.app", "%s%c%08X.app", "%s%c%08x", "%s%c%08X" };

    if (argc < 2 || argc > 5) {
        printf("%s %s - Wii U NUS content file decrypter\n"
            "Copyright (c) 2020-2023 VitaSmith, Copyright (c) 2013-2015 crediar\n"
            "Visit https://github.com/VitaSmith/cdecrypt for official source and downloads.\n\n"
            "Usage: %s [common key] <TMD or TIK file> <TIK or TMD file>\n"
            "Usage: %s [common key] <TMD or TIK file|input directory> [output directory]\n"
            "Usage: %s [common key] <TMD or TIK file|input directory> <file to decrypt> <output filename>\n\n"
            "This program is free software; you can redistribute it and/or modify it under\n"
            "the terms of the GNU General Public License as published by the Free Software\n"
            "Foundation; either version 3 of the License or any later version.\n",
            _appname(argv[0]), APP_VERSION_STR, _appname(argv[0]), _appname(argv[0]), _appname(argv[0]));
        return EXIT_SUCCESS;
    }

    if (!is_file(argv[1]) && !is_directory(argv[1]))
    {
        if (is_common_key(argv[1]))
        {
            if (to_bytearray(argv[1], WiiUCommonKey, 16))
            {
                key_source = KEY_COM_LINE;
                printf("Wii U Common Key found.\n");
            }
            else
            {
                printf("Invalid Wii U Common Key: '%hs'\n", argv[1]);
                return EXIT_FAILURE;
            }
        }
        else if (is_common_dev_key(argv[1]))
        {
            if (to_bytearray(argv[1], WiiUCommonDevKey, 16))
            {
                key_source = KEY_COM_LINE;
                printf("Wii U Common Dev Key found.\n");
            }
            else
            {
                printf("Invalid Wii U Common Dev Key: '%hs'\n", argv[1]);
                return EXIT_FAILURE;
            }
        }
        else
        {
            printf("ERROR: '%s' is an invalid file or directory!\n"
                "Invalid Wii U Common Key: '%hs'\n\n"
                "Usage: %s [common key] <TMD or TIK file> <TIK or TMD file>\n"
                "Usage: %s [common key] <TMD or TIK file|input directory> [output directory]\n"
                "Usage: %s [common key] <TMD or TIK file|input directory> <file to decrypt> <output filename>\n",
                argv[1], argv[1], _appname(argv[0]), _appname(argv[0]), _appname(argv[0]));
            return EXIT_FAILURE;
        }
    }
    else if (!load_keys(WiiUCommonKey, WiiUCommonDevKey))
        return EXIT_FAILURE;

    if (key_source == KEY_COM_LINE && argc == 2)
    {
        printf("ERROR: Invalid file or directory!\n\n"
            "Usage: %s [common key] <TMD or TIK file> <TIK or TMD file>\n"
            "Usage: %s [common key] <TMD or TIK file|input directory> [output directory]\n"
            "Usage: %s [common key] <TMD or TIK file|input directory> <file to decrypt> <output filename>\n",
            _appname(argv[0]), _appname(argv[0]), _appname(argv[0]));
        return EXIT_FAILURE;
    }

    if (is_file(argv[1 + key_source]))
    {
        // We'll need the current path for locating files, which we set in argv[1 + key_source]
        argv[1 + key_source][get_trailing_slash(argv[1 + key_source])] = 0;
        if (argv[1 + key_source][0] == 0) {
            argv[1 + key_source][0] = '.';
            argv[1 + key_source][1] = 0;
        }
    }

    // If the condition below is true, argv[1 + key_source] is a valid directory
    if (is_directory(argv[1 + key_source]))
    {
        uint8_t* buf = NULL;
        size_t size = strlen(argv[1 + key_source]);
        free(tmd_path);
        free(tik_path);
        tmd_path = calloc(size + 16, 1);
        tik_path = calloc(size + 16, 1);
        sprintf(tmd_path, "%s%ctitle.tmd", argv[1 + key_source], PATH_SEP);
        sprintf(tik_path, "%s%ctitle.tik", argv[1 + key_source], PATH_SEP);

        if (is_file(tmd_path))
        {
            size = read_file_max(tmd_path, &buf, T_MAGIC_OFFSET + sizeof(uint64_t));
            if (size == 0)
            {
                free(buf);
                goto out;
            }
            if (size >= T_MAGIC_OFFSET + sizeof(uint64_t))
            {
                uint64_t magic = getbe64(&buf[T_MAGIC_OFFSET]);
                if (magic != TMD_MAGIC)
                {
                    printf("ERROR: '%s' magic\n", tmd_path);
                    free(buf);
                    goto out;
                }
            }
            free(buf);
        }
        if (is_file(tik_path))
        {
            size = read_file_max(tik_path, &buf, T_MAGIC_OFFSET + sizeof(uint64_t));
            if (size == 0)
            {
                free(buf);
                goto out;
            }
            if (size >= T_MAGIC_OFFSET + sizeof(uint64_t))
            {
                uint64_t magic = getbe64(&buf[T_MAGIC_OFFSET]);
                if (magic != TIK_MAGIC)
                {
                    printf("ERROR: '%s' magic\n", tik_path);
                    free(buf);
                    goto out;
                }
            }
            free(buf);
        }
    }
    else
    {
        printf("ERROR: '%s' is an invalid directory\n", argv[1 + key_source]);
        goto out;
    }

    if (argc == 4 + key_source && !is_file(argv[2 + key_source]) && !is_directory(argv[2 + key_source]) && !is_directory(argv[3 + key_source]))
    {
        decrypt = DECRYPT_FILE;
        fdec_name = strdup(argv[3 + key_source]);
        argv[3 + key_source][get_trailing_slash(argv[3 + key_source])] = 0;
        if (argv[3 + key_source][0] == 0) {
            argv[3 + key_source][0] = '.';
            argv[3 + key_source][1] = 0;
        }
    }

    uint32_t tmd_len = read_file(tmd_path, (uint8_t**)&tmd);
    if (tmd_len == 0)
        goto out;

    uint32_t tik_len = read_file(tik_path, &tik);
    if (tik_len == 0)
        goto out;

    if (tmd->Version != 1) {
        fprintf(stderr, "ERROR: Unsupported TMD version: %u\n", tmd->Version);
        goto out;
    }

    printf("Title version: %u\n", getbe16(&tmd->TitleVersion));
    printf("Content count: %u\n", getbe16(&tmd->ContentCount));

    if (strcmp((char*)(&tmd->Issuer), "Root-CA00000003-CP0000000b") == 0) {
        aes_setkey_dec(&ctx, WiiUCommonKey, sizeof(WiiUCommonKey) * 8);
    } else if (strcmp((char*)(&tmd->Issuer), "Root-CA00000004-CP00000010") == 0) {
        aes_setkey_dec(&ctx, WiiUCommonDevKey, sizeof(WiiUCommonDevKey) * 8);
    } else {
        fprintf(stderr, "ERROR: Unknown Root type: '%s'\n", (char*)tmd + 0x140);
        goto out;
    }

    memset(title_id, 0, sizeof(title_id));

    memcpy(title_id, &tmd->TitleID, 8);
    memcpy(title_key, tik + 0x1BF, 16);

    aes_crypt_cbc(&ctx, AES_DECRYPT, sizeof(title_key), title_id, title_key, title_key);
    aes_setkey_dec(&ctx, title_key, sizeof(title_key) * 8);

    uint8_t iv[16];
    memset(iv, 0, sizeof(iv));

    for (uint32_t k = 0; k < (array_size(pattern) / 2); k++) {
        sprintf(str, pattern[k], argv[1 + key_source], PATH_SEP, getbe32(&tmd->Contents[0].ID));
        if (is_file(str))
            break;
    }

    uint32_t cnt_len = read_file(str, &cnt);
    if (cnt_len == 0) {
        for (uint32_t k = (array_size(pattern) / 2); k < array_size(pattern); k++) {
            sprintf(str, pattern[k], argv[1 + key_source], PATH_SEP, getbe32(&tmd->Contents[0].ID));
            if (is_file(str))
                break;
        }
        cnt_len = read_file(str, &cnt);
        if (cnt_len == 0)
            goto out;
    }

    if (getbe64(&tmd->Contents[0].Size) != (uint64_t)cnt_len) {
        fprintf(stderr, "ERROR: Size of content %u is wrong: %u:%" PRIu64 "\n",
            getbe32(&tmd->Contents[0].ID), cnt_len, getbe64(&tmd->Contents[0].Size));
        goto out;
    }

    aes_crypt_cbc(&ctx, AES_DECRYPT, cnt_len, iv, cnt, cnt);

    if (getbe32(cnt) != FST_MAGIC) {
        sprintf(str, "%s%c%08X.dec", argv[1 + key_source], PATH_SEP, getbe32(&tmd->Contents[0].ID));
        fprintf(stderr, "ERROR: Unexpected content magic. Dumping decrypted file as '%s'.\n", str);
        file_dump(str, cnt, cnt_len);
        goto out;
    }

    struct FST* fst = (struct FST*)cnt;

    printf("FSTInfo Entries: %u\n", getbe32(&fst->EntryCount));
    if (getbe32(&fst->EntryCount) > MAX_ENTRIES) {
        fprintf(stderr, "ERROR: Too many entries\n");
        goto out;
    }

    struct FEntry* fe = (struct FEntry*)(cnt + 0x20 + (uintptr_t)getbe32(&fst->EntryCount) * 0x20);

    uint32_t entries = getbe32(cnt + 0x20 + (uintptr_t)getbe32(&fst->EntryCount) * 0x20 + 8);
    uint32_t name_offset = 0x20 + getbe32(&fst->EntryCount) * 0x20 + entries * 0x10;

    printf("FST entries: %u\n", entries);

    char* dst_dir = NULL;
    if (decrypt == DECRYPT_FILE)
        dst_dir = argv[3 + key_source];
    else
        dst_dir = ((argc <= (2 + key_source)) || is_file(argv[2 + key_source])) ? argv[1 + key_source] : argv[2 + key_source];
    printf("Extracting to directory: '%s'\n", dst_dir);
    create_path(dst_dir);
    char path[PATH_MAX] = { 0 };
    uint32_t entry[16];
    uint32_t l_entry[16];

    uint32_t level = 0;

    for (uint32_t i = 1; i < entries; i++) {
        if (level > 0) {
            while ((level >= 1) && (l_entry[level - 1] == i))
                level--;
        }

        if (fe[i].Type & 1) {
            entry[level] = i;
            l_entry[level++] = getbe32(&fe[i].NextOffset);
            if (level >= MAX_LEVELS) {
                fprintf(stderr, "ERROR: Too many levels\n");
                break;
            }
        } else {
            uint32_t offset;
            memset(path, 0, sizeof(path));
            strcpy(path, dst_dir);

            size_t short_path = strlen(path) + 1;
            for (uint32_t j = 0; j < level; j++) {
                path[strlen(path)] = PATH_SEP;
                offset = getbe32(&fe[entry[j]].TypeName) & 0x00FFFFFF;
                memcpy(path + strlen(path), cnt + name_offset + offset, strlen((char*)cnt + name_offset + offset));
                if (decrypt == DECRYPT_ALL) create_path(path);
            }
            path[strlen(path)] = PATH_SEP;
            offset = getbe32(&fe[i].TypeName) & 0x00FFFFFF;
            memcpy(path + strlen(path), cnt + name_offset + offset, strlen((char*)cnt + name_offset + offset));

            int file_to_decrypt_found = (decrypt == DECRYPT_FILE && (strcmp(&path[short_path], argv[2 + key_source]) == 0));
            if (decrypt == DECRYPT_ALL || file_to_decrypt_found) {
                if (file_to_decrypt_found) {
                    short_path = 0;
                    strcpy(path, fdec_name);
                }

                uint64_t cnt_offset = ((uint64_t)getbe32(&fe[i].FileOffset));
                if ((getbe16(&fe[i].Flags) & 4) == 0)
                    cnt_offset <<= 5;

                printf("Size:%07X Offset:0x%010" PRIx64 " CID:%02X U:%02X %s\n", getbe32(&fe[i].FileLength),
                    cnt_offset, getbe16(&fe[i].ContentID), getbe16(&fe[i].Flags), &path[short_path]);

                uint32_t cnt_file_id = getbe32(&tmd->Contents[getbe16(&fe[i].ContentID)].ID);

                if (!(fe[i].Type & 0x80)) {
                    uint16_t tmd_flags = tmd->Contents[getbe16(&fe[i].ContentID)].Type;
                    // Handle upper/lowercase for target as well as files without extension
                    for (uint32_t k = 0; k < array_size(pattern); k++) {
                        sprintf(str, pattern[k], argv[1 + key_source], PATH_SEP, cnt_file_id);
                        if (is_file(str))
                            break;
                    }
                    src = fopen_utf8(str, "rb");
                    if (src == NULL) {
                        fprintf(stderr, "ERROR: Could not open: '%s'\n", str);
                        goto out;
                    }
                    if ((getbe16(&tmd_flags) & 0x02)) {
                        if (!extract_file_hash(src, 0, cnt_offset, getbe32(&fe[i].FileLength), path, getbe16(&fe[i].ContentID)))
                            goto out;
                    }
                    else {
                        if (!extract_file(src, 0, cnt_offset, getbe32(&fe[i].FileLength), path, getbe16(&fe[i].ContentID)))
                            goto out;
                    }
                    fclose(src);
                    src = NULL;
                }
            }
        }
    }
    r = EXIT_SUCCESS;

out:
    free(tmd);
    free(tik);
    free(cnt);
    free(tmd_path);
    free(tik_path);
    if (src != NULL)
        fclose(src);
    return r;
}

CALL_MAIN
