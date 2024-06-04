/**
 * \file md5.h
 *
 * \brief MD5 message digest algorithm (hash function)
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org) and was downloaded from
 *  https://github.com/Secure-Embedded-Systems/RSA-example/tree/master/include/.
 */
#ifndef MD5_H
#define MD5_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

    /**
     * \brief          MD5 context structure
     */
    typedef struct
    {
        uint32_t total[2];          /*!< number of bytes processed  */
        uint32_t state[4];          /*!< intermediate digest state  */
        unsigned char buffer[64];   /*!< data block being processed */
    }
    md5_context;

    /**
     * \brief          Initialize MD5 context
     *
     * \param ctx      MD5 context to be initialized
     */
    void md5_init(md5_context* ctx);

    /**
     * \brief          Clear MD5 context
     *
     * \param ctx      MD5 context to be cleared
     */
    void md5_free(md5_context* ctx);

    /**
     * \brief          Clone (the state of) an MD5 context
     *
     * \param dst      The destination context
     * \param src      The context to be cloned
     */
    void md5_clone(md5_context* dst,
        const md5_context* src);

    /**
     * \brief          MD5 context setup
     *
     * \param ctx      context to be initialized
     */
    void md5_starts(md5_context* ctx);

    /**
     * \brief          MD5 process buffer
     *
     * \param ctx      MD5 context
     * \param input    buffer holding the  data
     * \param ilen     length of the input data
     */
    void md5_update(md5_context* ctx, const unsigned char* input, size_t ilen);

    /**
     * \brief          MD5 final digest
     *
     * \param ctx      MD5 context
     * \param output   MD5 checksum result
     */
    void md5_finish(md5_context* ctx, unsigned char output[16]);

    /* Internal use */
    void md5_process(md5_context* ctx, const unsigned char data[64]);

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_md5.h */
