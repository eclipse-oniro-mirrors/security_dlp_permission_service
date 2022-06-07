/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dlp_fuse.h"
#include "dlp_utils.h"
#include "dlp_format.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <unordered_map>
#include <cstdio>
#include <cerrno>
#include <securec.h>
#include <unistd.h>
#include <new>

#ifdef __cplusplus
extern "C" {
#endif

using namespace std;
struct DlpFuseInfo {
    uint32_t txtOffset;
    struct DlpBlob key;
    struct DlpBlob iv;
};

std::unordered_map<int32_t, struct DlpFuseInfo *> g_DlpFdMap;
OHOS::Utils::RWLock g_DlpMapLock;

int32_t DlpFileRead(int32_t fd, uint32_t offset, void *buf, uint32_t size)
{
    struct DlpBlob *key;
    struct DlpBlob *iv;
    uint32_t dlpOffset;
    int32_t ret;

    if (buf == nullptr) {
        return DLP_ERROR_NULL_POINTER;
    }

    OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> mapGuard(g_DlpMapLock);
    auto iter = g_DlpFdMap.find(fd);
    if (iter != g_DlpFdMap.end()) {
        key = &(iter->second->key);
        iv = &(iter->second->iv);
        dlpOffset = iter->second->txtOffset;
    } else {
        return DLP_ERROR_INVALID_FD;
    }

    ret = lseek(fd, dlpOffset + offset, SEEK_SET);
    if (ret < 0) {
        return DLP_ERROR_LSEEK_FAIL;
    }

    uint8_t *encBuff = new (std::nothrow) uint8_t[size];
    if (encBuff == nullptr) {
        return DLP_ERROR_MALLOC_FAIL;
    }

    ret = read(fd, (void *)encBuff, size);
    if (ret < 0) {
        return DLP_ERROR_READ_FAIL;
    }

    struct DlpCipherParam tagIv;
    tagIv.iv.data = iv->data;
    tagIv.iv.size = iv->size;
    struct DlpUsageSpec usageSpec = {
        .mode = DLP_MODE_CTR,
        .padding = DLP_PADDING_NONE,
        .algParam = &tagIv,
    };
    struct DlpBlob message1 = { .size = size };
    struct DlpBlob message2 = { .size = size };
    message1.data = encBuff;
    message2.data = static_cast<uint8_t *>(buf);
    ret = DlpOpensslAesDecrypt(key, &usageSpec, &message1, &message2);
    if (ret != 0) {
        return DLP_ERROR_CRYPT_FAIL;
    }

    return ret;
}

int32_t DlpFileWrite(int32_t fd, uint32_t offset, void *buf, uint32_t size)
{
    struct DlpBlob *key;
    struct DlpBlob *iv;
    uint32_t dlpOffset;
    int32_t ret;

    if (buf == nullptr) {
        return DLP_ERROR_NULL_POINTER;
    }

    OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> mapGuard(g_DlpMapLock);
    auto iter = g_DlpFdMap.find(fd);
    if (iter != g_DlpFdMap.end()) {
        key = &(iter->second->key);
        iv = &(iter->second->iv);
        dlpOffset = iter->second->txtOffset;
    } else {
        return DLP_ERROR_INVALID_FD;
    }

    ret = lseek(fd, dlpOffset + offset, SEEK_SET);
    if (ret < 0) {
        return DLP_ERROR_LSEEK_FAIL;
    }

    uint8_t *encBuff = new (std::nothrow) uint8_t[size];
    if (encBuff == nullptr) {
        return DLP_ERROR_MALLOC_FAIL;
    }

    struct DlpCipherParam tagIv;
    tagIv.iv.data = iv->data;
    tagIv.iv.size = iv->size;
    struct DlpUsageSpec usageSpec = {
        .mode = DLP_MODE_CTR,
        .padding = DLP_PADDING_NONE,
        .algParam = &tagIv,
    };
    struct DlpBlob message1 = { .size = size };
    struct DlpBlob message2 = { .size = size };
    message1.data = static_cast<uint8_t *>(buf);
    message2.data = encBuff;
    ret = DlpOpensslAesEncrypt(key, &usageSpec, &message1, &message2);
    if (ret != 0) {
        return DLP_ERROR_CRYPT_FAIL;
    }

    ret = write(fd, (void *)encBuff, size);
    if (ret < 0) {
        return DLP_ERROR_WRITE_FAIL;
    }
    return DLP_SUCCESS;
}

int32_t DlpFileAdd(int32_t fd, struct DlpBlob *key, struct DlpBlob *iv)
{
    static DLP::DlpFile var;
    int32_t ret = 0;
    uint32_t offset = 0;
    ret = var.FileParse(fd, offset);
    if (ret != 0) {
        return DLP_ERROR_CRYPT_FILE_PARSE_FAIL;
    }

    struct DlpFuseInfo *buf = new (std::nothrow) struct DlpFuseInfo;
    if (buf == nullptr) {
        return DLP_ERROR_MALLOC_FAIL;
    }

    buf->txtOffset = offset;

    buf->key.data = new (std::nothrow) uint8_t[key->size];
    if (buf->key.data == nullptr) {
        delete buf;
        return DLP_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(buf->key.data, key->size, key->data, key->size);
    buf->key.size = key->size;

    buf->iv.data = new (std::nothrow) uint8_t[iv->size];
    if (buf->iv.data == nullptr) {
        delete[] buf->key.data;
        delete buf;
        return DLP_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(buf->iv.data, iv->size, iv->data, iv->size);
    buf->iv.size = iv->size;

    {
        OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> mapGuard(g_DlpMapLock);
        auto iter = g_DlpFdMap.find(fd);
        if (iter != g_DlpFdMap.end()) {
            delete[] buf->key.data;
            delete[] buf->iv.data;
            delete buf;
        } else {
            g_DlpFdMap[fd] = buf;
        }
    }
    return DLP_SUCCESS;
}

int32_t DlpFileDel(int32_t fd)
{
    OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> mapGuard(g_DlpMapLock);
    auto iter = g_DlpFdMap.find(fd);
    if (iter == g_DlpFdMap.end()) {
        return DLP_SUCCESS;
    } else {
        // clear cipher
        (void)memset_s(iter->second->key.data, iter->second->key.size, 0, iter->second->key.size);
        delete[] iter->second->key.data;

        (void)memset_s(iter->second->iv.data, iter->second->iv.size, 0, iter->second->iv.size);
        delete[] iter->second->iv.data;
        g_DlpFdMap.erase(iter);
        delete iter->second;
        return DLP_SUCCESS;
    }
}


#ifdef __cplusplus
}
#endif
