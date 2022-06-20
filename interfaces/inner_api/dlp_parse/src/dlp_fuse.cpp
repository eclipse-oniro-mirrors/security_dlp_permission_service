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
#include <cerrno>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <new>
#include <securec.h>
#include <string>
#include <vector>
#include <unistd.h>
#include <unordered_map>

#ifdef __cplusplus
extern "C" {
#endif

using namespace std;
using namespace  OHOS::Security::DlpFormat;
struct DlpFuseInfo {
    uint32_t txtOffset;
    struct DlpBlob key;
    struct DlpBlob iv;
};

static std::unordered_map<int32_t, struct DlpFuseInfo *> g_DlpFdMap;
static OHOS::Utils::RWLock g_DlpMapLock;

static uint32_t GetFdConfig(int32_t fd, struct DlpBlob **key, struct DlpUsageSpec &usageSpec,
    struct DlpCipherParam &tagIv, uint32_t &dlpOffset)
{
    struct DlpBlob *iv;
    auto iter = g_DlpFdMap.find(fd);
    if (iter != g_DlpFdMap.end()) {
        *key = &(iter->second->key);
        iv = &(iter->second->iv);
        dlpOffset = iter->second->txtOffset;
        tagIv.iv.size = iv->size;
        tagIv.iv.data = iv->data;
        usageSpec.mode = DLP_MODE_CTR;
        usageSpec.algParam = &tagIv;
        return DLP_SUCCESS;
    } else {
        return DLP_ERROR_INVALID_FD;
    }
}

int32_t DlpFileRead(int32_t fd, uint32_t offset, void *buf, uint32_t size)
{
    struct DlpBlob *key;
    struct DlpUsageSpec usageSpec;
    struct DlpCipherParam tagIv;
    uint32_t dlpOffset;
    int32_t ret;

    if (buf == nullptr || size == 0 || size > DLP_FUSE_MAX_BUFFLEN) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> mapGuard(g_DlpMapLock);
    if (GetFdConfig(fd, &key, usageSpec, tagIv, dlpOffset) != DLP_SUCCESS) {
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
        delete[] encBuff;
        return DLP_ERROR_READ_FAIL;
    }

    struct DlpBlob message1 = { .size = size, .data = encBuff };
    struct DlpBlob message2 = { .size = size, .data = static_cast<uint8_t *>(buf) };
    ret = DlpOpensslAesDecrypt(key, &usageSpec, &message1, &message2);
    delete[] encBuff;
    if (ret != 0) {
        return DLP_ERROR_CRYPT_FAIL;
    }

    return ret;
}

int32_t DlpFileWrite(int32_t fd, uint32_t offset, void *buf, uint32_t size)
{
    if (buf == nullptr || size == 0 || size > DLP_FUSE_MAX_BUFFLEN) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    struct DlpBlob *key;
    struct DlpUsageSpec usageSpec;
    struct DlpCipherParam tagIv;
    uint32_t dlpOffset;

    OHOS::Utils::UniqueReadGuard<OHOS::Utils::RWLock> mapGuard(g_DlpMapLock);
    if (GetFdConfig(fd, &key, usageSpec, tagIv, dlpOffset) != DLP_SUCCESS) {
        return DLP_ERROR_INVALID_FD;
    }

    int32_t ret = lseek(fd, dlpOffset + offset, SEEK_SET);
    if (ret < 0) {
        return DLP_ERROR_LSEEK_FAIL;
    }

    uint8_t *writeBuff = new (std::nothrow) uint8_t[size];
    if (writeBuff == nullptr) {
        return DLP_ERROR_MALLOC_FAIL;
    }

    struct DlpBlob message1 = { .size = size, .data = static_cast<uint8_t *>(buf) };
    struct DlpBlob message2 = { .size = size, .data = writeBuff };

    ret = DlpOpensslAesEncrypt(key, &usageSpec, &message1, &message2);
    if (ret != 0) {
        delete[] writeBuff;
        return DLP_ERROR_CRYPT_FAIL;
    }

    ret = write(fd, (void *)writeBuff, size);
    delete[] writeBuff;
    if (ret < 0) {
        return DLP_ERROR_WRITE_FAIL;
    }
    return DLP_SUCCESS;
}

static struct DlpFuseInfo *PrepareFuseInfo(struct DlpBlob *key, struct DlpBlob *iv, uint32_t offset)
{
    struct DlpFuseInfo *buf = new (std::nothrow) struct DlpFuseInfo;
    if (buf == nullptr) {
        return nullptr;
    }
    buf->txtOffset = offset;

    buf->key.data = new (std::nothrow) uint8_t[key->size];
    if (buf->key.data == nullptr) {
        delete buf;
        return nullptr;
    }

    buf->key.size = key->size;
    if (memcpy_s(buf->key.data, buf->key.size, key->data, key->size) != 0) {
        delete[] buf->key.data;
        delete buf;
        return nullptr;
    }

    buf->iv.data = new (std::nothrow) uint8_t[iv->size];
    if (buf->iv.data == nullptr) {
        delete[] buf->key.data;
        delete buf;
        return nullptr;
    }

    buf->iv.size = iv->size;
    if (memcpy_s(buf->iv.data, buf->iv.size, iv->data, iv->size) != 0) {
        delete[] buf->iv.data;
        delete[] buf->key.data;
        delete buf;
        return nullptr;
    }
    return buf;
}

static int32_t ValidateCipher(const struct DlpBlob *key, const struct DlpBlob *iv)
{
    if (key == nullptr || iv == nullptr) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    if (key->data == nullptr || iv->data == nullptr) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    if (iv->size != VALID_IV_SIZE) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    if (key->size != DLP_KEY_LEN_128 && key->size != DLP_KEY_LEN_192 && key->size != DLP_KEY_LEN_256) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    return DLP_SUCCESS;
}

// use DlpUsageSpec param later
int32_t DlpFileAdd(int32_t fd, struct DlpBlob *key, struct DlpBlob *iv)
{
    if (ValidateCipher(key, iv) != DLP_SUCCESS) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    static OHOS::Security::DlpFormat::DlpFile var;
    int32_t ret = 0;
    uint32_t offset = 0;

    ret = var.FileParse(fd);
    if (ret != 0) {
        return DLP_ERROR_CRYPT_FILE_PARSE_FAIL;
    }

    offset = var.GetTxtOffset();

    struct DlpFuseInfo *buf = PrepareFuseInfo(key, iv, offset);
    if (buf == nullptr) {
        return DLP_ERROR_MALLOC_FAIL;
    }

    {
        OHOS::Utils::UniqueWriteGuard<OHOS::Utils::RWLock> mapGuard(g_DlpMapLock);
        auto iter = g_DlpFdMap.find(fd);
        if (iter != g_DlpFdMap.end()) {
            (void)memset_s(buf->key.data, buf->key.size, 0, buf->key.size);
            (void)memset_s(buf->iv.data, buf->iv.size, 0, buf->iv.size);
            delete[] buf->key.data;
            delete[] buf->iv.data;
            delete buf;
            return DLP_ERROR_FD_EXIST;
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
        delete iter->second;
        g_DlpFdMap.erase(iter);
        return DLP_SUCCESS;
    }
}


#ifdef __cplusplus
}
#endif
