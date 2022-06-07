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

#include "dlp_format.h"
#include "dlp_utils.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <securec.h>
#include <unistd.h>
#include <new>

namespace DLP {
using namespace std;
static void dumpptr(uint8_t *ptr, uint32_t len)
{
    uint8_t *abc = nullptr;
    abc = (uint8_t *)ptr;
    for (uint32_t i = 0; i < len; i++) {
        printf("%x ", *abc);
        abc++;
    }
    printf("\n");
}

#define DLP_BUFF_LEN (4096)
#define VALID_KEY_SIZE (32)
#define VALID_IV_SIZE (16)
#define DLP_FILE_MAGIC (0x87f4922)
#define DLP_MAX_CERT_SIZE (1024 * 1024)

DlpFile::DlpFile()
{
    head_.magic = DLP_FILE_MAGIC;
    head_.version = 1;
    head_.txtOffset = 0xffffffff;
    head_.txtSize = 0xffffffff;
    cert_.certBuff = nullptr;
    head_.certOffset = sizeof(struct DlpHeader);
    head_.certSize = 0;

    cipher_.tagIv.iv.data = nullptr;
    cipher_.tagIv.iv.size = 0;

    cipher_.encKey.data = nullptr;
    cipher_.encKey.size = 0;

    cipher_.usageSpec = { 0 };
}

DlpFile::~DlpFile()
{
    // clear key
    if (cipher_.encKey.data != nullptr) {
        (void)memset_s(cipher_.encKey.data, cipher_.encKey.size, 0, cipher_.encKey.size);
        delete[] cipher_.encKey.data;
        cipher_.encKey.data = nullptr;
    }

    // clear iv
    if (cipher_.tagIv.iv.data != nullptr) {
        (void)memset_s(cipher_.tagIv.iv.data, cipher_.tagIv.iv.size, 0, cipher_.tagIv.iv.size);
        delete[] cipher_.tagIv.iv.data;
        cipher_.tagIv.iv.data = nullptr;
    }

    // clear encrypt cert
    if (cert_.certBuff != nullptr) {
        (void)memset_s(cert_.certBuff, head_.certSize, 0, head_.certSize);
        delete[] cert_.certBuff;
        cert_.certBuff = nullptr;
    }
}
// 生存明文证书

// 文件系统读写接口

int32_t DlpFile::SetCipher(const struct DlpBlob &key, const struct DlpUsageSpec &spec)
{
    if (key.data == nullptr) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    if (spec.mode != DLP_MODE_CTR || spec.padding != DLP_PADDING_NONE || spec.algParam == nullptr) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    struct DlpBlob *iv = &(spec.algParam->iv);

    if (key.size != 32 || iv->size != 16) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    cipher_.tagIv.iv.data = new (std::nothrow) uint8_t[iv->size];
    if (cipher_.tagIv.iv.data == nullptr) {
        return DLP_ERROR_MALLOC_FAIL;
    }

    (void)memcpy_s(cipher_.tagIv.iv.data, iv->size, iv->data, iv->size);
    cipher_.tagIv.iv.size = iv->size;

    cipher_.encKey.data = new (std::nothrow) uint8_t[key.size];
    if (cipher_.encKey.data == nullptr) {
        (void)memset_s(cipher_.tagIv.iv.data, iv->size, 0, iv->size);
        delete[] cipher_.tagIv.iv.data;
        cipher_.tagIv.iv.data = nullptr;
        return DLP_ERROR_MALLOC_FAIL;
    }

    (void)memcpy_s(cipher_.encKey.data, key.size, key.data, key.size);
    cipher_.encKey.size = key.size;

    cipher_.usageSpec.mode = spec.mode;
    cipher_.usageSpec.padding = spec.padding;
    cipher_.usageSpec.algParam = &cipher_.tagIv;

    return DLP_SUCCESS;
}

int32_t DlpFile::SetEncryptCert(const struct DlpBlob &data)
{
    if (data.data == nullptr) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    if (data.size == 0 || data.size > DLP_MAX_CERT_SIZE) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    cert_.certBuff = new (nothrow)uint8_t[data.size];
    if (cert_.certBuff == nullptr) {
        return DLP_ERROR_MALLOC_FAIL;
    }

    (void)memcpy_s(cert_.certBuff, data.size, data.data, data.size);

    head_.certOffset = sizeof(struct DlpHeader);
    head_.certSize = data.size;
    head_.txtOffset = sizeof(struct DlpHeader) + data.size;

    return DLP_SUCCESS;
}

static int32_t ValidateDlpHeader(struct DlpHeader &head)
{
    if (head.magic != DLP_FILE_MAGIC) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    if (head.certSize == 0 || head.certSize > DLP_MAX_CERT_SIZE) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }
    return DLP_SUCCESS;
}

int32_t DlpFile::FileParse(const std::string &inputFileUri, struct DlpHeader &head, struct DlpEncryptCert &cert)
{
    ifstream in(inputFileUri, ios::in | ios::binary);

    if (!in.is_open()) {
        return DLP_ERROR_FILE_FAIL;
    }

    in.read((char *)&head_, sizeof(struct DlpHeader));
    if (ValidateDlpHeader(head_) != 0) {
        (void)memset_s(&head_, sizeof(struct DlpHeader), 0, sizeof(struct DlpHeader));
        in.close();
        return DLP_ERROR_NOT_DLP_FILE;
    }

    (void)memcpy_s(&head, sizeof(struct DlpHeader), &head_, sizeof(struct DlpHeader));
    // parse cert
    uint8_t *buf = new (nothrow)uint8_t[head_.certSize];
    if (buf == nullptr) {
        in.close();
        (void)memset_s(&head_, sizeof(struct DlpHeader), 0, sizeof(struct DlpHeader));
        return DLP_ERROR_MALLOC_FAIL;
    }
    in.read((char *)buf, head_.certSize);
    cert_.certBuff = buf;

    uint8_t *outBuf = new (nothrow)uint8_t[head_.certSize];
    if (outBuf == nullptr) {
        in.close();
        (void)memset_s(&head_, sizeof(struct DlpHeader), 0, sizeof(struct DlpHeader));
        return DLP_ERROR_MALLOC_FAIL;
    }
    (void)memcpy_s(outBuf, head_.certSize, buf, head_.certSize);
    cert.certBuff = outBuf;
    head.certSize = head_.certSize;
    in.close();
    return DLP_SUCCESS;
}

int32_t DlpFile::FileParse(const std::string &inputFileUri)
{
    ifstream in(inputFileUri, ios::in | ios::binary);

    if (!in.is_open()) {
        return DLP_ERROR_FILE_FAIL;
    }

    in.read((char *)&head_, sizeof(struct DlpHeader));
    if (ValidateDlpHeader(head_) != 0) {
        (void)memset_s(&head_, sizeof(struct DlpHeader), 0, sizeof(struct DlpHeader));
        in.close();
        return DLP_ERROR_NOT_DLP_FILE;
    }

    // parse cert
    uint8_t *buf = new (nothrow)uint8_t[head_.certSize];
    if (buf == nullptr) {
        in.close();
        return DLP_ERROR_MALLOC_FAIL;
    }
    in.read((char *)buf, head_.certSize);
    cert_.certBuff = buf;
    in.close();
    return DLP_SUCCESS;
}

int32_t DlpFile::FileParse(int32_t fd, uint32_t &offset)
{
    struct DlpHeader *tmp = new (nothrow) struct DlpHeader[1];
    (void)read(fd, (void *)tmp, sizeof(struct DlpHeader));
    if (ValidateDlpHeader(*tmp) != 0) {
        return DLP_ERROR_NOT_DLP_FILE;
    }

    offset = tmp->txtOffset;
    delete[] tmp;
    return 0;
}

int32_t DlpFile::GenFile(const std::string &inputFileUri, const std::string &outputFileUri)
{
    ifstream in(inputFileUri, ios::in | ios::binary);
    if (!in.is_open()) {
        DLP_LOG_E("open file %s fail!", inputFileUri.c_str());
        return DLP_ERROR_FILE_FAIL;
    }

    ofstream out(outputFileUri, ios::ate | ios::out | ios::binary);
    if (!out.is_open()) {
        DLP_LOG_E("open file %s fail!", outputFileUri.c_str());
        in.close();
        return DLP_ERROR_FILE_FAIL;
    }

    in.seekg(0, ios::end);
    uint32_t file_len = in.tellg();
    in.seekg(0, ios::beg);

    head_.txtSize = file_len;
    out.write((char *)&head_, sizeof(struct DlpHeader));
    out.write((char *)cert_.certBuff, head_.certSize);

    struct DlpBlob message1 = {
        .size = DLP_BUFF_LEN
    };
    struct DlpBlob message2 = {
        .size = DLP_BUFF_LEN
    };
    message1.data = new (nothrow)uint8_t[DLP_BUFF_LEN];
    if (message1.data == nullptr) {
        in.close();
        out.close();
        return DLP_ERROR_MALLOC_FAIL;
    }
    message2.data = new (nothrow)uint8_t[DLP_BUFF_LEN];
    if (message2.data == nullptr) {
        in.close();
        out.close();
        delete message1.data;
        return DLP_ERROR_MALLOC_FAIL;
    }

    (void)memset_s(message1.data, DLP_BUFF_LEN, 0, DLP_BUFF_LEN);
    (void)memset_s(message2.data, DLP_BUFF_LEN, 0, DLP_BUFF_LEN);

    uint32_t offset = 0;
    uint32_t ret = 0;
    while (offset < file_len) {
        uint32_t read_len = ((file_len - offset) < DLP_BUFF_LEN) ? (file_len - offset) : DLP_BUFF_LEN;
        in.read((char *)message1.data, read_len);

        offset = in.tellg();
        message1.size = read_len;
        message2.size = read_len;
        ret = DlpOpensslAesEncrypt(&cipher_.encKey, &cipher_.usageSpec, &message1, &message2);
        if (ret != 0) {
            break;
        }

        dumpptr(message2.data, read_len);
        out.write((char *)message2.data, read_len);
    }
    delete[] message1.data;
    delete[] message2.data;

    out.close();
    in.close();

    if (ret != 0) {
        DLP_LOG_E("crypt operation fail, remove file");
        remove(outputFileUri.c_str());
        return DLP_ERROR_CRYPT_FAIL;
    }

    return DLP_SUCCESS;
}

int32_t DlpFile::RemoveDlpPermission(const std::string &inputFileUri, const std::string &outputFileUri)
{
    ifstream in(inputFileUri, ios::in | ios::binary);
    if (!in.is_open()) {
        DLP_LOG_E("open file %s fail!", inputFileUri.c_str());
        return DLP_ERROR_FILE_FAIL;
    }

    ofstream out(outputFileUri, ios::ate | ios::out | ios::binary);
    if (!out.is_open()) {
        DLP_LOG_E("open file %s fail!", outputFileUri.c_str());
        in.close();
        return DLP_ERROR_FILE_FAIL;
    }

    in.seekg(0, ios::end);
    uint32_t file_len = in.tellg();
    in.seekg(0, ios::beg);

    struct DlpBlob message1 = {
        .size = DLP_BUFF_LEN
    };
    struct DlpBlob message2 = {
        .size = DLP_BUFF_LEN
    };
    message1.data = new (nothrow)uint8_t[DLP_BUFF_LEN];
    if (message1.data == nullptr) {
        in.close();
        out.close();
        return DLP_ERROR_MALLOC_FAIL;
    }
    message2.data = new (nothrow)uint8_t[DLP_BUFF_LEN];
    if (message2.data == nullptr) {
        in.close();
        out.close();
        delete[] message1.data;
        return DLP_ERROR_MALLOC_FAIL;
    }

    (void)memset_s(message1.data, DLP_BUFF_LEN, 0, DLP_BUFF_LEN);
    (void)memset_s(message2.data, DLP_BUFF_LEN, 0, DLP_BUFF_LEN);

    in.seekg(head_.txtOffset, ios::beg);

    uint32_t offset = in.tellg();
    uint32_t ret = 0;
    while (offset < file_len) {
        uint32_t read_len = ((file_len - offset) < DLP_BUFF_LEN) ? (file_len - offset) : DLP_BUFF_LEN;
        in.read((char *)message1.data, read_len);
        offset = in.tellg();
        message1.size = read_len;
        message2.size = read_len;
        ret = DlpOpensslAesDecrypt(&cipher_.encKey, &cipher_.usageSpec, &message1, &message2);
        if (ret != 0) {
            break;
        }
        dumpptr(message2.data, read_len);
        out.write((char *)message2.data, read_len);
    }

    delete[] message1.data;
    delete[] message2.data;

    out.close();
    in.close();

    if (ret != 0) {
        DLP_LOG_E("crypt operation fail, remove file");
        remove(outputFileUri.c_str());
        return DLP_ERROR_CRYPT_FAIL;
    }
    return DLP_SUCCESS;
}

int32_t DlpFile::Operation(const std::string &inputFileUri, const std::string &outputFileUri, uint32_t op_flag)
{
    if (cipher_.encKey.data == nullptr || cipher_.tagIv.iv.data == nullptr || cert_.certBuff == nullptr) {
        return DLP_ERROR_INVALID_ARGUMENT;
    }

    switch (op_flag) {
        case DLP_ENCRYPTION:
            GenFile(inputFileUri, outputFileUri);
            break;
        case DLP_DECRYPTION:
            RemoveDlpPermission(inputFileUri, outputFileUri);
            break;
        default:
            return DLP_ERROR_INVALID_MODE;
    }
    return DLP_SUCCESS;
}
}

// end name space DLP;
