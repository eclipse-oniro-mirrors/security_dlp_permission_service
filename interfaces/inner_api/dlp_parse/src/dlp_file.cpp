/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dlp_file.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "ohos_account_kits.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFile"};
} // namespace

static void IncIvCounterLitteEndian(struct DlpBlob& iv, uint32_t count)
{
    uint8_t* data = iv.data;
    for (uint32_t i = iv.size - 1; i >= 0; i--) {
        count += data[i];
        data[i] = (uint8_t)count;
        count >>= BYTE_LEN;
        if (count == 0) {
            break;
        }
    }
}

static void IncIvCounterBigEndian(struct DlpBlob& iv, uint32_t count)
{
    uint32_t size = iv.size;
    uint8_t* data = iv.data;
    for (uint32_t i = 0; i < size; i++) {
        count += data[i];
        data[i] = (uint8_t)count;
        count >>= BYTE_LEN;
        if (count == 0) {
            break;
        }
    }
}

static void IncreaeIvCounter(struct DlpBlob& iv, uint32_t count)
{
    if (iv.data == nullptr || iv.size == 0) {
        DLP_LOG_ERROR(LABEL, "param error");
        return;
    }

    unsigned long bsCheck = 1;
    bool isLitteEndian = ((*(uint8_t *)&bsCheck) == 1);
    if (isLitteEndian) {
        IncIvCounterLitteEndian(iv, count);
    } else {
        IncIvCounterBigEndian(iv, count);
    }
}

DlpFile::DlpFile(int32_t dlpFd) : dlpFd_(dlpFd), isFuseLink_(false), isReadOnly_(true)
{
    head_.magic = DLP_FILE_MAGIC;
    head_.version = 1;
    head_.txtOffset = INVALID_FILE_SIZE;
    head_.txtSize = INVALID_FILE_SIZE;
    head_.certOffset = sizeof(struct DlpHeader);
    head_.certSize = 0;
    head_.contactAccountOffset = 0;
    head_.contactAccountSize = 0;

    cert_.data = nullptr;
    cert_.size = 0;

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
    if (cert_.data != nullptr) {
        (void)memset_s(cert_.data, head_.certSize, 0, head_.certSize);
        delete[] cert_.data;
        cert_.data = nullptr;
    }
}

bool DlpFile::IsValidCipher(const struct DlpBlob& key, const struct DlpUsageSpec& spec) const
{
    if (key.data == nullptr) {
        DLP_LOG_ERROR(LABEL, "key data null");
        return false;
    }

    if (key.size != DLP_KEY_LEN_128 && key.size != DLP_KEY_LEN_192 && key.size != DLP_KEY_LEN_256) {
        DLP_LOG_ERROR(LABEL, "key size invalid");
        return false;
    }

    if (spec.mode != DLP_MODE_CTR || spec.algParam == nullptr) {
        DLP_LOG_ERROR(LABEL, "spec invalid");
        return false;
    }

    struct DlpBlob& iv = spec.algParam->iv;
    if (iv.size != IV_SIZE || iv.data == nullptr) {
        DLP_LOG_ERROR(LABEL, "iv invalid");
        return false;
    }
    return true;
}

int32_t DlpFile::CopyBlobParam(const struct DlpBlob& src, struct DlpBlob& dst) const
{
    if (src.data == nullptr || src.size == 0 || src.size > DLP_MAX_CERT_SIZE) {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint8_t* blobData = new (std::nothrow)uint8_t[src.size];
    if (blobData == nullptr) {
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    if (memcpy_s(blobData, src.size, src.data, src.size) != EOK) {
        delete[] blobData;
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    dst.data = blobData;
    dst.size = src.size;
    return DLP_OK;
}

void DlpFile::CleanBlobParam(struct DlpBlob& blob) const
{
    if (blob.data == nullptr || blob.size == 0) {
        return;
    }

    (void)memset_s(blob.data, blob.size, 0, blob.size);
    delete[] blob.data;
    blob.data = nullptr;
    blob.size = 0;
}

int32_t DlpFile::GetLocalAccountName(std::string& account) const
{
    std::pair<bool, AccountSA::OhosAccountInfo> accountInfo =
        AccountSA::OhosAccountKits::GetInstance().QueryOhosAccountInfo();
    if (accountInfo.first) {
        account = accountInfo.second.name_;
        return DLP_OK;
    }
    return DLP_PARSE_ERROR_ACCOUNT_INVALID;
}

void DlpFile::UpdateDlpFilePermission()
{
    std::string accountName;
    if (GetLocalAccountName(accountName) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "query current account failed");
        return;
    }
    DLP_LOG_DEBUG(LABEL, "current account Name %{private}s", accountName.c_str());

    if (accountName == policy_.ownerAccount_) {
        DLP_LOG_DEBUG(LABEL, "current account is owner, it has full permission");
        isReadOnly_ = false;
        return;
    }

    for (int32_t i = 0; i < (int32_t)policy_.authUsers_.size(); i++) {
        if (accountName == policy_.authUsers_[i].authAccount) {
            isReadOnly_ = (policy_.authUsers_[i].authPerm == READ_ONLY);
            DLP_LOG_DEBUG(LABEL, "current account match authUsers list, isReadOnly_ %{public}s",
                isReadOnly_ ? "true" : "false");
        }
    }
}

int32_t DlpFile::SetCipher(const struct DlpBlob& key, const struct DlpUsageSpec& spec)
{
    if (!IsValidCipher(key, spec)) {
        DLP_LOG_ERROR(LABEL, "dlp file cipher is invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    // copy iv from param.
    int32_t res = CopyBlobParam(spec.algParam->iv, cipher_.tagIv.iv);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "dlp file copy iv param failed, res %{public}d", res);
        return res;
    }

    // copy key from param.
    res = CopyBlobParam(key, cipher_.encKey);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "dlp file copy key param failed, res %{public}d", res);
        CleanBlobParam(cipher_.tagIv.iv);
        return res;
    }

    cipher_.usageSpec.mode = spec.mode;
    cipher_.usageSpec.algParam = &cipher_.tagIv;
    return DLP_OK;
}

int32_t DlpFile::SetContactAccount(const std::string& contactAccount)
{
    if (contactAccount.size() == 0 || contactAccount.size() > DLP_MAX_CERT_SIZE) {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    contactAccount_ = contactAccount;
    if (head_.certSize != 0) {
        head_.contactAccountSize = contactAccount.size();
        head_.contactAccountOffset = head_.certOffset + head_.certSize;
        head_.txtOffset = head_.contactAccountOffset + head_.contactAccountSize;
    }
    return DLP_OK;
};

int32_t DlpFile::SetPolicy(const PermissionPolicy& policy)
{
    if (!policy.IsValid()) {
        DLP_LOG_ERROR(LABEL, "invalid policy");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    policy_.CopyPermissionPolicy(policy);
    UpdateDlpFilePermission();
    return DLP_OK;
};

bool DlpFile::IsValidDlpHeader(const struct DlpHeader& head) const
{
    if (head.magic != DLP_FILE_MAGIC || head.certSize == 0 || head.certSize > DLP_MAX_CERT_SIZE
        || head.contactAccountSize == 0 || head.contactAccountSize > DLP_MAX_CERT_SIZE) {
        return false;
    }
    return true;
}

int32_t DlpFile::ParseDlpHeader()
{
    if (dlpFd_ < 0) {
        DLP_LOG_ERROR(LABEL, "dlp file fd is invalid");
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    if (isFuseLink_) {
        DLP_LOG_ERROR(LABEL, "current dlp file is linking, do not operate it.");
        return DLP_PARSE_ERROR_FILE_LINKING;
    }

    if (lseek(dlpFd_, 0, SEEK_SET) == (off_t)-1) {
        DLP_LOG_ERROR(LABEL, "seek dlp file start failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (read(dlpFd_, &head_, sizeof(struct DlpHeader)) != sizeof(struct DlpHeader)) {
        DLP_LOG_ERROR(LABEL, "can not read dlp file head, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_FORMAT_ERROR;
    }

    if (!IsValidDlpHeader(head_)) {
        DLP_LOG_ERROR(LABEL, "parse dlp file header error.");
        (void)memset_s(&head_, sizeof(struct DlpHeader), 0, sizeof(struct DlpHeader));
        return DLP_PARSE_ERROR_FILE_NOT_DLP;
    }

    // get cert encrypt context
    uint8_t* buf = new (std::nothrow)uint8_t[head_.certSize];
    if (buf == nullptr) {
        DLP_LOG_WARN(LABEL, "alloc buffer failed.");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    if (read(dlpFd_, buf, head_.certSize) != head_.certSize) {
        delete[] buf;
        DLP_LOG_ERROR(LABEL, "can not read dlp file cert, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    cert_.data = buf;
    cert_.size = head_.certSize;

    uint8_t *tmpBuf = new (std::nothrow)uint8_t[head_.contactAccountSize];
    if (tmpBuf == nullptr) {
        DLP_LOG_WARN(LABEL, "alloc tmpBuf failed.");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    if (read(dlpFd_, tmpBuf, head_.contactAccountSize) != head_.contactAccountSize) {
        delete[] tmpBuf;
        DLP_LOG_ERROR(LABEL, "can not read dlp contact account, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    contactAccount_ = std::string(tmpBuf, tmpBuf + head_.contactAccountSize);
    delete[] tmpBuf;
    return DLP_OK;
}

int32_t DlpFile::GetEncryptCert(struct DlpBlob& cert) const
{
    cert.data = cert_.data;
    cert.size = cert_.size;
    return DLP_OK;
}

int32_t DlpFile::SetEncryptCert(const struct DlpBlob& cert)
{
    if (cert.data == nullptr || cert.size > DLP_MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Cert data invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (cert_.data != nullptr) {
        delete[] cert_.data;
        cert_.data = nullptr;
    }

    if (CopyBlobParam(cert, cert_) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Cert copy failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    head_.certOffset = sizeof(struct DlpHeader);
    head_.certSize = cert_.size;
    head_.txtOffset = sizeof(struct DlpHeader) + cert_.size;
    return DLP_OK;
}

int32_t DlpFile::PrepareBuff(struct DlpBlob& message1, struct DlpBlob& message2) const
{
    message1.size = DLP_BUFF_LEN;
    message1.data = new (std::nothrow) uint8_t[DLP_BUFF_LEN];
    if (message1.data == nullptr) {
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    message2.size = DLP_BUFF_LEN;
    message2.data = new (std::nothrow) uint8_t[DLP_BUFF_LEN];
    if (message2.data == nullptr) {
        delete[] message1.data;
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    (void)memset_s(message1.data, DLP_BUFF_LEN, 0, DLP_BUFF_LEN);
    (void)memset_s(message2.data, DLP_BUFF_LEN, 0, DLP_BUFF_LEN);
    return DLP_OK;
}

int32_t DlpFile::DupUsageSpec(struct DlpUsageSpec& spec)
{
    spec.mode = cipher_.usageSpec.mode;
    spec.algParam = new (std::nothrow) struct DlpCipherParam;
    if (spec.algParam == nullptr) {
        DLP_LOG_ERROR(LABEL, "new alg param failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    spec.algParam->iv.data = new (std::nothrow) uint8_t[IV_SIZE]();
    if (spec.algParam->iv.data == nullptr) {
        delete spec.algParam;
        DLP_LOG_ERROR(LABEL, "new iv failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    spec.algParam->iv.size = cipher_.usageSpec.algParam->iv.size;
    if (memcpy_s(spec.algParam->iv.data, IV_SIZE,
        cipher_.usageSpec.algParam->iv.data, cipher_.usageSpec.algParam->iv.size) != EOK) {
        delete[] spec.algParam->iv.data;
        delete spec.algParam;
        DLP_LOG_ERROR(LABEL, "copy iv failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    return DLP_OK;
}

int32_t DlpFile::DoDlpBlockCryptOperation(struct DlpBlob& message1, struct DlpBlob& message2,
    uint32_t offset, bool isEncrypt)
{
    if (offset % DLP_BLOCK_SIZE != 0 || message1.data == nullptr || message1.size == 0
        ||  message2.data == nullptr || message2.size == 0) {
        DLP_LOG_ERROR(LABEL, "params is error");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint32_t counterIndex = offset / DLP_BLOCK_SIZE;
    struct DlpUsageSpec spec;
    if (DupUsageSpec(spec) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "spec dup failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    IncreaeIvCounter(spec.algParam->iv, counterIndex);
    int32_t ret = isEncrypt ? DlpOpensslAesEncrypt(&cipher_.encKey, &spec, &message1, &message2) :
        DlpOpensslAesDecrypt(&cipher_.encKey, &spec, &message1, &message2);
    delete[] spec.algParam->iv.data;
    delete spec.algParam;
    if (ret != 0) {
        DLP_LOG_ERROR(LABEL, "do block crypt fail");
        return DLP_PARSE_ERROR_CRYPT_FAIL;
    }
    return DLP_OK;
}

int32_t DlpFile::DoDlpContentCryptyOperation(int32_t inFd, int32_t outFd, uint32_t inOffset,
    uint32_t inFileLen, bool isEncrypt)
{
    struct DlpBlob message, outMessage;
    if (PrepareBuff(message, outMessage) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "prepare buff failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    uint32_t dlpContentOffset = inOffset;
    int32_t ret = DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    while (inOffset < inFileLen) {
        uint32_t readLen = ((inFileLen - inOffset) < DLP_BUFF_LEN) ? (inFileLen - inOffset) : DLP_BUFF_LEN;
        (void)memset_s(message.data, DLP_BUFF_LEN, 0, DLP_BUFF_LEN);
        (void)memset_s(outMessage.data, DLP_BUFF_LEN, 0, DLP_BUFF_LEN);
        if (read(inFd, message.data, readLen) != readLen) {
            DLP_LOG_ERROR(LABEL, "Read size do not equal readLen");
            ret = DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
            break;
        }

        message.size = readLen;
        outMessage.size = readLen;
        // Implicit condition: DLP_BUFF_LEN must be DLP_BLOCK_SIZE aligned
        ret = DoDlpBlockCryptOperation(message, outMessage, inOffset - dlpContentOffset, isEncrypt);
        if (ret != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "do crypt operation fail");
            break;
        }

        if (write(outFd, outMessage.data, readLen) != readLen) {
            DLP_LOG_ERROR(LABEL, "write fd failed, %{public}s", strerror(errno));
            ret = DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
            break;
        }
        inOffset += readLen;
    }

    delete[] message.data;
    delete[] outMessage.data;
    return ret;
}

int32_t DlpFile::GenFile(int32_t inPlainFileFd)
{
    if (inPlainFileFd < 0 || dlpFd_ < 0 || !IsValidCipher(cipher_.encKey, cipher_.usageSpec)) {
        DLP_LOG_ERROR(LABEL, "params is error");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    off_t fileLen = lseek(inPlainFileFd, 0, SEEK_END);
    if (fileLen == (off_t)-1) {
        DLP_LOG_ERROR(LABEL, "can not get inFd len, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    head_.txtSize = (uint32_t)fileLen;
    DLP_LOG_DEBUG(LABEL, "fileLen %{private}ld", fileLen);

    // clean dlpFile
    if (ftruncate(dlpFd_, 0) == -1) {
        DLP_LOG_ERROR(LABEL, "truncate dlp file to zero failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (lseek(inPlainFileFd, 0, SEEK_SET) == (off_t)-1) {
        DLP_LOG_ERROR(LABEL, "seek plain file start failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (lseek(dlpFd_, 0, SEEK_SET) == (off_t)-1) {
        DLP_LOG_ERROR(LABEL, "seek dlp file start failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (write(dlpFd_, &head_, sizeof(struct DlpHeader)) != sizeof(struct DlpHeader)) {
        DLP_LOG_ERROR(LABEL, "write dlp head failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (write(dlpFd_, cert_.data, head_.certSize) != head_.certSize) {
        DLP_LOG_ERROR(LABEL, "write dlp cert data failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (write(dlpFd_, contactAccount_.c_str(), contactAccount_.size()) != (int32_t)contactAccount_.size()) {
        DLP_LOG_ERROR(LABEL, "write dlp contact data failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (fileLen == 0) {
        DLP_LOG_INFO(LABEL, "Plaintext file len is 0, do not need encrypt");
        return DLP_OK;
    }
    return DoDlpContentCryptyOperation(inPlainFileFd, dlpFd_, 0, fileLen, true);
}

int32_t DlpFile::RemoveDlpPermission(int32_t outPlainFileFd)
{
    if (isFuseLink_) {
        DLP_LOG_ERROR(LABEL, "current dlp file is linking, do not operate it.");
        return DLP_PARSE_ERROR_FILE_LINKING;
    }

    if (isReadOnly_) {
        DLP_LOG_ERROR(LABEL, "dlp file is read only, remove dlp permission failed.");
        return DLP_PARSE_ERROR_FILE_READ_ONLY;
    }

    if (outPlainFileFd < 0 || dlpFd_ < 0) {
        DLP_LOG_ERROR(LABEL, "fd is invalid");
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    if (!IsValidCipher(cipher_.encKey, cipher_.usageSpec)) {
        DLP_LOG_ERROR(LABEL, "cipher params is invalid");
        return DLP_PARSE_ERROR_CIPHER_PARAMS_INVALID;
    }

    off_t fileLen = lseek(dlpFd_, 0, SEEK_END);
    if (fileLen == (off_t)-1) {
        DLP_LOG_ERROR(LABEL, "can not get dlp file len, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    // clean plainTxtFile
    if (ftruncate(outPlainFileFd, 0) == -1) {
        DLP_LOG_ERROR(LABEL, "truncate plain file to zero failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (lseek(outPlainFileFd, 0, SEEK_SET) == (off_t)-1) {
        DLP_LOG_ERROR(LABEL, "seek plain file start failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (lseek(dlpFd_, head_.txtOffset, SEEK_SET) == (off_t)-1) {
        DLP_LOG_ERROR(LABEL, "seek dlp file start failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (fileLen == head_.txtOffset) {
        DLP_LOG_INFO(LABEL, "Dlp file have no content");
        return DLP_OK;
    }

    return DoDlpContentCryptyOperation(dlpFd_, outPlainFileFd, head_.txtOffset, fileLen, false);
}

static void DeleteBufs(uint8_t* buff1, uint8_t* buff2)
{
    if (buff1 != nullptr) {
        delete[] buff1;
    }
    if (buff2 != nullptr) {
        delete[] buff2;
    }
}

int32_t DlpFile::DlpFileRead(uint32_t offset, void* buf, uint32_t size)
{
    if (buf == nullptr || size == 0 || size > DLP_FUSE_MAX_BUFFLEN ||
        dlpFd_ < 0 || !IsValidCipher(cipher_.encKey, cipher_.usageSpec)) {
        DLP_LOG_ERROR(LABEL, "params is error");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint32_t alignOffset = (offset / DLP_BLOCK_SIZE) * DLP_BLOCK_SIZE;
    uint32_t prefixingSize = offset - alignOffset;
    uint32_t alignSize = size + prefixingSize;
    if (lseek(dlpFd_, head_.txtOffset + alignOffset, SEEK_SET) == -1) {
        DLP_LOG_ERROR(LABEL, "lseek dlp file failed. %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    uint8_t* encBuff = new (std::nothrow) uint8_t[alignSize]();
    if (encBuff == nullptr) {
        DLP_LOG_ERROR(LABEL, "new buff fail");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    uint8_t* outBuff = new (std::nothrow) uint8_t[alignSize]();
    if (outBuff == nullptr) {
        DeleteBufs(encBuff, nullptr);
        DLP_LOG_ERROR(LABEL, "new buff fail");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    int32_t readLen = read(dlpFd_, encBuff, alignSize);
    if (readLen == -1) {
        DeleteBufs(encBuff, outBuff);
        DLP_LOG_ERROR(LABEL, "read buff fail, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    if (readLen <= (int32_t)prefixingSize) {
        DeleteBufs(encBuff, outBuff);
        return 0;
    }

    struct DlpBlob message1 = {.size = readLen, .data = encBuff};
    struct DlpBlob message2 = {.size = readLen, .data = static_cast<uint8_t*>(outBuff)};
    if (DoDlpBlockCryptOperation(message1, message2, alignOffset, false) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "decrypt fail");
        DeleteBufs(encBuff, outBuff);
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (memcpy_s(buf, size, outBuff + prefixingSize, message2.size - prefixingSize) != EOK) {
        DeleteBufs(encBuff, outBuff);
        DLP_LOG_ERROR(LABEL, "copy decrypt result failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    DeleteBufs(encBuff, outBuff);
    return message2.size - prefixingSize;
}

int32_t DlpFile::WriteFirstBlockData(uint32_t offset, void* buf, uint32_t size)
{
    uint32_t alignOffset = (offset / DLP_BLOCK_SIZE) * DLP_BLOCK_SIZE;
    uint32_t prefixingSize = offset % DLP_BLOCK_SIZE;
    uint32_t requestSize = (size < (DLP_BLOCK_SIZE - prefixingSize)) ? size : (DLP_BLOCK_SIZE - prefixingSize);
    uint32_t writtenSize = prefixingSize + requestSize;
    uint8_t enBuf[DLP_BLOCK_SIZE] = {0};
    uint8_t deBuf[DLP_BLOCK_SIZE] = {0};

    do {
        if (prefixingSize == 0) {
            break;
        }
        int32_t readLen = read(dlpFd_, enBuf, prefixingSize);
        if (readLen == -1) {
            DLP_LOG_ERROR(LABEL, "read first block prefixing fail, %{public}s", strerror(errno));
            return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
        }
        if (readLen == 0) {
            break;
        }

        struct DlpBlob message1 = {.size = prefixingSize, .data = enBuf};
        struct DlpBlob message2 = {.size = prefixingSize, .data = deBuf};
        if (DoDlpBlockCryptOperation(message1, message2, alignOffset, false) != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "decrypt appending bytes fail, %{public}s", strerror(errno));
            return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
        }
    } while (false);

    if (memcpy_s(deBuf + prefixingSize, DLP_BLOCK_SIZE, buf, requestSize)) {
        DLP_LOG_ERROR(LABEL, "copy write buffer first block failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    struct DlpBlob message1 = {.size = writtenSize, .data = deBuf};
    struct DlpBlob message2 = {.size = writtenSize, .data = enBuf};
    if (DoDlpBlockCryptOperation(message1, message2, alignOffset, true) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "enrypt first block fail");
        return DLP_PARSE_ERROR_CRYPT_FAIL;
    }

    if (lseek(dlpFd_, head_.txtOffset + alignOffset, SEEK_SET) == (off_t)-1) {
        DLP_LOG_ERROR(LABEL, "lseek failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    if (write(dlpFd_, enBuf, writtenSize) != writtenSize) {
        DLP_LOG_ERROR(LABEL, "write failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    return requestSize;
}

int32_t DlpFile::DoDlpFileWrite(uint32_t offset, void* buf, uint32_t size)
{
    uint32_t alignOffset = (offset / DLP_BLOCK_SIZE * DLP_BLOCK_SIZE);
    if (lseek(dlpFd_, head_.txtOffset + alignOffset, SEEK_SET) == (off_t)-1) {
        DLP_LOG_ERROR(LABEL, "lseek dlp file offset %{public}d failed, %{public}s",
            head_.txtOffset + offset, strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    /* write first block data, if it may be not aligned */
    int32_t writenSize = WriteFirstBlockData(offset, (uint8_t *)buf, size);
    if (writenSize < 0) {
        DLP_LOG_ERROR(LABEL, "encrypt prefix data failed");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    if (static_cast<uint32_t>(writenSize) >= size) {
        return writenSize;
    }

    uint8_t *restBlocksPtr = (uint8_t *)buf + writenSize;
    uint32_t restBlocksSize = size - static_cast<uint32_t>(writenSize);
    uint8_t* writeBuff = new (std::nothrow) uint8_t[restBlocksSize]();
    if (writeBuff == nullptr) {
        DLP_LOG_ERROR(LABEL, "alloc write buffer fail");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    /* first aligned block has been writen, write the rest */
    struct DlpBlob message1 = {.size = restBlocksSize, .data = restBlocksPtr};
    struct DlpBlob message2 = {.size = restBlocksSize, .data = writeBuff};

    int ret = DoDlpBlockCryptOperation(message1, message2, alignOffset + DLP_BLOCK_SIZE, true);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "encrypt write buffer fail");
        delete[] writeBuff;
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    ret = write(dlpFd_, writeBuff, restBlocksSize);
    delete[] writeBuff;
    if (ret <= 0) {
        DLP_LOG_ERROR(LABEL, "write buff failed, %{public}s", strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }

    return ret + (int32_t)writenSize;
}

uint32_t DlpFile::GetFsContentSize() const
{
    struct stat fileStat;
    int32_t ret = fstat(dlpFd_, &fileStat);
    if (ret != 0) {
        return INVALID_FILE_SIZE;
    }
    if (head_.txtOffset > fileStat.st_size) {
        return INVALID_FILE_SIZE;
    }
    return (uint32_t)fileStat.st_size - head_.txtOffset;
}

void DlpFile::UpdateDlpFileContentSize()
{
    uint32_t contentSize = GetFsContentSize();
    if (contentSize == INVALID_FILE_SIZE) {
        DLP_LOG_ERROR(LABEL, "get fs content size failed");
        return;
    }
    head_.txtSize = contentSize;
    DLP_LOG_DEBUG(LABEL, "Update dlp file content size");

    if (lseek(dlpFd_, 0, SEEK_SET) == static_cast<off_t>(-1)) {
        DLP_LOG_ERROR(LABEL, "Lseek failed, %{public}s", strerror(errno));
        return;
    }

    if (write(dlpFd_, &head_, sizeof(head_)) != sizeof(head_)) {
        DLP_LOG_ERROR(LABEL, "Write failed, %{public}s", strerror(errno));
        return;
    }
}

int32_t DlpFile::FillHoleData(uint32_t holeStart, uint32_t holeSize)
{
    DLP_LOG_INFO(LABEL, "Need create a hole filled with 0s, hole start %{public}x size %{public}x",
        holeStart, holeSize);
    uint32_t holeBufSize = (holeSize < HOLE_BUFF_SMALL_SIZE) ? HOLE_BUFF_SMALL_SIZE : HOLE_BUFF_SIZE;
    std::unique_ptr<uint8_t[]> holeBuff(new (std::nothrow) uint8_t[holeBufSize]());
    if (holeBuff == nullptr) {
        DLP_LOG_ERROR(LABEL, "New buf failed.");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    uint32_t fillLen = 0;
    while (fillLen < holeSize) {
        uint32_t writeSize = ((holeSize - fillLen) < holeBufSize) ? (holeSize - fillLen) : holeBufSize;
        int32_t res = DoDlpFileWrite(holeStart + fillLen, holeBuff.get(), writeSize);
        if (res < 0) {
            DLP_LOG_ERROR(LABEL, "Write failed, error %{public}d.", res);
            break;
        }
        fillLen += writeSize;
    }
    return DLP_OK;
}

int32_t DlpFile::DlpFileWrite(uint32_t offset, void* buf, uint32_t size)
{
    if (isReadOnly_) {
        DLP_LOG_ERROR(LABEL, "Dlp file is readonly, write failed");
        return DLP_PARSE_ERROR_FILE_READ_ONLY;
    }

    if (buf == nullptr || size == 0 || size > DLP_FUSE_MAX_BUFFLEN ||
        dlpFd_ < 0 || !IsValidCipher(cipher_.encKey, cipher_.usageSpec)) {
        DLP_LOG_ERROR(LABEL, "Dlp file param invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint32_t curSize = GetFsContentSize();
    if (curSize != INVALID_FILE_SIZE && curSize < offset &&
        (FillHoleData(curSize, offset - curSize) != DLP_OK)) {
        DLP_LOG_ERROR(LABEL, "Fill hole data failed");
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    int32_t res = DoDlpFileWrite(offset, buf, size);
    UpdateDlpFileContentSize();
    return res;
}

int32_t DlpFile::Truncate(uint32_t size)
{
    DLP_LOG_INFO(LABEL, "Truncate file size %{public}d", size);

    if (isReadOnly_) {
        DLP_LOG_ERROR(LABEL, "Dlp file is readonly, truncate failed");
        return DLP_PARSE_ERROR_FILE_READ_ONLY;
    }

    if (dlpFd_ < 0 || size >= INVALID_FILE_SIZE - head_.txtOffset) {
        DLP_LOG_ERROR(LABEL, "Param invalid");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint32_t curSize = GetFsContentSize();
    int res = DLP_OK;
    if (size < curSize) {
        res = ftruncate(dlpFd_, head_.txtOffset + size);
        UpdateDlpFileContentSize();
    } else if (size > curSize) {
        res = FillHoleData(curSize, size - curSize);
        UpdateDlpFileContentSize();
    } else {
        DLP_LOG_INFO(LABEL, "Truncate file size equals origin file");
    }

    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Truncate file size %{public}d failed, %{public}s", size, strerror(errno));
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    return DLP_OK;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
