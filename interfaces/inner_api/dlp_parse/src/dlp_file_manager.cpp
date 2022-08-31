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
#include "dlp_file_manager.h"

#include "dlp_crypt.h"
#include "dlp_file.h"
#include "dlp_permission.h"
#include "dlp_permission_kit.h"
#include "dlp_permission_log.h"
#include "hitrace_meter.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFileManager"};
}

int32_t DlpFileManager::AddDlpFileNode(const std::shared_ptr<DlpFile>& filePtr)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->g_DlpMapLock_);
    if (g_DlpFileMap_.count(filePtr->dlpFd_) > 0) {
        DLP_LOG_ERROR(LABEL, "fd %{public}d is exist", filePtr->dlpFd_);
        return DLP_PARSE_ERROR_FILE_ALREADY_OPENED;
    }
    g_DlpFileMap_[filePtr->dlpFd_] = filePtr;
    return DLP_OK;
}

int32_t DlpFileManager::RemoveDlpFileNode(const std::shared_ptr<DlpFile>& filePtr)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->g_DlpMapLock_);
    if (g_DlpFileMap_.count(filePtr->dlpFd_) == 0) {
        DLP_LOG_ERROR(LABEL, "fd %{public}d is not exist", filePtr->dlpFd_);
        return DLP_PARSE_ERROR_FILE_NOT_OPENED;
    }
    g_DlpFileMap_.erase(filePtr->dlpFd_);
    return DLP_OK;
}

std::shared_ptr<DlpFile> DlpFileManager::GetDlpFile(int32_t dlpFd)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->g_DlpMapLock_);
    if (g_DlpFileMap_.count(dlpFd) != 0) {
        return g_DlpFileMap_[dlpFd];
    }
    return nullptr;
}

int32_t DlpFileManager::GenerateCertData(const PermissionPolicy& policy, struct DlpBlob& certData) const
{
    std::vector<uint8_t> cert;
    StartTrace(HITRACE_TAG_ACCESS_CONTROL, "DlpGenerateCertificate");
    int32_t result = DlpPermissionKit::GenerateDlpCertificate(policy, cert);
    FinishTrace(HITRACE_TAG_ACCESS_CONTROL);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "generate dlp cert failed.");
        return result;
    }

    uint32_t certSize = cert.size();
    if (certSize > DLP_MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "generate dlp cert too large.");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint8_t* certBuffer = new (std::nothrow) uint8_t[certSize];
    if (certBuffer == nullptr) {
        DLP_LOG_ERROR(LABEL, "alloc cert data failed.");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    if (memcpy_s(certBuffer, certSize, &cert[0], certSize) != EOK) {
        DLP_LOG_ERROR(LABEL, "memcpy failed.");
        delete[] certBuffer;
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    certData.data = certBuffer;
    certData.size = certSize;
    return DLP_OK;
}

int32_t DlpFileManager::PrepareDlpEncryptParms(
    PermissionPolicy& policy, struct DlpBlob& key, struct DlpUsageSpec& usage, struct DlpBlob& certData) const
{
    DLP_LOG_INFO(LABEL, "begin generate key");
    int32_t res = DlpOpensslGenerateRandomKey(DLP_AES_KEY_SIZE_256, &key);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "alloc crypt key failed.");
        return res;
    }

    struct DlpCipherParam* tagIv = new (std::nothrow) struct DlpCipherParam;
    if (tagIv == nullptr) {
        DLP_LOG_ERROR(LABEL, "alloc cipher param failed.");
        delete key.data;
        key.data = nullptr;
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    DLP_LOG_INFO(LABEL, "begin generate iv");
    res = DlpOpensslGenerateRandomKey(IV_SIZE * BIT_NUM_OF_UINT8, &tagIv->iv);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "alloc crypt iv failed.");
        delete key.data;
        delete tagIv;
        key.data = nullptr;
        tagIv = nullptr;
        return res;
    }

    usage.mode = DLP_MODE_CTR;
    usage.algParam = tagIv;
    policy.SetAeskey(key.data, key.size);
    policy.SetIv(tagIv->iv.data, tagIv->iv.size);

    res = GenerateCertData(policy, certData);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "generate cert data failed.");
        delete key.data;
        delete tagIv->iv.data;
        delete tagIv;
        key.data = nullptr;
        tagIv->iv.data = nullptr;
        tagIv = nullptr;
        return res;
    }

    return DLP_OK;
}

int32_t DlpFileManager::ParseDlpFileFormat(std::shared_ptr<DlpFile>& filePtr) const
{
    int32_t result = filePtr->ParseDlpHeader();
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "dlp file format error.");
        return result;
    }

    struct DlpBlob cert;
    result = filePtr->GetEncryptCert(cert);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "dlp file get cert data failed.");
        return result;
    }

    std::vector<uint8_t> certBuf = std::vector<uint8_t>(cert.data, cert.data + cert.size);
    PermissionPolicy policy;
    DLP_LOG_DEBUG(LABEL, "certBuf size %{public}zu.", certBuf.size());
    StartTrace(HITRACE_TAG_ACCESS_CONTROL, "DlpParseCertificate");
    result = DlpPermissionKit::ParseDlpCertificate(certBuf, policy);
    FinishTrace(HITRACE_TAG_ACCESS_CONTROL);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "parse dlp cert failed.");
        return result;
    }

    result = filePtr->SetPolicy(policy);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "set policy failed.");
        return result;
    }

    struct DlpBlob key = {.data = policy.GetAeskey(), .size = policy.GetAeskeyLen()};
    struct DlpCipherParam param = {
        .iv = {.data = policy.GetIv(), .size = policy.GetIvLen()},
    };
    struct DlpUsageSpec usage = {
        .mode = DLP_MODE_CTR,
        .algParam = &param,
    };
    result = filePtr->SetCipher(key, usage);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "set cipher failed.");
    }

    return result;
}

void DlpFileManager::FreeChiperBlob(struct DlpBlob& key, struct DlpBlob& certData, struct DlpUsageSpec& usage) const
{
    if (key.data != nullptr) {
        delete key.data;
        key.data = nullptr;
    }

    if (certData.data != nullptr) {
        delete certData.data;
        certData.data = nullptr;
    }
    if (usage.algParam != nullptr) {
        if (usage.algParam->iv.data != nullptr) {
            delete usage.algParam->iv.data;
            usage.algParam->iv.data = nullptr;
        }
        delete usage.algParam;
        usage.algParam = nullptr;
    }
}

int32_t DlpFileManager::SetDlpFileParams(std::shared_ptr<DlpFile>& filePtr, const DlpProperty& property) const
{
    PermissionPolicy policy(property);
    struct DlpBlob key;
    struct DlpBlob certData;
    struct DlpUsageSpec usage;

    int32_t result = PrepareDlpEncryptParms(policy, key, usage, certData);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Prepare dlp encrypt params failed, error: %{public}d", result);
        return result;
    }
    result = filePtr->SetCipher(key, usage);
    if (result != DLP_OK) {
        FreeChiperBlob(key, certData, usage);
        DLP_LOG_ERROR(LABEL, "set dlp cipher failed, error: %{public}d", result);
        return result;
    }

    result = filePtr->SetPolicy(policy);
    if (result != DLP_OK) {
        FreeChiperBlob(key, certData, usage);
        DLP_LOG_ERROR(LABEL, "set policy failed, error: %{public}d", result);
        return result;
    }

    result = filePtr->SetEncryptCert(certData);
    if (result != DLP_OK) {
        FreeChiperBlob(key, certData, usage);
        DLP_LOG_ERROR(LABEL, "set encrypt cert failed, error: %{public}d", result);
        return result;
    }

    result = filePtr->SetContactAccount(property.contractAccount);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "set contactAccount failed, error: %{public}d", result);
    }
    FreeChiperBlob(key, certData, usage);
    return result;
}

int32_t DlpFileManager::GenerateDlpFile(
    int32_t plainFileFd, int32_t dlpFileFd, const DlpProperty& property, std::shared_ptr<DlpFile>& filePtr)
{
    if (plainFileFd < 0 || dlpFileFd < 0) {
        DLP_LOG_ERROR(LABEL, "plainFileFd or dlpFileFd is invalid.");
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    if (GetDlpFile(dlpFileFd) != nullptr) {
        DLP_LOG_ERROR(LABEL, "dlpFile has generated, If you want to rebuild, close it first.");
        return DLP_PARSE_ERROR_FILE_ALREADY_OPENED;
    }

    filePtr = std::make_shared<DlpFile>(dlpFileFd);
    if (filePtr == nullptr) {
        DLP_LOG_ERROR(LABEL, "alloc dlp file failed.");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    int32_t result = SetDlpFileParams(filePtr, property);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "set flp file param failed, error: %{public}d", result);
        return result;
    }

    result = filePtr->GenFile(plainFileFd);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "gen dlp file failed, error: %{public}d", result);
        return result;
    }

    return AddDlpFileNode(filePtr);
}

int32_t DlpFileManager::OpenDlpFile(int32_t dlpFileFd, std::shared_ptr<DlpFile>& filePtr)
{
    if (dlpFileFd < 0) {
        DLP_LOG_ERROR(LABEL, "fd is invalid.");
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    filePtr = GetDlpFile(dlpFileFd);
    if (filePtr != nullptr) {
        DLP_LOG_INFO(LABEL, "dlp file has open.");
        return DLP_OK;
    }

    filePtr = std::make_shared<DlpFile>(dlpFileFd);
    if (filePtr == nullptr) {
        DLP_LOG_ERROR(LABEL, "alloc dlp file failed.");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    int32_t result = ParseDlpFileFormat(filePtr);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "parse dlp file failed.");
        return result;
    }

    return AddDlpFileNode(filePtr);
}

int32_t DlpFileManager::IsDlpFile(int32_t dlpFileFd, bool& isDlpFile)
{
    if (dlpFileFd < 0) {
        DLP_LOG_ERROR(LABEL, "fd is invalid.");
        isDlpFile = false;
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    std::shared_ptr<DlpFile> filePtr = GetDlpFile(dlpFileFd);
    if (filePtr != nullptr) {
        DLP_LOG_INFO(LABEL, "dlp file has opened.");
        isDlpFile = true;
        return DLP_OK;
    }

    filePtr = std::make_shared<DlpFile>(dlpFileFd);
    if (filePtr == nullptr) {
        DLP_LOG_ERROR(LABEL, "alloc dlp file failed.");
        isDlpFile = false;
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    int32_t result = filePtr->ParseDlpHeader();
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "parse dlp file failed, res: %{public}d", result);
        isDlpFile = false;
        return result;
    }
    isDlpFile = true;
    return DLP_OK;
}

int32_t DlpFileManager::CloseDlpFile(const std::shared_ptr<DlpFile>& dlpFile)
{
    if (dlpFile == nullptr) {
        DLP_LOG_ERROR(LABEL, "dlp file is null.");
        return DLP_PARSE_ERROR_PTR_NULL;
    }
    return RemoveDlpFileNode(dlpFile);
}

int32_t DlpFileManager::RecoverDlpFile(std::shared_ptr<DlpFile>& filePtr, int32_t plainFd) const
{
    if (filePtr == nullptr) {
        DLP_LOG_ERROR(LABEL, "dlp file is null.");
        return DLP_PARSE_ERROR_PTR_NULL;
    }
    if (plainFd < 0) {
        DLP_LOG_ERROR(LABEL, "fd is invalid.");
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    return filePtr->RemoveDlpPermission(plainFd);
}

DlpFileManager& DlpFileManager::GetInstance()
{
    static DlpFileManager instance;
    return instance;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
