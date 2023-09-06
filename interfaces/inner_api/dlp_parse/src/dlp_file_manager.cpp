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
static constexpr uint32_t MAX_DLP_FILE_SIZE = 1000; // max open dlp file
}

int32_t DlpFileManager::AddDlpFileNode(const std::shared_ptr<DlpFile>& filePtr)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->g_DlpMapLock_);
    if (g_DlpFileMap_.size() >= MAX_DLP_FILE_SIZE) {
        DLP_LOG_ERROR(LABEL, "Add dlp file node failed, too many files");
        return DLP_PARSE_ERROR_TOO_MANY_OPEN_DLP_FILE;
    }
    if (g_DlpFileMap_.count(filePtr->dlpFd_) > 0) {
        DLP_LOG_ERROR(LABEL, "Add dlp file node fail, fd %{public}d already exist", filePtr->dlpFd_);
        return DLP_PARSE_ERROR_FILE_ALREADY_OPENED;
    }
    g_DlpFileMap_[filePtr->dlpFd_] = filePtr;
    return DLP_OK;
}

int32_t DlpFileManager::RemoveDlpFileNode(const std::shared_ptr<DlpFile>& filePtr)
{
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->g_DlpMapLock_);
    for (auto iter = g_DlpFileMap_.begin(); iter != g_DlpFileMap_.end(); iter++) {
        if (filePtr->dlpFd_ == iter->first) {
            g_DlpFileMap_.erase(iter);
            return DLP_OK;
        }
    }

    DLP_LOG_ERROR(LABEL, "Remove dlp file node fail, fd %{public}d not exist", filePtr->dlpFd_);
    return DLP_PARSE_ERROR_FILE_NOT_OPENED;
}

std::shared_ptr<DlpFile> DlpFileManager::GetDlpFile(int32_t dlpFd)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(this->g_DlpMapLock_);
    for (auto iter = g_DlpFileMap_.begin(); iter != g_DlpFileMap_.end(); iter++) {
        if (dlpFd == iter->first) {
            return iter->second;
        }
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
        DLP_LOG_ERROR(LABEL, "Generate dlp cert fail, errno=%{public}d", result);
        return result;
    }

    size_t certSize = cert.size();
    if (certSize > DLP_MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Check dlp cert fail, cert is too large, size=%{public}zu", certSize);
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint8_t* certBuffer = new (std::nothrow) uint8_t[certSize];
    if (certBuffer == nullptr) {
        DLP_LOG_ERROR(LABEL, "Copy dlp cert fail, alloc buff fail");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    if (memcpy_s(certBuffer, certSize, &cert[0], certSize) != EOK) {
        DLP_LOG_ERROR(LABEL, "Copy dlp cert fail, memcpy_s fail");
        delete[] certBuffer;
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    certData.data = certBuffer;
    certData.size = static_cast<uint32_t>(certSize);
    return DLP_OK;
}

int32_t DlpFileManager::PrepareDlpEncryptParms(
    PermissionPolicy& policy, struct DlpBlob& key, struct DlpUsageSpec& usage, struct DlpBlob& certData) const
{
    DLP_LOG_INFO(LABEL, "Generate key");
    int32_t res = DlpOpensslGenerateRandomKey(DLP_AES_KEY_SIZE_256, &key);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Generate key fail, errno=%{public}d", res);
        return res;
    }

    struct DlpCipherParam* tagIv = new (std::nothrow) struct DlpCipherParam;
    if (tagIv == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc iv buff fail");
        delete[] key.data;
        key.data = nullptr;
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    DLP_LOG_INFO(LABEL, "Generate iv");
    res = DlpOpensslGenerateRandomKey(IV_SIZE * BIT_NUM_OF_UINT8, &tagIv->iv);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Generate iv fail, errno=%{public}d", res);
        delete[] key.data;
        key.data = nullptr;
        delete tagIv;
        tagIv = nullptr;
        return res;
    }

    usage.mode = DLP_MODE_CTR;
    usage.algParam = tagIv;
    policy.SetAeskey(key.data, key.size);
    policy.SetIv(tagIv->iv.data, tagIv->iv.size);

    DLP_LOG_INFO(LABEL, "Generate cert");
    res = GenerateCertData(policy, certData);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Generate cert fail, errno=%{public}d", res);
        delete[] key.data;
        key.data = nullptr;
        delete[] tagIv->iv.data;
        tagIv->iv.data = nullptr;
        delete tagIv;
        tagIv = nullptr;
        return res;
    }

    return DLP_OK;
}

int32_t DlpFileManager::ParseDlpFileFormat(std::shared_ptr<DlpFile>& filePtr, const std::string& workDir) const
{
    int32_t result = filePtr->ParseDlpHeader();
    if (result != DLP_OK) {
        return result;
    }

    struct DlpBlob cert;
    filePtr->GetEncryptCert(cert);
    std::vector<uint8_t> certBuf = std::vector<uint8_t>(cert.data, cert.data + cert.size);

    std::vector<uint8_t> offlineCertBuf;
    struct DlpBlob offlineCert = { 0 };
    uint32_t flag =  filePtr->GetOfflineAccess();
    if (flag != 0) {
        filePtr->GetOfflineCert(offlineCert);
        offlineCertBuf = std::vector<uint8_t>(offlineCert.data, offlineCert.data + offlineCert.size);
    }

    PermissionPolicy policy;
    StartTrace(HITRACE_TAG_ACCESS_CONTROL, "DlpParseCertificate");
    result = DlpPermissionKit::ParseDlpCertificate(certBuf, offlineCertBuf, flag, policy);
    FinishTrace(HITRACE_TAG_ACCESS_CONTROL);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Parse cert fail, errno=%{public}d", result);
        return result;
    }

    result = filePtr->SetPolicy(policy);
    if (result != DLP_OK) {
        return result;
    }

    struct DlpBlob key = {.size = policy.GetAeskeyLen(), .data = policy.GetAeskey()};
    struct DlpCipherParam param = {
        .iv = {.size = policy.GetIvLen(), .data = policy.GetIv()},
    };
    struct DlpUsageSpec usage = {
        .mode = DLP_MODE_CTR,
        .algParam = &param,
    };
    result = filePtr->SetCipher(key, usage);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Parse file header fail, set cipher error, errno=%{public}d", result);
    }

    // only add offline cert when first time open the file.
    if (flag == DLP_CERT_UPDATED) {
        DLP_LOG_DEBUG(LABEL, "update offline cert");
        result = filePtr->AddOfflineCert(offlineCertBuf, workDir);
        if (result != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "Add offline cert fail, errno=%{public}d", result);
            return result;
        }
    }

    return result;
}

void DlpFileManager::FreeChiperBlob(struct DlpBlob& key, struct DlpBlob& certData, struct DlpUsageSpec& usage) const
{
    if (key.data != nullptr) {
        delete[] key.data;
        key.data = nullptr;
    }

    if (certData.data != nullptr) {
        delete[] certData.data;
        certData.data = nullptr;
    }
    if (usage.algParam != nullptr) {
        if (usage.algParam->iv.data != nullptr) {
            delete[] usage.algParam->iv.data;
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
        DLP_LOG_ERROR(LABEL, "Set dlp obj params fail, prepare encrypt params error, errno=%{public}d", result);
        return result;
    }
    result = filePtr->SetCipher(key, usage);
    if (result != DLP_OK) {
        FreeChiperBlob(key, certData, usage);
        DLP_LOG_ERROR(LABEL, "Set dlp obj params fail, set cipher error, errno=%{public}d", result);
        return result;
    }

    result = filePtr->SetPolicy(policy);
    if (result != DLP_OK) {
        FreeChiperBlob(key, certData, usage);
        DLP_LOG_ERROR(LABEL, "Set dlp obj params fail, set policy error, errno=%{public}d", result);
        return result;
    }

    result = filePtr->SetEncryptCert(certData);
    if (result != DLP_OK) {
        FreeChiperBlob(key, certData, usage);
        DLP_LOG_ERROR(LABEL, "Set dlp obj params fail, set cert error, errno=%{public}d", result);
        return result;
    }

    result = filePtr->SetContactAccount(property.contractAccount);
    if (result != DLP_OK) {
        DLP_LOG_WARN(LABEL, "Set dlp obj params fail, set contact account error, errno=%{public}d", result);
    }

    filePtr->SetOfflineAccess(property.offlineAccess);

    FreeChiperBlob(key, certData, usage);
    return result;
}

int32_t DlpFileManager::GenerateDlpFilePrepare(const DlpProperty& property, std::shared_ptr<DlpFile>& filePtr)
{
    filePtr = std::make_shared<DlpFile>(-1);

    int32_t result = SetDlpFileParams(filePtr, property);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Generate dlp file fail, set dlp obj params error, errno=%{public}d", result);
        return result;
    }

    return result;
}

int32_t DlpFileManager::GenerateDlpFileFinish(int32_t plainFileFd, int32_t dlpFileFd, std::shared_ptr<DlpFile>& filePtr)
{
    if (plainFileFd < 0 || dlpFileFd < 0) {
        DLP_LOG_ERROR(LABEL, "Generate dlp file fail, plain file fd or dlp file fd invalid");
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    if (GetDlpFile(dlpFileFd) != nullptr) {
        DLP_LOG_ERROR(LABEL, "Generate dlp file fail, dlp file has generated, if you want to rebuild, close it first");
        return DLP_PARSE_ERROR_FILE_ALREADY_OPENED;
    }

    if (filePtr == nullptr) {
        DLP_LOG_ERROR(LABEL, "Generate dlp file fail, alloc dlp obj fail");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    filePtr->SetFileFd(dlpFileFd);

    int32_t result = filePtr->GenFile(plainFileFd);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Generate dlp file fail, errno=%{public}d", result);
        return result;
    }

    return AddDlpFileNode(filePtr);
}

int32_t DlpFileManager::OpenDlpFile(int32_t dlpFileFd, std::shared_ptr<DlpFile>& filePtr, const std::string& workDir)
{
    if (dlpFileFd < 0) {
        DLP_LOG_ERROR(LABEL, "Open dlp file fail, fd %{public}d is invalid", dlpFileFd);
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    filePtr = GetDlpFile(dlpFileFd);
    if (filePtr != nullptr) {
        DLP_LOG_INFO(LABEL, "Open dlp file fail, fd %{public}d has opened", dlpFileFd);
        return DLP_OK;
    }

    filePtr = std::make_shared<DlpFile>(dlpFileFd);

    int32_t result = ParseDlpFileFormat(filePtr, workDir);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Open dlp file fail, parse dlp file error, errno=%{public}d", result);
        return result;
    }

    return AddDlpFileNode(filePtr);
}

int32_t DlpFileManager::IsDlpFile(int32_t dlpFileFd, bool& isDlpFile)
{
    if (dlpFileFd < 0) {
        DLP_LOG_ERROR(LABEL, "File type check fail, fd %{public}d is invalid", dlpFileFd);
        isDlpFile = false;
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    std::shared_ptr<DlpFile> filePtr = GetDlpFile(dlpFileFd);
    if (filePtr != nullptr) {
        DLP_LOG_INFO(LABEL, "File type check fail, fd %{public}d has opened", dlpFileFd);
        isDlpFile = true;
        return DLP_OK;
    }

    filePtr = std::make_shared<DlpFile>(dlpFileFd);

    int32_t result = filePtr->ParseDlpHeader();
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "File type check fail, parse dlp file error, errno=%{public}d", result);
        isDlpFile = false;
        return result;
    }
    isDlpFile = true;
    return DLP_OK;
}

int32_t DlpFileManager::CloseDlpFile(const std::shared_ptr<DlpFile>& dlpFile)
{
    if (dlpFile == nullptr) {
        DLP_LOG_ERROR(LABEL, "Close dlp file fail, dlp obj is null");
        return DLP_PARSE_ERROR_PTR_NULL;
    }
    return RemoveDlpFileNode(dlpFile);
}

int32_t DlpFileManager::RecoverDlpFile(std::shared_ptr<DlpFile>& filePtr, int32_t plainFd) const
{
    if (filePtr == nullptr) {
        DLP_LOG_ERROR(LABEL, "Recover dlp file fail, dlp obj is null");
        return DLP_PARSE_ERROR_PTR_NULL;
    }
    if (plainFd < 0) {
        DLP_LOG_ERROR(LABEL, "Recover dlp file fail, fd %{public}d is invalid", plainFd);
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
