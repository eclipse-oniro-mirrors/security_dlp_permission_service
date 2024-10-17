/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <dirent.h>
#include <cstdio>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string>

#include "dlp_crypt.h"
#include "dlp_file.h"
#include "dlp_permission.h"
#include "dlp_permission_kit.h"
#include "dlp_permission_log.h"
#include "hitrace_meter.h"
#include "securec.h"
#include "dlp_utils.h"
#include "dlp_file_kits.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFileManager"};
static constexpr uint32_t MAX_DLP_FILE_SIZE = 1000; // max open dlp file
const std::string PATH_CACHE = "/cache";
std::recursive_mutex instanceMutex_;
}

int32_t DlpFileManager::AddDlpFileNode(const std::shared_ptr<DlpFile>& filePtr)
{
    if (filePtr == nullptr) {
        DLP_LOG_ERROR(LABEL, "Add dlp file node failed, filePtr is null");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(this->g_DlpMapLock_);
    if (g_DlpFileMap_.size() >= MAX_DLP_FILE_SIZE) {
        DLP_LOG_ERROR(LABEL, "Add dlp file node failed, too many files");
        return DLP_PARSE_ERROR_TOO_MANY_OPEN_DLP_FILE;
    }
    auto iter = g_DlpFileMap_.find(filePtr->dlpFd_);
    if (iter != g_DlpFileMap_.end()) {
        DLP_LOG_ERROR(LABEL, "Add dlp file node fail, fd %{public}d already exist", filePtr->dlpFd_);
        return DLP_PARSE_ERROR_FILE_ALREADY_OPENED;
    }
    g_DlpFileMap_[filePtr->dlpFd_] = filePtr;
    return DLP_OK;
}

int32_t DlpFileManager::RemoveDlpFileNode(const std::shared_ptr<DlpFile>& filePtr)
{
    if (filePtr == nullptr) {
        DLP_LOG_ERROR(LABEL, "Remove dlp file node fail, filePtr is null");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
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
    return GenerateCertBlob(cert, certData);
}

int32_t DlpFileManager::GenerateCertBlob(const std::vector<uint8_t>& cert, struct DlpBlob& certData) const
{
    size_t certSize = cert.size();
    if (certSize > DLP_MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Check dlp cert fail, cert is too large, size=%{public}zu", certSize);
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (certSize == 0) {
        DLP_LOG_ERROR(LABEL, "Check dlp cert fail, cert is zero, size=%{public}zu", certSize);
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint8_t* certBuffer = new (std::nothrow) uint8_t[certSize];
    if (certBuffer == nullptr) {
        DLP_LOG_ERROR(LABEL, "Copy dlp cert fail, alloc buff fail");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    if (memcpy_s(certBuffer, certSize, &cert[0], certSize) != EOK) {
        DLP_LOG_ERROR(LABEL, "Copy dlp cert fail, memcpy_s fail");
        (void)memset_s(certBuffer, certSize, 0, certSize);
        delete[] certBuffer;
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    if (certData.data != nullptr) {
        (void)memset_s(certData.data, certData.size, 0, certData.size);
        delete[] certData.data;
    }
    certData.data = certBuffer;
    certData.size = static_cast<uint32_t>(certSize);
    return DLP_OK;
}

static int32_t CleanBlobParam(struct DlpBlob& blob)
{
    if (blob.data == nullptr || blob.size == 0) {
        DLP_LOG_ERROR(LABEL, "blobData null");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    (void)memset_s(blob.data, blob.size, 0, blob.size);
    delete[] blob.data;
    blob.data = nullptr;
    blob.size = 0;
    return DLP_OK;
}

void DlpFileManager::CleanTempBlob(struct DlpBlob& key, struct DlpCipherParam** tagIv, struct DlpBlob& hmacKey) const
{
    if (key.data != nullptr) {
        CleanBlobParam(key);
    }
    if (hmacKey.data != nullptr) {
        CleanBlobParam(hmacKey);
    }
    if (tagIv == nullptr || (*tagIv) == nullptr) {
        return;
    }
    if ((*tagIv)->iv.data != nullptr) {
        CleanBlobParam((*tagIv)->iv);
    }
    delete (*tagIv);
    (*tagIv) = nullptr;
}

int32_t DlpFileManager::PrepareDlpEncryptParms(PermissionPolicy& policy, struct DlpBlob& key,
    struct DlpUsageSpec& usage, struct DlpBlob& certData, struct DlpBlob& hmacKey) const
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
        CleanTempBlob(key, &tagIv, hmacKey);
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    DLP_LOG_INFO(LABEL, "Generate iv");
    res = DlpOpensslGenerateRandomKey(IV_SIZE * BIT_NUM_OF_UINT8, &tagIv->iv);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Generate iv fail, errno=%{public}d", res);
        CleanTempBlob(key, &tagIv, hmacKey);
        return res;
    }

    DLP_LOG_INFO(LABEL, "Generate hmac key");
    res = DlpOpensslGenerateRandomKey(DLP_AES_KEY_SIZE_256, &hmacKey);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Generate hmacKey fail, errno=%{public}d", res);
        CleanTempBlob(key, &tagIv, hmacKey);
        return res;
    }

    usage.mode = DLP_MODE_CTR;
    usage.algParam = tagIv;
    policy.SetAeskey(key.data, key.size);
    policy.SetIv(tagIv->iv.data, tagIv->iv.size);
    policy.SetHmacKey(hmacKey.data, hmacKey.size);

    DLP_LOG_INFO(LABEL, "Generate cert");
    res = GenerateCertData(policy, certData);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Generate cert fail, errno=%{public}d", res);
        CleanTempBlob(key, &tagIv, hmacKey);
        return res;
    }

    return DLP_OK;
}

int32_t DlpFileManager::UpdateDlpFile(bool isNeedAdapter, uint32_t oldCertSize, const std::string& workDir,
    const std::vector<uint8_t>& cert, std::shared_ptr<DlpFile>& filePtr)
{
    std::lock_guard<std::mutex> lock(g_offlineLock_);
    int32_t result = filePtr->CheckDlpFile();
    if (result != DLP_OK) {
        return result;
    }
    struct DlpBlob certBlob;
#ifdef SUPPORT_DLP_CREDENTIAL
    result = GenerateCertBlob(cert, certBlob);
    if (result != DLP_OK) {
        return result;
    }
#else
    return DLP_OK;
#endif
    int32_t res = DLP_OK;
    if (isNeedAdapter || oldCertSize != certBlob.size) {
        res = filePtr->UpdateCertAndText(cert, workDir, certBlob);
    } else {
        res = filePtr->UpdateCert(certBlob);
    }
    (void)memset_s(certBlob.data, certBlob.size, 0, certBlob.size);
    delete[] certBlob.data;
    return res;
}

int32_t DlpFileManager::ParseDlpFileFormat(std::shared_ptr<DlpFile>& filePtr, const std::string& workDir,
    const std::string& appId)
{
    int32_t result = filePtr->ParseDlpHeader();
    if (result != DLP_OK) {
        return result;
    }
    struct DlpBlob cert;
    filePtr->GetEncryptCert(cert);
    sptr<CertParcel> certParcel = new (std::nothrow) CertParcel();
    if (certParcel == nullptr) {
        DLP_LOG_ERROR(LABEL, "Alloc certParcel parcel fail");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }
    certParcel->cert = std::vector<uint8_t>(cert.data, cert.data + cert.size);
    uint32_t oldCertSize = cert.size;
    struct DlpBlob offlineCert = { 0 };
    uint32_t flag =  filePtr->GetOfflineAccess();
    if (flag != 0) {
        filePtr->GetOfflineCert(offlineCert);
        certParcel->offlineCert = std::vector<uint8_t>(offlineCert.data, offlineCert.data + offlineCert.size);
    }
    PermissionPolicy policy;
    filePtr->GetContactAccount(certParcel->contactAccount);
    certParcel->isNeedAdapter = filePtr->NeedAdapter();
    StartTrace(HITRACE_TAG_ACCESS_CONTROL, "DlpParseCertificate");
    result = DlpPermissionKit::ParseDlpCertificate(certParcel, policy, appId, filePtr->GetOfflineAccess());
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
    struct DlpCipherParam param = {.iv = {.size = policy.GetIvLen(), .data = policy.GetIv()}};
    struct DlpUsageSpec usage = {.mode = DLP_MODE_CTR, .algParam = &param};
    struct DlpBlob hmacKey = {.size = policy.GetHmacKeyLen(), .data = policy.GetHmacKey()};
    result = filePtr->SetCipher(key, usage, hmacKey);
    if (result != DLP_OK) {
        return result;
    }
    result = filePtr->HmacCheck();
    if (result != DLP_OK) {
        return result;
    }
    return UpdateDlpFile(filePtr->NeedAdapter(), oldCertSize, workDir, certParcel->offlineCert, filePtr);
}

void DlpFileManager::FreeChiperBlob(struct DlpBlob& key, struct DlpBlob& certData,
    struct DlpUsageSpec& usage, struct DlpBlob& hmacKey) const
{
    if (key.data != nullptr) {
        CleanBlobParam(key);
    }

    if (certData.data != nullptr) {
        CleanBlobParam(certData);
    }
    if (usage.algParam != nullptr) {
        if (usage.algParam->iv.data != nullptr) {
            CleanBlobParam(usage.algParam->iv);
        }
        delete usage.algParam;
        usage.algParam = nullptr;
    }

    if (hmacKey.data != nullptr) {
        CleanBlobParam(hmacKey);
    }
}

int32_t DlpFileManager::SetDlpFileParams(std::shared_ptr<DlpFile>& filePtr, const DlpProperty& property) const
{
    PermissionPolicy policy(property);
    struct DlpBlob key;
    struct DlpBlob certData;
    struct DlpUsageSpec usage;
    struct DlpBlob hmacKey;

    int32_t result = PrepareDlpEncryptParms(policy, key, usage, certData, hmacKey);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Set dlp obj params fail, prepare encrypt params error, errno=%{public}d", result);
        return result;
    }
    result = filePtr->SetCipher(key, usage, hmacKey);
    if (result != DLP_OK) {
        FreeChiperBlob(key, certData, usage, hmacKey);
        DLP_LOG_ERROR(LABEL, "Set dlp obj params fail, set cipher error, errno=%{public}d", result);
        return result;
    }

    result = filePtr->SetPolicy(policy);
    if (result != DLP_OK) {
        FreeChiperBlob(key, certData, usage, hmacKey);
        DLP_LOG_ERROR(LABEL, "Set dlp obj params fail, set policy error, errno=%{public}d", result);
        return result;
    }

    result = filePtr->SetEncryptCert(certData);
    if (result != DLP_OK) {
        FreeChiperBlob(key, certData, usage, hmacKey);
        DLP_LOG_ERROR(LABEL, "Set dlp obj params fail, set cert error, errno=%{public}d", result);
        return result;
    }

    result = filePtr->SetContactAccount(property.contactAccount);
    if (result != DLP_OK) {
        DLP_LOG_WARN(LABEL, "Set dlp obj params fail, set contact account error, errno=%{public}d", result);
    }

    filePtr->SetOfflineAccess(property.offlineAccess);

    FreeChiperBlob(key, certData, usage, hmacKey);
    return result;
}

static bool RemoveDirRecursive(const char *path)
{
    if (path == nullptr) {
        return false;
    }
    DIR *dir = opendir(path);
    if (dir == nullptr) {
        return false;
    }

    dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        std::string subPath = std::string(path) + "/" + entry->d_name;
        if ((entry->d_type == DT_DIR) && (!RemoveDirRecursive(subPath.c_str()))) {
            closedir(dir);
            return false;
        }
        if ((entry->d_type != DT_DIR) && (remove(subPath.c_str()) != 0)) {
            closedir(dir);
            return false;
        }
    }

    closedir(dir);

    if (rmdir(path) != 0) {
        DLP_LOG_ERROR(LABEL, "rmdir fail, errno %{public}s", strerror(errno));
        return false;
    }
    return true;
}

std::mutex g_dirCleanLock;
static void PrepareDirs(const std::string& path)
{
    std::lock_guard<std::mutex> lock(g_dirCleanLock);
    static bool cleanOnce = true;
    if (cleanOnce) {
        cleanOnce = false;
        RemoveDirRecursive(path.c_str());
        mkdir(path.c_str(), S_IRWXU);
    }
}

int32_t DlpFileManager::GenerateDlpFile(
    int32_t plainFileFd, int32_t dlpFileFd, const DlpProperty& property, std::shared_ptr<DlpFile>& filePtr,
    const std::string& workDir)
{
    if (plainFileFd < 0 || dlpFileFd < 0) {
        DLP_LOG_ERROR(LABEL, "Generate dlp file fail, plain file fd or dlp file fd invalid");
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    if (GetDlpFile(dlpFileFd) != nullptr) {
        DLP_LOG_ERROR(LABEL, "Generate dlp file fail, dlp file has generated, if you want to rebuild, close it first");
        return DLP_PARSE_ERROR_FILE_ALREADY_OPENED;
    }

    std::string cache = workDir + PATH_CACHE;
    PrepareDirs(cache);
    int64_t timeStamp =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    filePtr = std::make_shared<DlpFile>(dlpFileFd, cache, timeStamp, true);

    int32_t result = SetDlpFileParams(filePtr, property);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Generate dlp file fail, set dlp obj params error, errno=%{public}d", result);
        return result;
    }

    result = filePtr->GenFile(plainFileFd);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Generate dlp file fail, errno=%{public}d", result);
        return result;
    }

    return AddDlpFileNode(filePtr);
}

static int32_t GetFileNameWithFd(const int32_t &fd, std::string &srcFileName)
{
    char *fileName = new (std::nothrow) char[MAX_DLP_FILE_SIZE + 1];
    if (fileName == nullptr) {
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    std::string path = "/proc/self/fd/" + std::to_string(fd);

    int readLinkRes = readlink(path.c_str(), fileName, MAX_DLP_FILE_SIZE);
    if (readLinkRes < 0) {
        DLP_LOG_ERROR(LABEL, "fail to readlink uri");
        delete[] fileName;
        return DLP_PARSE_ERROR_FD_ERROR;
    }
    fileName[readLinkRes] = '\0';

    srcFileName = std::string(fileName);
    delete[] fileName;
    return DLP_OK;
}

static bool GetBundleInfoWithBundleName(const std::string &bundleName, int32_t flag,
    AppExecFwk::BundleInfo &bundleInfo, int32_t userId)
{
    auto bundleMgrProxy = DlpUtils::GetBundleMgrProxy();
    if (bundleMgrProxy == nullptr) {
        return false;
    }
    return bundleMgrProxy->GetBundleInfo(bundleName, flag, bundleInfo, userId);
}

static std::string GetAppIdWithBundleName(const std::string &bundleName, const int32_t &userId)
{
    AppExecFwk::BundleInfo bundleInfo;
    bool result = GetBundleInfoWithBundleName(bundleName,
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO), bundleInfo, userId);
    if (!result) {
        DLP_LOG_ERROR(LABEL, "get appId error");
        return DEFAULT_STRING;
    }
    return bundleInfo.appId;
}

static int32_t SupportDlpWithAppId(const std::string &appId, const std::string &fileName)
{
    std::string realSuffix = DlpUtils::GetDlpFileRealSuffix(fileName);
    if (realSuffix == DEFAULT_STRING) {
        DLP_LOG_ERROR(LABEL, "get realSuffix error.");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    std::string fileType = DlpUtils::GetFileTypeBySuffix(realSuffix);
    if (fileType == DEFAULT_STRING) {
        DLP_LOG_ERROR(LABEL, "get fileType error.");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t userId = 0;
    int32_t ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != ERR_OK) {
        DLP_LOG_ERROR(LABEL, "Get os account localId error, %{public}d", ret);
        return DLP_PARSE_ERROR_GET_ACCOUNT_FAIL;
    }

    std::vector<std::string> whitelist;
    if (!DlpUtils::GetWhitelistWithType(DLP_WHITELIST, fileType, whitelist)) {
        DLP_LOG_DEBUG(LABEL, "not have white list.");
        return DLP_OK;
    }
    for (size_t i = 0; i < whitelist.size(); i++) {
        if (appId == GetAppIdWithBundleName(whitelist[i], userId)) {
            return DLP_OK;
        }
    }
    DLP_LOG_ERROR(LABEL, "Check DLP whitelist error.");
    return DLP_CREDENTIAL_ERROR_APPID_NOT_AUTHORIZED;
}

int32_t DlpFileManager::OpenDlpFile(int32_t dlpFileFd, std::shared_ptr<DlpFile>& filePtr, const std::string& workDir,
    const std::string& appId)
{
    if (dlpFileFd < 0) {
        DLP_LOG_ERROR(LABEL, "Open dlp file fail, fd %{public}d is invalid", dlpFileFd);
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    std::string fileName;
    int32_t ret = GetFileNameWithFd(dlpFileFd, fileName);
    if (ret != DLP_OK) {
        return ret;
    }

    ret = SupportDlpWithAppId(appId, fileName);
    if (ret != DLP_OK) {
        return ret;
    }

    filePtr = GetDlpFile(dlpFileFd);
    if (filePtr != nullptr) {
        DLP_LOG_INFO(LABEL, "Open dlp file fail, fd %{public}d has opened", dlpFileFd);
        return DLP_OK;
    }

    std::string cache = workDir + PATH_CACHE;
    PrepareDirs(cache);
    int64_t timeStamp =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    filePtr = std::make_shared<DlpFile>(dlpFileFd, cache, timeStamp, false);

    int32_t result = ParseDlpFileFormat(filePtr, workDir, appId);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Open dlp file fail, parse dlp file error, errno=%{public}d", result);
        return result;
    }

    return AddDlpFileNode(filePtr);
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
    static DlpFileManager* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::recursive_mutex> lock(instanceMutex_);
        if (instance == nullptr) {
            instance = new DlpFileManager();
        }
    }
    return *instance;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
