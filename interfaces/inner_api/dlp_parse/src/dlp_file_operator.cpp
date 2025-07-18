/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "dlp_file_operator.h"

#include <cstdio>
#include <dirent.h>
#include <memory>
#include <openssl/rand.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "nlohmann/json.hpp"

#include "cert_parcel.h"
#include "dlp_crypt.h"
#include "dlp_file_manager.h"
#include "dlp_permission.h"
#include "dlp_permission_kit.h"
#include "dlp_permission_log.h"
#include "dlp_utils.h"
#include "permission_policy.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {

namespace {
static const std::string ACCOUNT_INDEX = "account";
static const std::string ACCOUNT_TYPE = "accountType";
static const std::string EDIT_INDEX = "edit";
static const std::string ENC_ACCOUNT_TYPE = "accountType";
static const std::string EVERYONE_INDEX = "everyone";
static const std::string FC_INDEX = "fullCtrl";
static const std::string NEED_ONLINE = "needOnline";
static const std::string OWNER_ACCOUNT_NAME = "ownerAccountName";
static const std::string OWNER_ACCOUNT = "ownerAccount";
static const std::string OWNER_ACCOUNT_ID = "ownerAccountId";
static const std::string OWNER_ACCOUNT_TYPE = "ownerAccountType";
static const std::string AUTHUSER_LIST = "authUserList";
static const std::string CONTACT_ACCOUNT = "contactAccount";
static const std::string OFFLINE_ACCESS = "offlineAccess";
static const std::string EVERYONE_ACCESS_LIST = "everyoneAccessList";
static const std::string PERM_EXPIRY_TIME = "expireTime";
static const std::string ACTION_UPON_EXPIRY = "actionUponExpiry";
static const std::string POLICY_INDEX = "policy";
static const std::string READ_INDEX = "read";
static const std::string RIGHT_INDEX = "right";
static const std::string CUSTOM_PROPERTY = "customProperty";
const std::string PATH_CACHE = "cache";

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "EnterpriseDlpPermissionKit"
};
using Defer = std::shared_ptr<void>;
using json = nlohmann::ordered_json;
std::mutex g_dirCleanLock;
std::mutex g_missionMutex;
std::mutex instanceMutex;
std::shared_ptr<std::thread> g_missionThread = nullptr;
const std::string APPID = "com.ohos.dlpmanager_BAurHtxID8irkrB1VYVHLCWnMGKeOwaGNcJymGCMdhIpP+"
    "PyVFlFnmikA0NIVqmvB+TnZpjup0qT4D0nEdTM/soy4Ab/wzCdSyoJYPNjl6IR/lW/IktytZ7Mn6auB9dJ4g==";
}

EnterpriseSpaceDlpPermissionKit::EnterpriseSpaceDlpPermissionKit() {}

EnterpriseSpaceDlpPermissionKit* EnterpriseSpaceDlpPermissionKit::GetInstance()
{
    static EnterpriseSpaceDlpPermissionKit* instance = nullptr;
    if (instance == nullptr) {
        std::lock_guard<std::mutex> lock(instanceMutex);
        if (instance == nullptr) {
            instance = new EnterpriseSpaceDlpPermissionKit();
            DLP_LOG_INFO(LABEL, "EnterpriseSpaceDlpPermissionKit init complete");
        }
    }
    return instance;
}

EnterpriseSpaceDlpPermissionKit::~EnterpriseSpaceDlpPermissionKit() {}

static int32_t GenerateRandomWorkDir(std::string &workDir)
{
    DlpBlob dir;
    int32_t res = DlpOpensslGenerateRandom(sizeof(uint64_t) * BIT_NUM_OF_UINT8, &dir);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Generate dir fail, errno=%{public}d", res);
        return res;
    }

    workDir = std::to_string(*reinterpret_cast<uint64_t *>(dir.data));
    delete[] dir.data;
    return DLP_OK;
}

static int32_t PrepareWorkDir(const std::string& path)
{
    if (mkdir(path.c_str(), S_IRWXU) < 0) {
        DLP_LOG_ERROR(LABEL, "mkdir work dir failed errno %{public}d", errno);
        return DLP_PARSE_ERROR_FILE_OPERATE_FAIL;
    }
    return DLP_OK;
}

static void SerializePermInfo(DLPFileAccess perm, json& rightInfoJson)
{
    bool read = false;
    bool edit = false;
    bool fullCtrl = false;

    switch (perm) {
        case DLPFileAccess::READ_ONLY: {
            read = true;
            break;
        }
        case DLPFileAccess::CONTENT_EDIT: {
            edit = true;
            break;
        }
        case DLPFileAccess::FULL_CONTROL: {
            read = true;
            edit = true;
            fullCtrl = true;
            break;
        }
        default:
            break;
    }
    rightInfoJson[READ_INDEX] = read;
    rightInfoJson[EDIT_INDEX] = edit;
    rightInfoJson[FC_INDEX] = fullCtrl;
}

static void SerializeAuthUserList(const std::vector<AuthUserInfo>& authUsers, json& authUsersJson)
{
    for (const AuthUserInfo& info : authUsers) {
        json rightInfoJson;
        SerializePermInfo(info.authPerm, rightInfoJson);
        authUsersJson[info.authAccount.c_str()][RIGHT_INDEX] = rightInfoJson;
    }
}

static void SerializeEveryoneInfo(const PermissionPolicy& policy, json& permInfoJson)
{
    if (policy.supportEveryone_) {
        json rightInfoJson;
        SerializePermInfo(policy.everyonePerm_, rightInfoJson);
        permInfoJson[EVERYONE_INDEX][RIGHT_INDEX] = rightInfoJson;
        return;
    }
}

static int32_t SerializePermissionPolicy(const PermissionPolicy& policy, std::string& policyString)
{
    json policyJson;
    json authUsersJson;
    SerializeAuthUserList(policy.authUsers_, authUsersJson);
    policyJson[OWNER_ACCOUNT_NAME] = policy.ownerAccount_;
    policyJson[OWNER_ACCOUNT_ID] = policy.ownerAccountId_;
    policyJson[ACCOUNT_INDEX] = authUsersJson;
    policyJson[PERM_EXPIRY_TIME] = policy.expireTime_;
    policyJson[NEED_ONLINE] = policy.needOnline_;
    policyJson[CUSTOM_PROPERTY] = policy.customProperty_;
    SerializeEveryoneInfo(policy, policyJson);
    policyString = policyJson.dump();
    return DLP_OK;
}

static void SetCustomProperty(DlpProperty& property, const CustomProperty& customProperty)
{
    property.customProperty.enterprise = customProperty.enterprise;
}

int32_t EnterpriseSpaceDlpPermissionKit::EnterpriseSpaceParseDlpFileProperty(std::shared_ptr<DlpFile>& filePtr,
    PermissionPolicy& policy, bool needCheckCustomProperty)
{
    int32_t result = filePtr->ProcessDlpFile();
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
    struct DlpBlob offlineCert = { 0 };
    uint32_t flag = filePtr->GetOfflineAccess();
    if (flag != 0) {
        filePtr->GetOfflineCert(offlineCert);
        certParcel->offlineCert = std::vector<uint8_t>(offlineCert.data, offlineCert.data + offlineCert.size);
    }
    filePtr->GetContactAccount(certParcel->contactAccount);
    certParcel->isNeedAdapter = filePtr->NeedAdapter();
    certParcel->needCheckCustomProperty = needCheckCustomProperty;
    result = DlpPermissionKit::ParseDlpCertificate(certParcel, policy, APPID, filePtr->GetOfflineAccess());
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Parse cert fail, errno=%{public}d", result);
        return result;
    }
    result = filePtr->SetPolicy(policy);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Set policy fail, errno=%{public}d", result);
        return result;
    }
    return DLP_OK;
}

int32_t EnterpriseSpaceDlpPermissionKit::EnterpriseSpacePrepareWorkDir(int32_t dlpFileFd,
    std::shared_ptr<DlpFile>& filePtr, std::string& workDir)
{
    int32_t result = DlpUtils::GetFilePathWithFd(dlpFileFd, workDir);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Get file path with fd fail, errno = %{public}d.", result);
        return result;
    }

    workDir += PATH_CACHE;

    std::string randomWorkDir;
    result = GenerateRandomWorkDir(randomWorkDir);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Generate dir fail, errno=%{public}d", result);
        return result;
    }

    std::string realWorkDir = workDir + '_' + randomWorkDir;
    result = PrepareWorkDir(realWorkDir);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Prepare dir fail, errno=%{public}d", result);
        return result;
    }

    int64_t timeStamp =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    bool isFromUriName = false;
    std::string realSuffix = DlpUtils::GetRealTypeWithFd(dlpFileFd, isFromUriName);
    if (realSuffix == "") {
        DLP_LOG_ERROR(LABEL, "Get real suffix error.");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    std::string lower = DlpUtils::ToLowerString(realSuffix);
    std::string realType = "";
    for (size_t len = MAX_REALY_TYPE_LENGTH; len >= MIN_REALY_TYPE_LENGTH; len--) {
        if (len > lower.size()) {
            continue;
        }
        std::string newStr = lower.substr(0, len);
        auto iter = FILE_TYPE_MAP.find(newStr);
        if (iter != FILE_TYPE_MAP.end()) {
            realType = newStr;
            break;
        }
    }
    filePtr = std::make_shared<DlpZipFile>(dlpFileFd, realWorkDir, timeStamp, realType);
    return DLP_OK;
}

int32_t EnterpriseSpaceDlpPermissionKit::EnterpriseSpaceParseDlpFileFormat(std::shared_ptr<DlpFile>& filePtr,
    bool needCheckCustomProperty)
{
    PermissionPolicy policy;
    int result = EnterpriseSpaceParseDlpFileProperty(filePtr, policy, needCheckCustomProperty);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Enterprise space parse dlp property fail, errno=%{public}d", result);
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
    return result;
}

int32_t EnterpriseSpaceDlpPermissionKit::EncryptDlpFile(DlpProperty property,
    CustomProperty customProperty, int32_t plainFileFd, int32_t dlpFileFd)
{
    DLP_LOG_INFO(LABEL, "Start generate dlp file from enterprise space service.");
    if (plainFileFd < 0 || dlpFileFd < 0) {
        DLP_LOG_ERROR(LABEL, "Encrypt dlp file fail, plain file fd or dlp file fd invalid");
        return DLP_PARSE_ERROR_FD_ERROR;
    }
    SetCustomProperty(property, customProperty);
    std::shared_ptr<DlpFile> filePtr = nullptr;
    std::string workDir;
    int32_t result = EnterpriseSpacePrepareWorkDir(dlpFileFd, filePtr, workDir);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Enterprise space prepare workDir fail, errno=%{public}d", result);
        return result;
    }

    result = DlpFileManager::GetInstance().SetDlpFileParams(filePtr, property);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Generate dlp file fail, set dlp obj params error, errno=%{public}d", result);
        return result;
    }

    result = filePtr->GenFile(plainFileFd);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Generate dlp file fail, errno=%{public}d", result);
        return result;
    }

    return DLP_OK;
}

int32_t EnterpriseSpaceDlpPermissionKit::DecryptDlpFile(int32_t plainFileFd, int32_t dlpFileFd)
{
    DLP_LOG_INFO(LABEL, "Start decrypt dlp file from enterprise space service.");
    if (plainFileFd < 0 || dlpFileFd < 0) {
        DLP_LOG_ERROR(LABEL, "Decrypt dlp file fail, plain file fd or dlp file fd invalid");
        return DLP_PARSE_ERROR_FD_ERROR;
    }
    
    std::shared_ptr<DlpFile> filePtr = nullptr;
    std::string workDir;
    int32_t result = EnterpriseSpacePrepareWorkDir(dlpFileFd, filePtr, workDir);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Enterprise space prepare workDir fail, errno=%{public}d", result);
        return result;
    }

    result = EnterpriseSpaceParseDlpFileFormat(filePtr, true);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Open dlp file fail, parse dlp file error, errno=%{public}d", result);
        return result;
    }

    result = DlpFileManager::GetInstance().RecoverDlpFile(filePtr, plainFileFd);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "recover dlp file fail with enterprise space.");
    }
    return DLP_OK;
}

int32_t EnterpriseSpaceDlpPermissionKit::QueryDlpFileProperty(int32_t dlpFileFd, std::string &policyJsonString)
{
    DLP_LOG_INFO(LABEL, "Start query dlp file property from enterprise space service.");
    if (dlpFileFd < 0) {
        DLP_LOG_ERROR(LABEL, "Query dlp property fail, dlp file fd invalid");
        return DLP_PARSE_ERROR_FD_ERROR;
    }

    std::shared_ptr<DlpFile> filePtr = nullptr;
    std::string workDir;
    int32_t result = EnterpriseSpacePrepareWorkDir(dlpFileFd, filePtr, workDir);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Enterprise space prepare workDir fail, errno=%{public}d", result);
        return result;
    }
    PermissionPolicy policy;
    result = EnterpriseSpaceParseDlpFileProperty(filePtr, policy, false);
    if (result != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Enterprise space parse dlp property fail, errno=%{public}d", result);
        return result;
    }
    SerializePermissionPolicy(policy, policyJsonString);
    return DLP_OK;
}

}
}
}
