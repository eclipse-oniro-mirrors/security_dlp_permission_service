/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "retention_file_manager.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "app_uninstall_observer.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
constexpr OHOS::HiviewDFX::HiLogLabel LABEL = { LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "RetentionFileManager" };
const std::string PATH_SEPARATOR = "/";
const std::string USER_INFO_BASE = "/data/service/el1/public/dlp_permission_service";
const std::string DLP_RETENTION_JSON_PATH = USER_INFO_BASE + PATH_SEPARATOR + "retention_sandbox_info.json";
}

RetentionFileManager::RetentionFileManager()
{
    hasInit = false;
    fileOperator_ = std::make_shared<FileOperator>();
    SandboxJsonManager_ = std::make_shared<SandboxJsonManager>();

    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    auto appUninstallObserver = std::make_shared<AppUninstallObserver>(subscribeInfo);
    EventFwk::CommonEventManager::SubscribeCommonEvent(appUninstallObserver);

    Init();
}

RetentionFileManager::~RetentionFileManager() {}

RetentionFileManager& RetentionFileManager::GetInstance()
{
    static RetentionFileManager instance;
    return instance;
}

bool RetentionFileManager::HasRetentionSandboxInfo(const std::string& bundleName)
{
    return SandboxJsonManager_->HasRetentionSandboxInfo(bundleName);
}

bool RetentionFileManager::Init()
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (fileOperator_->IsExistFile(DLP_RETENTION_JSON_PATH)) {
        std::string constraintsConfigStr;
        if (fileOperator_->GetFileContentByPath(DLP_RETENTION_JSON_PATH, constraintsConfigStr) != DLP_OK) {
            return false;
        }
        if (constraintsConfigStr.empty()) {
            hasInit = true;
            return true;
        }
        Json callbackInfoJson = Json::parse(constraintsConfigStr, nullptr, false);
        SandboxJsonManager_->FromJson(callbackInfoJson);
        int32_t res = SandboxJsonManager_->ClearDateByUninstall();
        if (res == DLP_RETENTION_UPDATE_ERROR) {
            return false;
        }
        DLP_LOG_DEBUG(LABEL, "ClearDateByUninstall %{public}d", res);
        int32_t updateRes = UpdateFile(res);
        if (updateRes != DLP_OK) {
            return false;
        }
    }
    hasInit = true;
    return true;
}

int32_t RetentionFileManager::UpdateFile(const int32_t& jsonRes)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (jsonRes == DLP_RETENTION_NOT_UPDATE) {
        return DLP_OK;
    }
    if (jsonRes != DLP_OK) {
        return jsonRes;
    }
    std::string jsonStr = SandboxJsonManager_->ToString();
    if (fileOperator_->InputFileByPathAndContent(DLP_RETENTION_JSON_PATH, jsonStr) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "InputFileByPathAndContent failed!");
        return DLP_RETENTION_INSERT_FILE_ERROR;
    }
    return DLP_OK;
}

int32_t RetentionFileManager::AddSandboxInfo(const int32_t& appIndex, const uint32_t& tokenId,
    const std::string& bundleName, const int32_t& userId)
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    int32_t res = SandboxJsonManager_->AddSandboxInfo(appIndex, tokenId, bundleName, userId);
    return UpdateFile(res);
}

int32_t RetentionFileManager::DelSandboxInfo(uint32_t tokenId)
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    int32_t res = SandboxJsonManager_->DelSandboxInfo(tokenId);
    return UpdateFile(res);
}

bool RetentionFileManager::CanUninstall(const uint32_t& tokenId)
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    return SandboxJsonManager_->CanUninstall(tokenId);
}

int32_t RetentionFileManager::UpdateSandboxInfo(const std::set<std::string>& docUriSet, RetentionInfo& info,
    bool isRetention)
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    int32_t res = SandboxJsonManager_->UpdateRetentionState(docUriSet, info, isRetention);
    return UpdateFile(res);
}

int32_t RetentionFileManager::RemoveRetentionState(const std::string& bundleName, const int32_t& appIndex)
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    int32_t res = SandboxJsonManager_->RemoveRetentionState(bundleName, appIndex);
    return UpdateFile(res);
}

int32_t RetentionFileManager::ClearUnreservedSandbox()
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    int32_t res = SandboxJsonManager_->ClearUnreservedSandbox();
    return UpdateFile(res);
}

int32_t RetentionFileManager::GetRetentionSandboxList(const std::string& bundleName,
    std::vector<RetentionSandBoxInfo>& retentionSandBoxInfoVec, bool isRetention)
{
    if (!hasInit && !Init()) {
        DLP_LOG_ERROR(LABEL, "Init failed!");
        return DLP_RETENTION_UPDATE_ERROR;
    }
    return SandboxJsonManager_->GetRetentionSandboxList(bundleName, retentionSandBoxInfoVec, isRetention);
}
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
