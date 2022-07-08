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
#include "dlp_link_manager.h"

#include "dlp_file.h"
#include "dlp_permission_log.h"
#include "fuse_daemon.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpLinkManager"};
}

DlpLinkManager::DlpLinkManager()
{
    FuseDaemon::InitFuseFs(FUSE_DEV_FD);
}

static bool IsLinkNameValid(const std::string& linkName)
{
    uint32_t size = linkName.size();
    return !(size == 0 || size > MAX_FILE_NAME_LEN);
}

int32_t DlpLinkManager::AddDlpLinkFile(std::shared_ptr<DlpFile>& filePtr, const std::string& dlpLinkName)
{
    if (filePtr == nullptr || !IsLinkNameValid(dlpLinkName)) {
        return DLP_LINK_FAILURE;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(g_DlpLinkMapLock_);
    if (g_DlpLinkFileNameMap_.count(dlpLinkName) > 0) {
        DLP_LOG_WARN(LABEL, "dlpLinkName %{public}s exist.", dlpLinkName.c_str());
        return DLP_LINK_FAILURE;
    }

    DlpLinkFile *node = new (std::nothrow) DlpLinkFile(dlpLinkName, filePtr);
    if (node == nullptr) {
        DLP_LOG_ERROR(LABEL, "alloc Dlp link file %{public}s failed.", dlpLinkName.c_str());
        return DLP_LINK_FAILURE;
    }

    DLP_LOG_INFO(LABEL, "add dlp link filename %{public}s", dlpLinkName.c_str());
    g_DlpLinkFileNameMap_[dlpLinkName] = node;
    filePtr->SetLinkStatus();
    return DLP_LINK_SUCCESS;
}

int32_t DlpLinkManager::DeleteDlpLinkFile(std::shared_ptr<DlpFile>& filePtr)
{
    if (filePtr == nullptr) {
        return DLP_LINK_FAILURE;
    }

    Utils::UniqueWriteGuard<Utils::RWLock> infoGuard(g_DlpLinkMapLock_);
    for (auto iter = g_DlpLinkFileNameMap_.begin(); iter != g_DlpLinkFileNameMap_.end();) {
        DlpLinkFile* tmp = iter->second;
        if (tmp != nullptr && filePtr == tmp->GetDlpFilePtr()) {
            filePtr->RemoveLinkStatus();
            g_DlpLinkFileNameMap_.erase(iter++);
            if (tmp->SubAndCheckZeroRef(1)) {
                delete tmp;
            }
            break;
        }
    }

    return DLP_LINK_SUCCESS;
}

DlpLinkFile* DlpLinkManager::LookUpDlpLinkFile(const std::string& dlpLinkName)
{
    Utils::UniqueReadGuard<Utils::RWLock> infoGuard(g_DlpLinkMapLock_);
    if (g_DlpLinkFileNameMap_.count(dlpLinkName) <= 0) {
        DLP_LOG_ERROR(LABEL, "dlpLinkName %{public}s is not exist.", dlpLinkName.c_str());
        return nullptr;
    }
    DlpLinkFile* node = g_DlpLinkFileNameMap_[dlpLinkName];
    if (node == nullptr) {
        DLP_LOG_ERROR(LABEL, "dlpLinkName %{public}s is nullptr.", dlpLinkName.c_str());
        return nullptr;
    }
    node->IncreaseRef();
    return node;
}

DlpLinkManager& DlpLinkManager::GetInstance()
{
    static DlpLinkManager instance;
    return instance;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
