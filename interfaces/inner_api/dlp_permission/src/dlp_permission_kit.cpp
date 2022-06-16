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

#include "dlp_permission_kit.h"
#include <string>
#include <vector>
#include "dlp_permission_client.h"
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionKit"};
}  // namespace

int32_t DlpPermissionKit::GenerateDlpCertificate(
    const PermissionPolicy& policy, AccountType accountType, std::shared_ptr<GenerateDlpCertificateCallback> callback)
{
    DLP_LOG_DEBUG(LABEL, "Called");
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Callback is null");
        return DLP_VALUE_INVALID;
    }
    return DlpPermissionClient::GetInstance().GenerateDlpCertificate(policy, accountType, callback);
}

int32_t DlpPermissionKit::ParseDlpCertificate(
    const std::vector<uint8_t>& cert, std::shared_ptr<ParseDlpCertificateCallback> callback)
{
    DLP_LOG_DEBUG(LABEL, "Called");
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Callback is null");
        return DLP_VALUE_INVALID;
    }
    return DlpPermissionClient::GetInstance().ParseDlpCertificate(cert, callback);
}

int32_t DlpPermissionKit::InstallDlpSandbox(
    const std::string& bundleName, AuthPermType permType, int32_t userId, int32_t& appIndex)
{
    DLP_LOG_DEBUG(LABEL, "Called");
    return DlpPermissionClient::GetInstance().InstallDlpSandbox(bundleName, permType, userId, appIndex);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
