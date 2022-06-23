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
#include <thread>
#include <vector>
#include "datetime_ex.h"
#include "dlp_permission_client.h"
#include "dlp_permission_log.h"
#include "dlp_policy.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionKit"};
const int64_t TIME_WAIT_TIME_OUT = 10;
const int32_t WAIT_ONE_TIME = 10;
}  // namespace

void ClientGenerateDlpCertificateCallback::onGenerateDlpCertificate(int32_t result, const std::vector<uint8_t>& cert)
{
    DLP_LOG_INFO(LABEL, "Callback");
    this->result_ = result;
    this->cert_ = cert;
    this->isCallBack_ = true;
}

void ClientParseDlpCertificateCallback::onParseDlpCertificate(int32_t result, const PermissionPolicy& policy)
{
    DLP_LOG_INFO(LABEL, "Callback");
    this->result_ = result;
    this->policy_.CopyPermissionPolicy(policy);
    this->isCallBack_ = true;
}

int32_t DlpPermissionKit::GenerateDlpCertificate(const PermissionPolicy& policy, std::vector<uint8_t>& cert)
{
    DLP_LOG_DEBUG(LABEL, "Called");
    std::shared_ptr<ClientGenerateDlpCertificateCallback> callback =
        std::make_shared<ClientGenerateDlpCertificateCallback>();
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Callback is null");
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    int32_t res = DlpPermissionClient::GetInstance().GenerateDlpCertificate(policy, callback);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "begin generate cert fail, error: %{public}d", res);
        return res;
    }

    // wait callback
    struct tm startTime = {0};
    struct tm nowTime = {0};
    OHOS::GetSystemCurrentTime(&startTime);
    OHOS::GetSystemCurrentTime(&nowTime);
    while (OHOS::GetSecondsBetween(startTime, nowTime) < TIME_WAIT_TIME_OUT && !callback->isCallBack_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_ONE_TIME));
        OHOS::GetSystemCurrentTime(&nowTime);
    }
    if (!callback->isCallBack_) {
        DLP_LOG_ERROR(LABEL, "service did not call back! timeout!");
        return DLP_SERVICE_ERROR_CREDENTIAL_TASK_TIMEOUT;
    }
    DLP_LOG_INFO(LABEL, "get callback succeed!");
    cert = callback->cert_;
    return callback->result_;
}

int32_t DlpPermissionKit::ParseDlpCertificate(const std::vector<uint8_t>& cert, PermissionPolicy& policy)
{
    DLP_LOG_DEBUG(LABEL, "Called");
    std::shared_ptr<ClientParseDlpCertificateCallback> callback = std::make_shared<ClientParseDlpCertificateCallback>();
    if (callback == nullptr) {
        DLP_LOG_ERROR(LABEL, "Callback is null");
        return DLP_SERVICE_ERROR_CREDENTIAL_TASK_TIMEOUT;
    }
    int32_t res = DlpPermissionClient::GetInstance().ParseDlpCertificate(cert, callback);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "begin parse cert fail, error: %{public}d", res);
        return res;
    }

    // wait callback
    struct tm startTime = {0};
    struct tm nowTime = {0};
    OHOS::GetSystemCurrentTime(&startTime);
    OHOS::GetSystemCurrentTime(&nowTime);
    while (OHOS::GetSecondsBetween(startTime, nowTime) < TIME_WAIT_TIME_OUT && !callback->isCallBack_) {
        std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_ONE_TIME));
        OHOS::GetSystemCurrentTime(&nowTime);
    }
    if (!callback->isCallBack_) {
        DLP_LOG_ERROR(LABEL, "service did not call back! timeout!");
        return DLP_SERVICE_ERROR_CREDENTIAL_TASK_TIMEOUT;
    }
    DLP_LOG_INFO(LABEL, "get callback succeed!");
    policy.CopyPermissionPolicy(callback->policy_);
    return callback->result_;
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
