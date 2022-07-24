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

#ifndef DLP_PERMISSION_PROXY_H
#define DLP_PERMISSION_PROXY_H

#include <string>
#include <vector>
#include "iremote_proxy.h"
#include "dlp_permission.h"
#include "i_dlp_permission_service.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class DlpPermissionProxy : public IRemoteProxy<IDlpPermissionService> {
public:
    explicit DlpPermissionProxy(const sptr<IRemoteObject>& impl);
    ~DlpPermissionProxy() override;

    int32_t GenerateDlpCertificate(
        const sptr<DlpPolicyParcel>& policyParcel, sptr<IDlpPermissionCallback>& callback) override;
    int32_t ParseDlpCertificate(const std::vector<uint8_t>& cert, sptr<IDlpPermissionCallback>& callback) override;
    int32_t InstallDlpSandbox(
        const std::string& bundleName, AuthPermType permType, int32_t userId, int32_t& appIndex) override;
    int32_t UninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId) override;
    int32_t GetSandboxExternalAuthorization(int sandboxUid, const AAFwk::Want& want,
        SandBoxExternalAuthorType& authType) override;

private:
    static inline BrokerDelegator<DlpPermissionProxy> delegator_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_PROXY_H
