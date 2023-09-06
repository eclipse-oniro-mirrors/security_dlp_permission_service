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

#ifndef DLP_PERMISSION_SERVICE_H
#define DLP_PERMISSION_SERVICE_H

#include <string>
#include <vector>
#include "app_state_observer.h"
#include "dlp_permission_stub.h"
#include "iremote_object.h"
#include "nocopyable.h"
#include "singleton.h"
#include "system_ability.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
enum class ServiceRunningState { STATE_NOT_START, STATE_RUNNING };
class DlpPermissionService final : public SystemAbility, public DlpPermissionStub {
    DECLARE_DELAYED_SINGLETON(DlpPermissionService);
    DECLEAR_SYSTEM_ABILITY(DlpPermissionService);

public:
    DlpPermissionService(int saId, bool runOnCreate);
    void OnStart() override;
    void OnStop() override;

    bool RegisterAppStateObserver();
    void UnregisterAppStateObserver();

    int32_t GenerateDlpCertificate(
        const sptr<DlpPolicyParcel>& policyParcel, sptr<IDlpPermissionCallback>& callback) override;
    int32_t ParseDlpCertificate(const std::vector<uint8_t>& cert, uint32_t flag,
        sptr<IDlpPermissionCallback>& callback) override;
    int32_t InstallDlpSandbox(
        const std::string& bundleName, AuthPermType permType, int32_t userId, int32_t& appIndex) override;
    int32_t UninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId) override;
    int32_t GetSandboxExternalAuthorization(
        int sandboxUid, const AAFwk::Want& want, SandBoxExternalAuthorType& authType) override;

    int32_t QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId) override;
    int32_t QueryDlpFileAccess(AuthPermType& permType) override;
    int32_t IsInDlpSandbox(bool& inSandbox) override;
    int32_t GetDlpSupportFileType(std::vector<std::string>& supportFileType) override;

    int Dump(int fd, const std::vector<std::u16string>& args) override;

private:
    bool Initialize() const;

    void InsertDlpSandboxInfo(const std::string& bundleName, AuthPermType permType, int32_t userId, int32_t appIndex);
    void DeleteDlpSandboxInfo(const std::string& bundleName, int32_t appIndex, int32_t userId);

    ServiceRunningState state_;
    sptr<AppExecFwk::IAppMgr> iAppMgr_;
    sptr<AppStateObserver> appStateObserver_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_SERVICE_H
