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

#ifndef DLP_PERMISSION_CLIENT_H
#define DLP_PERMISSION_CLIENT_H

#include <condition_variable>
#include <mutex>
#include <string>
#include <vector>

#include "dlp_permission_death_recipient.h"
#include "dlp_permission.h"
#include "i_dlp_permission_service.h"
#include "dlp_permission_callback.h"
#include "nocopyable.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class DlpPermissionClient final {
public:
    static DlpPermissionClient& GetInstance();

    int32_t GenerateDlpCertificate(
        const PermissionPolicy& policy, std::shared_ptr<GenerateDlpCertificateCallback> callback);
    int32_t ParseDlpCertificate(
        const std::vector<uint8_t>& cert, std::shared_ptr<ParseDlpCertificateCallback> callback);
    int32_t InstallDlpSandbox(const std::string& bundleName, AuthPermType permType, int32_t userId, int32_t& appIndex);
    int32_t UninstallDlpSandbox(const std::string& bundleName, int32_t appIndex, int32_t userId);
    int32_t GetSandboxExternalAuthorization(int sandboxUid, const AAFwk::Want& want,
        SandBoxExternalAuthorType& authType);
    int32_t QueryDlpFileCopyableByTokenId(bool& copyable, uint32_t tokenId);
    int32_t QueryDlpFileAccess(AuthPermType& permType);
    int32_t IsInDlpSandbox(bool& inSandbox);
    int32_t GetDlpSupportFileType(std::vector<std::string>& supportFileType);

    void FinishStartSASuccess(const sptr<IRemoteObject>& remoteObject);
    void FinishStartSAFail();
    void OnRemoteDiedHandle();

private:
    DlpPermissionClient();
    virtual ~DlpPermissionClient();
    DISALLOW_COPY_AND_MOVE(DlpPermissionClient);

    bool StartLoadDlpPermissionSa();
    void WaitForDlpPermissionSa();
    void GetDlpPermissionSa();
    void LoadDlpPermissionSa();

    sptr<IDlpPermissionService> GetProxy(bool doLoadSa);
    void GetProxyFromRemoteObject(const sptr<IRemoteObject>& remoteObject);

    std::mutex cvLock_;
    bool readyFlag_ = false;
    std::condition_variable dlpPermissionCon_;
    std::mutex proxyMutex_;
    sptr<IDlpPermissionService> proxy_ = nullptr;
    sptr<DlpPermissionDeathRecipient> serviceDeathObserver_ = nullptr;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_CLIENT_H
