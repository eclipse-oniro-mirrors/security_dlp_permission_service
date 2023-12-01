/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef DLP_BUNDLE_MANAGER_ADAPTER_H
#define DLP_BUNDLE_MANAGER_ADAPTER_H

#include <mutex>
#include <string>
#include <vector>
#include "ability_info.h"
#include "account_error_no.h"
#include "bundle_info.h"
#include "bundle_mgr_interface.h"


namespace OHOS {
namespace Security {
namespace DlpPermission {
class BundleManagerAdapter {
public:
    static BundleManagerAdapter& GetInstance();
    bool GetBundleInfo(const std::string &bundleName, int32_t flag,
        AppExecFwk::BundleInfo &bundleInfo, int32_t userId);
    int32_t GetBundleInfoV9(const std::string &bundleName, AppExecFwk::BundleFlag flag,
        AppExecFwk::BundleInfo &bundleInfo, int32_t userId);

private:
    BundleManagerAdapter();
    virtual ~BundleManagerAdapter();
    DISALLOW_COPY_AND_MOVE(BundleManagerAdapter);
    int32_t Connect();
    std::mutex proxyMutex_;
    sptr<AppExecFwk::IBundleMgr> proxy_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_BUNDLE_MANAGER_ADAPTER_H