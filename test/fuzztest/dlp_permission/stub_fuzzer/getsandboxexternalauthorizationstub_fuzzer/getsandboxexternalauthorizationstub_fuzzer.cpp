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

#include "getsandboxexternalauthorizationstub_fuzzer.h"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include "accesstoken_kit.h"
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
namespace OHOS {
static void FuzzTest(const uint8_t* data, size_t size)
{
    int sandboxUid = static_cast<int>(size);
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    AAFwk::Want want;
    want.SetBundle(bundleName);
    MessageParcel datas;
    datas.WriteInterfaceToken(IDlpPermissionService::GetDescriptor());

    if (!datas.WriteInt32(sandboxUid)) {
        return;
    }
    if (!datas.WriteParcelable(&want)) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(DlpPermissionServiceInterfaceCode::GET_SANDBOX_EXTERNAL_AUTH);
    MessageParcel reply;
    MessageOption option;
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->OnStart();
    service->OnRemoteRequest(code, datas, reply, option);
}

bool GetSandboxExternalAuthorizationFuzzTest(const uint8_t* data, size_t size)
{
    int selfTokenId = GetSelfTokenID();
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.dlpmanager", 0); // user_id = 100
    SetSelfTokenID(tokenId);
    FuzzTest(data, size);
    SetSelfTokenID(selfTokenId);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::GetSandboxExternalAuthorizationFuzzTest(data, size);
    return 0;
}