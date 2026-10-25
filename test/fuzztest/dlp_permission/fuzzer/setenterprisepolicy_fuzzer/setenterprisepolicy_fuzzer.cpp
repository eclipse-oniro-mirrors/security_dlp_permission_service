/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "setenterprisepolicy_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <string>
#include "accesstoken_kit.h"
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "securec.h"
#include "token_setproc.h"
#include "dlp_permission_client.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;

namespace {
static const uint64_t SYSTEM_APP_MASK = 0x100000000;
static const int32_t DEFAULT_USER_ID = 100;
static const size_t MAX_SAFE_SIZE = 1024;
} // namespace

namespace OHOS {
static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0) || (size > MAX_SAFE_SIZE)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    EnterprisePolicy policy;
    policy.policyString = fdp.ConsumeBytesAsString(size);
    DlpPermissionKit::SetEnterprisePolicy(policy);
    EnterprisePolicy emptyPolicy;
    DlpPermissionKit::SetEnterprisePolicy(emptyPolicy);
    DlpPermissionClient::GetInstance().SetEnterprisePolicy(policy.policyString);
    DlpPermissionClient::GetInstance().SetEnterprisePolicy("");
}

bool SetEnterprisePolicyFuzzTest(const uint8_t* data, size_t size)
{
    FuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    AccessTokenIDEx tokenIdEx = AccessTokenKit::GetHapTokenIDEx(DEFAULT_USER_ID, "com.ohos.dlpmanager", 0);
    tokenIdEx.tokenIDEx |= SYSTEM_APP_MASK;
    SetSelfTokenID(tokenIdEx.tokenIDEx);
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::SetEnterprisePolicyFuzzTest(data, size);
    return 0;
}
