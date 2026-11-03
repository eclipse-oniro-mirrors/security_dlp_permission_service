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

#include "appstateobserveratomic_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <string>
#include "accesstoken_kit.h"
#include "dlp_permission_kit.h"
#include "dlp_permission_log.h"
#include "mock_sandbox_init.h"
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;

namespace {
static const int32_t MIN_PERM = 0;
static const int32_t MAX_PERM = 4; // ATOMIC_CONTROL = 4
static const int32_t DEFAULT_USER_ID = 100;
static const int32_t STRING_SIZE_32 = 32;
static const int32_t STRING_SIZE_64 = 64;
static const int32_t MIN_SIZE = sizeof(uint32_t) * 2;
static const size_t MAX_SAFE_SIZE = 1024;
} // namespace

namespace OHOS {
static pthread_once_t g_callOnce = PTHREAD_ONCE_INIT;

static void FuzzInstallAndQuery(FuzzedDataProvider& fdp)
{
    int32_t userId = DEFAULT_USER_ID;
    int32_t perm = fdp.ConsumeIntegralInRange<int32_t>(MIN_PERM, MAX_PERM);
    DLPFileAccess access = static_cast<DLPFileAccess>(perm);
    std::string bundleName = fdp.ConsumeRandomLengthString(STRING_SIZE_32);
    std::string uri = fdp.ConsumeRandomLengthString(STRING_SIZE_64);
    SandboxInfo sandboxInfo;
    DlpPermissionKit::InstallDlpSandbox(
        bundleName, access, userId, sandboxInfo, uri);
    DLPPermissionInfo permInfo;
    permInfo.dlpFileAccess = access;
    DlpPermissionKit::QueryDlpFileAccess(permInfo);
    bool copyable = false;
    uint32_t tokenId = fdp.ConsumeIntegral<uint32_t>();
    DlpPermissionKit::QueryDlpFileCopyableByTokenId(copyable, tokenId);
}

static void FuzzQueryWithAtomicAccess(FuzzedDataProvider& fdp)
{
    int32_t perm = fdp.ConsumeIntegralInRange<int32_t>(MIN_PERM, MAX_PERM);
    DLPPermissionInfo permInfo;
    permInfo.dlpFileAccess = static_cast<DLPFileAccess>(perm);
    DlpPermissionKit::QueryDlpFileAccess(permInfo);
    bool copyable = false;
    uint32_t tokenId = fdp.ConsumeIntegral<uint32_t>();
    DlpPermissionKit::QueryDlpFileCopyableByTokenId(copyable, tokenId);
    EnterpriseInfo enterpriseInfo;
    enterpriseInfo.uri = fdp.ConsumeRandomLengthString(STRING_SIZE_32);
    enterpriseInfo.classificationLabel = fdp.ConsumeRandomLengthString(STRING_SIZE_32);
    enterpriseInfo.dlpFileAccess = static_cast<DLPFileAccess>(perm);
    enterpriseInfo.fileId = fdp.ConsumeRandomLengthString(STRING_SIZE_32);
    enterpriseInfo.appIdentifier = fdp.ConsumeRandomLengthString(STRING_SIZE_32);
    enterpriseInfo.atomicDlpFileAccess = fdp.ConsumeIntegral<uint32_t>();
    (void)enterpriseInfo;
}

static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < MIN_SIZE) || (size > MAX_SAFE_SIZE)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    FuzzInstallAndQuery(fdp);
    FuzzQueryWithAtomicAccess(fdp);
}

bool AppStateObserverAtomicFuzzTest(const uint8_t* data, size_t size)
{
    pthread_once(&g_callOnce, InitTokenId);
    FuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::AppStateObserverAtomicFuzzTest(data, size);
    return 0;
}
