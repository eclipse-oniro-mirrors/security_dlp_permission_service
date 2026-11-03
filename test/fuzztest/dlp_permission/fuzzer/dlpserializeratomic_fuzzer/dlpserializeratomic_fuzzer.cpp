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

#include "dlpserializeratomic_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <string>
#include "dlp_permission_log.h"
#include "nlohmann/json.hpp"
#include "securec.h"

using namespace OHOS::Security::DlpPermission;

namespace {
static const size_t MIN_SIZE = sizeof(uint32_t) * 2;
static const size_t MAX_SAFE_SIZE = 4096;
static const int32_t MIN_PERM = 0;
static const int32_t MAX_PERM = 4; // ATOMIC_CONTROL = 4
static const int32_t TWO = 2;
static const int32_t STRING_SIZE_32 = 32;
} // namespace

namespace OHOS {
using unordered_json = nlohmann::ordered_json;

static DLPFileAccess GenAccess(FuzzedDataProvider& fdp)
{
    int32_t v = fdp.ConsumeIntegralInRange<int32_t>(MIN_PERM, MAX_PERM);
    return static_cast<DLPFileAccess>(v);
}

static void FuzzSerialize(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    PermissionPolicy policy;
    int32_t perm = fdp.ConsumeIntegralInRange<int32_t>(MIN_PERM, MAX_PERM);
    policy.everyonePerm_ = static_cast<DLPFileAccess>(perm);
    policy.supportEveryone_ = fdp.ConsumeBool();
    policy.ownerAccountType_ = DlpAccountType::CLOUD_ACCOUNT;
    AuthUserInfo user;
    user.authAccount = fdp.ConsumeRandomLengthString(STRING_SIZE_32);
    user.authPerm = GenAccess(fdp);
    user.atomicDlpFileAccess = fdp.ConsumeIntegral<uint32_t>();
    user.authAccountType = DlpAccountType::CLOUD_ACCOUNT;
    user.permExpiryTime = fdp.ConsumeIntegral<uint64_t>();
    policy.authUsers_.emplace_back(user);
    unordered_json out;
    DlpPermissionSerializer::GetInstance().SerializeDlpPermission(policy, out);
}

static void FuzzDeserialize(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    std::string jsonStr = fdp.ConsumeRemainingBytesAsString();
    unordered_json parsed;
    if (!ParseJsonWithDepthCheck(jsonStr, parsed)) {
        return;
    }
    PermissionPolicy policy;
    DlpPermissionSerializer::GetInstance().DeserializeDlpPermission(parsed, policy);
    (void)policy.everyonePerm_;
    (void)policy.authUsers_.empty();
}

static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < MIN_SIZE) || (size > MAX_SAFE_SIZE)) {
        return;
    }
    FuzzSerialize(data, size / TWO);
    FuzzDeserialize(data + size / TWO, size - size / TWO);
}

bool DlpSerializerAtomicFuzzTest(const uint8_t* data, size_t size)
{
    FuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DlpSerializerAtomicFuzzTest(data, size);
    return 0;
}
