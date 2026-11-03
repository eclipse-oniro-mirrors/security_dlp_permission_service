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

#include "enterpriseinfoparcel_fuzzer.h"
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>
#include <string>
#include "dlp_permission_log.h"
#include "parcel.h"
#include "securec.h"

using namespace OHOS::Security::DlpPermission;

namespace {
static const size_t MIN_SIZE = sizeof(uint32_t) * 3;
static const size_t MAX_SAFE_SIZE = 2048;
static const int32_t MIN_DLPFILEACCESS = 0;
static const int32_t MAX_DLPFILEACCESS = 4; // ATOMIC_CONTROL = 4
static const int32_t STRING_SIZE_64 = 64;
static const int32_t STRING_SIZE_RANDOM = 128;
} // namespace

namespace OHOS {
static void FillEnterpriseInfo(EnterpriseInfo& info, FuzzedDataProvider& fdp)
{
    info.uri = fdp.ConsumeRandomLengthString(STRING_SIZE_RANDOM);
    info.classificationLabel = fdp.ConsumeRandomLengthString(STRING_SIZE_64);
    int32_t access = fdp.ConsumeIntegralInRange<int32_t>(MIN_DLPFILEACCESS, MAX_DLPFILEACCESS);
    info.dlpFileAccess = static_cast<DLPFileAccess>(access);
    info.fileId = fdp.ConsumeRandomLengthString(STRING_SIZE_64);
    info.appIdentifier = fdp.ConsumeRandomLengthString(STRING_SIZE_64);
    info.atomicDlpFileAccess = fdp.ConsumeIntegral<uint32_t>();
    info.uid = fdp.ConsumeIntegral<int32_t>();
}

static void FuzzMarshallingRoundTrip(const EnterpriseInfo& info)
{
    MessageParcel out;
    if (!info.Marshalling(out)) {
        return;
    }
    EnterpriseInfo* decoded = EnterpriseInfo::Unmarshalling(out);
    if (decoded != nullptr) {
        // touch decoded fields so they are not optimized away
        (void)decoded->uri;
        (void)decoded->atomicDlpFileAccess;
        (void)decoded->dlpFileAccess;
        delete decoded;
    }
}

static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < MIN_SIZE) || (size > MAX_SAFE_SIZE)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    EnterpriseInfo info;
    FillEnterpriseInfo(info, fdp);
    FuzzMarshallingRoundTrip(info);
}

bool EnterpriseInfoParcelFuzzTest(const uint8_t* data, size_t size)
{
    FuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::EnterpriseInfoParcelFuzzTest(data, size);
    return 0;
}
