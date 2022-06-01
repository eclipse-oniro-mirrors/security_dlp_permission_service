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

#ifndef TEST_FUZZTEST_GENERATE_CERT_FUZZER_H
#define TEST_FUZZTEST_GENERATE_CERT_FUZZER_H

#define FUZZ_PROJECT_NAME "generate_cert_fuzzer"

#include "dlp_permission_kit.h"
namespace OHOS {
class TestGenerateDlpCertificateCallback : public OHOS::Security::DlpPermission::GenerateDlpCertificateCallback {
public:
    TestGenerateDlpCertificateCallback() = default;
    virtual ~TestGenerateDlpCertificateCallback() = default;

    void onGenerateDlpCertificate(const int32_t result, const std::vector<uint8_t>& cert) override;
};
}  // namespace OHOS

#endif  // TEST_FUZZTEST_GENERATE_CERT_FUZZER_H
