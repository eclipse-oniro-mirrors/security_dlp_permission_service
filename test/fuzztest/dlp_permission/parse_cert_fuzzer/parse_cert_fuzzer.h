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

#ifndef TEST_FUZZTEST_PARSE_CERT_FUZZER_H
#define TEST_FUZZTEST_PARSE_CERT_FUZZER_H

#define FUZZ_PROJECT_NAME "parse_cert_fuzzer"

#include "dlp_permission_kit.h"
namespace OHOS {
class TestParseDlpCertificateCallback : public OHOS::Security::DlpPermission::ParseDlpCertificateCallback {
public:
    TestParseDlpCertificateCallback() = default;
    virtual ~TestParseDlpCertificateCallback() = default;

    void onParseDlpCertificate(int32_t result, const OHOS::Security::DlpPermission::PermissionPolicy& policy) override;
};
}  // namespace OHOS

#endif  // TEST_FUZZTEST_PARSE_CERT_FUZZER_H
