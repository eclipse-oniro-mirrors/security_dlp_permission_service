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

#ifndef DLP_PERMISSION_KIT_TEST
#define DLP_PERMISSION_KIT_TEST

#include <gtest/gtest.h>
#include "dlp_permission_kit.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
class TestGenerateDlpCertificateCallback : public GenerateDlpCertificateCallback {
public:
    TestGenerateDlpCertificateCallback() = default;
    virtual ~TestGenerateDlpCertificateCallback() = default;

    void onGenerateDlpCertificate(int32_t result, const std::vector<uint8_t>& cert) override;
};

class TestParseDlpCertificateCallback : public ParseDlpCertificateCallback {
public:
    TestParseDlpCertificateCallback() = default;
    virtual ~TestParseDlpCertificateCallback() = default;

    void onParseDlpCertificate(int32_t result, const PermissionPolicy& policy) override;
};

class DlpPermissionKitTest : public testing::Test {
public:
    static void SetUpTestCase();

    static void TearDownTestCase();

    void SetUp() override;

    void TearDown() override;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // DLP_PERMISSION_KIT_TEST
