/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "retention_file_manager_test.h"
#include <cerrno>
#include <gtest/gtest.h>
#include <securec.h>
#include "dlp_permission.h"
#include "dlp_permission_log.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;
using namespace std;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "RetentionFileManagerTest"};
}

void RetentionFileManagerTest::SetUpTestCase() {}

void RetentionFileManagerTest::TearDownTestCase() {}

void RetentionFileManagerTest::SetUp() {}

void RetentionFileManagerTest::TearDown() {}

/**
 * @tc.name: UpdateReadFlag001
 * @tc.desc: UpdateReadFlag test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RetentionFileManagerTest, UpdateReadFlag001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "UpdateReadFlag001");

    uint32_t tokenId = 0;
    ASSERT_EQ(DLP_OK, RetentionFileManager::GetInstance().UpdateReadFlag(tokenId));
}

/**
 * @tc.name: HasRetentionSandboxInfo001
 * @tc.desc: Test HasRetentionSandboxInfo with empty bundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RetentionFileManagerTest, HasRetentionSandboxInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "HasRetentionSandboxInfo001");
    bool result = RetentionFileManager::GetInstance().HasRetentionSandboxInfo("");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: HasRetentionSandboxInfo002
 * @tc.desc: Test HasRetentionSandboxInfo with non-existent bundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RetentionFileManagerTest, HasRetentionSandboxInfo002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "HasRetentionSandboxInfo002");
    bool result = RetentionFileManager::GetInstance().HasRetentionSandboxInfo("non_existent_bundle_12345");
    EXPECT_FALSE(result);
}

/**
 * @tc.name: AddSandboxInfo001
 * @tc.desc: Test AddSandboxInfo with invalid params (appIndex = -1)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RetentionFileManagerTest, AddSandboxInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddSandboxInfo001");
    RetentionInfo info;
    info.appIndex = -1;
    info.tokenId = 0;
    info.bundleName = "";
    info.userId = -1;
    int32_t ret = RetentionFileManager::GetInstance().AddSandboxInfo(info);
    EXPECT_NE(DLP_OK, ret);
}

/**
 * @tc.name: CanUninstall001
 * @tc.desc: Test CanUninstall with non-existent tokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RetentionFileManagerTest, CanUninstall001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "CanUninstall001");
    uint32_t tokenId = 999999;
    bool result = RetentionFileManager::GetInstance().CanUninstall(tokenId);
    EXPECT_TRUE(result);
    DLP_LOG_INFO(LABEL, "SetInitStatus001");
    uint32_t tokenId = 999999;
    RetentionFileManager::GetInstance().SetInitStatus(tokenId);
}

/**
 * @tc.name: RemoveRetentionState001
 * @tc.desc: Test RemoveRetentionState with empty bundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RetentionFileManagerTest, RemoveRetentionState001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "RemoveRetentionState001");
    int32_t ret = RetentionFileManager::GetInstance().RemoveRetentionState("", -1);
    EXPECT_NE(DLP_OK, ret);
}

/**
 * @tc.name: ClearUnreservedSandbox001
 * @tc.desc: Test ClearUnreservedSandbox with isNotMatch = 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RetentionFileManagerTest, ClearUnreservedSandbox001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "ClearUnreservedSandbox001");
    int32_t ret = RetentionFileManager::GetInstance().ClearUnreservedSandbox(0);
    EXPECT_TRUE(ret == DLP_OK || ret == DLP_FILE_NO_NEED_UPDATE);
}

/**
 * @tc.name: GetRetentionSandboxList001
 * @tc.desc: Test GetRetentionSandboxList with empty bundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RetentionFileManagerTest, GetRetentionSandboxList001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetRetentionSandboxList001");
    std::vector<RetentionSandBoxInfo> vec;
    int32_t ret = RetentionFileManager::GetInstance().GetRetentionSandboxList("non_existent_bundle", vec, true);
    EXPECT_TRUE(ret == DLP_OK || ret == DLP_RETENTION_SERVICE_ERROR);
}

/**
 * @tc.name: GetBundleNameSetByUserId001
 * @tc.desc: Test GetBundleNameSetByUserId with non-existent userId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RetentionFileManagerTest, GetBundleNameSetByUserId001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetBundleNameSetByUserId001");
    std::set<std::string> bundleSet;
    int32_t ret = RetentionFileManager::GetInstance().GetBundleNameSetByUserId(99999, bundleSet);
    EXPECT_TRUE(ret == DLP_OK || ret == DLP_FILE_NO_NEED_UPDATE);
}

/**
 * @tc.name: RemoveRetentionInfoByUserId001
 * @tc.desc: Test RemoveRetentionInfoByUserId with non-existent userId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RetentionFileManagerTest, RemoveRetentionInfoByUserId001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "RemoveRetentionInfoByUserId001");
    std::set<std::string> bundleSet;
    int32_t ret = RetentionFileManager::GetInstance().RemoveRetentionInfoByUserId(99999, bundleSet);
    EXPECT_TRUE(ret == DLP_OK || ret == DLP_FILE_NO_NEED_UPDATE);
}

/**
 * @tc.name: UpdateSandboxInfo001
 * @tc.desc: Test UpdateSandboxInfo with empty docUriSet and isRetention=true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RetentionFileManagerTest, UpdateSandboxInfo001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "UpdateSandboxInfo001");
    RetentionInfo info;
    info.appIndex = 0;
    info.tokenId = 0;
    info.bundleName = "";
    info.userId = -1;
    int32_t ret = RetentionFileManager::GetInstance().UpdateSandboxInfo({}, info, true);
    EXPECT_EQ(DLP_OK, ret);
}

/**
 * @tc.name: UpdateReadFlag002
 * @tc.desc: Test UpdateReadFlag with non-existent tokenId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RetentionFileManagerTest, UpdateReadFlag002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "UpdateReadFlag002");
    uint32_t tokenId = 888888;
    int32_t ret = RetentionFileManager::GetInstance().UpdateReadFlag(tokenId);
    EXPECT_EQ(DLP_OK, ret);
}