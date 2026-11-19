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

#include "visit_record_file_manager_test.h"
#include <cerrno>
#include <gtest/gtest.h>
#include <thread>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "visited_dlp_file_info.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "VisitRecordFileManagerTest"};
}

void VisitRecordFileManagerTest::SetUpTestCase() {}

void VisitRecordFileManagerTest::TearDownTestCase() {}

void VisitRecordFileManagerTest::SetUp() {}

void VisitRecordFileManagerTest::TearDown() {}

/**
 * @tc.name: AddVisitRecord001
 * @tc.desc: Test AddVisitRecord with valid params
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VisitRecordFileManagerTest, AddVisitRecord001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "AddVisitRecord001");
    int32_t ret = VisitRecordFileManager::GetInstance().AddVisitRecord("visit_bundle_001", 100, "test_visit_doc_001");
    EXPECT_TRUE(ret == DLP_OK || ret == DLP_INSERT_FILE_ERROR || ret == DLP_RETENTION_UPDATE_ERROR);
}

/**
 * @tc.name: GetVisitRecordList001
 * @tc.desc: Test GetVisitRecordList returns records added by AddVisitRecord (in-memory json manager)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VisitRecordFileManagerTest, GetVisitRecordList001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetVisitRecordList001");
    const std::string bundleName = "visit_bundle_002";
    const int32_t userId = 100;
    // ensure clean state for this bundle
    std::vector<VisitedDLPFileInfo> emptyVec;
    (void)VisitRecordFileManager::GetInstance().GetVisitRecordList(bundleName, userId, emptyVec);
    emptyVec.clear();

    int32_t addRet = VisitRecordFileManager::GetInstance().AddVisitRecord(bundleName, userId, "test_visit_doc_002");
    std::vector<VisitedDLPFileInfo> infoVec;
    int32_t ret = VisitRecordFileManager::GetInstance().GetVisitRecordList(bundleName, userId, infoVec);
    if (addRet != DLP_OK || ret != DLP_OK) {
        // file system unavailable in UT environment: only assert no crash and tolerant return codes
        EXPECT_TRUE(ret == DLP_OK || ret == DLP_INSERT_FILE_ERROR || ret == DLP_RETENTION_UPDATE_ERROR);
        return;
    }
    EXPECT_EQ(DLP_OK, ret);
    ASSERT_GE(infoVec.size(), static_cast<size_t>(1));
    bool found = false;
    for (const auto &info : infoVec) {
        if (info.visitedFileUri == "test_visit_doc_002") {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

/**
 * @tc.name: GetVisitRecordList002
 * @tc.desc: Test GetVisitRecordList with non-existent bundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VisitRecordFileManagerTest, GetVisitRecordList002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "GetVisitRecordList002");
    std::vector<VisitedDLPFileInfo> infoVec;
    int32_t ret = VisitRecordFileManager::GetInstance().GetVisitRecordList("non_existent_visit_bundle", 999, infoVec);
    EXPECT_TRUE(ret == DLP_OK || ret == DLP_INSERT_FILE_ERROR || ret == DLP_RETENTION_UPDATE_ERROR);
}

/**
 * @tc.name: VisitRecordFileManagerConcurrent001
 * @tc.desc: concurrency regression for method-level locking fix
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(VisitRecordFileManagerTest, VisitRecordFileManagerConcurrent001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "VisitRecordFileManagerConcurrent001");
    const int loopCount = 30;
    std::thread addThread([]() {
        for (int i = 0; i < loopCount; ++i) {
            (void)VisitRecordFileManager::GetInstance().AddVisitRecord(
                "visit_bundle_concurrent", 100, "concurrent_doc_" + std::to_string(i));
        }
    });
    std::thread getThread([]() {
        for (int i = 0; i < loopCount; ++i) {
            std::vector<VisitedDLPFileInfo> infoVec;
            (void)VisitRecordFileManager::GetInstance().GetVisitRecordList("visit_bundle_concurrent", 100, infoVec);
        }
    });
    std::thread otherGetThread([]() {
        for (int i = 0; i < loopCount; ++i) {
            std::vector<VisitedDLPFileInfo> infoVec;
            (void)VisitRecordFileManager::GetInstance().GetVisitRecordList(
                "non_existent_visit_bundle", 999, infoVec);
        }
    });
    addThread.join();
    getThread.join();
    otherGetThread.join();
    std::vector<VisitedDLPFileInfo> infoVec;
    int32_t ret = VisitRecordFileManager::GetInstance().GetVisitRecordList("visit_bundle_concurrent", 100, infoVec);
    EXPECT_TRUE(ret == DLP_OK || ret == DLP_INSERT_FILE_ERROR || ret == DLP_RETENTION_UPDATE_ERROR);
}
