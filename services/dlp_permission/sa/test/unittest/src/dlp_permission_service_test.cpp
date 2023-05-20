/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "dlp_permission_service_test.h"
#include <string>
#define private public
#include "callback_manager.h"
#undef private
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_sandbox_change_callback_stub.h"
#include "dlp_sandbox_change_callback_death_recipient.h"
#include "file_operator.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionServiceTest"};
const std::string TEST_URI = "/data/service/el1/public/dlp_permission_service1/retention_sandbox_info.json";
}

void DlpPermissionServiceTest::SetUpTestCase()
{}

void DlpPermissionServiceTest::TearDownTestCase()
{}

void DlpPermissionServiceTest::SetUp()
{
    DLP_LOG_INFO(LABEL, "setup");
    if (dlpPermissionService_ != nullptr) {
        return;
    }
    dlpPermissionService_ = std::make_shared<DlpPermissionService>(3521, true);
    ASSERT_NE(nullptr, dlpPermissionService_);
    dlpPermissionService_->appStateObserver_ = new (std::nothrow) AppStateObserver();
    ASSERT_TRUE(dlpPermissionService_->appStateObserver_ != nullptr);
}

void DlpPermissionServiceTest::TearDown()
{
    if (dlpPermissionService_ != nullptr) {
        dlpPermissionService_->appStateObserver_ = nullptr;
    }
    dlpPermissionService_ = nullptr;
}

/**
 * @tc.name: DumpTest001
 * @tc.desc: dlp permission service dump test
 * @tc.type: FUNC
 * @tc.require:AR000HGIH9
 */
HWTEST_F(DlpPermissionServiceTest, DumpTest001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "DumpTest001");
    int fd = -1;
    std::vector<std::u16string> args;

    // fd is 0
    EXPECT_EQ(ERR_INVALID_VALUE, dlpPermissionService_->Dump(fd, args));

    fd = 1;  // 1: std output

    // hidumper
    EXPECT_EQ(ERR_OK, dlpPermissionService_->Dump(fd, args));

    // hidumper -h
    args.emplace_back(Str8ToStr16("-h"));
    EXPECT_EQ(ERR_OK, dlpPermissionService_->Dump(fd, args));

    args.clear();
    // hidumper -d
    args.emplace_back(Str8ToStr16("-d"));
    EXPECT_EQ(ERR_OK, dlpPermissionService_->Dump(fd, args));

    args.clear();
    // hidumper with not exist param
    args.emplace_back(Str8ToStr16("-n"));
    EXPECT_EQ(ERR_OK, dlpPermissionService_->Dump(fd, args));

    args.clear();
    // hidumper -d with observer null
    dlpPermissionService_->appStateObserver_ = nullptr;
    args.emplace_back(Str8ToStr16("-d"));
    EXPECT_EQ(ERR_INVALID_VALUE, dlpPermissionService_->Dump(fd, args));
}

class DlpSandboxChangeCallbackTest : public DlpSandboxChangeCallbackStub {
public:
    DlpSandboxChangeCallbackTest() = default;
    virtual ~DlpSandboxChangeCallbackTest() = default;

    void DlpSandboxStateChangeCallback(DlpSandboxCallbackInfo& result) override;
};

void DlpSandboxChangeCallbackTest::DlpSandboxStateChangeCallback(DlpSandboxCallbackInfo& result) {}

/**
 * @tc.name:DlpSandboxChangeCallbackDeathRecipient001
 * @tc.desc: DlpSandboxChangeCallbackDeathRecipient test
 * @tc.type: FUNC
 * @tc.require:DTS2023040302317
 */
HWTEST_F(DlpPermissionServiceTest, DlpSandboxChangeCallbackDeathRecipient001, TestSize.Level1)
{
    auto recipient = std::make_shared<DlpSandboxChangeCallbackDeathRecipient>();
    ASSERT_NE(nullptr, recipient);

    recipient->OnRemoteDied(nullptr); // remote is nullptr

    // backup
    sptr<IRemoteObject> callback;
    wptr<IRemoteObject> remote = new (std::nothrow) DlpSandboxChangeCallbackTest();
    callback = remote.promote();
    dlpPermissionService_->RegisterDlpSandboxChangeCallback(callback);
    ASSERT_EQ(static_cast<uint32_t>(1), CallbackManager::GetInstance().callbackInfoMap_.size());
    recipient->OnRemoteDied(remote); // remote is not nullptr
    ASSERT_EQ(static_cast<uint32_t>(0), CallbackManager::GetInstance().callbackInfoMap_.size());
    bool result;
    int32_t res = dlpPermissionService_->UnRegisterDlpSandboxChangeCallback(result);
    ASSERT_EQ(DLP_CALLBACK_PARAM_INVALID, res);
    recipient->OnRemoteDied(remote);
}

/**
 * @tc.name:FileOperator001
 * @tc.desc: FileOperator test
 * @tc.type: FUNC
 * @tc.require:SR000I38N7
 */
HWTEST_F(DlpPermissionServiceTest, FileOperator001, TestSize.Level1)
{
    std::shared_ptr<FileOperator> fileOperator_ = std::make_shared<FileOperator>();
    bool result = fileOperator_->IsExistFile("");
    ASSERT_TRUE(!result);
    std::string content = "test";
    result = fileOperator_->IsExistDir("");
    ASSERT_TRUE(!result);
    int32_t res = fileOperator_->InputFileByPathAndContent(TEST_URI, content);
    ASSERT_EQ(DLP_RETENTION_COMMON_FILE_OPEN_FAILED, res);
    res = fileOperator_->GetFileContentByPath(TEST_URI, content);
    ASSERT_EQ(DLP_RETENTION_FILE_FIND_FILE_ERROR, res);
};

/**
 * @tc.name:SandboxJsonManager001
 * @tc.desc: SandboxJsonManager test
 * @tc.type: FUNC
 * @tc.require:SR000I38N7
 */
HWTEST_F(DlpPermissionServiceTest, SandboxJsonManager001, TestSize.Level1)
{
    std::shared_ptr<SandboxJsonManager> sandboxJsonManager_ = std::make_shared<SandboxJsonManager>();
    sandboxJsonManager_->AddSandboxInfo(1, 123456, "test.bundlName", 100);
    int32_t res = sandboxJsonManager_->AddSandboxInfo(1, 123456, "test.bundlName", 100);
    ASSERT_EQ(DLP_RETENTION_INSERT_FILE_ERROR, res);
    std::set<std::string> docUriSet;
    docUriSet.emplace("testUri");
    RetentionInfo info;
    info.bundleName = "";
    info.tokenId = 0;
    res = sandboxJsonManager_->UpdateRetentionState(docUriSet, info, false);
    ASSERT_EQ(DLP_RETENTION_UPDATE_ERROR, res);
}