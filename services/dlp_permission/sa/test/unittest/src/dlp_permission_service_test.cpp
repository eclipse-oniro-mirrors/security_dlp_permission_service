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
#include "app_uninstall_observer.h"
#define private public
#include "callback_manager.h"
#undef private
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_policy.h"
#include "dlp_sandbox_change_callback_proxy.h"
#include "dlp_sandbox_change_callback_stub.h"
#include "dlp_sandbox_change_callback_death_recipient.h"
#include "file_operator.h"
#include "retention_file_manager.h"
#include "sandbox_json_manager.h"

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

/**
 * @tc.name:CallbackManager001
 * @tc.desc: CallbackManager test
 * @tc.type: FUNC
 * @tc.require:DTS2023040302317
 */
HWTEST_F(DlpPermissionServiceTest, CallbackManager001, TestSize.Level1)
{
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, CallbackManager::GetInstance().AddCallback(0, nullptr));
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, CallbackManager::GetInstance().RemoveCallback(nullptr));
    bool result;
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, CallbackManager::GetInstance().RemoveCallback(0, result));
    sptr<IRemoteObject> callback;
    wptr<IRemoteObject> remote = new (std::nothrow) DlpSandboxChangeCallbackTest();
    callback = remote.promote();
    dlpPermissionService_->RegisterDlpSandboxChangeCallback(callback);
    for (int i = 10000; i < 11024; i++) {
        CallbackManager::GetInstance().AddCallback(i, callback);
    }
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, CallbackManager::GetInstance().AddCallback(11024, callback));
    DlpSandboxInfo dlpSandboxInfo;
    dlpSandboxInfo.pid = 1;
    CallbackManager::GetInstance().ExecuteCallbackAsync(dlpSandboxInfo);
    dlpSandboxInfo.pid = 10010;
    CallbackManager::GetInstance().ExecuteCallbackAsync(dlpSandboxInfo);
}

/**
 * @tc.name:SandboxJsonManager002
 * @tc.desc: SandboxJsonManager test
 * @tc.type: FUNC
 * @tc.require:DTS2023040302317
 */
HWTEST_F(DlpPermissionServiceTest, SandboxJsonManager002, TestSize.Level1)
{
    std::shared_ptr<SandboxJsonManager> sandboxJsonManager_ = std::make_shared<SandboxJsonManager>();
    sandboxJsonManager_->AddSandboxInfo(1, 827878, "testbundle", 100);
    ASSERT_TRUE(!sandboxJsonManager_->HasRetentionSandboxInfo("testbundle1"));
    int32_t uid = getuid();
    setuid(20010031);
    ASSERT_TRUE(sandboxJsonManager_->HasRetentionSandboxInfo("testbundle"));
    sandboxJsonManager_->AddSandboxInfo(1, 827818, "testbundle1", 10000);
    ASSERT_TRUE(!sandboxJsonManager_->HasRetentionSandboxInfo("testbundle1"));

    ASSERT_EQ(DLP_RETENTION_SERVICE_ERROR, sandboxJsonManager_->DelSandboxInfo(8888));

    RetentionInfo info;
    info.tokenId = 827878;
    std::set<std::string> docUriSet;
    ASSERT_TRUE(!sandboxJsonManager_->UpdateDocUriSetByDifference(info, docUriSet));
    docUriSet.insert("testUri");
    sandboxJsonManager_->UpdateRetentionState(docUriSet, info, true);
    ASSERT_EQ(DLP_RETENTION_SERVICE_ERROR, sandboxJsonManager_->DelSandboxInfo(827878));
    sandboxJsonManager_->UpdateRetentionState(docUriSet, info, false);
    ASSERT_EQ(DLP_OK, sandboxJsonManager_->DelSandboxInfo(827878));
    setuid(uid);
}

/**
 * @tc.name:SandboxJsonManager003
 * @tc.desc: SandboxJsonManager test
 * @tc.type: FUNC
 * @tc.require:DTS2023040302317
 */
HWTEST_F(DlpPermissionServiceTest, SandboxJsonManager003, TestSize.Level1)
{
    std::shared_ptr<SandboxJsonManager> sandboxJsonManager_ = std::make_shared<SandboxJsonManager>();
    sandboxJsonManager_->AddSandboxInfo(1, 827818, "testbundle1", 10000);
    int32_t uid = getuid();
    ASSERT_EQ(DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY,
        sandboxJsonManager_->RemoveRetentionState("testbundle", -1));
    ASSERT_EQ(DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY,
        sandboxJsonManager_->RemoveRetentionState("testbundle1", -1));
    sandboxJsonManager_->AddSandboxInfo(1, 827878, "testbundle", 100);
    ASSERT_EQ(DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY,
        sandboxJsonManager_->RemoveRetentionState("testbundle1", -1));
    ASSERT_EQ(DLP_OK, sandboxJsonManager_->RemoveRetentionState("testbundle", -1));
    sandboxJsonManager_->AddSandboxInfo(1, 827878, "testbundle", 100);
    ASSERT_EQ(DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY,
        sandboxJsonManager_->RemoveRetentionState("testbundle", 2));
    ASSERT_EQ(DLP_OK, sandboxJsonManager_->RemoveRetentionState("testbundle", 1));
    setuid(uid);
}

/**
 * @tc.name:RetentionFileManager001
 * @tc.desc: RetentionFileManager test
 * @tc.type: FUNC
 * @tc.require:DTS2023040302317
 */
HWTEST_F(DlpPermissionServiceTest, RetentionFileManager001, TestSize.Level1)
{
    std::shared_ptr<SandboxJsonManager> sandboxJsonManager_ = std::make_shared<SandboxJsonManager>();
    sandboxJsonManager_->AddSandboxInfo(1, 827878, "testbundle", 100);
    int32_t uid = getuid();
    setuid(10031);
    ASSERT_TRUE(!RetentionFileManager::GetInstance().HasRetentionSandboxInfo("testbundle1"));
    setuid(20010031);
    RetentionFileManager::GetInstance().hasInit = false;
    ASSERT_EQ(DLP_OK, RetentionFileManager::GetInstance().AddSandboxInfo(1, 827878, "testbundle", 100));
    RetentionFileManager::GetInstance().hasInit = false;
    ASSERT_EQ(DLP_RETENTION_SERVICE_ERROR, RetentionFileManager::GetInstance().DelSandboxInfo(8888));
    RetentionFileManager::GetInstance().hasInit = false;
    ASSERT_TRUE(RetentionFileManager::GetInstance().CanUninstall(8888));
    RetentionFileManager::GetInstance().hasInit = false;
    ASSERT_EQ(DLP_RETENTION_GET_DATA_FROM_BASE_CONSTRAINTS_FILE_EMPTY,
        RetentionFileManager::GetInstance().RemoveRetentionState("testbundle1", -1));
    RetentionFileManager::GetInstance().hasInit = false;
    ASSERT_EQ(DLP_OK, RetentionFileManager::GetInstance().ClearUnreservedSandbox());
    RetentionFileManager::GetInstance().hasInit = false;
    std::vector<RetentionSandBoxInfo> vec;
    ASSERT_EQ(DLP_OK, RetentionFileManager::GetInstance().GetRetentionSandboxList("testbundle1", vec, false));

    setuid(uid);
}

/**
 * @tc.name:UninstallDlpSandbox001
 * @tc.desc:UninstallDlpSandbox test
 * @tc.type: FUNC
 * @tc.require:DTS2023040302317
 */
HWTEST_F(DlpPermissionServiceTest, UninstallDlpSandbox001, TestSize.Level1)
{
    int32_t appIndex;
    uint32_t permType = 5;
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID,
        dlpPermissionService_->InstallDlpSandbox("", static_cast<AuthPermType>(permType), 100, appIndex, "testUri"));
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, dlpPermissionService_->InstallDlpSandbox("testbundle",
        static_cast<AuthPermType>(permType), 100, appIndex, "testUri"));
    permType = 0;
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, dlpPermissionService_->InstallDlpSandbox("testbundle",
        static_cast<AuthPermType>(permType), 100, appIndex, "testUri"));
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, dlpPermissionService_->UninstallDlpSandbox("", -1, -1));
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, dlpPermissionService_->UninstallDlpSandbox("testbundle", -1, -1));
    permType = 0;
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, dlpPermissionService_->UninstallDlpSandbox("testbundle", 1, -1));
}

/**
 * @tc.name:AppUninstallObserver001
 * @tc.desc:AppUninstallObserver test
 * @tc.type: FUNC
 * @tc.require:DTS2023040302317
 */
HWTEST_F(DlpPermissionServiceTest, AppUninstallObserver001, TestSize.Level1)
{
    EventFwk::CommonEventSubscribeInfo subscribeInfo;
    std::shared_ptr<AppUninstallObserver> observer_ = std::make_shared<AppUninstallObserver>(subscribeInfo);
    EventFwk::CommonEventData data;
    OHOS::AAFwk::Want want;
    want.SetBundle("testbundle1");
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    data.SetWant(want);
    observer_->OnReceiveEvent(data);
    std::shared_ptr<SandboxJsonManager> sandboxJsonManager_ = std::make_shared<SandboxJsonManager>();
    sandboxJsonManager_->AddSandboxInfo(1, 827818, "testbundle", 100);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_FULLY_REMOVED);
    want.SetBundle("testbundle");
    data.SetWant(want);
    observer_->OnReceiveEvent(data);
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_DATA_CLEARED);
    data.SetWant(want);
    observer_->OnReceiveEvent(data);
}