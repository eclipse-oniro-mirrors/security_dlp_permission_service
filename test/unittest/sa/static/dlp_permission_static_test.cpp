/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
 
 
#include "dlp_permission_static_test.h"
#include <string>
#include <thread>
#include <unistd.h>
#include <unordered_map>
#include <iostream>
#include "account_adapt.h"
#include "cert_parcel.h"
#include "dlp_credential_client.h"
#include "dlp_permission.h"
#include "dlp_permission_async_proxy.h"
#include "dlp_permission_log.h"
#include "dlp_permission_serializer.h"
#include "dlp_policy_parcel.h"
#include "dlp_credential.h"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_stub.h"
#include "nlohmann/json.hpp"
#include "permission_policy.h"
#include "securec.h"
#include "accesstoken_kit.h"
#include "nativetoken_kit.h"
#include "token_setproc.h"
#define private public
#include "dlp_permission_service.h"
#include "dlp_permission_service.cpp"
#include "dlp_permission_service_ext.cpp"
namespace OHOS {
namespace Security {
namespace DlpPermission {
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;

namespace {
static constexpr uint32_t WAIT_FOR_ACCESS_TOKEN_START = 500;
#define AC_TKN_SVC "accesstoken_service"
#define SVC_CTRL "service_control"
static constexpr char PID_OF_ACCESS_TOKEN_SERVICE[] = "pidof " AC_TKN_SVC;
uint64_t g_selfTokenId = 0;
std::shared_ptr<DlpPermissionService> dlpPermissionService_ = nullptr;
}
static void RestartAccessTokenService()
{
    std::cout << PID_OF_ACCESS_TOKEN_SERVICE << std::endl;
    std::system(PID_OF_ACCESS_TOKEN_SERVICE);

    std::system(SVC_CTRL " stop " AC_TKN_SVC);

    std::cout << PID_OF_ACCESS_TOKEN_SERVICE << std::endl;
    std::system(PID_OF_ACCESS_TOKEN_SERVICE);

    std::system(SVC_CTRL " start " AC_TKN_SVC);

    std::this_thread::sleep_for(std::chrono::milliseconds(WAIT_FOR_ACCESS_TOKEN_START));

    std::cout << PID_OF_ACCESS_TOKEN_SERVICE << std::endl;
    std::system(PID_OF_ACCESS_TOKEN_SERVICE);
}
void DlpPermissionStaticTest::SetUpTestCase()
{
    g_selfTokenId = GetSelfTokenID();
    uint64_t tokenId;
    const char *acls[] = {
        PERMISSION_ACCESS_DLP_FILE.c_str(),
    };
    const char *perms[] = {
        PERMISSION_ACCESS_DLP_FILE.c_str(),
    };
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .dcaps = nullptr,
        .perms = perms,
        .aplStr = "system_basic",
    };
    infoInstance.acls = acls;
    infoInstance.aclsNum = 1;
    infoInstance.processName = "test_get_local_account";
    tokenId = GetAccessTokenId(&infoInstance);
    ASSERT_EQ(0, SetSelfTokenID(tokenId));
    RestartAccessTokenService();
}

void DlpPermissionStaticTest::TearDownTestCase()
{
    ASSERT_EQ(0, SetSelfTokenID(g_selfTokenId));
    RestartAccessTokenService();
}

void DlpPermissionStaticTest::SetUp()
{
    DLP_LOG_INFO(LABEL, "setup");
    dlpPermissionService_ = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    ASSERT_NE(nullptr, dlpPermissionService_);
    dlpPermissionService_->appStateObserver_ = new (std::nothrow) AppStateObserver();
    ASSERT_TRUE(dlpPermissionService_->appStateObserver_ != nullptr);
}
 
void DlpPermissionStaticTest::TearDown()
{
    if (dlpPermissionService_ != nullptr) {
        dlpPermissionService_->appStateObserver_ = nullptr;
    }
    dlpPermissionService_ = nullptr;
}
 
/**
 * @tc.name: DlpPermissionStaticTest001
 * @tc.desc: previewBindInstall test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, DlpPermissionStaticTest001, TestSize.Level1)
{
    DlpSandboxInfo appInfo = {
        .uid = 1,
        .userId = 123,
        .bundleName = "testbundle1",
        .hasRead = false,
        .appIndex = -1,
        .bindAppIndex = 1001,
    };
    DLPFileAccess dlpFileAccess = DLPFileAccess::READ_ONLY;
    int32_t userId = 100;
    previewBindInstall(appInfo, userId, dlpFileAccess);
    ASSERT_EQ(appInfo.bindAppIndex, 1001);
    appInfo.bindAppIndex = -1;
    previewBindInstall(appInfo, userId, dlpFileAccess);
    appInfo.appIndex = 1001;
    previewBindInstall(appInfo, userId, dlpFileAccess);
    appInfo.bindAppIndex = 1001;
    previewBindInstall(appInfo, userId, dlpFileAccess);
    ASSERT_EQ(appInfo.bindAppIndex, 1001);
}

/**
 * @tc.name: DlpPermissionStaticTest002
 * @tc.desc: InstallDlpSandboxExecute test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, DlpPermissionStaticTest002, TestSize.Level1)
{
    DlpSandboxInfo appInfo = {
        .uid = 1,
        .userId = 123,
        .bundleName = "testbundle1",
        .hasRead = false,
        .appIndex = -1,
        .bindAppIndex = 1001,
    };
    DLPFileAccess dlpFileAccess = DLPFileAccess::READ_ONLY;
    int32_t userId = 100;
    std::string bundleName = HIPREVIEW_HIGH;
    bool isNeedInstall = false;
    InputSandboxInfo inputSandboxInfo = {
        .bundleName = bundleName,
        .dlpFileAccess = dlpFileAccess,
        .userId = userId,
    };
    int32_t ret = InstallDlpSandboxExecute(isNeedInstall, inputSandboxInfo, appInfo);
    ASSERT_EQ(ret, DLP_OK);
}

/**
 * @tc.name: DlpPermissionStaticTest003
 * @tc.desc: GetSandboxExternalAuthorization test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, DlpPermissionStaticTest003, TestSize.Level1)
{
    DLP_LOG_DEBUG(LABEL, "DlpPermissionStaticTest003");

    int sandboxUid = -1;
    AAFwk::Want want;
    SandBoxExternalAuthorType authType;
    int32_t ret = dlpPermissionService_->GetSandboxExternalAuthorization(sandboxUid, want, authType);
    ASSERT_EQ(DLP_SERVICE_ERROR_VALUE_INVALID, ret);
    ASSERT_EQ(authType, SandBoxExternalAuthorType::DENY_START_ABILITY);
    sandboxUid = 0;
    ret = dlpPermissionService_->GetSandboxExternalAuthorization(sandboxUid, want, authType);
    want.SetBundle(HIPREVIEW_LOW);
    DlpSandboxInfo appInfo = {
        .uid = -1,
        .userId = 123,
        .bundleName = "testbundle1",
        .hasRead = false,
        .appIndex = -1,
        .bindAppIndex = 1001,
    };
    dlpPermissionService_->appStateObserver_->AddDlpSandboxInfo(appInfo);
    ret = dlpPermissionService_->GetSandboxExternalAuthorization(sandboxUid, want, authType);
    dlpPermissionService_->appStateObserver_->EraseDlpSandboxInfo(appInfo.uid);
    ASSERT_EQ(DLP_OK, ret);
    ASSERT_EQ(authType, SandBoxExternalAuthorType::ALLOW_START_ABILITY);
    appInfo.appIndex = 1001;
    dlpPermissionService_->appStateObserver_->AddDlpSandboxInfo(appInfo);
    ret = dlpPermissionService_->GetSandboxExternalAuthorization(sandboxUid, want, authType);
    dlpPermissionService_->appStateObserver_->EraseDlpSandboxInfo(appInfo.uid);
    ASSERT_EQ(DLP_OK, ret);
    ASSERT_EQ(authType, SandBoxExternalAuthorType::ALLOW_START_ABILITY);
    sandboxUid = 1;
    appInfo.uid = 1;
    dlpPermissionService_->appStateObserver_->AddDlpSandboxInfo(appInfo);
    ret = dlpPermissionService_->GetSandboxExternalAuthorization(sandboxUid, want, authType);
    dlpPermissionService_->appStateObserver_->EraseDlpSandboxInfo(appInfo.uid);
    ASSERT_EQ(DLP_OK, ret);
    ASSERT_EQ(authType, SandBoxExternalAuthorType::ALLOW_START_ABILITY);
}
/**
 * @tc.name: DlpPermissionStaticTest004
 * @tc.desc: GetPixelmapFromFd test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, DlpPermissionStaticTest004, TestSize.Level1)
{
    WaterMarkInfo waterMarkInfo;
    int32_t ret = GetPixelmapFromFd(waterMarkInfo);
    ASSERT_EQ(ret, DLP_IPC_CALLBACK_ERROR);
    waterMarkInfo.waterMarkFd = 0;
    ret = GetPixelmapFromFd(waterMarkInfo);
    ASSERT_NE(ret, DLP_OK);
}

/**
 * @tc.name: DlpPermissionStaticTest005
 * @tc.desc: SetWatermarkToRS test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, DlpPermissionStaticTest005, TestSize.Level1)
{
    std::string name = "";
    WaterMarkInfo waterMarkInfo;
    int32_t ret = SetWatermarkToRS(waterMarkInfo.maskInfo, waterMarkInfo.waterMarkImg);
    ASSERT_NE(ret, DLP_OK);
}

/**
 * @tc.name: DlpPermissionStaticTest006
 * @tc.desc: FillDlpSandboxInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, DlpPermissionStaticTest006, TestSize.Level1)
{
    DlpSandboxInfo appInfo = {
        .uid = 1,
        .userId = 123,
        .bundleName = "testbundle1",
        .hasRead = false,
        .appIndex = -1,
        .bindAppIndex = 1001,
    };
    FillDlpSandboxInfo(appInfo, appInfo.bundleName,
        appInfo.dlpFileAccess, appInfo.userId, "");
    ASSERT_EQ(appInfo.uri, "");
}

/**
 * @tc.name: DlpPermissionStaticTest007
 * @tc.desc: ClearKvStorage test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, DlpPermissionStaticTest007, TestSize.Level1)
{
    bool ret = true;
    ClearKvStorage();
    ASSERT_NE(ret, false);
}

/**
 * @tc.name: DlpPermissionStaticTest008
 * @tc.desc: GetApplicationInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, DlpPermissionStaticTest008, TestSize.Level1)
{
    AppExecFwk::ApplicationInfo applicationInfo;
    std::string appId = "";
    bool ret = GetApplicationInfo(appId, applicationInfo);
    ASSERT_EQ(ret, false);
    appId = "dlp_dlp";
    ret = GetApplicationInfo(appId, applicationInfo);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: FindMatchingSandboxTest001
 * @tc.desc: FindMatchingSandbox test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, FindMatchingSandboxTest001, TestSize.Level1)
{
    RetentionSandBoxInfo info;
    GetAppIndexParams params;
    params.isReadOnly = false;
    bool ret = FindMatchingSandbox(info, params);
    ASSERT_EQ(ret, false);
    params.isReadOnly = true;
    params.isNotOwnerAndReadOnce = true;
    ret = FindMatchingSandbox(info, params);
    ASSERT_EQ(ret, false);
    params.isNotOwnerAndReadOnce = false;
    info.isReadOnce_ = true;
    ret = FindMatchingSandbox(info, params);
    ASSERT_EQ(ret, false);
    info.isReadOnce_ = false;
    info.dlpFileAccess_ = DLPFileAccess::NO_PERMISSION;
    ret = FindMatchingSandbox(info, params);
    ASSERT_EQ(ret, false);
    info.dlpFileAccess_ = DLPFileAccess::READ_ONLY;
    ret = FindMatchingSandbox(info, params);
    ASSERT_EQ(ret, true);
    
    GetAppIndexParams params_sub = {"", params.isReadOnly, "uri", params.isNotOwnerAndReadOnce};
    info.isReadOnce_ = false;
    info.docUriSet_.insert(params.uri);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: CheckAllowAbilityListTest001
 * @tc.desc: CheckAllowAbilityList test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, CheckAllowAbilityListTest001, TestSize.Level1)
{
    AAFwk::Want want;
    bool ret = CheckAllowAbilityList(want);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: CalcAtomicSandboxType001
 * @tc.desc: print && networkAndSelinux -> CONTENT_EDIT (2)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, CalcAtomicSandboxType001, TestSize.Level1)
{
    uint32_t access = 0x10 | 0x20;
    EXPECT_EQ(CalcAtomicSandboxType(access), 2);
}

/**
 * @tc.name: CalcAtomicSandboxType002
 * @tc.desc: !print && networkAndSelinux -> READ_ONLY (1)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, CalcAtomicSandboxType002, TestSize.Level1)
{
    uint32_t access = 0x20;
    EXPECT_EQ(CalcAtomicSandboxType(access), 1);
}

/**
 * @tc.name: CalcAtomicSandboxType003
 * @tc.desc: print && !networkAndSelinux -> RESTRICTED_CONTENT_EDIT (5)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, CalcAtomicSandboxType003, TestSize.Level1)
{
    uint32_t access = 0x10;
    EXPECT_EQ(CalcAtomicSandboxType(access), 5);
}

/**
 * @tc.name: CalcAtomicSandboxType004
 * @tc.desc: !print && !networkAndSelinux -> RESTRICTED_READ_ONLY (6)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, CalcAtomicSandboxType004, TestSize.Level1)
{
    uint32_t access = 0x01;
    EXPECT_EQ(CalcAtomicSandboxType(access), 6);
}

/**
 * @tc.name: CalcAtomicSandboxParams001
 * @tc.desc: ATOMIC_CONTROL with edit bit -> isReadOnly=false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, CalcAtomicSandboxParams001, TestSize.Level1)
{
    InputSandboxInfo input = {
        .bundleName = "test",
        .dlpFileAccess = DLPFileAccess::ATOMIC_CONTROL,
        .userId = 100,
        .uri = "uri",
        .path = "path",
        .atomicDlpFileAccess = 0x02,
    };
    int32_t sandboxType = -1;
    bool isReadOnly = true;
    CalcAtomicSandboxParams(input, sandboxType, isReadOnly);
    EXPECT_FALSE(isReadOnly);
    EXPECT_EQ(sandboxType, CalcAtomicSandboxType(0x02));
}

/**
 * @tc.name: CalcAtomicSandboxParams002
 * @tc.desc: ATOMIC_CONTROL without edit bit -> isReadOnly=true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, CalcAtomicSandboxParams002, TestSize.Level1)
{
    InputSandboxInfo input = {
        .bundleName = "test",
        .dlpFileAccess = DLPFileAccess::ATOMIC_CONTROL,
        .userId = 100,
        .uri = "uri",
        .path = "path",
        .atomicDlpFileAccess = 0x01,
    };
    int32_t sandboxType = -1;
    bool isReadOnly = false;
    CalcAtomicSandboxParams(input, sandboxType, isReadOnly);
    EXPECT_TRUE(isReadOnly);
}

/**
 * @tc.name: CalcAtomicSandboxParams003
 * @tc.desc: READ_ONLY (non-ATOMIC) -> isReadOnly=true, sandboxType=-1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, CalcAtomicSandboxParams003, TestSize.Level1)
{
    InputSandboxInfo input = {
        .bundleName = "test",
        .dlpFileAccess = DLPFileAccess::READ_ONLY,
        .userId = 100,
        .uri = "uri",
        .path = "path",
        .atomicDlpFileAccess = 0,
    };
    int32_t sandboxType = -1;
    bool isReadOnly = false;
    CalcAtomicSandboxParams(input, sandboxType, isReadOnly);
    EXPECT_TRUE(isReadOnly);
    EXPECT_EQ(sandboxType, -1);
}

/**
 * @tc.name: CalcAtomicSandboxParams004
 * @tc.desc: FULL_CONTROL (non-ATOMIC) -> isReadOnly=false, sandboxType=-1
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, CalcAtomicSandboxParams004, TestSize.Level1)
{
    InputSandboxInfo input = {
        .bundleName = "test",
        .dlpFileAccess = DLPFileAccess::FULL_CONTROL,
        .userId = 100,
        .uri = "uri",
        .path = "path",
        .atomicDlpFileAccess = 0,
    };
    int32_t sandboxType = -1;
    bool isReadOnly = true;
    CalcAtomicSandboxParams(input, sandboxType, isReadOnly);
    EXPECT_FALSE(isReadOnly);
    EXPECT_EQ(sandboxType, -1);
}

/**
 * @tc.name: GetDlpActionFlagAtomic001
 * @tc.desc: ATOMIC_CONTROL with all bits set has expected flags
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, GetDlpActionFlagAtomic001, TestSize.Level1)
{
    uint32_t atomic = 0x01 | 0x02 | 0x04 | 0x08 | 0x10;
    ActionFlags flags = GetDlpActionFlag(DLPFileAccess::ATOMIC_CONTROL, atomic);
    EXPECT_NE(flags, ACTION_INVALID);
}

/**
 * @tc.name: GetDlpActionFlagAtomic002
 * @tc.desc: ATOMIC_CONTROL with no bits set returns ACTION_INVALID
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, GetDlpActionFlagAtomic002, TestSize.Level1)
{
    ActionFlags flags = GetDlpActionFlag(DLPFileAccess::ATOMIC_CONTROL, 0);
    EXPECT_EQ(flags, ACTION_INVALID);
}

/**
 * @tc.name: GetDlpActionFlagAtomic003
 * @tc.desc: ATOMIC_CONTROL with only read bit has ACTION_VIEW
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, GetDlpActionFlagAtomic003, TestSize.Level1)
{
    ActionFlags flags = GetDlpActionFlag(DLPFileAccess::ATOMIC_CONTROL, 0x01);
    EXPECT_NE(static_cast<int32_t>(flags) & static_cast<int32_t>(ACTION_VIEW), 0);
}

/**
 * @tc.name: GetDlpActionFlagAtomic004
 * @tc.desc: ATOMIC_CONTROL with only edit bit has ACTION_EDIT and ACTION_VIEW
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, GetDlpActionFlagAtomic004, TestSize.Level1)
{
    ActionFlags flags = GetDlpActionFlag(DLPFileAccess::ATOMIC_CONTROL, 0x02);
    int32_t val = static_cast<int32_t>(flags);
    EXPECT_NE(val & static_cast<int32_t>(ACTION_VIEW), 0);
    EXPECT_NE(val & static_cast<int32_t>(ACTION_EDIT), 0);
    EXPECT_NE(val & static_cast<int32_t>(ACTION_SAVE), 0);
}

/**
 * @tc.name: FindMatchingSandboxAtomic001
 * @tc.desc: FindMatchingSandbox checks dlpFileAccess match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, FindMatchingSandboxAtomic001, TestSize.Level1)
{
    RetentionSandBoxInfo info;
    info.isReadOnce_ = false;
    info.dlpFileAccess_ = DLPFileAccess::ATOMIC_CONTROL;
    info.docUriSet_.insert("test_uri");
    GetAppIndexParams params = {
        .bundleName = "",
        .isReadOnly = false,
        .uri = "test_uri",
        .isNotOwnerAndReadOnce = false,
        .dlpFileAccess = DLPFileAccess::ATOMIC_CONTROL,
    };
    bool ret = FindMatchingSandbox(info, params);
    EXPECT_TRUE(ret);
}

/**
 * @tc.name: FindMatchingSandboxAtomic002
 * @tc.desc: FindMatchingSandbox returns false when dlpFileAccess mismatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, FindMatchingSandboxAtomic002, TestSize.Level1)
{
    RetentionSandBoxInfo info;
    info.isReadOnce_ = false;
    info.dlpFileAccess_ = DLPFileAccess::READ_ONLY;
    info.docUriSet_.insert("test_uri2");
    GetAppIndexParams params = {
        .bundleName = "",
        .isReadOnly = false,
        .uri = "test_uri2",
        .isNotOwnerAndReadOnce = false,
        .dlpFileAccess = DLPFileAccess::ATOMIC_CONTROL,
    };
    bool ret = FindMatchingSandbox(info, params);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: CheckWithInstallDlpSandboxAtomic001
 * @tc.desc: ATOMIC_CONTROL passes validation in CheckWithInstallDlpSandbox
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, CheckWithInstallDlpSandboxAtomic001, TestSize.Level1)
{
    int32_t ret = CheckWithInstallDlpSandbox("bundle", "uri", DLPFileAccess::ATOMIC_CONTROL);
    EXPECT_EQ(ret, DLP_OK);
}

/**
 * @tc.name: CheckWithInstallDlpSandboxAtomic002
 * @tc.desc: perm > ATOMIC_CONTROL fails validation
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpPermissionStaticTest, CheckWithInstallDlpSandboxAtomic002, TestSize.Level1)
{
    int32_t ret = CheckWithInstallDlpSandbox("bundle", "uri", static_cast<DLPFileAccess>(5));
    EXPECT_EQ(ret, DLP_SERVICE_ERROR_VALUE_INVALID);
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS