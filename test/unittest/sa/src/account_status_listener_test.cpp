/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "account_status_listener_test.h"
#include <gtest/gtest.h>
#include "account_status_listener.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;

namespace {
static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "AccountStatusListenerTest"};
static uint32_t g_cntRegister = 0;
static uint32_t g_cntUnregister = 0;
}

void AccountStatusListenerTest::SetUpTestCase() {}

void AccountStatusListenerTest::TearDownTestCase() {}

void AccountStatusListenerTest::SetUp()
{
    g_cntRegister = 0;
    g_cntUnregister = 0;
    UnRegisterAccountMonitor();
}

void AccountStatusListenerTest::TearDown()
{
    UnRegisterAccountMonitor();
}

static void RegisterAccount()
{
    g_cntRegister++;
    return;
}

static void UnregisterAccount()
{
    g_cntUnregister++;
    return;
}

/**
 * @tc.name: RegisterAccountEventMonitor001
 * @tc.desc: RegisterAccountEventMonitor with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStatusListenerTest, RegisterAccountEventMonitor001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "RegisterAccountEventMonitor001");

    int32_t res = RegisterAccountEventMonitor(nullptr);
    EXPECT_EQ(DLP_ERROR, res);
}

/**
 * @tc.name: RegisterAccountEventMonitor002
 * @tc.desc: RegisterAccountEventMonitor with valid callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStatusListenerTest, RegisterAccountEventMonitor002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "RegisterAccountEventMonitor002");

    AccountListenerCallback callback;
    callback.registerAccount = RegisterAccount;
    callback.unregisterAccount = UnregisterAccount;
    int32_t res = RegisterAccountEventMonitor(&callback);
    if (res != DLP_SUCCESS) {
        ASSERT_EQ(DLP_ERROR, res);
        return;
    }
    ASSERT_EQ(DLP_SUCCESS, res);
}

/**
 * @tc.name: RegisterAccountEventMonitor003
 * @tc.desc: RegisterAccountEventMonitor already registered returns DLP_SUCCESS
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStatusListenerTest, RegisterAccountEventMonitor003, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "RegisterAccountEventMonitor003");

    AccountListenerCallback callback;
    callback.registerAccount = RegisterAccount;
    callback.unregisterAccount = UnregisterAccount;
    int32_t res = RegisterAccountEventMonitor(&callback);
    if (res != DLP_SUCCESS) {
        ASSERT_EQ(DLP_ERROR, res);
        return;
    }
    ASSERT_EQ(DLP_SUCCESS, res);
    int32_t res2 = RegisterAccountEventMonitor(&callback);
    EXPECT_EQ(DLP_SUCCESS, res2);
}

/**
 * @tc.name: UnRegisterAccountMonitor002
 * @tc.desc: UnRegisterAccountMonitor after successful registration
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStatusListenerTest, UnRegisterAccountMonitor002, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "UnRegisterAccountMonitor002");

    AccountListenerCallback callback;
    callback.registerAccount = RegisterAccount;
    callback.unregisterAccount = UnregisterAccount;
    int32_t res = RegisterAccountEventMonitor(&callback);
    if (res != DLP_SUCCESS) {
        ASSERT_EQ(DLP_ERROR, res);
        return;
    }
    ASSERT_EQ(DLP_SUCCESS, res);
    UnRegisterAccountMonitor();
    int32_t res2 = RegisterAccountEventMonitor(&callback);
    if (res2 != DLP_SUCCESS) {
        ASSERT_EQ(DLP_ERROR, res2);
    } else {
        ASSERT_EQ(DLP_SUCCESS, res2);
    }
    UnRegisterAccountMonitor();
}

/**
 * @tc.name: RegisterAndUnRegisterFlow001
 * @tc.desc: Register and unregister then register again flow
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AccountStatusListenerTest, RegisterAndUnRegisterFlow001, TestSize.Level1)
{
    DLP_LOG_INFO(LABEL, "RegisterAndUnRegisterFlow001");

    AccountListenerCallback callback;
    callback.registerAccount = RegisterAccount;
    callback.unregisterAccount = UnregisterAccount;
    int32_t res = RegisterAccountEventMonitor(&callback);
    if (res != DLP_SUCCESS) {
        ASSERT_EQ(DLP_ERROR, res);
        return;
    }
    ASSERT_EQ(DLP_SUCCESS, res);
    UnRegisterAccountMonitor();
    int32_t res2 = RegisterAccountEventMonitor(&callback);
    if (res2 != DLP_SUCCESS) {
        ASSERT_EQ(DLP_ERROR, res2);
    } else {
        ASSERT_EQ(DLP_SUCCESS, res2);
    }
}
