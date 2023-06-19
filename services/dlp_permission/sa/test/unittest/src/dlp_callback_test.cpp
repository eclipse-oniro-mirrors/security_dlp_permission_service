/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#define  private public
#include "dlp_sandbox_change_callback_manager.h"
#undef private
#include "dlp_callback_test.h"
#include "dlp_permission_log.h"
#include "dlp_permission.h"
#include "iremote_broker.h"
#include <string>

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::Security::DlpPermission;

namespace {
    static const uint32_t MAX_CALLBACK_SIZE = 1024;
}

void DlpCallbackTest::SetUpTestCase() {}

void DlpCallbackTest::TearDownTestCase() {}

void DlpCallbackTest::SetUp() {}

void DlpCallbackTest::TearDown() {}

class DlpTestRemoteObj : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.dlp.test");

    DlpTestRemoteObj() = default;
    virtual ~DlpTestRemoteObj() noexcept = default;
};
/**
 * @tc.name: DlpCallbackTest001
 * @tc.desc: DlpSandboxChangeCallbackProxy test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, DlpSandboxChangeCallbackProxy001, TestSize.Level1)
{
    sptr<DlpTestRemoteObj> callback = new (std::nothrow)IRemoteStub<DlpTestRemoteObj>();
    EXPECT_TRUE(callback != nullptr);

    auto proxy = std::make_shared<DlpSandboxChangeCallbackProxy>(callback->AsObject());
    DlpSandboxCallbackInfo input;
    proxy->DlpSandboxStateChangeCallback(input);
    EXPECT_EQ(true, (callback != nullptr));
}

class DlpSandboxChangeCallbackTest : public DlpSandboxChangeCallbackStub {
public:
    DlpSandboxChangeCallbackTest() = default;
    ~DlpSandboxChangeCallbackTest() override;

    void DlpSandboxStateChangeCallback(DlpSandboxCallbackInfo &result) override;
};

/**
 * @tc.name: DlpCallbackTest001
 * @tc.desc: DlpSandboxChangeCallbackManager test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DlpCallbackTest, CallbackManager002, TestSize.Level1)
{
    int32_t res = DlpSandboxChangeCallbackManager::GetInstance().AddCallback(0, nullptr);
    EXPECT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);

    sptr<DlpSandboxChangeCallbackTest> callback = new (std::nothrow) DlpSandboxChangeCallbackTest();
    EXPECT_TRUE(callback != nullptr);

    for (uint32_t index = 0; index <= MAX_CALLBACK_SIZE; ++index) {
        DlpSandboxChangeCallbackRecord recordInstance;
        recordInstance.callbackObject_ = callback->AsObject();
        recordInstance.pid = index;
        DlpSandboxChangeCallbackManager::GetInstance().callbackInfoMap_.
            insert(std::pair<int32_t, DlpSandboxChangeCallbackRecord>(index, recordInstance));
    }
    res = DlpSandboxChangeCallbackManager::GetInstance().AddCallback(0, callback->AsObject());
    EXPECT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);
    res = DlpSandboxChangeCallbackManager::GetInstance().RemoveCallback(nullptr);
    EXPECT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);
    DlpSandboxInfo dlpSandboxInfo;
    dlpSandboxInfo.pid = MAX_CALLBACK_SIZE + 1;
    DlpSandboxChangeCallbackManager::GetInstance().ExecuteCallbackAsync(dlpSandboxInfo);
    dlpSandboxInfo.pid = 1;
    DlpSandboxChangeCallbackManager::GetInstance().ExecuteCallbackAsync(dlpSandboxInfo);
    bool result = false;
    res = DlpSandboxChangeCallbackManager::GetInstance().RemoveCallback(0, result);
    EXPECT_EQ(res, DLP_SERVICE_ERROR_VALUE_INVALID);
    for (auto it = DlpSandboxChangeCallbackManager::GetInstance().callbackInfoMap_.begin();
        it != DlpSandboxChangeCallbackManager::GetInstance().callbackInfoMap_.end(); ++it) {
        it->second.callbackObject_ = nullptr;
        DlpSandboxChangeCallbackManager::GetInstance().callbackInfoMap_.erase(it);
    }
}
