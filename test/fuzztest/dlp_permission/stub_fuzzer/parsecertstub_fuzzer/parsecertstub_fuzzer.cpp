/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "parsecertstub_fuzzer.h"
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include "accesstoken_kit.h"
#include "dlp_permission.h"
#include "dlp_permission_async_stub.h"
#include "dlp_permission_kit.h"
#include "dlp_permission_log.h"
#include "idlp_permission_service.h"
#include "hex_string.h"
#include "securec.h"
#include "token_setproc.h"

using namespace OHOS::Security::DlpPermission;
using namespace OHOS::Security::AccessToken;
using Json = nlohmann::json;
namespace OHOS {
const std::string ENC_DATA_LEN = "encDataLen";
const std::string ENC_DATA = "encData";
const std::string ENC_ACCOUNT_TYPE = "accountType";
constexpr int BYTE_TO_HEX_OPER_LENGTH = 2;
const uint32_t BUFFER_LENGTH = 30;
const std::string DLP_MANAGER_BUNDLE_NAME = "com.ohos.dlpmanager_";
static constexpr int32_t SA_ID_DLP_PERMISSION_SERVICE = 3521;

static void InitCertJson(const uint8_t* data, size_t size, Json &certJson)
{
    certJson[ENC_DATA_LEN] = size;
    char hexStrBuffer[64] = {0};
    uint8_t byteBuffer[30] = {0};
    for (uint32_t i = 0; i < BUFFER_LENGTH; i++) {
        byteBuffer[i] = *(reinterpret_cast<const uint8_t*>(data + i));
    }
    int res = ByteToHexString(byteBuffer, sizeof(byteBuffer), hexStrBuffer, sizeof(hexStrBuffer));
    if (res != DLP_OK) {
        return;
    }
    certJson[ENC_DATA] = hexStrBuffer;
    certJson[ENC_ACCOUNT_TYPE] = AccountType::CLOUD_ACCOUNT;
}

static void FuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < BUFFER_LENGTH)) {
        return;
    }
    MessageParcel datas;
    if (!datas.WriteInterfaceToken(DlpPermissionServiceStub::GetDescriptor())) {
        return;
    }
    Json certJson;
    InitCertJson(data, size, certJson);
    std::string certStr = certJson.dump();
    sptr<CertParcel> certParcel = new (std::nothrow) CertParcel();
    std::vector<uint8_t> cert;
    cert.assign(certStr.begin(), certStr.end());
    certParcel->cert = cert;
    if (!datas.WriteParcelable(certParcel)) {
        return;
    }
    std::shared_ptr<ParseDlpCertificateCallback> callback = std::make_shared<ClientParseDlpCertificateCallback>();
    sptr<IDlpPermissionCallback> asyncStub = new (std::nothrow) DlpPermissionAsyncStub(callback);
    if (!datas.WriteRemoteObject(asyncStub->AsObject())) {
        return;
    }
    std::string appId(reinterpret_cast<const char*>(data + BUFFER_LENGTH), size - BUFFER_LENGTH);
    if (!datas.WriteString(DLP_MANAGER_BUNDLE_NAME + appId)) {
        return;
    }
    uint32_t flag = 0;
    if (!datas.WriteUint32(flag)) {
        return;
    }
    uint32_t code = static_cast<uint32_t>(IDlpPermissionServiceIpcCode::COMMAND_PARSE_DLP_CERTIFICATE);
    MessageParcel reply;
    MessageOption option;
    auto service = std::make_shared<DlpPermissionService>(SA_ID_DLP_PERMISSION_SERVICE, true);
    service->appStateObserver_ = new (std::nothrow) AppStateObserver();
    service->OnRemoteRequest(code, datas, reply, option);
}

bool ParseCertFuzzTest(const uint8_t* data, size_t size)
{
    FuzzTest(data, size);
    return true;
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    AccessTokenID tokenId = AccessTokenKit::GetHapTokenID(100, "com.ohos.dlpmanager", 0); // user_id = 100
    SetSelfTokenID(tokenId);
    return 0;
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::ParseCertFuzzTest(data, size);
    return 0;
}
