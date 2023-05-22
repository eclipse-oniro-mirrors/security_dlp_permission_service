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

#include "dlp_permission_serializer.h"
#include "dlp_permission.h"
#include "dlp_permission_log.h"
#include "dlp_policy.h"
#include "hex_string.h"
#include "securec.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
const std::string KIA_INDEX = "KIA";
const std::string OWNER_ACCOUNT_NAME = "ownerAccountName";
const std::string OWNER_ACCOUNT_ID = "ownerAccountId";
const std::string VERSION_INDEX = "version";
const std::string PERM_EXPIRY_TIME = "expireTime";
const std::string ACCOUNT_INDEX = "account";
const std::string AESKEY = "filekey";
const std::string AESKEY_LEN = "filekeyLen";
const std::string IV = "iv";
const std::string IV_LEN = "ivLen";
const std::string ENC_DATA_LEN = "encDataLen";
const std::string ENC_DATA = "encData";
const std::string EXTRA_INFO_LEN = "extraInfoLen";
const std::string EXTRA_INFO = "extraInfo";
const std::string ENC_ACCOUNT_TYPE = "accountType";
const std::string ONLINE_POLICY_CONTENT = "plaintextPolicy";
const std::string NEED_ONLINE = "needOnline";
const std::string FILE_INDEX = "file";
const std::string POLICY_INDEX = "policy";
const std::string READ_INDEX = "read";
const std::string EDIT_INDEX = "edit";
const std::string FC_INDEX = "fullCtrl";
const std::string RIGHT_INDEX = "right";
const std::string ENC_POLICY_INDEX = "encPolicy";

#define VALID_TIME_STAMP (2147483647)


static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {
    LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpPermissionSerializer"};
}  // namespace

DlpPermissionSerializer& DlpPermissionSerializer::GetInstance()
{
    static DlpPermissionSerializer instance;
    return instance;
}

static int32_t ReadUint8ArrayFromJson(const nlohmann::json& permJson, uint8_t** buff, uint32_t& buffLen,
    const std::string& keyName, const std::string& lenName)
{
    if (!lenName.empty() && permJson.find(lenName) != permJson.end() && permJson.at(lenName).is_number()) {
        permJson.at(lenName).get_to(buffLen);
    }

    if (permJson.find(keyName) != permJson.end() && permJson.at(keyName).is_string()) {
        std::string tmp = permJson.at(keyName).get<std::string>();

        uint32_t length = tmp.size() / BYTE_TO_HEX_OPER_LENGTH;
        if (length != buffLen) {
            buffLen = length;
        }
        *buff = new (std::nothrow) uint8_t[length];
        if (*buff == nullptr) {
            DLP_LOG_ERROR(LABEL, "New memory fail");
            return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
        }
        int32_t res = HexStringToByte(tmp.c_str(), *buff, length);
        if (res != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "Hexstring to byte fail");
            memset_s(*buff, length, 0, length);
            delete[] *buff;
            *buff = nullptr;
        }

        return res;
    }
    return DLP_OK;
}

static void TransHexStringToByte(std::string& outer, const std::string& input)
{
    uint32_t len = input.size() / BYTE_TO_HEX_OPER_LENGTH;
    uint8_t* buff = new (std::nothrow) uint8_t[len];
    if (buff == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return;
    }

    int32_t res = HexStringToByte(input.c_str(), buff, len);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Hexstring to byte fail");
        (void)memset_s(buff, len, 0, len);
        delete[] buff;
        buff = nullptr;
        return;
    }

    outer = reinterpret_cast<char *>(buff);
    (void)memset_s(buff, len, 0, len);
    delete[] buff;
}

void DlpPermissionSerializer::SerializeAuthUserInfo(nlohmann::json& authUsersJson,
    const AuthUserInfo& userInfo)
{
    bool read = false;
    bool edit = false;
    bool fullCtrl = false;

    switch (userInfo.authPerm) {
        case READ_ONLY: {
            read = true;
            break;
        }
        case EDIT_ONLY: {
            edit = true;
            break;
        }
        case FULL_CONTROL: {
            read = true;
            edit = true;
            fullCtrl = true;
            break;
        }
        default:
            break;
    }

    nlohmann::json rightInfoJson;
    rightInfoJson[READ_INDEX] = read;
    rightInfoJson[EDIT_INDEX] = edit;
    rightInfoJson[FC_INDEX] = fullCtrl;
    nlohmann::json accountRight;
    accountRight[RIGHT_INDEX] = rightInfoJson;
    authUsersJson[userInfo.authAccount.c_str()] = accountRight;
    return;
}

int32_t DlpPermissionSerializer::DeserializeAuthUserInfo(const nlohmann::json& accountInfoJson,
    AuthUserInfo& userInfo)
{
    nlohmann::json rightInfoJson;
    if (accountInfoJson.find(RIGHT_INDEX) != accountInfoJson.end() && accountInfoJson.at(RIGHT_INDEX).is_object()) {
        accountInfoJson.at(RIGHT_INDEX).get_to(rightInfoJson);
    }

    bool read = false;
    bool edit = false;
    bool fullCtrl = false;

    if (rightInfoJson.find(READ_INDEX) != rightInfoJson.end() && rightInfoJson.at(READ_INDEX).is_boolean()) {
        rightInfoJson.at(READ_INDEX).get_to(read);
    }

    if (rightInfoJson.find(EDIT_INDEX) != rightInfoJson.end() && rightInfoJson.at(EDIT_INDEX).is_boolean()) {
        rightInfoJson.at(EDIT_INDEX).get_to(edit);
    }

    if (rightInfoJson.find(FC_INDEX) != rightInfoJson.end() && rightInfoJson.at(FC_INDEX).is_boolean()) {
        rightInfoJson.at(FC_INDEX).get_to(fullCtrl);
    }

    if (fullCtrl) {
        userInfo.authPerm = FULL_CONTROL;
    } else if (edit) {
        userInfo.authPerm = EDIT_ONLY;
    } else {
        userInfo.authPerm = READ_ONLY;
    }

    userInfo.permExpiryTime = VALID_TIME_STAMP;
    userInfo.authAccountType = CLOUD_ACCOUNT;

    return DLP_OK;
}

nlohmann::json DlpPermissionSerializer::SerializeAuthUserList(const std::vector<AuthUserInfo>& authUsers)
{
    nlohmann::json authUsersJson;
    for (auto it = authUsers.begin(); it != authUsers.end(); ++it) {
        SerializeAuthUserInfo(authUsersJson, *it);
    }
    return authUsersJson;
}

int32_t DlpPermissionSerializer::DeserializeAuthUserList(
    const nlohmann::json& authUsersJson, std::vector<AuthUserInfo>& userList)
{
    for (auto iter = authUsersJson.begin(); iter != authUsersJson.end(); ++iter) {
        AuthUserInfo authInfo;
        std::string name = iter.key();
        authInfo.authAccount = name;
        nlohmann::json accountInfo = iter.value();
        int32_t res = DeserializeAuthUserInfo(accountInfo, authInfo);
        if (res == DLP_OK) {
            userList.emplace_back(authInfo);
        } else {
            userList.clear();
            return res;
        }
    }
    return DLP_OK;
}

int32_t DlpPermissionSerializer::SerializeDlpPermission(const PermissionPolicy& policy, nlohmann::json& permInfoJson)
{
    nlohmann::json authUsersJson = SerializeAuthUserList(policy.authUsers_);

    uint32_t keyHexLen = policy.GetAeskeyLen() * BYTE_TO_HEX_OPER_LENGTH + 1;
    char* keyHex = new (std::nothrow) char[keyHexLen];
    if (keyHex == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    int32_t res = ByteToHexString(policy.GetAeskey(), policy.GetAeskeyLen(), keyHex, keyHexLen);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Byte to hexstring fail");
        FreeCharBuffer(keyHex, keyHexLen);
        return res;
    }

    uint32_t ivHexLen = policy.GetIvLen() * BYTE_TO_HEX_OPER_LENGTH + 1;
    char* ivHex = new (std::nothrow) char[ivHexLen];
    if (ivHex == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    res = ByteToHexString(policy.GetIv(), policy.GetIvLen(), ivHex, ivHexLen);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Byte to hexstring fail");
        FreeCharBuffer(keyHex, keyHexLen);
        FreeCharBuffer(ivHex, ivHexLen);
        return res;
    }

    nlohmann::json policyJson;
    policyJson[KIA_INDEX] = "";
    policyJson[OWNER_ACCOUNT_NAME] = policy.ownerAccount_;
    policyJson[OWNER_ACCOUNT_ID] = policy.ownerAccount_;
    policyJson[VERSION_INDEX] = 1;
    policyJson[PERM_EXPIRY_TIME] = 0;
    policyJson[NEED_ONLINE] = 0;
    policyJson[ACCOUNT_INDEX] = authUsersJson;

    nlohmann::json fileEnc;
    fileEnc[AESKEY] = keyHex;
    fileEnc[AESKEY_LEN] = policy.GetAeskeyLen();
    fileEnc[IV] = ivHex;
    fileEnc[IV_LEN] = policy.GetIvLen();

    permInfoJson[FILE_INDEX] = fileEnc;
    permInfoJson[POLICY_INDEX] = policyJson;

    DLP_LOG_INFO(LABEL, "Serialize successfully!");
    FreeCharBuffer(keyHex, keyHexLen);
    FreeCharBuffer(ivHex, ivHexLen);
    return DLP_OK;
}

static void GetPolicyJson(const nlohmann::json& permJson, nlohmann::json& plainPolicyJson)
{
    if (permJson.find(ONLINE_POLICY_CONTENT) != permJson.end() && permJson.at(ONLINE_POLICY_CONTENT).is_string()) {
        std::string plainHexPolicy;
        permJson.at(ONLINE_POLICY_CONTENT).get_to(plainHexPolicy);
        std::string plainPolicy;
        TransHexStringToByte(plainPolicy, plainHexPolicy);
        plainPolicyJson = nlohmann::json::parse(plainPolicy);
        if (plainPolicyJson.is_discarded() || (!plainPolicyJson.is_object())) {
            DLP_LOG_ERROR(LABEL, "JsonObj is discarded");
            return;
        }
    } else {
        plainPolicyJson = permJson;
    }
}

int32_t DlpPermissionSerializer::DeserializeDlpPermission(const nlohmann::json& permJson, PermissionPolicy& policy)
{
    nlohmann::json plainPolicyJson;
    GetPolicyJson(permJson, plainPolicyJson);

    nlohmann::json policyJson;
    if (plainPolicyJson.find(POLICY_INDEX) != plainPolicyJson.end() && plainPolicyJson.at(POLICY_INDEX).is_object()) {
        plainPolicyJson.at(POLICY_INDEX).get_to(policyJson);
    }

    nlohmann::json accountListJson;
    if (policyJson.find(ACCOUNT_INDEX) != policyJson.end() && policyJson.at(ACCOUNT_INDEX).is_object()) {
        policyJson.at(ACCOUNT_INDEX).get_to(accountListJson);
    }

    std::vector<AuthUserInfo> userList;
    int32_t res = DeserializeAuthUserList(accountListJson, userList);
    if (res == DLP_OK) {
        policy.authUsers_ = userList;
    } else {
        return res;
    }

    if (policyJson.find(OWNER_ACCOUNT_NAME) != policyJson.end() && policyJson.at(OWNER_ACCOUNT_NAME).is_string()) {
        policyJson.at(OWNER_ACCOUNT_NAME).get_to(policy.ownerAccount_);
    }

    policy.ownerAccountType_ = CLOUD_ACCOUNT;

    nlohmann::json fileEncJson;
    if (plainPolicyJson.find(FILE_INDEX) != plainPolicyJson.end() && plainPolicyJson.at(FILE_INDEX).is_object()) {
        plainPolicyJson.at(FILE_INDEX).get_to(fileEncJson);
    }

    uint8_t* key = nullptr;
    uint32_t keyLen = 0;
    res = ReadUint8ArrayFromJson(fileEncJson, &key, keyLen, AESKEY, AESKEY_LEN);
    if (res != DLP_OK) {
        return res;
    }
    policy.SetAeskey(key, keyLen);
    delete[] key;
    key = nullptr;

    uint8_t* iv = nullptr;
    uint32_t ivLen = 0;
    res = ReadUint8ArrayFromJson(fileEncJson, &iv, ivLen, "iv", "ivLen");
    if (res != DLP_OK) {
        return res;
    }
    policy.SetIv(iv, ivLen);

    delete[] iv;
    iv = nullptr;

    return DLP_OK;
}

int32_t DlpPermissionSerializer::SerializeEncPolicyData(const DLP_EncPolicyData& encData, nlohmann::json& encDataJson)
{
    if (encData.dataLen == 0 || encData.dataLen > DLP_MAX_CERT_SIZE) {
        DLP_LOG_ERROR(LABEL, "Cert lenth %{public}d is invalid", encData.dataLen);
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    if (encData.options.extraInfoLen == 0 || encData.options.extraInfoLen > DLP_MAX_EXTRA_INFO_LEN) {
        DLP_LOG_ERROR(LABEL, "Cert extra info lenth %{public}d is invalid", encData.options.extraInfoLen);
        return DLP_SERVICE_ERROR_VALUE_INVALID;
    }
    uint32_t encDataHexLen = encData.dataLen * BYTE_TO_HEX_OPER_LENGTH + 1;
    char* encDataHex = new (std::nothrow) char[encDataHexLen];
    if (encDataHex == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    int32_t res = ByteToHexString(encData.data, encData.dataLen, encDataHex, encDataHexLen);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Byte to hexstring fail");
        FreeCharBuffer(encDataHex, encDataHexLen);
        return res;
    }

    uint32_t extraInfoHexLen = encData.options.extraInfoLen * BYTE_TO_HEX_OPER_LENGTH + 1;
    char* extraInfoHex = new (std::nothrow) char[extraInfoHexLen];
    if (extraInfoHex == nullptr) {
        DLP_LOG_ERROR(LABEL, "New memory fail");
        FreeCharBuffer(encDataHex, encDataHexLen);
        return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
    }
    res = ByteToHexString(encData.options.extraInfo, encData.options.extraInfoLen, extraInfoHex, extraInfoHexLen);
    if (res != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Byte to hexstring fail");
        FreeCharBuffer(encDataHex, encDataHexLen);
        FreeCharBuffer(extraInfoHex, extraInfoHexLen);
        return res;
    }

    encDataJson = {
        {ENC_DATA_LEN, encData.dataLen},
        {ENC_DATA, encDataHex},
        {EXTRA_INFO_LEN, encData.options.extraInfoLen},
        {EXTRA_INFO, extraInfoHex},
        {ENC_ACCOUNT_TYPE, encData.accountType},
    };
    DLP_LOG_INFO(LABEL, "Serialize successfully!");
    FreeCharBuffer(encDataHex, encDataHexLen);
    FreeCharBuffer(extraInfoHex, extraInfoHexLen);
    return DLP_OK;
}

int32_t DlpPermissionSerializer::DeserializeEncPolicyData(const nlohmann::json &encDataJson, DLP_EncPolicyData &encData,
    bool isOff)
{
    if (encDataJson.find(ENC_ACCOUNT_TYPE) != encDataJson.end() && encDataJson.at(ENC_ACCOUNT_TYPE).is_number()) {
        encDataJson.at(ENC_ACCOUNT_TYPE).get_to(encData.accountType);
    }

    if (isOff) {
        int32_t res = ReadUint8ArrayFromJson(encDataJson, &encData.data, encData.dataLen, ENC_POLICY_INDEX, "");
        if (res != DLP_OK) {
            return res;
        }

        res = ReadUint8ArrayFromJson(
            encDataJson, &encData.options.extraInfo, encData.options.extraInfoLen, EXTRA_INFO, "");
        if (res != DLP_OK) {
            return res;
        }
    } else {
        int32_t res = ReadUint8ArrayFromJson(encDataJson, &encData.data, encData.dataLen, ENC_DATA, ENC_DATA_LEN);
        if (res != DLP_OK) {
            return res;
        }

        res = ReadUint8ArrayFromJson(
            encDataJson, &encData.options.extraInfo, encData.options.extraInfoLen, EXTRA_INFO, EXTRA_INFO_LEN);
        if (res != DLP_OK) {
            return res;
        }
    }

    DLP_LOG_INFO(LABEL, "Deserialize successfully!");
    return DLP_OK;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
