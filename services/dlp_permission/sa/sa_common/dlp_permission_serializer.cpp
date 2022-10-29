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
const std::string OWNER_ACCOUNT = "ownerAccount";
const std::string OWNER_ACCOUNT_TYPE = "ownerAccountType";
const std::string AUTH_ACCOUNT = "authAccount";
const std::string AUTH_PERM = "authPerm";
const std::string PERM_EXPIRY_TIME = "permExpiryTime";
const std::string AUTH_ACCOUNT_TYPE = "authAccountType";
const std::string AUTH_USER_LIST = "authUsers";
const std::string AESKEY = "aeskey";
const std::string AESKEY_LEN = "aeskeyLen";
const std::string IV = "iv";
const std::string IV_LEN = "ivLen";
const std::string ENC_DATA_LEN = "encDataLen";
const std::string ENC_DATA = "encData";
const std::string EXTRA_INFO_LEN = "extraInfoLen";
const std::string EXTRA_INFO = "extraInfo";
const std::string ENC_ACCOUNT_TYPE = "encAccountType";

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
    if (permJson.find(lenName) != permJson.end() && permJson.at(lenName).is_number()) {
        permJson.at(lenName).get_to(buffLen);
    }

    if (permJson.find(keyName) != permJson.end() && permJson.at(keyName).is_string()) {
        char* value = static_cast<char*>(strdup((permJson.at(keyName).get<std::string>()).c_str()));
        if (value == nullptr) {
            DLP_LOG_ERROR(LABEL, "New memory fail");
            return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
        }
        uint32_t length = strlen(value) / BYTE_TO_HEX_OPER_LENGTH;
        if (length != buffLen) {
            DLP_LOG_ERROR(LABEL, "Buff size is not equal, please check");
            memset_s(value, strlen(value), 0, strlen(value));
            free(value);
            value = nullptr;
            return DLP_SERVICE_ERROR_JSON_OPERATE_FAIL;
        }
        *buff = new (std::nothrow) uint8_t[length];
        if (*buff == nullptr) {
            DLP_LOG_ERROR(LABEL, "New memory fail");
            memset_s(value, strlen(value), 0, strlen(value));
            free(value);
            value = nullptr;
            return DLP_SERVICE_ERROR_MEMORY_OPERATE_FAIL;
        }
        int32_t res = HexStringToByte(value, *buff, length);
        if (res != DLP_OK) {
            DLP_LOG_ERROR(LABEL, "Hexstring to byte fail");
            memset_s(*buff, length, 0, length);
            delete[] *buff;
            *buff = nullptr;
        }
        memset_s(value, strlen(value), 0, strlen(value));
        free(value);
        value = nullptr;
        return res;
    }
    return DLP_OK;
}

nlohmann::json DlpPermissionSerializer::SerializeAuthUserInfo(const AuthUserInfo& userInfo)
{
    nlohmann::json userInfoJson = {
        {AUTH_ACCOUNT, userInfo.authAccount},
        {AUTH_PERM, userInfo.authPerm},
        {PERM_EXPIRY_TIME, userInfo.permExpiryTime},
        {AUTH_ACCOUNT_TYPE, userInfo.authAccountType},
    };
    return userInfoJson;
}

int32_t DlpPermissionSerializer::DeserializeAuthUserInfo(const nlohmann::json& userInfoJson, AuthUserInfo& userInfo)
{
    if (userInfoJson.find(AUTH_ACCOUNT) != userInfoJson.end() && userInfoJson.at(AUTH_ACCOUNT).is_string()) {
        userInfoJson.at(AUTH_ACCOUNT).get_to(userInfo.authAccount);
    }
    if (userInfoJson.find(AUTH_PERM) != userInfoJson.end() && userInfoJson.at(AUTH_PERM).is_number()) {
        userInfoJson.at(AUTH_PERM).get_to(userInfo.authPerm);
    }
    if (userInfoJson.find(PERM_EXPIRY_TIME) != userInfoJson.end() && userInfoJson.at(PERM_EXPIRY_TIME).is_number()) {
        userInfoJson.at(PERM_EXPIRY_TIME).get_to(userInfo.permExpiryTime);
    }
    if (userInfoJson.find(AUTH_ACCOUNT_TYPE) != userInfoJson.end() && userInfoJson.at(AUTH_ACCOUNT_TYPE).is_number()) {
        userInfoJson.at(AUTH_ACCOUNT_TYPE).get_to(userInfo.authAccountType);
    }
    return DLP_OK;
}

nlohmann::json DlpPermissionSerializer::SerializeAuthUserList(const std::vector<AuthUserInfo>& authUsers)
{
    nlohmann::json authUsersJson;
    std::transform(authUsers.begin(), authUsers.end(),
        std::back_inserter(authUsersJson),
        [this](auto info) { return SerializeAuthUserInfo(info); });

    return authUsersJson;
}

int32_t DlpPermissionSerializer::DeserializeAuthUserList(
    const std::vector<nlohmann::json>& authUsersJson, std::vector<AuthUserInfo>& userList)
{
    for (auto iter : authUsersJson) {
        AuthUserInfo info;
        int32_t res = DeserializeAuthUserInfo(iter, info);
        if (res == DLP_OK) {
            userList.emplace_back(info);
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

    permInfoJson = {
        {AESKEY_LEN, policy.GetAeskeyLen()},
        {AESKEY, keyHex},
        {IV_LEN, policy.GetIvLen()},
        {IV, ivHex},
        {OWNER_ACCOUNT, policy.ownerAccount_},
        {OWNER_ACCOUNT_TYPE, policy.ownerAccountType_},
        {AUTH_USER_LIST, authUsersJson},
    };
    DLP_LOG_INFO(LABEL, "Serialize successfully!");
    FreeCharBuffer(keyHex, keyHexLen);
    FreeCharBuffer(ivHex, ivHexLen);
    return DLP_OK;
}

int32_t DlpPermissionSerializer::DeserializeDlpPermission(const nlohmann::json& permJson, PermissionPolicy& policy)
{
    if (permJson.find(AUTH_USER_LIST) != permJson.end() && permJson.at(AUTH_USER_LIST).is_array()) {
        auto jsonList = permJson.at(AUTH_USER_LIST).get<std::vector<nlohmann::json>>();
        std::vector<AuthUserInfo> userList;
        int32_t res = DeserializeAuthUserList(jsonList, userList);
        if (res == DLP_OK) {
            policy.authUsers_ = userList;
        } else {
            return res;
        }
    }

    if (permJson.find(OWNER_ACCOUNT) != permJson.end() && permJson.at(OWNER_ACCOUNT).is_string()) {
        permJson.at(OWNER_ACCOUNT).get_to(policy.ownerAccount_);
    }

    if (permJson.find(OWNER_ACCOUNT_TYPE) != permJson.end() && permJson.at(OWNER_ACCOUNT_TYPE).is_number()) {
        permJson.at(OWNER_ACCOUNT_TYPE).get_to(policy.ownerAccountType_);
    }
    uint8_t* key = nullptr;
    uint32_t keyLen = 0;
    int32_t res = ReadUint8ArrayFromJson(permJson, &key, keyLen, AESKEY, AESKEY_LEN);
    if (res != DLP_OK) {
        return res;
    }
    policy.SetAeskey(key, keyLen);
    if (key != nullptr) {
        delete[] key;
        key = nullptr;
    }
    uint8_t* iv = nullptr;
    uint32_t ivLen = 0;
    res = ReadUint8ArrayFromJson(permJson, &iv, ivLen, IV, IV_LEN);
    if (res != DLP_OK) {
        return res;
    }
    policy.SetIv(iv, ivLen);
    if (iv != nullptr) {
        delete[] iv;
        iv = nullptr;
    }
    DLP_LOG_INFO(LABEL, "Deserialize successfully!");
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

int32_t DlpPermissionSerializer::DeserializeEncPolicyData(const nlohmann::json &encDataJson, DLP_EncPolicyData &encData)
{
    if (encDataJson.find(ENC_ACCOUNT_TYPE) != encDataJson.end() && encDataJson.at(ENC_ACCOUNT_TYPE).is_number()) {
        encDataJson.at(ENC_ACCOUNT_TYPE).get_to(encData.accountType);
    }

    int32_t res = ReadUint8ArrayFromJson(encDataJson, &encData.data, encData.dataLen, ENC_DATA, ENC_DATA_LEN);
    if (res != DLP_OK) {
        return res;
    }

    res = ReadUint8ArrayFromJson(
        encDataJson, &encData.options.extraInfo, encData.options.extraInfoLen, EXTRA_INFO, EXTRA_INFO_LEN);
    if (res != DLP_OK) {
        return res;
    }

    DLP_LOG_INFO(LABEL, "Deserialize successfully!");
    return DLP_OK;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
