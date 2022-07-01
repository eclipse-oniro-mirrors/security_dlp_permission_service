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

#include "dlp_file_kits.h"
#include <unordered_map>
#include "base_object.h"
#include "dlp_permission_log.h"
#include "int_wrapper.h"
#include "string_wrapper.h"
#include "want_params_wrapper.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFileKits"};
} // namespace
using Want = OHOS::AAFwk::Want;
using WantParams = OHOS::AAFwk::WantParams;
using IWantParams = OHOS::AAFwk::IWantParams;
using IString = OHOS::AAFwk::IString;
using IInteger = OHOS::AAFwk::IInteger;
using WantParamWrapper = OHOS::AAFwk::WantParamWrapper;
using String = OHOS::AAFwk::String;
using Integer = OHOS::AAFwk::Integer;

static const std::unordered_map<std::string, std::string> SUFFIX_MIMETYPE_MAP = {
    {"txt", "text/plain"},
    {"doc", "text/plain"},
};

static WantParams GetWantParamsFromWantParams(const WantParams& param, const std::string& key)
{
    auto value = param.GetParam(key);
    IWantParams *wp = IWantParams::Query(value);
    if (wp != nullptr) {
        return WantParamWrapper::Unbox(wp);
    }
    return WantParams();
}

static std::string GetStringParam(const WantParams& param, const std::string& key)
{
    auto value = param.GetParam(key);
    IString *ao = IString::Query(value);
    if (ao != nullptr) {
        return String::Unbox(ao);
    }
    return std::string();
}

static int GetIntParam(const WantParams& param, const std::string& key, const int defaultValue)
{
    auto value = param.GetParam(key);
    IInteger *ao = IInteger::Query(value);
    if (ao != nullptr) {
        return Integer::Unbox(ao);
    }
    return defaultValue;
}

static std::string GetWantFileName(const WantParams& param)
{
    WantParams wp = GetWantParamsFromWantParams(param, TAG_FILE_NAME);
    if (wp.IsEmpty()) {
        DLP_LOG_DEBUG(LABEL, "has not fileName param");
        return std::string();
    }

    return GetStringParam(wp, TAG_FILE_NAME_VALUE);
}

static int GetWantFileDescriptor(const WantParams& param)
{
    WantParams wp = GetWantParamsFromWantParams(param, TAG_KEY_FD);
    if (wp.IsEmpty()) {
        DLP_LOG_WARN(LABEL, "has not fileFd param");
        return INVALID_FD;
    }

    std::string type = GetStringParam(wp, TAG_KEY_FD_TYPE);
    if (type != VALUE_KEY_FD_TYPE) {
        DLP_LOG_WARN(LABEL, "key fd type error. %{public}s", type.c_str());
        return INVALID_FD;
    }
    return GetIntParam(wp, TAG_KEY_FD_VALUE, INVALID_FD);
}

static bool IsDlpFileName(const std::string& dlpFileName)
{
    uint32_t dlpSuffixLen = DLP_FILE_SUFFIX.size();
    uint32_t fileNameLen = dlpFileName.size();
    if (fileNameLen <= dlpSuffixLen) {
        return false;
    }

    if (dlpFileName.substr(fileNameLen - dlpSuffixLen, dlpSuffixLen) != DLP_FILE_SUFFIX) {
        return false;
    }
    return true;
}

static std::string GetDlpFileRealSuffix(const std::string& dlpFileName)
{
    uint32_t dlpSuffixLen = DLP_FILE_SUFFIX.size();
    std::string realFileName = dlpFileName.substr(0, dlpFileName.size() - dlpSuffixLen);
    if (realFileName.empty()) {
        DLP_LOG_ERROR(LABEL, "realFileName is empty");
        return DEFAULT_STRING;
    }

    char escape = '.';
    uint32_t escapeLocate = realFileName.find_last_of(escape);
    if (escapeLocate >= realFileName.size()) {
        DLP_LOG_ERROR(LABEL, "realFile name can find escape");
        return DEFAULT_STRING;
    }

    return realFileName.substr(escapeLocate + 1);
}

static std::string GetMimeTypeBySuffix(const std::string& suffix)
{
    auto iter = SUFFIX_MIMETYPE_MAP.find(suffix);
    if (iter != SUFFIX_MIMETYPE_MAP.end()) {
        return iter->second;
    }
    return DEFAULT_STRING;
}

bool DlpFileKits::GetSandboxFlag(Want& want)
{
    std::string action = want.GetAction();
    if (action != TAG_ACTION_VIEW && action != TAG_ACTION_EDIT) {
        DLP_LOG_DEBUG(LABEL, "Want: action %{public}s is not dlp scene", action.c_str());
        return false;
    }

    const WantParams& param = want.GetParams();
    std::string fileName = GetWantFileName(param);
    if (fileName == DEFAULT_STRING || !IsDlpFileName(fileName)) {
        DLP_LOG_DEBUG(LABEL, "Want: fileName is not exist or not dlp file name. %{private}s", fileName.c_str());
        return false;
    }

    int fd = GetWantFileDescriptor(param);
    if (fd == INVALID_FD) {
        DLP_LOG_WARN(LABEL, "Want: Get file descriptor failed");
        return false;
    }

    bool isDlpFile = false;
    DlpFileManager::GetInstance().IsDlpFile(fd, isDlpFile);
    if (!isDlpFile) {
        DLP_LOG_WARN(LABEL, "Want: Fd %{public}d is not dlp file", fd);
        return false;
    }

    std::string realSuffix = GetDlpFileRealSuffix(fileName);
    if (realSuffix != DEFAULT_STRING) {
        DLP_LOG_DEBUG(LABEL, "Want: real suffix %{public}s", realSuffix.c_str());
        want.SetType(GetMimeTypeBySuffix(realSuffix));
    }
    DLP_LOG_INFO(LABEL, "Want: sanbox flag is true");
    return true;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
