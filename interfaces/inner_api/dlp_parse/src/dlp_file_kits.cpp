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
#include "dlp_permission_log.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
    static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpFileKits"};
} // namespace
using Want = OHOS::AAFwk::Want;
using WantParams = OHOS::AAFwk::WantParams;

static const std::unordered_map<std::string, std::string> SUFFIX_MIMETYPE_MAP = {
    {"txt", "text/plain"},
    {"doc", "text/plain"},
};

static std::string GetWantFileName(const WantParams& param)
{
    WantParams wp = param.GetWantParams(TAG_FILE_NAME);
    if (wp.IsEmpty()) {
        return std::string();
    }

    return wp.GetStringParam(TAG_FILE_NAME_VALUE);
}

static int GetWantFileDescriptor(const WantParams& param)
{
    WantParams wp = param.GetWantParams(TAG_KEY_FD);
    if (wp.IsEmpty()) {
        DLP_LOG_WARN(LABEL, "Get want params fail, no file fd param found");
        return INVALID_FD;
    }

    std::string type = wp.GetStringParam(TAG_KEY_FD_TYPE);
    if (type != VALUE_KEY_FD_TYPE) {
        DLP_LOG_WARN(LABEL, "Get want params fail, fd type error, type=%{public}s", type.c_str());
        return INVALID_FD;
    }
    return wp.GetIntParam(TAG_KEY_FD_VALUE, INVALID_FD);
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
        DLP_LOG_ERROR(LABEL, "Get file suffix fail, file name is empty");
        return DEFAULT_STRING;
    }

    char escape = '.';
    uint32_t escapeLocate = realFileName.find_last_of(escape);
    if (escapeLocate >= realFileName.size()) {
        DLP_LOG_ERROR(LABEL, "Get file suffix fail, no '.' in file name");
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
        DLP_LOG_DEBUG(LABEL, "Action %{public}s is not dlp scene", action.c_str());
        return false;
    }

    const WantParams& param = want.GetParams();
    std::string fileName = GetWantFileName(param);
    if (fileName == DEFAULT_STRING || !IsDlpFileName(fileName)) {
        DLP_LOG_DEBUG(LABEL, "File name is not exist or not dlp, name=%{private}s", fileName.c_str());
        return false;
    }

    int fd = GetWantFileDescriptor(param);
    if (fd == INVALID_FD) {
        DLP_LOG_WARN(LABEL, "Get file descriptor fail");
        return false;
    }

    bool isDlpFile = false;
    DlpFileManager::GetInstance().IsDlpFile(fd, isDlpFile);
    if (!isDlpFile) {
        DLP_LOG_WARN(LABEL, "Fd %{public}d is not dlp file", fd);
        return false;
    }

    std::string realSuffix = GetDlpFileRealSuffix(fileName);
    if (realSuffix != DEFAULT_STRING) {
        DLP_LOG_DEBUG(LABEL, "Real suffix is %{public}s", realSuffix.c_str());
        std::string realType = GetMimeTypeBySuffix(realSuffix);
        if (realType != DEFAULT_STRING) {
            want.SetType(realType);
        } else {
            DLP_LOG_INFO(LABEL, "Real suffix %{public}s not match known type, using origin type %{public}s",
                realSuffix.c_str(), want.GetType().c_str());
        }
    }
    DLP_LOG_INFO(LABEL, "Sanbox flag is true");
    return true;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
