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

#ifndef DLP_LINK_MANAGER_H
#define DLP_LINK_MANAGER_H
#include <unordered_map>
#include <string>
#include "dlp_file.h"
#include "dlp_link_file.h"
#include "rwlock.h"

namespace OHOS {
namespace Security {
namespace DlpPermission {
static const int FUSE_DEV_FD = 1000;

class DlpLinkManager final {
public:
    static DlpLinkManager& GetInstance();
    ~DlpLinkManager() {};

    int32_t AddDlpLinkFile(std::shared_ptr<DlpFile>& filePtr, const std::string& dlpLinkName);
    int32_t StopDlpLinkFile(std::shared_ptr<DlpFile>& filePtr);
    int32_t RestartDlpLinkFile(std::shared_ptr<DlpFile>& filePtr);
    int32_t ReplaceDlpLinkFile(std::shared_ptr<DlpFile>& filePtr, const std::string& dlpLinkName);
    int32_t DeleteDlpLinkFile(std::shared_ptr<DlpFile>& filePtr);
    DlpLinkFile* LookUpDlpLinkFile(const std::string& dlpLinkName);
    void DumpDlpLinkFile(std::vector<DlpLinkFileInfo>& linkList);

private:
    DlpLinkManager();
    DISALLOW_COPY_AND_MOVE(DlpLinkManager);

    OHOS::Utils::RWLock g_DlpLinkMapLock_;
    std::unordered_map<std::string, DlpLinkFile*> g_DlpLinkFileNameMap_;
};
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS

#endif
