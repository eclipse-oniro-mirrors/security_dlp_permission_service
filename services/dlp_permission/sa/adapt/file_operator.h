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

#ifndef DLP_FILE_OPERATOR_H
#define DLP_FILE_OPERATOR_H

#include <string>

namespace OHOS {
namespace Security {
namespace DlpPermission {
class FileOperator {
public:
    FileOperator();
    virtual ~FileOperator();

    int32_t InputFileByPathAndContent(const std::string& path, const std::string& content);
    int32_t GetFileContentByPath(const std::string& path, std::string& content);
    bool IsExistFile(const std::string& path);
    bool IsExistDir(const std::string& path);
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
#endif // DLP_FILE_OPERATOR_H
