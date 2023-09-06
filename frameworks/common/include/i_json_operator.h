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

#ifndef DLP_IJSON_OPERATOR_H
#define DLP_IJSON_OPERATOR_H

#include <string>
#include "nlohmann/json.hpp"

namespace OHOS {
namespace Security {
namespace DlpPermission {
using Json = nlohmann::json;

class IJsonOperator {
public:
    virtual ~IJsonOperator() {};
    virtual Json ToJson() const = 0;
    virtual void FromJson(const Json& jsonObject) = 0;
    virtual std::string ToString() const = 0;
};
} // namespace DlpPermission
} // namespace Security
} // namespace OHOS
#endif // DLP_IJSON_OPERATOR_H
