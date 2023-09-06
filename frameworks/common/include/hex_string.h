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

#ifndef HEX_STRING_H
#define HEX_STRING_H

#include <cstdint>

namespace OHOS {
namespace Security {
namespace DlpPermission {
constexpr int BYTE_TO_HEX_OPER_LENGTH = 2;
int32_t ByteToHexString(const uint8_t *byte, uint32_t byteLen, char *hexStr, uint32_t hexLen);
int32_t HexStringToByte(const char *hexStr, uint8_t *byte, uint32_t byteLen);
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS
#endif  // HEX_STRING_H
