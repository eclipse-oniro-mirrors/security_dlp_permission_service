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

#include "hex_string.h"
#include "dlp_permission.h"
#include <cstdio>
#include <cstring>

namespace OHOS {
namespace Security {
namespace DlpPermission {
namespace {
constexpr int NUMBER_9_IN_DECIMAL = 9;
constexpr int DEC = 10;
constexpr int OUT_OF_HEX = 16;
}  // namespace
static char HexToChar(uint8_t hex)
{
    return (hex > NUMBER_9_IN_DECIMAL) ? (hex + 0x37) : (hex + 0x30); /* Convert to the corresponding character */
}

int32_t ByteToHexString(const uint8_t* byte, uint32_t byteLen, char* hexStr, uint32_t hexLen)
{
    if (byte == nullptr || hexStr == nullptr) {
        return DLP_VALUE_INVALID;
    }
    /* The terminator('\0') needs 1 bit */
    if (hexLen < byteLen * BYTE_TO_HEX_OPER_LENGTH + 1) {
        return DLP_VALUE_INVALID;
    }

    for (uint32_t i = 0; i < byteLen; i++) {
        hexStr[i * BYTE_TO_HEX_OPER_LENGTH] = HexToChar((byte[i] & 0xF0) >> 4); /* 4: shift right for filling */
        hexStr[i * BYTE_TO_HEX_OPER_LENGTH + 1] = HexToChar(byte[i] & 0x0F);    /* get low four bits */
    }
    hexStr[byteLen * BYTE_TO_HEX_OPER_LENGTH] = '\0';

    return DLP_OK;
}

static uint8_t CharToHex(char c)
{
    if ((c >= 'A') && (c <= 'F')) {
        return (c - 'A' + DEC);
    } else if ((c >= 'a') && (c <= 'f')) {
        return (c - 'a' + DEC);
    } else if ((c >= '0') && (c <= '9')) {
        return (c - '0');
    } else {
        return OUT_OF_HEX;
    }
}

int32_t HexStringToByte(const char* hexStr, uint8_t* byte, uint32_t byteLen)
{
    if (byte == nullptr || hexStr == nullptr) {
        return DLP_VALUE_INVALID;
    }
    uint32_t realHexLen = strlen(hexStr);
    /* even number or not */
    if (realHexLen % BYTE_TO_HEX_OPER_LENGTH != 0 || byteLen < realHexLen / BYTE_TO_HEX_OPER_LENGTH) {
        return DLP_VALUE_INVALID;
    }

    for (uint32_t i = 0; i < realHexLen / BYTE_TO_HEX_OPER_LENGTH; i++) {
        uint8_t high = CharToHex(hexStr[i * BYTE_TO_HEX_OPER_LENGTH]);
        uint8_t low = CharToHex(hexStr[i * BYTE_TO_HEX_OPER_LENGTH + 1]);
        if (high == OUT_OF_HEX || low == OUT_OF_HEX) {
            return DLP_VALUE_INVALID;
        }
        byte[i] = high << 4; /* 4: Set the high nibble */
        byte[i] |= low;      /* Set the low nibble */
    }
    return DLP_OK;
}
}  // namespace DlpPermission
}  // namespace Security
}  // namespace OHOS