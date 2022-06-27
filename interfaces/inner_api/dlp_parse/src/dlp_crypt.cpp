/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "dlp_crypt.h"
#include <cstdio>
#include <cstdlib>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <securec.h>
#include "dlp_permission.h"
#include "dlp_permission_log.h"
using namespace OHOS::Security::DlpPermission;

static constexpr OHOS::HiviewDFX::HiLogLabel LABEL = {LOG_CORE, SECURITY_DOMAIN_DLP_PERMISSION, "DlpParse"};

#ifdef __cplusplus
extern "C" {
#endif

inline int32_t DlpOpensslCheckBlob(const struct DlpBlob* blob)
{
    if ((blob == nullptr) || (blob->data == nullptr)) {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    return DLP_OK;
}

inline int32_t DlpOpensslCheckBlobZero(const struct DlpBlob* blob)
{
    if (blob == nullptr) {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (blob->data == nullptr && blob->size == 0) {
        return DLP_OK;
    }

    if (blob->data == nullptr) {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    return DLP_OK;
}

static int32_t AesGenKeyCheckParam(const uint32_t keySize)
{
    if ((keySize != DLP_AES_KEY_SIZE_128) && (keySize != DLP_AES_KEY_SIZE_192) && (keySize != DLP_AES_KEY_SIZE_256)) {
        DLP_LOG_ERROR(LABEL, "Invalid aes key len %x!", keySize);
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    return DLP_OK;
}

int32_t DlpOpensslGenerateRandomKey(const uint32_t keySize, struct DlpBlob* key)
{
    if (AesGenKeyCheckParam(keySize) != DLP_OK || key == nullptr) {
        DLP_LOG_ERROR(LABEL, "aes generate key invalid params!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    uint32_t keySizeByte = keySize / BIT_NUM_OF_UINT8;

    uint8_t* tmpKey = (uint8_t*)malloc(keySizeByte);

    if (tmpKey == nullptr) {
        DLP_LOG_ERROR(LABEL, "malloc buffer failed");
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    int res = RAND_bytes(tmpKey, keySizeByte);
    if (res <= 0) {
        DLP_LOG_ERROR(LABEL, "generate key is failed, errorCode: %{public}d", res);
        (void)memset_s(tmpKey, keySizeByte, 0, keySizeByte);
        free(tmpKey);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    } else {
        key->data = tmpKey;
        key->size = keySizeByte;
    }
    return DLP_OK;
}

static const EVP_CIPHER* GetCtrCipherType(uint32_t keySize)
{
    switch (keySize) {
        case DLP_KEY_BYTES(DLP_AES_KEY_SIZE_128):
            return EVP_aes_128_ctr();
        case DLP_KEY_BYTES(DLP_AES_KEY_SIZE_192):
            return EVP_aes_192_ctr();
        case DLP_KEY_BYTES(DLP_AES_KEY_SIZE_256):
            return EVP_aes_256_ctr();
        default:
            return nullptr;
    }
}

static const EVP_CIPHER* GetCipherType(uint32_t keySize, uint32_t mode)
{
    if (mode == DLP_MODE_CTR) {
        return GetCtrCipherType(keySize);
    }

    return nullptr;
}

inline void DlpLogOpensslError(void)
{
    char szErr[DLP_OPENSSL_ERROR_LEN] = {0};
    unsigned long errCode;

    errCode = ERR_get_error();
    ERR_error_string_n(errCode, szErr, DLP_OPENSSL_ERROR_LEN);

    DLP_LOG_ERROR(LABEL, "Openssl engine fail, error code = %{public}lu, error string = %{public}s", errCode, szErr);
}

static int32_t OpensslAesCipherInit(
    const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec, bool isEncrypt, EVP_CIPHER_CTX** ctx)
{
    int32_t ret;
    struct DlpCipherParam* cipherParam = usageSpec->algParam;

    *ctx = EVP_CIPHER_CTX_new();
    if (*ctx == nullptr) {
        DlpLogOpensslError();
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    const EVP_CIPHER* cipher = GetCipherType(key->size, usageSpec->mode);
    if (cipher == nullptr) {
        EVP_CIPHER_CTX_free(*ctx);
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (isEncrypt) {
        ret = EVP_EncryptInit_ex(*ctx, cipher, nullptr, nullptr, nullptr);
    } else {
        ret = EVP_DecryptInit_ex(*ctx, cipher, nullptr, nullptr, nullptr);
    }
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_CIPHER_CTX_free(*ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    if (isEncrypt) {
        ret = EVP_EncryptInit_ex(
            *ctx, nullptr, nullptr, key->data, (cipherParam == nullptr) ? nullptr : cipherParam->iv.data);
    } else {
        ret = EVP_DecryptInit_ex(
            *ctx, nullptr, nullptr, key->data, (cipherParam == nullptr) ? nullptr : cipherParam->iv.data);
    }
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_CIPHER_CTX_free(*ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    ret = EVP_CIPHER_CTX_set_padding(*ctx, OPENSSL_CTX_PADDING_ENABLE);
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_CIPHER_CTX_free(*ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    return DLP_OK;
}

static int32_t OpensslAesCipherEncryptFinal(
    EVP_CIPHER_CTX* ctx, const struct DlpBlob* message, struct DlpBlob* cipherText)
{
    int32_t outLen = 0;

    if (EVP_EncryptUpdate(ctx, cipherText->data, &outLen, message->data, message->size) != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_CIPHER_CTX_free(ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    cipherText->size = (uint32_t)outLen;

    if (EVP_EncryptFinal_ex(ctx, cipherText->data + outLen, &outLen) != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_CIPHER_CTX_free(ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    cipherText->size += (uint32_t)outLen;

    EVP_CIPHER_CTX_free(ctx);
    return DLP_OK;
}

static int32_t OpensslAesCipherCryptInitParams(const struct DlpBlob* key, EVP_CIPHER_CTX* ctx,
    const struct DlpCipherParam* cipherParam, bool isEncrypt, const struct DlpUsageSpec* usageSpec)
{
    int32_t ret;
    if (isEncrypt) {
        ret = EVP_EncryptInit_ex(
            ctx, nullptr, nullptr, key->data, (cipherParam == nullptr) ? nullptr : cipherParam->iv.data);
    } else {
        ret = EVP_DecryptInit_ex(
            ctx, nullptr, nullptr, key->data, (cipherParam == nullptr) ? nullptr : cipherParam->iv.data);
    }
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    ret = EVP_CIPHER_CTX_set_padding(ctx, OPENSSL_CTX_PADDING_ENABLE);
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return DLP_OK;
}

static int32_t OpensslAesCipherCryptInit(
    const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec, bool isEncrypt, void** cryptoCtx)
{
    int32_t ret;
    struct DlpCipherParam* cipherParam = (struct DlpCipherParam*)usageSpec->algParam;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr) {
        DlpLogOpensslError();
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    const EVP_CIPHER* cipher = GetCipherType(key->size, usageSpec->mode);
    if (cipher == nullptr) {
        EVP_CIPHER_CTX_free(ctx);
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (isEncrypt) {
        ret = EVP_EncryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    } else {
        ret = EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr);
    }
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_CIPHER_CTX_free(ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    ret = OpensslAesCipherCryptInitParams(key, ctx, cipherParam, isEncrypt, usageSpec);
    if (ret != DLP_OK) {
        EVP_CIPHER_CTX_free(ctx);
        DLP_LOG_ERROR(LABEL, "OpensslAesCipherCryptInitParams fail, ret = %d", ret);
        return ret;
    }

    struct DlpOpensslAesCtx* outCtx = (struct DlpOpensslAesCtx*)malloc(sizeof(DlpOpensslAesCtx));
    if (outCtx == nullptr) {
        EVP_CIPHER_CTX_free(ctx);
        return DLP_PARSE_ERROR_MEMORY_OPERATE_FAIL;
    }

    outCtx->mode = usageSpec->mode;
    outCtx->append = static_cast<void*>(ctx);

    *cryptoCtx = static_cast<void*>(outCtx);

    return DLP_OK;
}

static int32_t OpensslAesCipherEncryptUpdate(void* cryptoCtx, const struct DlpBlob* message, struct DlpBlob* cipherText)
{
    struct DlpOpensslAesCtx* aesCtx = (struct DlpOpensslAesCtx*)cryptoCtx;
    EVP_CIPHER_CTX* ctx = (EVP_CIPHER_CTX*)aesCtx->append;

    if (ctx == nullptr) {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t outLen = 0;
    if (EVP_EncryptUpdate(ctx, cipherText->data, &outLen, message->data, message->size) != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    cipherText->size = (uint32_t)outLen;

    return DLP_OK;
}

static int32_t OpensslAesCipherEncryptFinalThree(
    void** cryptoCtx, const struct DlpBlob* message, struct DlpBlob* cipherText)
{
    struct DlpOpensslAesCtx* aesCtx = (struct DlpOpensslAesCtx*)*cryptoCtx;
    EVP_CIPHER_CTX* ctx = (EVP_CIPHER_CTX*)aesCtx->append;

    if (ctx == nullptr) {
        DLP_FREE_PTR(*cryptoCtx);
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t ret = DLP_OK;
    do {
        int32_t outLen = 0;
        if (message->size != 0) {
            if (EVP_EncryptUpdate(ctx, cipherText->data, &outLen, message->data, message->size) !=
                DLP_OPENSSL_SUCCESS) {
                DlpLogOpensslError();
                ret = DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
                break;
            }
            cipherText->size = (uint32_t)outLen;
        }

        if (EVP_EncryptFinal_ex(ctx, (cipherText->data + outLen), &outLen) != DLP_OPENSSL_SUCCESS) {
            DlpLogOpensslError();
            ret = DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        cipherText->size += (uint32_t)outLen;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    aesCtx->append = nullptr;
    DLP_FREE_PTR(*cryptoCtx);

    return ret;
}

static int32_t OpensslAesCipherDecryptUpdate(void* cryptoCtx, const struct DlpBlob* message, struct DlpBlob* plainText)
{
    struct DlpOpensslAesCtx* aesCtx = (struct DlpOpensslAesCtx*)cryptoCtx;
    EVP_CIPHER_CTX* ctx = (EVP_CIPHER_CTX*)aesCtx->append;

    if (ctx == nullptr) {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t outLen = 0;
    if (EVP_DecryptUpdate(ctx, plainText->data, &outLen, message->data, message->size) != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    plainText->size = (uint32_t)outLen;

    return DLP_OK;
}

static int32_t OpensslAesCipherDecryptFinalThree(
    void** cryptoCtx, const struct DlpBlob* message, struct DlpBlob* plainText)
{
    struct DlpOpensslAesCtx* aesCtx = (struct DlpOpensslAesCtx*)*cryptoCtx;
    EVP_CIPHER_CTX* ctx = (EVP_CIPHER_CTX*)aesCtx->append;
    if (ctx == nullptr) {
        DLP_FREE_PTR(*cryptoCtx);
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t ret = DLP_OK;
    do {
        int32_t outLen = 0;
        if (message->size != 0) {
            if (EVP_DecryptUpdate(ctx, plainText->data, &outLen, message->data, message->size) != DLP_OPENSSL_SUCCESS) {
                DlpLogOpensslError();
                ret = DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
                break;
            }
            plainText->size = (uint32_t)outLen;
        }

        if (EVP_DecryptFinal_ex(ctx, plainText->data + outLen, &outLen) != DLP_OPENSSL_SUCCESS) {
            DlpLogOpensslError();
            ret = DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
            break;
        }
        plainText->size += (uint32_t)outLen;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    aesCtx->append = nullptr;
    DLP_FREE_PTR(*cryptoCtx);
    return ret;
}

static int32_t OpensslAesCipherDecryptFinal(
    EVP_CIPHER_CTX* ctx, const struct DlpBlob* message, struct DlpBlob* plainText)
{
    int32_t outLen = 0;

    if (EVP_DecryptUpdate(ctx, plainText->data, &outLen, message->data, message->size) != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_CIPHER_CTX_free(ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    plainText->size = (uint32_t)outLen;

    if (EVP_DecryptFinal_ex(ctx, plainText->data + outLen, &outLen) != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_CIPHER_CTX_free(ctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    plainText->size += (uint32_t)outLen;

    EVP_CIPHER_CTX_free(ctx);
    return DLP_OK;
}

int32_t DlpOpensslAesEncryptInit(void** cryptoCtx, const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec)
{
    if (cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid param cryptoCtx!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (DlpOpensslCheckBlob(key) != DLP_OK || usageSpec == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid param!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t ret;
    switch (usageSpec->mode) {
        case DLP_MODE_CTR:
            ret = OpensslAesCipherCryptInit(key, usageSpec, true, cryptoCtx);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "OpensslAesCipherCryptInit fail, ret = %d", ret);
                return ret;
            }
            break;

        default:
            DLP_LOG_ERROR(LABEL, "Unsupport aes mode! mode = 0x%x", usageSpec->mode);
            return DLP_PARSE_ERROR_OPERATION_UNSUPPORTED;
    }

    return DLP_OK;
}

int32_t DlpOpensslAesEncryptUpdate(void* cryptoCtx, const struct DlpBlob* message, struct DlpBlob* cipherText)
{
    if (cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid param cryptoCtx!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (DlpOpensslCheckBlob(message) != DLP_OK || DlpOpensslCheckBlob(cipherText) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Invalid param!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    struct DlpOpensslAesCtx* contex = (struct DlpOpensslAesCtx*)cryptoCtx;
    uint32_t mode = contex->mode;

    int32_t ret;
    switch (mode) {
        case DLP_MODE_CTR:
            ret = OpensslAesCipherEncryptUpdate(cryptoCtx, message, cipherText);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "OpensslAesCipherEncryptUpdate fail, ret = %d", ret);
                return ret;
            }
            break;
        default:
            DLP_LOG_ERROR(LABEL, "Unsupport aes mode! mode = 0x%x", mode);
            return DLP_PARSE_ERROR_OPERATION_UNSUPPORTED;
    }

    return DLP_OK;
}

int32_t DlpOpensslAesEncryptFinal(void** cryptoCtx, const struct DlpBlob* message, struct DlpBlob* cipherText)
{
    if (cryptoCtx == nullptr || *cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid param cryptoCtx!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (DlpOpensslCheckBlobZero(message) != DLP_OK || DlpOpensslCheckBlob(cipherText) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Invalid param!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    struct DlpOpensslAesCtx* contex = (struct DlpOpensslAesCtx*)*cryptoCtx;
    uint32_t mode = contex->mode;

    int32_t ret;
    switch (mode) {
        case DLP_MODE_CTR:
            ret = OpensslAesCipherEncryptFinalThree(cryptoCtx, message, cipherText);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "OpensslAesCipherEncryptFinalThree fail, ret = %d", ret);
                return ret;
            }
            break;
        default:
            DLP_LOG_ERROR(LABEL, "Unsupport aes mode! mode = 0x%x", mode);
            return DLP_PARSE_ERROR_OPERATION_UNSUPPORTED;
    }

    return DLP_OK;
}

int32_t DlpOpensslAesDecryptInit(void** cryptoCtx, const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec)
{
    if (cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid param cryptoCtx!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (DlpOpensslCheckBlob(key) != DLP_OK || usageSpec == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid param!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t ret;
    switch (usageSpec->mode) {
        case DLP_MODE_CTR:
            ret = OpensslAesCipherCryptInit(key, usageSpec, false, cryptoCtx);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "OpensslAesCipherCryptInit fail, ret = %d", ret);
                return ret;
            }
            break;
        default:
            DLP_LOG_ERROR(LABEL, "Unsupport aes mode! mode = 0x%x", usageSpec->mode);
            return DLP_PARSE_ERROR_OPERATION_UNSUPPORTED;
    }

    return ret;
}

int32_t DlpOpensslAesDecryptUpdate(void* cryptoCtx, const struct DlpBlob* message, struct DlpBlob* plainText)
{
    if (cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid param cryptoCtx!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (DlpOpensslCheckBlob(message) != DLP_OK || DlpOpensslCheckBlob(plainText) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Invalid param!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    struct DlpOpensslAesCtx* contex = (struct DlpOpensslAesCtx*)cryptoCtx;
    uint32_t mode = contex->mode;

    int32_t ret;
    switch (mode) {
        case DLP_MODE_CTR:
            ret = OpensslAesCipherDecryptUpdate(cryptoCtx, message, plainText);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "OpensslAesCipherDecryptUpdate fail, ret = %d", ret);
                return ret;
            }
            break;
        default:
            DLP_LOG_ERROR(LABEL, "Unsupport aes mode! mode = 0x%x", mode);
            return DLP_PARSE_ERROR_OPERATION_UNSUPPORTED;
    }

    return ret;
}

int32_t DlpOpensslAesDecryptFinal(void** cryptoCtx, const struct DlpBlob* message, struct DlpBlob* cipherText)
{
    if (cryptoCtx == nullptr || *cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid param cryptoCtx!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (DlpOpensslCheckBlobZero(message) != DLP_OK || DlpOpensslCheckBlob(cipherText) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Invalid param!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    struct DlpOpensslAesCtx* contex = (struct DlpOpensslAesCtx*)*cryptoCtx;
    uint32_t mode = contex->mode;

    int32_t ret;
    switch (mode) {
        case DLP_MODE_CTR:
            ret = OpensslAesCipherDecryptFinalThree(cryptoCtx, message, cipherText);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "OpensslAesCipherDecryptFinalThree fail, ret = %d", ret);
                return ret;
            }
            break;
        default:
            DLP_LOG_ERROR(LABEL, "Unsupport aes mode! mode = 0x%x", mode);
            return DLP_PARSE_ERROR_OPERATION_UNSUPPORTED;
    }

    return DLP_OK;
}

void DlpOpensslAesHalFreeCtx(void** cryptoCtx)
{
    if (cryptoCtx == nullptr || *cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Openssl aes free ctx is null");
        return;
    }

    struct DlpOpensslAesCtx* opensslAesCtx = (struct DlpOpensslAesCtx*)*cryptoCtx;
    switch (opensslAesCtx->mode) {
        case DLP_MODE_CTR:
            if ((EVP_CIPHER_CTX*)opensslAesCtx->append != nullptr) {
                EVP_CIPHER_CTX_free((EVP_CIPHER_CTX*)opensslAesCtx->append);
                opensslAesCtx->append = nullptr;
            }
            break;

        default:
            DLP_LOG_ERROR(LABEL, "Unsupport aes mode! mode = 0x%x", opensslAesCtx->mode);
            break;
    }

    DLP_FREE_PTR(*cryptoCtx);
}

static int32_t AesParamCheck(const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec,
    const struct DlpBlob* message, struct DlpBlob* cipherText)
{
    if (DlpOpensslCheckBlob(key) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Invalid param key!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (DlpOpensslCheckBlob(message) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Invalid param message!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (DlpOpensslCheckBlob(cipherText) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Invalid param cipherText!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (usageSpec == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid param usageSpec!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    return DLP_OK;
}

int32_t DlpOpensslAesEncrypt(const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec,
    const struct DlpBlob* message, struct DlpBlob* cipherText)
{
    if (AesParamCheck(key, usageSpec, message, cipherText) != DLP_OK) {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    EVP_CIPHER_CTX* ctx = nullptr;
    struct DlpBlob tmpCipherText = *cipherText;

    int32_t ret;
    switch (usageSpec->mode) {
        case DLP_MODE_CTR:
            ret = OpensslAesCipherInit(key, usageSpec, true, &ctx);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "OpensslAesCipherInit fail, ret = %d", ret);
                return ret;
            }

            ret = OpensslAesCipherEncryptFinal(ctx, message, &tmpCipherText);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "OpensslAesCipherEncryptFinal fail, ret = %d", ret);
                return ret;
            }
            break;

        default:
            DLP_LOG_ERROR(LABEL, "Unsupport aes mode! mode = 0x%x", usageSpec->mode);
            return DLP_PARSE_ERROR_OPERATION_UNSUPPORTED;
    }

    cipherText->size = tmpCipherText.size;
    return DLP_OK;
}

int32_t DlpOpensslAesDecrypt(const struct DlpBlob* key, const struct DlpUsageSpec* usageSpec,
    const struct DlpBlob* message, struct DlpBlob* plainText)
{
    if (AesParamCheck(key, usageSpec, message, plainText) != DLP_OK) {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    EVP_CIPHER_CTX* ctx = nullptr;
    struct DlpBlob tmpPlainText = *plainText;

    int32_t ret;
    switch (usageSpec->mode) {
        case DLP_MODE_CTR:
            ret = OpensslAesCipherInit(key, usageSpec, false, &ctx);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "OpensslAesCipherInit fail, ret = %d", ret);
                return ret;
            }

            ret = OpensslAesCipherDecryptFinal(ctx, message, &tmpPlainText);
            if (ret != DLP_OK) {
                DLP_LOG_ERROR(LABEL, "OpensslAesCipherDecryptFinal fail, ret = %d", ret);
                return ret;
            }
            break;
        default:
            DLP_LOG_ERROR(LABEL, "Unsupport aes mode! mode = 0x%x", usageSpec->mode);
            return DLP_PARSE_ERROR_OPERATION_UNSUPPORTED;
    }

    plainText->size = tmpPlainText.size;
    return ret;
}

static int32_t CheckDigestAlg(uint32_t alg)
{
    switch (alg) {
        case DLP_DIGEST_SHA256:
        case DLP_DIGEST_SHA384:
        case DLP_DIGEST_SHA512:
            break;
        default:
            DLP_LOG_ERROR(LABEL, "Unsupport HASH Type!");
            return DLP_PARSE_ERROR_DIGEST_INVALID;
    }

    return DLP_OK;
}

const EVP_MD* GetOpensslAlg(uint32_t alg)
{
    switch (alg) {
        case DLP_DIGEST_SHA256:
            return EVP_sha256();
        case DLP_DIGEST_SHA384:
            return EVP_sha384();
        case DLP_DIGEST_SHA512:
            return EVP_sha512();
        default:
            return nullptr;
    }
}

static uint32_t GetHashLen(uint32_t alg)
{
    if (alg == DLP_DIGEST_SHA256) {
        return SHA256_LEN;
    } else if (alg == DLP_DIGEST_SHA384) {
        return SHA384_LEN;
    } else {
        return SHA512_LEN;
    }
}

static int32_t HashCheckParam(uint32_t alg, const struct DlpBlob* msg, struct DlpBlob* hash)
{
    if (CheckDigestAlg(alg) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Unsupport HASH Type!");
        return DLP_PARSE_ERROR_DIGEST_INVALID;
    }

    if (DlpOpensslCheckBlob(hash) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Invalid param hash!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    uint32_t hashLen = GetHashLen(alg);
    if (hash->size < hashLen) {
        DLP_LOG_ERROR(LABEL, "hash buff too short!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (DlpOpensslCheckBlob(msg) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Invalid param msg!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    return DLP_OK;
}

int32_t DlpOpensslHash(uint32_t alg, const struct DlpBlob* msg, struct DlpBlob* hash)
{
    int32_t ret = HashCheckParam(alg, msg, hash);
    if (ret != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Invalid Params!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    const EVP_MD* opensslAlg = GetOpensslAlg(alg);
    if (opensslAlg == nullptr) {
        DLP_LOG_ERROR(LABEL, "get openssl algorithm fail");
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    ret = EVP_Digest(msg->data, msg->size, hash->data, &hash->size, opensslAlg, nullptr);
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return DLP_OK;
}

int32_t DlpOpensslHashInit(void** cryptoCtx, uint32_t alg)
{
    if (cryptoCtx == nullptr || CheckDigestAlg(alg) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "invalid param!");
        return DLP_PARSE_ERROR_DIGEST_INVALID;
    }

    const EVP_MD* opensslAlg = GetOpensslAlg(alg);
    if (opensslAlg == nullptr) {
        DLP_LOG_ERROR(LABEL, "get openssl algorithm fail");
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    EVP_MD_CTX* tmpctx = EVP_MD_CTX_new();
    if (tmpctx == nullptr) {
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    EVP_MD_CTX_set_flags(tmpctx, EVP_MD_CTX_FLAG_ONESHOT);
    int32_t ret = EVP_DigestInit_ex(tmpctx, opensslAlg, nullptr);
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_MD_CTX_free(tmpctx);
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    *cryptoCtx = static_cast<void*>(tmpctx);
    return DLP_OK;
}

int32_t DlpOpensslHashUpdate(void* cryptoCtx, const struct DlpBlob* msg)
{
    if (cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid param cryptoCtx!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (DlpOpensslCheckBlob(msg) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Invalid param msg!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t ret = EVP_DigestUpdate((EVP_MD_CTX*)cryptoCtx, (void*)msg->data, msg->size);
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }
    return DLP_OK;
}

int32_t DlpOpensslHashFinal(void** cryptoCtx, const struct DlpBlob* msg, struct DlpBlob* hash)
{
    if (cryptoCtx == nullptr || *cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Invalid param cryptoCtx!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    if (DlpOpensslCheckBlobZero(msg) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Invalid param msg!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }
    if (DlpOpensslCheckBlob(hash) != DLP_OK) {
        DLP_LOG_ERROR(LABEL, "Invalid param hash!");
        return DLP_PARSE_ERROR_VALUE_INVALID;
    }

    int32_t ret;
    if (msg->size != 0) {
        ret = EVP_DigestUpdate((EVP_MD_CTX*)*cryptoCtx, msg->data, msg->size);
        if (ret != DLP_OPENSSL_SUCCESS) {
            DlpLogOpensslError();
            EVP_MD_CTX_free((EVP_MD_CTX*)*cryptoCtx);
            *cryptoCtx = nullptr;
            return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
        }
    }

    ret = EVP_DigestFinal_ex((EVP_MD_CTX*)*cryptoCtx, hash->data, &hash->size);
    if (ret != DLP_OPENSSL_SUCCESS) {
        DlpLogOpensslError();
        EVP_MD_CTX_free((EVP_MD_CTX*)*cryptoCtx);
        *cryptoCtx = nullptr;
        return DLP_PARSE_ERROR_CRYPTO_ENGINE_ERROR;
    }

    EVP_MD_CTX_free((EVP_MD_CTX*)*cryptoCtx);
    *cryptoCtx = nullptr;
    return DLP_OK;
}

void DlpOpensslHashFreeCtx(void** cryptoCtx)
{
    if (cryptoCtx == nullptr || *cryptoCtx == nullptr) {
        DLP_LOG_ERROR(LABEL, "Openssl Hash freeCtx param error");
        return;
    }

    if (*cryptoCtx != nullptr) {
        EVP_MD_CTX_free((EVP_MD_CTX*)*cryptoCtx);
        *cryptoCtx = nullptr;
    }
}

#ifdef __cplusplus
}
#endif
