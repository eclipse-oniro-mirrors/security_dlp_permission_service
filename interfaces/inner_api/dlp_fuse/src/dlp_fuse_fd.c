/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "dlp_fuse_fd.h"

#include <pthread.h>
#include <unistd.h>
#include "dlp_permission_log.h"
#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "DlFuseFd"
#endif

static int g_dlpFuseFd = -1;
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

int GetDlpFuseFd(void)
{
    pthread_mutex_lock(&g_mutex);
    if (g_dlpFuseFd == -1) {
        DLP_LOG_ERROR("Fuse fd not set!");
    }
    DLP_LOG_DEBUG("fuseFd: %d\n", g_dlpFuseFd);
    pthread_mutex_unlock(&g_mutex);
    return g_dlpFuseFd;
}

void SetDlpFuseFd(int fd)
{
    pthread_mutex_lock(&g_mutex);
    if (g_dlpFuseFd != -1) {
        DLP_LOG_DEBUG("close fuseFd: %d first\n", g_dlpFuseFd);
        close(g_dlpFuseFd);
    }
    g_dlpFuseFd = fd;
    DLP_LOG_DEBUG("fuseFd: %d\n", g_dlpFuseFd);
    pthread_mutex_unlock(&g_mutex);
}

void CloseDlpFuseFd(void)
{
    pthread_mutex_lock(&g_mutex);
    if (g_dlpFuseFd == -1) {
        DLP_LOG_DEBUG("fuseFd: %d\n", g_dlpFuseFd);
        pthread_mutex_unlock(&g_mutex);
        return;
    }
    close(g_dlpFuseFd);
    g_dlpFuseFd = -1;
    pthread_mutex_unlock(&g_mutex);
}
