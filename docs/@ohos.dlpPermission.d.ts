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

import type { AsyncCallback } from '@ohos.base';

/**
 * Provides the capability to access the data loss prevention (DLP) files.
 *
 * @namespace dlpPermission
 * @syscap SystemCapability.Security.DataLossPrevention
 * @since 10
 */
declare namespace dlpPermission {
  /**
   * Enumerates the types of actions that can be performed on a DLP file.
   *
   * @enum { number }
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  export enum ActionFlagType {
    /**
     * View a DLP file.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    ACTION_VIEW = 0x00000001,

    /**
     * Save a DLP file.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    ACTION_SAVE = 0x00000002,

    /**
     * Save a DLP file as another file.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    ACTION_SAVE_AS = 0x00000004,

    /**
     * Edit a DLP file.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    ACTION_EDIT = 0x00000008,

    /**
     * Take a screenshot of a DLP file.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    ACTION_SCREEN_CAPTURE = 0x00000010,

    /**
     * Share the screen, on which a DLP file is opened.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    ACTION_SCREEN_SHARE = 0x00000020,

    /**
     * Record the screen, on which a DLP file is opened.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    ACTION_SCREEN_RECORD = 0x00000040,

    /**
     * Copy a DLP file.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    ACTION_COPY = 0x00000080,

    /**
     * Print a DLP file.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    ACTION_PRINT = 0x00000100,

    /**
     * Export a DLP file.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    ACTION_EXPORT = 0x00000200,

    /**
     * Change the permissions for a DLP file.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    ACTION_PERMISSION_CHANGE = 0x00000400
  }

  /**
   * Enumerates the access permissions for a DLP file.
   *
   * @enum { number }
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  export enum DLPFileAccess {
    /**
     * No permission.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    NO_PERMISSION = 0,

    /**
     * Read-only.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    READ_ONLY = 1,

    /**
     * Edit.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    CONTENT_EDIT = 2,

    /**
     * Full control.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    FULL_CONTROL = 3
  }

  /**
   * Represents the permission info of a DLP file.
   *
   * @interface DLPPermissionInfo
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  export interface DLPPermissionInfo {
    /**
     * Access permission for the DLP file.
     *
     * @type { DLPFileAccess }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    dlpFileAccess: DLPFileAccess;

    /**
     * Actions allowed for the DLP file. The value is a combination of flags in {@code ActionFlagType}.
     *
     * @type { number }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    flags: number;
  }

  /**
   * Represents the visited DLP file info.
   *
   * @interface VisitedDLPFileInfo
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  export interface VisitedDLPFileInfo {
    /**
     * URI of the DLP file.
     *
     * @type { string }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    uri: string;

    /**
     * Time when the DLP file was last opened.
     *
     * @type { number }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    recentOpenTime: number;
  }

  /**
   * Represents the retention sandbox info.
   *
   * @interface RetentionSandboxInfo
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  export interface RetentionSandboxInfo {
    /**
     * Application index of the DLP sandbox.
     *
     * @type { number }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    appIndex: number;

    /**
     * Bundle name of the application.
     *
     * @type { string }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    bundleName: string;

    /**
     * List of file URIs.
     *
     * @type { Array<string> }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @since 10
     */
    docUris: Array<string>;
  }

  /**
   * Checks whether a file is a DLP file. This method uses a promise to return the result.
   *
   * @param { number } fd - Indicates the file descriptor of the file to check.
   * @returns { Promise<boolean> } Returns {@code true} if {@code fd} is a DLP file; returns {@code false} otherwise.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function isDLPFile(fd: number): Promise<boolean>;

  /**
   * Checks whether a file is a DLP file. This method uses an asynchronous callback to return the result.
   *
   * @param { number } fd - Indicates the file descriptor of the file to check.
   * @param { AsyncCallback<boolean> } callback - Indicates the callback invoked to return the result.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function isDLPFile(fd: number, callback: AsyncCallback<boolean>): void;

  /**
   * Obtains the permission info of this DLP file. This method uses a promise to return the result.
   *
   * @returns { Promise<DLPPermissionInfo> } Returns a {@code DLPPermissionInfo} object.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100006 - No permission to invoke this api, which is for DLP sandbox application.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function getDLPPermissionInfo(): Promise<DLPPermissionInfo>;

  /**
   * Obtains the permission info of this DLP file. This method uses an asynchronous callback to return the result.
   *
   * @param { AsyncCallback<DLPPermissionInfo> } callback - Indicates the callback invoked to return the result.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100006 - No permission to invoke this api, which is for DLP sandbox application.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function getDLPPermissionInfo(callback: AsyncCallback<DLPPermissionInfo>): void;

  /**
   * Obtains the original file name from a DLP file name. This method removes the DLP file name extension from the DLP file name.
   *
   * @param { string } fileName - Indicates DLP file name.
   * @returns { string } Returns the original file name obtained.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function getOriginalFileName(fileName: string): string;

  /**
   * Obtains the DLP file name extension.
   *
   * @returns { string } Returns the DLP file name extension obtained.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function getDLPSuffix(): string;

  /**
   * Subscribes to the event reported when a DLP file is opened by the given application.
   *
   * @param { 'openDLPFile' } type - Indicates the type of the event to subscribe to.
   * @param { Callback<VisitedDLPFileInfo> } listener - Indicates the callback invoked when a DLP file is opened by the given application.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100007 - No permission to invoke this api, which is not for DLP sandbox application.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function on(type: 'openDLPFile', listener: Callback<VisitedDLPFileInfo>): void;

  /**
   * Unsubscribes from the event reported when a DLP file is opened by the given application.
   *
   * @param { 'openDLPFile' } type - Indicates the type of the event to unsubscribe from.
   * @param { Callback<VisitedDLPFileInfo> } listener - Indicates the callback invoked when a DLP file is opened by the given application.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100007 - No permission to invoke this api, which is not for DLP sandbox application.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function off(type: 'openDLPFile', listener?: Callback<VisitedDLPFileInfo>): void;

  /**
   * Checks whether this application is in the DLP sandbox. This method uses a promise to return the result.
   *
   * @returns { Promise<boolean> } Returns {@code true} if the application is in a DLP sandbox; returns {@code false} otherwise.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function isInSandbox(): Promise<boolean>;

  /**
   * Checks whether this application is in the DLP sandbox. This method uses an asynchronous callback to return the result.
   *
   * @param { AsyncCallback<boolean> } callback - Indicates the callback invoked to return the result.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function isInSandbox(callback: AsyncCallback<boolean>): void;

  /**
   * Obtains the file types supported by DLP. This method uses a promise to return the result.
   *
   * @returns { Promise<Array<string>> } Returns the list of file types supported.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function getDLPSupportedFileTypes(): Promise<Array<string>>;

  /**
   * Obtains the file types supported by DLP. This method uses an asynchronous callback to return the result.
   *
   * @param { AsyncCallback<Array<string>> } callback - Indicates the callback invoked to return the result.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function getDLPSupportedFileTypes(callback: AsyncCallback<Array<string>>): void;

  /**
   * Sets the retention status for the files specified by {@code dorUri}. This method uses an asynchronous callback to return the result.
   *
   * @param { Array<string> } docUris - Indicates the URIs of the files, for which the retention status is to set.
   * @param { AsyncCallback<void> } callback - Indicates the callback invoked to return the result.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100006 - No permission to invoke this api, which is for DLP sandbox application.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function setRetentionState(docUris: Array<string>, callback: AsyncCallback<void>): void;

  /**
   * Sets the retention status for the files specified by {@code dorUri}. This method uses a promise to return the result.
   *
   * @param { Array<string> } docUris - Indicates the URIs of the files, for which the retention status is to set.
   * @returns { Promise<void> } Promise used to return the result.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100006 - No permission to invoke this api, which is for DLP sandbox application.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function setRetentionState(docUris: Array<string>): Promise<void>;

  /**
   * Cancels the retention status for the files specified by {@code dorUri}. This method uses an asynchronous callback to return the result.
   *
   * @param { Array<string> } docUris - Indicates the list of the file URIs.
   * @param { AsyncCallback<void> } callback - Indicates the callback invoked to return the result.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function cancelRetentionState(docUris: Array<string>, callback: AsyncCallback<void>): void;

  /**
   * Cancels the retention status for the files specified by {@code dorUri}. This method uses a promise to return the result.
   *
   * @param { Array<string> } docUris - Indicates the list of the file URIs.
   * @returns { Promise<void> } Promise used to return the result.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function cancelRetentionState(docUris: Array<string>): Promise<void>;

  /**
   * Obtains information about the retained DLP sandboxes of an application. This method uses a promise to return the result.
   *
   * @param { string } bundleName - Indicates the bundle name of the application.
   * @returns { Promise<Array<RetentionSandboxInfo>> } Returns a list of {@code RetentionSandboxInfo}.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100007 - No permission to invoke this api, which is not for DLP sandbox application.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function getRetentionSandboxList(bundleName?: string): Promise<Array<RetentionSandboxInfo>>;

  /**
   * Obtains information about the retained DLP sandboxes of an application. This method uses an asynchronous callback to return the result.
   *
   * @param { string } bundleName - Indicates the bundle name of the application.
   * @param { AsyncCallback<Array<RetentionSandboxInfo>> } callback - Indicates the callback invoked to return the result.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100007 - No permission to invoke this api, which is not for DLP sandbox application.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function getRetentionSandboxList(bundleName: string, callback: AsyncCallback<Array<RetentionSandboxInfo>>): void;

  /**
   * Obtains information about retained DLP sandboxes. This method uses an asynchronous callback to return the result.
   *
   * @param { AsyncCallback<Array<RetentionSandboxInfo>> } callback - Indicates the callback invoked to return the result.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100007 - No permission to invoke this api, which is not for DLP sandbox application.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function getRetentionSandboxList(callback: AsyncCallback<Array<RetentionSandboxInfo>>): void;

  /**
   * Obtains the DLP file visit records. This method uses a promise to return the result.
   *
   * @returns { Promise<Array<VisitedDLPFileInfo>> } Returns a list of DLP files visited recently.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100007 - No permission to invoke this api, which is not for DLP sandbox application.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function getDLPFileVisitRecords(): Promise<Array<VisitedDLPFileInfo>>;

  /**
   * Obtains the DLP file visit records. This method uses an asynchronous callback to return the result.
   *
   * @param { AsyncCallback<Array<VisitedDLPFileInfo>> } callback - Indicates the callback invoked to return the result.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100007 - No permission to invoke this api, which is not for DLP sandbox application.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @since 10
   */
  function getDLPFileVisitRecords(callback: AsyncCallback<Array<VisitedDLPFileInfo>>): void;

  /**
   * Enumerates the gathering policy types for DLP files.
   *
   * @enum { number }
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  export enum GatheringPolicyType {
    /**
     * Gathering, which allows multiple DLP files to be opened in a sandbox.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    GATHERING = 1,

    /**
     * Non-gathering, which allows only one DLP file to be opened in a sandbox.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    NON_GATHERING = 2
  }

  /**
   * Obtains the DLP sandbox gathering policy. This method uses a promise to return the result.
   *
   * @permission ohos.permission.ACCESS_DLP_FILE
   * @returns { Promise<GatheringPolicyType> } Returns a {@code GatheringPolicyType} object.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function getDLPGatheringPolicy(): Promise<GatheringPolicyType>;

  /**
   * Obtains the DLP sandbox gathering policy. This method uses an asynchronous callback to return the result.
   *
   * @permission ohos.permission.ACCESS_DLP_FILE
   * @param { AsyncCallback<GatheringPolicyType> } callback - Indicates the callback invoked to return the result.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function getDLPGatheringPolicy(callback: AsyncCallback<GatheringPolicyType>): void;

  /**
   * Represents the installed DLP sandbox application info.
   *
   * @interface DLPSandboxInfo
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  export interface DLPSandboxInfo {
    /**
     * Index of the installed DLP sandbox application.
     *
     * @type { number }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    appIndex: number;

    /**
     * Token ID of the installed DLP sandbox application..
     *
     * @type { number }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    tokenID: number;
  }

  /**
   * Installs a DLP sandbox application. This method uses a promise to return the result.
   *
   * @permission ohos.permission.ACCESS_DLP_FILE
   * @param { string } bundleName - Indicates the bundle name of the application.
   * @param { DLPFileAccess } access - Indicates the access permission for the DLP file.
   * @param { number } userId - Indicates the user ID.
   * @param { string } uri - Indicates the URI of the file.
   * @returns { Promise<DLPSandboxInfo> } Returns the {@code DLPSandboxInfo} of the installed sandbox application.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function installDLPSandbox(
    bundleName: string,
    access: DLPFileAccess,
    userId: number,
    uri: string
  ): Promise<DLPSandboxInfo>;

  /**
   * Installs a DLP sandbox application. This method uses an asynchronous callback to return the result.
   *
   * @permission ohos.permission.ACCESS_DLP_FILE
   * @param { string } bundleName - Indicates the bundle name of the application.
   * @param { DLPFileAccess } access - Indicates the access permission for the DLP file.
   * @param { number } userId - Indicates the user ID.
   * @param { string } uri - Indicates the URI of the file.
   * @param { AsyncCallback<DLPSandboxInfo> } callback - Indicates the callback invoked to return the result.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function installDLPSandbox(
    bundleName: string,
    access: DLPFileAccess,
    userId: number,
    uri: string,
    callback: AsyncCallback<DLPSandboxInfo>
  ): void;

  /**
   * Uninstalls a DLP sandbox application. This method uses a promise to return the result.
   *
   * @permission ohos.permission.ACCESS_DLP_FILE
   * @param { string } bundleName - Indicates the bundle name of the application.
   * @param { number } userId - Indicates the user ID.
   * @param { number } appIndex - Indicates the index of DLP sandbox.
   * @returns { Promise<void> } Promise used to return the result.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function uninstallDLPSandbox(bundleName: string, userId: number, appIndex: number): Promise<void>;

  /**
   * Uninstalls a DLP sandbox application. This method uses an asynchronous callback to return the result.
   *
   * @permission ohos.permission.ACCESS_DLP_FILE
   * @param { string } bundleName - Indicates the bundle name of the application.
   * @param { number } userId - Indicates the user ID.
   * @param { number } appIndex - Indicates the index of DLP sandbox.
   * @param { AsyncCallback<void> } callback - Indicates the callback invoked to return the result.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function uninstallDLPSandbox(
    bundleName: string,
    userId: number,
    appIndex: number,
    callback: AsyncCallback<void>
  ): void;

  /**
   * Represents the DLP sandbox state.
   *
   * @interface DLPSandboxState
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  export interface DLPSandboxState {
    /**
     * Bundle name of the application.
     *
     * @type { string }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    bundleName: string;

    /**
     * Application index of the DLP sandbox.
     *
     * @type { number }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    appIndex: number;
  }

  /**
   * Subscribes to the event reported when a DLP sandbox application is uninstalled.
   *
   * @permission ohos.permission.ACCESS_DLP_FILE
   * @param { 'uninstallDLPSandbox' } type - Indicates the type of the event to subscribe to.
   * @param { Callback<DLPSandboxState> } listener - Indicates the callback for the DLP sandbox application uninstall event.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function on(type: 'uninstallDLPSandbox', listener: Callback<DLPSandboxState>): void;

  /**
   * Unsubscribes from the event reported when a DLP sandbox application is uninstalled.
   *
   * @permission ohos.permission.ACCESS_DLP_FILE
   * @param { 'uninstallDLPSandbox' } type - Indicates the type of the event to unsubscribe from.
   * @param { Callback<DLPSandboxState> } listener - Indicates the callback for the DLP sandbox application uninstall event.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function off(type: 'uninstallDLPSandbox', listener?: Callback<DLPSandboxState>): void;

  /**
   * Enumerates the account types for a DLP file.
   *
   * @enum { number }
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  export enum AccountType {
    /**
     * Cloud account.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    CLOUD_ACCOUNT = 1,

    /**
     * Domain account.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    DOMAIN_ACCOUNT = 2,

    /**
     * Application account.
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    APPLICATION_ACCOUNT = 3
  }

  /**
   * Represents the authorized user information.
   *
   * @interface AuthUser
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  export interface AuthUser {
    /**
     * Authorized account of the DLP file.
     *
     * @type { string }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    authAccount: string;

    /**
     * Type of the authorized account.
     *
     * @type { AccountType }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    authAccountType: AccountType;

    /**
     * Authorized permission for the DLP file.
     *
     * @type { DLPFileAccess }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    dlpFileAccess: DLPFileAccess;

    /**
     * Authorization expiration time of the DLP file.
     *
     * @type { number }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    permExpiryTime: number;
  }

  /**
   * Represents the DLP file property.
   *
   * @interface DLPProperty
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  export interface DLPProperty {
    /**
     * Owner account of the DLP file.
     *
     * @type { string }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    ownerAccount: string;

    /**
     * Owner account ID of the DLP file.
     *
     * @type { string }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    ownerAccountID: string;

    /**
     * Authorized users of the DLP file.
     *
     * @type { Array<AuthUser>? }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    authUserList?: Array<AuthUser>;

    /**
     * Contact account of the DLP file.
     *
     * @type { string }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    contractAccount: string;

    /**
     * Type of the owner account of the DLP file.
     *
     * @type { AccountType }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    ownerAccountType: AccountType;

    /**
     * Whether the DLP file can be accessed offline.
     * If the DLP file supports offline access, the credential server needs to be connected to the network only when the DLP file is opened for the first time.
     *
     * @type { boolean }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    offlineAccess: boolean;

    /**
     * Everyone access list for the DLP file.
     *
     * @type { Array<DLPFileAccess> }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    everyoneAccessList: Array<DLPFileAccess>;

    /**
     * Everyone Access support
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    supportEveryone: boolean;

    /**
     * Everyone's Access permission
     *
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    everyonePerm: DLPFileAccess;
  }

  /**
   * Defines the DLP file object.
   *
   * @interface DLPFile
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  export interface DLPFile {
    /**
     * DLP file property.
     *
     * @type { DLPProperty }
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    dlpProperty: DLPProperty;

    /**
     * Adds a link file for the DLP file. This method uses a promise to return the result.
     * The link file is implemented through the Filesystem in Userspace (FUSE).
     *
     * @permission ohos.permission.ACCESS_DLP_FILE
     * @param { string } linkFileName - Indicates the name of link file to add.
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 19100001 - Invalid parameter value.
     * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
     * @throws { BusinessError } 19100011 - System service exception.
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    addDLPLinkFile(linkFileName: string): Promise<void>;

    /**
     * Adds a link file for the DLP file. This method uses an asynchronous callback to return the result.
     * The link file is implemented through the FUSE.
     *
     * @permission ohos.permission.ACCESS_DLP_FILE
     * @param { string } linkFileName - Indicates the name of link file to add.
     * @param { AsyncCallback<void> } callback - Indicates the callback invoked to return the result.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 19100001 - Invalid parameter value.
     * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
     * @throws { BusinessError } 19100011 - System service exception.
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    addDLPLinkFile(linkFileName: string, callback: AsyncCallback<void>): void;

    /**
     * Stops the FUSE link between the DLP file and a link life. This method uses a promise to return the result.
     *
     * @permission ohos.permission.ACCESS_DLP_FILE
     * @param { string } linkFileName - Indicates the name of link file.
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 19100001 - Invalid parameter value.
     * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
     * @throws { BusinessError } 19100011 - System service exception.
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    stopFuseLink(linkFileName: string): Promise<void>;

    /**
     * Stops the FUSE link between the DLP file and a link life. This method uses an asynchronous callback to return the result.
     *
     * @permission ohos.permission.ACCESS_DLP_FILE
     * @param { string } linkFileName - Indicates the name of link file.
     * @param { AsyncCallback<void> } callback - Indicates the callback of stopFuseLink.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 19100001 - Invalid parameter value.
     * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
     * @throws { BusinessError } 19100011 - System service exception.
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    stopFuseLink(linkFileName: string, callback: AsyncCallback<void>): void;

    /**
     * Resumes the FUSE link between the DLP file and a link life. This method uses a promise to return the result.
     *
     * @permission ohos.permission.ACCESS_DLP_FILE
     * @param { string } linkFileName - Indicates the name of link file.
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 19100001 - Invalid parameter value.
     * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
     * @throws { BusinessError } 19100011 - System service exception.
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    resumeFuseLink(linkFileName: string): Promise<void>;

    /**
     * Resumes the FUSE link between the DLP file and a link life. This method uses an asynchronous callback to return the result.
     *
     * @permission ohos.permission.ACCESS_DLP_FILE
     * @param { string } linkFileName - Indicates the name of link file.
     * @param { AsyncCallback<void> } callback - Indicates the callback of resumeFuseLink.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 19100001 - Invalid parameter value.
     * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
     * @throws { BusinessError } 19100011 - System service exception.
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    resumeFuseLink(linkFileName: string, callback: AsyncCallback<void>): void;

    /**
     * Replaces the link file of the DLP file. This method uses a promise to return the result.
     *
     * @permission ohos.permission.ACCESS_DLP_FILE
     * @param { string } linkFileName - Indicates the name of link file.
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 19100001 - Invalid parameter value.
     * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
     * @throws { BusinessError } 19100011 - System service exception.
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    replaceDLPLinkFile(linkFileName: string): Promise<void>;

    /**
     * Replaces the link file of the DLP file. This method uses an asynchronous callback to return the result.
     *
     * @permission ohos.permission.ACCESS_DLP_FILE
     * @param { string } linkFileName - Indicates the name of link file.
     * @param { AsyncCallback<void> } callback - Indicates the callback invoked to return the result.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 19100001 - Invalid parameter value.
     * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
     * @throws { BusinessError } 19100011 - System service exception.
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    replaceDLPLinkFile(linkFileName: string, callback: AsyncCallback<void>): void;

    /**
     * Deletes a link file of the DLP file. This method uses a promise to return the result.
     *
     * @permission ohos.permission.ACCESS_DLP_FILE
     * @param { string } linkFileName - Indicates the name of link file to delete.
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 19100001 - Invalid parameter value.
     * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
     * @throws { BusinessError } 19100011 - System service exception.
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    deleteDLPLinkFile(linkFileName: string): Promise<void>;

    /**
     * Deletes a link file of the DLP file. This method uses an asynchronous callback to return the result.
     *
     * @permission ohos.permission.ACCESS_DLP_FILE
     * @param { string } linkFileName - Indicates the name of link file to delete.
     * @param { AsyncCallback<void> } callback - Indicates the callback invoked to return the result.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 19100001 - Invalid parameter value.
     * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
     * @throws { BusinessError } 19100011 - System service exception.
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    deleteDLPLinkFile(linkFileName: string, callback: AsyncCallback<void>): void;

    /**
     * Recovers the file in plaintext from the DLP file. This method uses a promise to return the result.
     *
     * @permission ohos.permission.ACCESS_DLP_FILE
     * @param { number } plainFd - Indicates the file descriptor of the file in plaintext.
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 19100001 - Invalid parameter value.
     * @throws { BusinessError } 19100002 - Credential task error.
     * @throws { BusinessError } 19100003 - Credential task timed out.
     * @throws { BusinessError } 19100004 - Credential service error.
     * @throws { BusinessError } 19100005 - Remote credential server error.
     * @throws { BusinessError } 19100008 - Not DLP file.
     * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
     * @throws { BusinessError } 19100010 - DLP file is read-only.
     * @throws { BusinessError } 19100011 - System service exception.
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    recoverDLPFile(plainFd: number): Promise<void>;

    /**
     * Recovers the file in plaintext from the DLP file. This method uses an asynchronous callback to return the result.
     *
     * @permission ohos.permission.ACCESS_DLP_FILE
     * @param { number } plainFd - Indicates the file descriptor of the file in plaintext.
     * @param { AsyncCallback<void> } callback - Indicates the callback invoked to return the result.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 19100001 - Invalid parameter value.
     * @throws { BusinessError } 19100002 - Credential task error.
     * @throws { BusinessError } 19100003 - Credential task timed out.
     * @throws { BusinessError } 19100004 - Credential service error.
     * @throws { BusinessError } 19100005 - Remote credential server error.
     * @throws { BusinessError } 19100008 - Not DLP file.
     * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
     * @throws { BusinessError } 19100010 - DLP file is read-only.
     * @throws { BusinessError } 19100011 - System service exception.
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    recoverDLPFile(plainFd: number, callback: AsyncCallback<void>): void;

    /**
     * Closes the DLP file when the object is no longer used. This method uses a promise to return the result.
     *
     * @permission ohos.permission.ACCESS_DLP_FILE
     * @returns { Promise<void> } Promise used to return the result.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
     * @throws { BusinessError } 19100011 - System service exception.
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    closeDLPFile(): Promise<void>;

    /**
     * Closes the DLP file when the object is no longer used. This method uses an asynchronous callback to return the result.
     *
     * @permission ohos.permission.ACCESS_DLP_FILE
     * @param { AsyncCallback<void> } callback - Indicates the callback invoked to return the result.
     * @throws { BusinessError } 201 - Permission denied.
     * @throws { BusinessError } 202 - Non-system applications use system APIs.
     * @throws { BusinessError } 401 - Parameter error.
     * @throws { BusinessError } 19100001 - Invalid parameter value.
     * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
     * @throws { BusinessError } 19100011 - System service exception.
     * @syscap SystemCapability.Security.DataLossPrevention
     * @systemapi Hide this for inner system use.
     * @since 10
     */
    closeDLPFile(callback: AsyncCallback<void>): void;
  }

  /**
   * Generates a DLP file. This method uses a promise to return the result.
   *
   * @permission ohos.permission.ACCESS_DLP_FILE
   * @param { number } plainTextFd Indicates the file descriptor of the file in plaintext.
   * @param { number } cipherTextFd Indicates the file descriptor of the DLP file.
   * @param { DLPProperty } property - Indicates the property of the DLP file.
   * @returns { Promise<DLPFile> } Returns a {@code DLPFile} object.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100002 - Credential task error.
   * @throws { BusinessError } 19100003 - Credential task timed out.
   * @throws { BusinessError } 19100004 - Credential service error.
   * @throws { BusinessError } 19100005 - Remote credential server error.
   * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function generateDLPFile(plainTextFd: number, cipherTextFd: number, property: DLPProperty): Promise<DLPFile>;

  /**
   * Generates a DLP file. This method uses an asynchronous callback to return the result.
   *
   * @permission ohos.permission.ACCESS_DLP_FILE
   * @param { number } plainTextFd Indicates the file descriptor of the file in plaintext.
   * @param { number } cipherTextFd - Indicates the file descriptor of the DLP file.
   * @param { DLPProperty } property Indicates the property of the DLP file.
   * @param { AsyncCallback<DLPFile> } callback - Indicates the callback invoked to return the result.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100002 - Credential task error.
   * @throws { BusinessError } 19100003 - Credential task timed out.
   * @throws { BusinessError } 19100004 - Credential service error.
   * @throws { BusinessError } 19100005 - Remote credential server error.
   * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function generateDLPFile(
    plainTextFd: number,
    cipherTextFd: number,
    property: DLPProperty,
    callback: AsyncCallback<DLPFile>
  ): void;

  /**
   * Opens a DLP file. This method uses a promise to return a {@code DLPFile} object.
   *
   * @permission ohos.permission.ACCESS_DLP_FILE
   * @param { number } cipherTextFd - Indicates the file descriptor of the DLP file to open.
   * @returns { Promise<DLPFile> } Returns a {@code DLPFile} object.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100002 - Credential task error.
   * @throws { BusinessError } 19100003 - Credential task timed out.
   * @throws { BusinessError } 19100004 - Credential service error.
   * @throws { BusinessError } 19100005 - Remote credential server error.
   * @throws { BusinessError } 19100008 - Not DLP file.
   * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function openDLPFile(cipherTextFd: number): Promise<DLPFile>;

  /**
   * Opens a DLP file. This method uses an asynchronous callback to return a {@code DLPFile} object.
   *
   * @permission ohos.permission.ACCESS_DLP_FILE
   * @param { number } cipherTextFd - Indicates the file descriptor of the DLP file to open.
   * @param { AsyncCallback<DLPFile> } callback - Indicates the callback invoked to return the result.
   * @throws { BusinessError } 201 - Permission denied.
   * @throws { BusinessError } 202 - Non-system applications use system APIs.
   * @throws { BusinessError } 401 - Parameter error.
   * @throws { BusinessError } 19100001 - Invalid parameter value.
   * @throws { BusinessError } 19100002 - Credential task error.
   * @throws { BusinessError } 19100003 - Credential task timed out.
   * @throws { BusinessError } 19100004 - Credential service error.
   * @throws { BusinessError } 19100005 - Remote credential server error.
   * @throws { BusinessError } 19100008 - Not DLP file.
   * @throws { BusinessError } 19100009 - Failed to operate the DLP file.
   * @throws { BusinessError } 19100011 - System service exception.
   * @syscap SystemCapability.Security.DataLossPrevention
   * @systemapi Hide this for inner system use.
   * @since 10
   */
  function openDLPFile(cipherTextFd: number, callback: AsyncCallback<DLPFile>): void;
}
export default dlpPermission;
