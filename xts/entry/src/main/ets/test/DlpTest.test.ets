/**
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
import dlpPermission from '@ohos.dlpPermission';
import fs from '@ohos.file.fs';
import account from '@ohos.account.distributedAccount'
import account_osAccount from '@ohos.account.osAccount';
import type Want from '@ohos.app.ability.Want';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from '@ohos/hypium'
import bundle from '@ohos.bundle';

var DLPErrCode = {
  DLP_OK: 0,
  ERR_JS_PERMISSION_DENY: 201,
  ERR_JS_NOT_SYSTEM_APP: 202,
  ERR_JS_PARAMETER_ERROR: 401,
  ERR_JS_INVALID_PARAMETER: 19100001,
  ERR_JS_BEGIN_CREDENTIAL_FAIL: 19100002,
  ERR_JS_CREDENTIAL_TIMEOUT: 19100003,
  ERR_JS_CREDENTIAL_SERVICE_ERROR: 19100004,
  ERR_JS_CREDENTIAL_SERVER_ERROR: 19100005,
  ERR_JS_API_FOR_SANDBOX_ERROR: 19100006,
  ERR_JS_API_NOT_FOR_SANDBOX_ERROR: 19100007,
  ERR_JS_NOT_DLP_FILE: 19100008,
  ERR_JS_OPERATE_DLP_FILE_FAIL: 19100009,
  ERR_JS_DLP_FILE_READ_ONLY: 19100010,
  ERR_JS_SYSTEM_SERVICE_EXCEPTION: 19100011,
  ERR_JS_OUT_OF_MEMORY: 19100012,
};

export class TestDlpFileInfo {
  dlpFile: dlpPermission.DLPFile = null;
  plaintextPath: string = '';
  ciphertextPath: string = '';
  plaintextFd: number = -1;
  ciphertextFd: number = -1;
}

const TAG = "DLP_XTS ";
var user1: dlpPermission.AuthUser = {
  "authAccount": "123@ohos.com",
  "authAccountType": dlpPermission.AccountType.CLOUD_ACCOUNT,
  "dlpFileAccess": dlpPermission.DLPFileAccess.READ_ONLY,
  "permExpiryTime": 8888520175,
};
var user2: dlpPermission.AuthUser = {
  "authAccount": "456@ohos.com",
  "authAccountType": dlpPermission.AccountType.CLOUD_ACCOUNT,
  "dlpFileAccess": dlpPermission.DLPFileAccess.FULL_CONTROL,
  "permExpiryTime": 8888520175,
};

var userList = new Array(2);
userList[0] = user1;
userList[1] = user2;

var userId;

const accountAbility = account.getDistributedAccountAbility()
const bundleName = "com.ohos.dlp_xts"
const rootDir = "/data/storage/el1/base/"

export default function dlpTest() {
  describe('dlpTest', function () {
    // 获取帐号信息
    async function getOsAccountInfo(): Promise<account_osAccount.OsAccountInfo> {
      try {
        let accountMgr = account_osAccount.getAccountManager();
        return await accountMgr.getCurrentOsAccount();
      } catch (err) {
        console.error(TAG, 'getCurrentOsAccount failed', err.code, err.message);
        expect(false).assertTrue();
      }
    }

    // 帐号登录
    async function AccountLogin(accountName) {
      await AccountLogout()
      var info = {
        name: "",
        id: "1234",
        event: "Ohos.account.event.LOGIN",
        nickname: "nickname",
        avatar: "avatar"
      }
      info.name = accountName
      info.event = "Ohos.account.event.LOGIN"
      try {
        await accountAbility.setOsAccountDistributedInfo(info)
      } catch (err) {
        console.error(TAG, "setOsAccountDistributedInfo LOGIN failed", err.code, err.message);
        expect(null).assertFail()
        return
      }
      var user = await accountAbility.getOsAccountDistributedInfo()
      expect(user.name).assertEqual(accountName)
    }

    // 帐号登出
    async function AccountLogout() {
      try {
        var accountInfo = await accountAbility.getOsAccountDistributedInfo();
      } catch (err) {
        console.error(TAG, "getOsAccountDistributedInfo failed", err.code, err.message);
        expect(null).assertFail();
        return
      }
      var info = {
        name: "",
        id: "1234",
        event: "Ohos.account.event.LOGIN",
        nickname: "nickname",
        avatar: "avatar"
      }
      if (accountInfo.name === "ohosAnonymousName") {
        return
      }
      info.name = accountInfo.name
      info.event = "Ohos.account.event.LOGOUT"
      try {
        await accountAbility.setOsAccountDistributedInfo(info)
      } catch (err) {
        console.error(TAG, "setOsAccountDistributedInfo LOGOUT failed", err.code, err.message);
        expect(null).assertFail()
        return
      }
      var user = await accountAbility.getOsAccountDistributedInfo()
      expect(user.name).assertEqual("ohosAnonymousName")
    }

    // 生成文件
    function genFile(path, content?) {
      try {
        var file = fs.openSync(path, fs.OpenMode.CREATE | fs.OpenMode.READ_WRITE);
        let fd = file.fd;
        if (content !== undefined) {
          fs.writeSync(fd, content);
        }
        return fd;
      } catch (err) {
        console.error(TAG, 'openSync', path, 'failed', err.code, err.message);
        return -1;
      }
    }

    // 生成可选参数的DLP策略
    async function genTestOptionalDlpProperty(): Promise<dlpPermission.DLPProperty> {
      var accountInfo = await getOsAccountInfo();
      var property: dlpPermission.DLPProperty = {
        "ownerAccount": accountInfo.distributedInfo.name,
        "ownerAccountID": accountInfo.distributedInfo.id,
        "ownerAccountType": dlpPermission.AccountType.CLOUD_ACCOUNT,
        "contactAccount": accountInfo.distributedInfo.name,
        "offlineAccess": true,
      };
      return property;
    }

    // 生成DLP策略
    async function genTestDlpProperty(): Promise<dlpPermission.DLPProperty> {
      var accountInfo = await getOsAccountInfo();
      var property: dlpPermission.DLPProperty = {
        "ownerAccount": accountInfo.distributedInfo.name,
        "ownerAccountID": accountInfo.distributedInfo.id,
        "ownerAccountType": dlpPermission.AccountType.CLOUD_ACCOUNT,
        "authUserList": userList,
        "contactAccount": accountInfo.distributedInfo.name,
        "offlineAccess": true,
        "everyoneAccessList": [],
      };
      return property;
    }

    // 生成测试DLP文件
    async function genTestDlpFile(): Promise<TestDlpFileInfo> {
      let dlpInfo: TestDlpFileInfo = new TestDlpFileInfo();
      dlpInfo.plaintextPath = rootDir + "test_dlp.txt";
      dlpInfo.ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      dlpInfo.plaintextFd = genFile(dlpInfo.plaintextPath, writeContent);
      expect(dlpInfo.plaintextFd >= 0).assertTrue();
      dlpInfo.ciphertextFd = genFile(dlpInfo.ciphertextPath);
      expect(dlpInfo.ciphertextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();

      try {
        var dlpFile = await dlpPermission.generateDLPFile(dlpInfo.plaintextFd, dlpInfo.ciphertextFd, property);
        expect(true).assertTrue()
        dlpInfo.dlpFile = dlpFile;
        return dlpInfo;
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(dlpInfo.plaintextFd);
        fs.closeSync(dlpInfo.ciphertextFd);
        fs.unlinkSync(dlpInfo.ciphertextPath);
        fs.unlinkSync(dlpInfo.plaintextPath);
        expect(false).assertTrue()
        return null;
      }
    }

    // 关闭测试DLP文件
    async function closeTestDlpFile(dlpInfo: TestDlpFileInfo) {
      try {
        await dlpInfo.dlpFile.closeDLPFile();
      } catch (err) {
        console.error(TAG, "closeDLPFile failed", err.code, err.message);
      }
      fs.closeSync(dlpInfo.plaintextFd);
      fs.closeSync(dlpInfo.ciphertextFd);
      fs.unlinkSync(dlpInfo.ciphertextPath);
      fs.unlinkSync(dlpInfo.plaintextPath);
    }

    function timeOut() {
      return new Promise((resolve) => {
        setTimeout(() => {
          resolve('')
        }, 200)
      })
    }

    beforeAll(async function () {
      // Presets an action, which is performed only once before all test cases of the test suite start.
      // This API supports only one parameter: preset action function.
      await AccountLogin("owner@ohos.com");
      const accountMgr = account_osAccount.getAccountManager();
      userId = await accountMgr.getOsAccountLocalIdFromProcess();
    })
    beforeEach(function () {
      // Presets an action, which is performed before each unit test case starts.
      // The number of execution times is the same as the number of test cases defined by **it**.
      // This API supports only one parameter: preset action function.
    })
    afterEach(function () {
      // Presets a clear action, which is performed after each unit test case ends.
      // The number of execution times is the same as the number of test cases defined by **it**.
      // This API supports only one parameter: clear action function.
      let files = fs.listFileSync(rootDir);
      if (files.length != 0) {
        console.error(TAG, "tmp file need delete", files);
      }
    })
    afterAll(async function () {
      // Presets a clear action, which is performed after all test cases of the test suite end.
      // This API supports only one parameter: clear action function.
      await AccountLogout();
    })

    /**
     * @tc.number Test_generateDLPFile_001
     * @tc.name Test dlpPermission.generateDLPFile.
     * @tc.desc generateDLPFile success (Promise).
     */
    it('Test_generateDLPFile_001', 0, async function () {
      var curTag = TAG + "Test_generateDLPFile_001";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();

      try {
        var dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);

        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }

      try {
        await dlpFile.closeDLPFile();
      } catch (err) {
        console.error(TAG, "closeDLPFile failed", err.code, err.message);
        expect(false).assertTrue();
      }
      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);

      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_generateDLPFile_002
     * @tc.name Test dlpPermission.generateDLPFile.
     * @tc.desc generateDLPFile success (Callback).
     */
    it('Test_generateDLPFile_002', 0, async function (done) {
      var curTag = TAG + "Test_generateDLPFile_002";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();

      dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property, async (err, dlpFile) => {
        expect(err).assertEqual(null);
        expect(typeof (dlpFile)).assertEqual("object");
        expect(typeof (dlpFile.dlpProperty)).assertEqual("object");
        try {
          await dlpFile.closeDLPFile();
        } catch (err) {
          console.error(TAG, "closeDLPFile failed", err.code, err.message);
          expect(false).assertTrue();
        }
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);

        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_generateDLPFile_003
     * @tc.name Test dlpPermission.generateDLPFile.
     * @tc.desc generateDLPFile with optional param (Promise).
     */
    it('Test_generateDLPFile_003', 0, async function () {
      var curTag = TAG + "Test_generateDLPFile_003";
      console.info(curTag, "start");


      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      // property has optional param
      var property = await genTestOptionalDlpProperty();

      try {
        let dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(true).assertTrue();
        try {
          await dlpFile.closeDLPFile();
        } catch (err) {
          console.error(TAG, "closeDLPFile failed", err.code, err.message);
          expect(false).assertTrue();
        }
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        expect(false).assertTrue();
      }

      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);

      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_generateDLPFile_004
     * @tc.name Test dlpPermission.generateDLPFile.
     * @tc.desc generateDLPFile with optianal param (Callback).
     */
    it('Test_generateDLPFile_004', 0, async function (done) {
      var curTag = TAG + "Test_generateDLPFile_004";
      console.info(curTag, "start");


      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      // property has optional param
      let property = await genTestOptionalDlpProperty();
      dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property, async (err, dlpFile) => {
        expect(err).assertEqual(null);
        try {
          await dlpFile.closeDLPFile();
        } catch (err) {
          console.error(TAG, "closeDLPFile failed", err.code, err.message);
          expect(false).assertTrue();
        }
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);

        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_generateDLPFile_005
     * @tc.name Test dlpPermission.generateDLPFile.
     * @tc.desc generateDLPFile with invalid plaintextFd (Promise).
     */
    it('Test_generateDLPFile_005', 0, async function () {
      var curTag = TAG + "Test_generateDLPFile_005";
      console.info(curTag, "start");


      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();

      try { // plaintextFd invalid
        let dlpFile = await dlpPermission.generateDLPFile(-1, ciphertextFd, property);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        expect(true).assertTrue();
      }

      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);

      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_generateDLPFile_006
     * @tc.name Test dlpPermission.generateDLPFile.
     * @tc.desc generateDLPFile with invalid plaintextFd (Callback).
     */
    it('Test_generateDLPFile_006', 0, async function (done) {
      var curTag = TAG + "Test_generateDLPFile_006";
      console.info(curTag, "start");


      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();

      // plaintextFd invalid
      dlpPermission.generateDLPFile(-1, ciphertextFd, property, async (err, dlpFile) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);

        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_generateDLPFile_007
     * @tc.name Test dlpPermission.generateDLPFile.
     * @tc.desc generateDLPFile with invalid ciphertextFd (Promise).
     */
    it('Test_generateDLPFile_007', 0, async function () {
      var curTag = TAG + "Test_generateDLPFile_007";
      console.info(curTag, "start");


      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();

      try { // ciphertextFd invalid
        let dlpFile = await dlpPermission.generateDLPFile(plaintextFd, -1, property);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        expect(true).assertTrue();
      }

      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);

      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_generateDLPFile_008
     * @tc.name Test dlpPermission.generateDLPFile.
     * @tc.desc generateDLPFile with invalid ciphertextFd (Callback).
     */
    it('Test_generateDLPFile_008', 0, async function (done) {
      var curTag = TAG + "Test_generateDLPFile_008";
      console.info(curTag, "start");


      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();

      // ciphertextFd invalid
      dlpPermission.generateDLPFile(plaintextFd, -1, property, async (err, dlpFile) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);

        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_generateDLPFile_009
     * @tc.name Test dlpPermission.generateDLPFile.
     * @tc.desc generateDLPFile with invalid property (Promise).
     */
    it('Test_generateDLPFile_009', 0, async function () {
      var curTag = TAG + "Test_generateDLPFile_009";
      console.info(curTag, "start");


      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      try { // property invalid
        property.ownerAccountType = 0;
        let dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        expect(true).assertTrue();
      }

      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);

      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_generateDLPFile_010
     * @tc.name Test dlpPermission.generateDLPFile.
     * @tc.desc generateDLPFile with invalid property (Callback).
     */
    it('Test_generateDLPFile_010', 0, async function (done) {
      var curTag = TAG + "Test_generateDLPFile_010";
      console.info(curTag, "start");


      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // property invalid
      property.ownerAccountType = 0;
      dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property, async (err, dlpFile) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_getDLPSupportedFileTypes_001
     * @tc.name Test dlpPermission.getDLPSupportedFileTypes.
     * @tc.desc generateDLPFile success (Promise).
     */
    it('Test_getDLPSupportedFileTypes_001', 0, async function () {
      var curTag = TAG + "Test_getDLPSupportedFileTypes_001";
      console.info(curTag, "start");

      try {
        var fileTypes = await dlpPermission.getDLPSupportedFileTypes();
        expect(typeof (fileTypes)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "getDLPSupportedFileTypes failed", err.code, err.message);

        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }

      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_getDLPSupportedFileTypes_002
     * @tc.name Test dlpPermission.getDLPSupportedFileTypes.
     * @tc.desc generateDLPFile success (Callback).
     */
    it('Test_getDLPSupportedFileTypes_002', 0, async function (done) {
      var curTag = TAG + "Test_generateDLPFile_002";
      console.info(curTag, "start");

      dlpPermission.getDLPSupportedFileTypes(async (err, fileTypes) => {
        expect(err).assertEqual(null);
        expect(typeof (fileTypes)).assertEqual("object");

        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_setRetentionState_001
     * @tc.name Test dlpPermission.setRetentionState.
     * @tc.desc setRetentionState not from sandbox fail with code 19100006 (Promise).
     */
    it('Test_setRetentionState_001', 0, async function () {
      var curTag = TAG + "Test_setRetentionState_001";
      console.info(curTag, "start");

      try {
        var uriArray = ['uri'];
        await dlpPermission.setRetentionState(uriArray);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_API_FOR_SANDBOX_ERROR);
      }

      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_setRetentionState_002
     * @tc.name Test dlpPermission.setRetentionState.
     * @tc.desc setRetentionState not from sandbox fail with code 19100006 (Callback).
     */
    it('Test_setRetentionState_002', 0, async function (done) {
      var curTag = TAG + "Test_setRetentionState_002";
      console.info(curTag, "start");

      var uriArray = ['uri'];
      dlpPermission.setRetentionState(uriArray, async (err) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_API_FOR_SANDBOX_ERROR);
        console.info(curTag, "end");
        done();
      });
    });

    /**
     * @tc.number Test_setRetentionState_003
     * @tc.name Test dlpPermission.setRetentionState.
     * @tc.desc setRetentionState sandbox  call success  (Callback).
     */
    it('Test_setRetentionState_003', 0, async function (done) {
      var curTag = TAG + "Test_setRetentionState_003";
      console.info(curTag, "start");
      var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, 'uri');
      let want: Want = {
        "abilityName": "SetRetentionStateCallback",
        "bundleName": bundleName,
        "parameters": {
          'ohos.dlp.params.index': sandboxInfo.appIndex,
          'ohos.dlp.params.success': true
        }
      }
      let result;
      try {
        result = await globalThis.context.startAbilityForResult(want);
      } catch (err) {
        console.info(curTag, "startAbility failed", err.code, err.message);
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      var uriArray = ['uri'];
      await dlpPermission.cancelRetentionState(uriArray);
      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.info(curTag, "uninstallDLPSandbox failed", err.code, err.message);
      }
      expect(result.resultCode).assertEqual(0);
      console.info(curTag, "end");
      done();
    })

    /**
     * @tc.number Test_setRetentionState_004
     * @tc.name Test dlpPermission.setRetentionState.
     * @tc.desc setRetentionState sandbox call success  (Promise).
     */
    it('Test_setRetentionState_004', 0, async function (done) {
      var curTag = TAG + "Test_setRetentionState_004";
      console.info(curTag, "start", bundleName);
      var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, 'uri');
      let want: Want = {
        "abilityName": "SetRetentionStatePromise",
        "bundleName": bundleName,
        "parameters": {
          'ohos.dlp.params.index': sandboxInfo.appIndex,
          'ohos.dlp.params.success': true
        }
      };
      let result;
      try {
        result = await globalThis.context.startAbilityForResult(want);
      } catch (err) {
        console.info(curTag, "startAbility failed", err.code, err.message);
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      var uriArray = ['uri'];
      await dlpPermission.cancelRetentionState(uriArray);
      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.info(curTag, "uninstallDLPSandbox failed", err.code, err.message);
      }
      expect(result.resultCode).assertEqual(0);
      console.info(curTag, "end");
      done();
    })

    /**
     * @tc.number Test_setRetentionState_005
     * @tc.name Test dlpPermission.setRetentionState.
     * @tc.desc setRetentionState sandbox  call parameter error  (Callback).
     */
    it('Test_setRetentionState_005', 0, async function (done) {
      var curTag = TAG + "Test_setRetentionState_005";
      console.info(curTag, "start");
      var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, 'uri');
      let want: Want = {
        "abilityName": "SetRetentionStateCallback",
        "bundleName": bundleName,
        "parameters": {
          'ohos.dlp.params.index': sandboxInfo.appIndex,
          'ohos.dlp.params.success': false
        }
      }
      let result;
      try {
        result = await globalThis.context.startAbilityForResult(want);
      } catch (err) {
        console.info(curTag, "startAbility failed", err.code, err.message);
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      expect(result.resultCode).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.info(curTag, "uninstallDLPSandbox failed", err.code, err.message);
      }
      console.info(curTag, "end");
      done();
    })

    /**
     * @tc.number Test_setRetentionState_006
     * @tc.name Test dlpPermission.setRetentionState.
     * @tc.desc setRetentionState sandbox call parameter error  (Promise).
     */
    it('Test_setRetentionState_006', 0, async function (done) {
      var curTag = TAG + "Test_setRetentionState_006";
      console.info(curTag, "start", bundleName);
      var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, 'uri');
      let want: Want = {
        "abilityName": "SetRetentionStatePromise",
        "bundleName": bundleName,
        "parameters": {
          'ohos.dlp.params.index': sandboxInfo.appIndex,
          'ohos.dlp.params.success': false
        }
      };
      let result;
      try {
        result = await globalThis.context.startAbilityForResult(want);
      } catch (err) {
        console.info(curTag, "startAbility failed", err.code, err.message);
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      expect(result.resultCode).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.info(curTag, "uninstallDLPSandbox failed", err.code, err.message);
      }
      console.info(curTag, "end");
      done();
    })

    /**
     * @tc.number Test_cancelRetentionState_001
     * @tc.name Test dlpPermission.cancelRetentionState.
     * @tc.desc cancelRetentionState success (Promise).
     */
    it('Test_cancelRetentionState_001', 0, async function () {
      var curTag = TAG + "Test_cancelRetentionState_001";
      console.info(curTag, "start");

      try {
        var uriArray = ['uri'];
        await dlpPermission.cancelRetentionState(uriArray);
        expect(true).assertTrue();
      } catch (err) {
        console.error(curTag, "cancelRetentionState failed", err.code, err.message);
        expect(false).assertTrue();
      }

      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_cancelRetentionState_002
     * @tc.name Test dlpPermission.cancelRetentionState.
     * @tc.desc cancelRetentionState success (Callback).
     */
    it('Test_cancelRetentionState_002', 0, async function (done) {
      var curTag = TAG + "Test_cancelRetentionState_002";
      console.info(curTag, "start");

      var uriArray = ['uri'];
      dlpPermission.cancelRetentionState(uriArray, async (err) => {
        expect(err).assertEqual(null);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_cancelRetentionState_003
     * @tc.name Test dlpPermission.cancelRetentionState.
     * @tc.desc cancelRetentionState invalid docUris  (Promise).
     */
    it('Test_cancelRetentionState_003', 0, async function () {
      var curTag = TAG + "Test_cancelRetentionState_003";
      console.info(curTag, "start");

      try {
        var docUris = [];
        await dlpPermission.cancelRetentionState(docUris);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code === DLPErrCode.ERR_JS_INVALID_PARAMETER).assertTrue();
      }

      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_cancelRetentionState_004
     * @tc.name Test dlpPermission.cancelRetentionState.
     * @tc.desc cancelRetentionState invalid docUris  (Callback).
     */
    it('Test_cancelRetentionState_004', 0, async function (done) {
      var curTag = TAG + "Test_cancelRetentionState_004";
      console.info(curTag, "start");

      var docUris = [];
      dlpPermission.cancelRetentionState(docUris, async (err) => {
        expect(err.code === DLPErrCode.ERR_JS_INVALID_PARAMETER).assertTrue();

        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_getRetentionSandboxList_001
     * @tc.name Test dlpPermission.getRetentionSandboxList
     * @tc.desc getRetentionSandboxList with bundle name success (Promise).
     */
    it('Test_getRetentionSandboxList_001', 0, async function () {
      var curTag = TAG + "Test_getRetentionSandboxList_001";
      console.info(curTag, "start");
      let uri = 'uri';
      var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, uri);
      let want: Want = {
        "abilityName": "SetRetentionStatePromise",
        "bundleName": bundleName,
        "parameters": {
          'ohos.dlp.params.index': sandboxInfo.appIndex,
          'ohos.dlp.params.success': true
        }
      };
      let result;
      try {
        result = await globalThis.context.startAbilityForResult(want);
        expect(result.resultCode).assertEqual(0);
      } catch (err) {
        console.info(curTag, "startAbility failed", err.code, err.message);
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }

      try {
        var uriArray = await dlpPermission.getRetentionSandboxList(bundleName);
        expect(typeof (uriArray)).assertEqual("object");
        expect(uriArray[0].docUris[0]).assertEqual(uri);
      } catch (err) {
        console.error(curTag, "setRetentionState failed", err.code, err.message);
        expect(false).assertTrue();
      }

      try {
        await dlpPermission.cancelRetentionState([uri]);
        expect(true).assertTrue();
      } catch (err) {
        console.error(curTag, "cancelRetentionState failed", err.code, err.message);
        expect(false).assertTrue();
      }

      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.info(curTag, "uninstallDLPSandbox failed", err.code, err.message);
      }

      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_getRetentionSandboxList_002
     * @tc.name Test dlpPermission.getRetentionSandboxList.
     * @tc.desc getRetentionSandboxList with bundleName success (Callback).
     */
    it('Test_getRetentionSandboxList_002', 0, async function (done) {
      var curTag = TAG + "Test_getRetentionSandboxList_002";
      console.info(curTag, "start");

      let uri = 'uri';
      var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, uri);
      let want: Want = {
        "abilityName": "SetRetentionStatePromise",
        "bundleName": bundleName,
        "parameters": {
          'ohos.dlp.params.index': sandboxInfo.appIndex,
          'ohos.dlp.params.success': true
        }
      };
      let result;
      try {
        result = await globalThis.context.startAbilityForResult(want);
        expect(result.resultCode).assertEqual(0);
      } catch (err) {
        console.info(curTag, "startAbility failed", err.code, err.message);
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }

      dlpPermission.getRetentionSandboxList(bundleName, async (err, data) => {
        expect(err).assertEqual(null);
        try {
          await dlpPermission.cancelRetentionState([uri]);
          expect(true).assertTrue();
        } catch (err) {
          console.error(curTag, "cancelRetentionState failed", err.code, err.message);
          expect(false).assertTrue();
        }

        try {
          await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        } catch (err) {
          console.info(curTag, "uninstallDLPSandbox failed", err.code, err.message);
        }
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_getRetentionSandboxList_003
     * @tc.name Test dlpPermission.getRetentionSandboxList
     * @tc.desc getRetentionSandboxList without bundle name success (Promise).
     */
    it('Test_getRetentionSandboxList_003', 0, async function () {
      var curTag = TAG + "Test_getRetentionSandboxList_003";
      console.info(curTag, "start");

      try {
        var uriArray = await dlpPermission.getRetentionSandboxList();
        expect(typeof (uriArray)).assertEqual("object");
      } catch (err) {
        console.error(curTag, "getRetentionSandboxList failed", err.code, err.message);
        expect(false).assertTrue();
      }

      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_getRetentionSandboxList_004
     * @tc.name Test dlpPermission.getRetentionSandboxList.
     * @tc.desc getRetentionSandboxList without bundleName success (Callback).
     */
    it('Test_getRetentionSandboxList_004', 0, async function (done) {
      var curTag = TAG + "Test_getRetentionSandboxList_004";
      console.info(curTag, "start");

      dlpPermission.getRetentionSandboxList(async (err, data) => {
        expect(err).assertEqual(null);

        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_getRetentionSandboxList_005
     * @tc.name Test dlpPermission.getRetentionSandboxList.
     * @tc.desc getRetentionSandboxList sandbox not allow call error  (Callback).
     */
    it('Test_getRetentionSandboxList_005', 0, async function (done) {
      var curTag = TAG + "Test_getRetentionSandboxList_005";
      console.info(curTag, "start");
      var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, 'uri');
      let want: Want = {
        "abilityName": "GetRetentionSandboxListCallback",
        "bundleName": bundleName,
        "parameters": {
          'ohos.dlp.params.index': sandboxInfo.appIndex,
        }
      }

      try {
        let result = await globalThis.context.startAbilityForResult(want);
        expect(result.resultCode).assertEqual(DLPErrCode.ERR_JS_API_NOT_FOR_SANDBOX_ERROR);
      } catch (err) {
        console.info(curTag, "startAbility failed", err.code, err.message);
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.info(curTag, "uninstallDLPSandbox failed", err.code, err.message);
      }
      console.info(curTag, "end");
      done();
    })

    /**
     * @tc.number Test_getRetentionSandboxList_006
     * @tc.name Test dlpPermission.getRetentionSandboxList.
     * @tc.desc getRetentionSandboxList sandbox not allow call error  (Promise).
     */
    it('Test_getRetentionSandboxList_006', 0, async function (done) {
      var curTag = TAG + "Test_getRetentionSandboxList_006";
      console.info(curTag, "start");
      var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, 'uri');
      let want: Want = {
        "abilityName": "GetRetentionSandboxListPromise",
        "bundleName": bundleName,
        "parameters": {
          'ohos.dlp.params.index': sandboxInfo.appIndex,
        }
      }
      let result;
      try {
        result = await globalThis.context.startAbilityForResult(want);
      } catch (err) {
        console.info(curTag, "startAbility failed", err.code, err.message);
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.info(curTag, "uninstallDLPSandbox failed", err.code, err.message);
      }
      expect(result.resultCode).assertEqual(DLPErrCode.ERR_JS_API_NOT_FOR_SANDBOX_ERROR);
      console.info(curTag, "end");
      done();
    })

    /**
     * @tc.number Test_getRetentionSandboxList_007
     * @tc.name Test dlpPermission.getRetentionSandboxList
     * @tc.desc getRetentionSandboxList  invalid parameter (Promise).
     */
    it('Test_getRetentionSandboxList_007', 0, async function () {
      var curTag = TAG + "Test_getRetentionSandboxList_007";
      console.info(curTag, "start");
      try {
        // @ts-ignore
        var uriArray = await dlpPermission.getRetentionSandboxList(-1);
        expect(false).assertEqual(true);
      } catch (err) {
        expect(true).assertTrue();
      }
      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_getRetentionSandboxList_008
     * @tc.name Test dlpPermission.getRetentionSandboxList.
     * @tc.desc getRetentionSandboxList without bundleName success (Callback).
     */
    it('Test_getRetentionSandboxList_008', 0, async function (done) {
      var curTag = TAG + "Test_getRetentionSandboxList_008";
      console.info(curTag, "start");
      try {
        // @ts-ignore
        dlpPermission.getRetentionSandboxList(-1, async (err, data) => {
          expect(false).assertTrue();
          console.info(curTag, "end");
          done();
        });
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_PARAMETER_ERROR);
        console.info(curTag, "end");
        done();
        return;
      }
      expect(false).assertTrue();
      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_getDLPFileAccessRecords_001
     * @tc.name Test dlpPermission.getDLPFileAccessRecords
     * @tc.desc getDLPFileAccessRecords success (Promise).
     */
    it('Test_getDLPFileAccessRecords_001', 0, async function () {
      var curTag = TAG + "Test_getDLPFileAccessRecords_001";
      console.info(curTag, "start");
      var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, 'uri');
      try {
        var accessRecords = await dlpPermission.getDLPFileAccessRecords();
        expect(typeof (accessRecords)).assertEqual("object");
        expect(accessRecords.length).assertLarger(0);
        expect(accessRecords[accessRecords.length - 1].lastOpenTime).assertLarger(0);
        expect(accessRecords[accessRecords.length - 1].uri).assertEqual('uri');
      } catch (err) {
        console.error(curTag, "getDLPFileAccessRecords failed", err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.info(curTag, "uninstallDLPSandbox failed", err.code, err.message);
      }
      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_getDLPFileAccessRecords_002
     * @tc.name Test dlpPermission.getDLPFileAccessRecords.
     * @tc.desc getDLPFileAccessRecords success (Callback).
     */
    it('Test_getDLPFileAccessRecords_002', 0, async function (done) {
      var curTag = TAG + "Test_getRetentionSandboxList_002";
      console.info(curTag, "start");
      var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, 'uri');
      dlpPermission.getDLPFileAccessRecords(async (err, accessRecords) => {
        expect(err).assertEqual(null);
        expect(accessRecords.length).assertLarger(0);
        expect(accessRecords[accessRecords.length - 1].lastOpenTime).assertLarger(0);
        expect(accessRecords[accessRecords.length - 1].uri).assertEqual('uri');
        try {
          await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        } catch (err) {
          console.info(curTag, "uninstallDLPSandbox failed", err.code, err.message);
        }
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_getDLPFileAccessRecords_003
     * @tc.name Test dlpPermission.getDLPFileAccessRecords.
     * @tc.desc getDLPFileAccessRecords sandbox not allow call error  (Callback).
     */
    it('Test_getDLPFileAccessRecords_003', 0, async function (done) {
      var curTag = TAG + "Test_getDLPFileAccessRecords_003";
      console.info(curTag, "start");
      var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, 'uri');
      let want: Want = {
        "abilityName": "GetDLPFileAccessRecordsCallback",
        "bundleName": bundleName,
        "parameters": {
          'ohos.dlp.params.index': sandboxInfo.appIndex,
        }
      }
      let result;
      try {
        result = await globalThis.context.startAbilityForResult(want);
      } catch (err) {
        console.info(curTag, "startAbility failed", err.code, err.message);
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.info(curTag, "uninstallDLPSandbox failed", err.code, err.message);
      }
      expect(result.resultCode).assertEqual(DLPErrCode.ERR_JS_API_NOT_FOR_SANDBOX_ERROR);
      console.info(curTag, "end");
      done();
    })

    /**
     * @tc.number Test_getDLPFileAccessRecords_004
     * @tc.name Test dlpPermission.getDLPFileAccessRecords.
     * @tc.desc getDLPFileAccessRecords sandbox not allow call error  (Promise).
     */
    it('Test_getDLPFileAccessRecords_004', 0, async function (done) {
      var curTag = TAG + "Test_getDLPFileAccessRecords_004";
      console.info(curTag, "start");
      var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, 'uri');
      let want: Want = {
        "abilityName": "GetDLPFileAccessRecordsPromise",
        "bundleName": bundleName,
        "parameters": {
          'ohos.dlp.params.index': sandboxInfo.appIndex,
        }
      }
      let result;
      try {
        result = await globalThis.context.startAbilityForResult(want);
      } catch (err) {
        console.info(curTag, "startAbility failed", err.code, err.message);
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.info(curTag, "uninstallDLPSandbox failed", err.code, err.message);
      }
      expect(result.resultCode).assertEqual(DLPErrCode.ERR_JS_API_NOT_FOR_SANDBOX_ERROR);
      console.info(curTag, "end");
      done();
    })

    /**
     * @tc.number Test_getDLPGatheringPolicy_001
     * @tc.name Test dlpPermission.getDLPGatheringPolicy
     * @tc.desc getDLPGatheringPolicy success (Promise).
     */
    it('Test_getDLPGatheringPolicy_001', 0, async function () {
      var curTag = TAG + "Test_getDLPGatheringPolicy_001";
      console.info(curTag, "start");
      try {
        var policy = await dlpPermission.getDLPGatheringPolicy();
        expect(typeof (policy)).assertEqual("number");
        expect(policy).assertLargerOrEqual(dlpPermission.GatheringPolicyType.GATHERING);
        expect(policy).assertLessOrEqual(dlpPermission.GatheringPolicyType.NON_GATHERING);
      } catch (err) {
        console.error(curTag, "getDLPGatheringPolicy failed", err.code, err.message);
        expect(false).assertTrue();

      }
      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_getDLPGatheringPolicy_002
     * @tc.name Test dlpPermission.getDLPGatheringPolicy.
     * @tc.desc getDLPGatheringPolicy success (Callback).
     */
    it('Test_getDLPGatheringPolicy_002', 0, async function (done) {
      var curTag = TAG + "Test_getDLPGatheringPolicy_002";
      console.info(curTag, "start");

      dlpPermission.getDLPGatheringPolicy(async (err, data) => {
        expect(err).assertEqual(null);

        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_installDLPSandbox_001
     * @tc.name Test dlpPermission.installDLPSandbox
     * @tc.desc installDLPSandbox success (Promise).
     */
    it('Test_installDLPSandbox_001', 0, async function () {
      var curTag = TAG + "Test_installDLPSandbox_001";
      console.info(curTag, "start");
      var dlpFileAccess = dlpPermission.DLPFileAccess.READ_ONLY;
      var uri = "uri";
      try {
        var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpFileAccess, userId, uri);
        expect(typeof (sandboxInfo)).assertEqual("object");
        expect(sandboxInfo.tokenID).assertLarger(0);
      } catch (err) {
        console.error(curTag, "installDLPSandbox failed", err.code, err.message);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        expect(true).assertTrue();
      } catch (err) {
        console.error(curTag, "uninstallDLPSandbox failed", err.code, err.message);
        expect(false).assertTrue();
      }
      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_installDLPSandbox_002
     * @tc.name Test dlpPermission.installDLPSandbox
     * @tc.desc installDLPSandbox success (Callback).
     */
    it('Test_installDLPSandbox_002', 0, async function (done) {
      var curTag = TAG + "Test_installDLPSandbox_002";
      console.info(curTag, "start");
      var dlpFileAccess = dlpPermission.DLPFileAccess.READ_ONLY;
      var uri = "uri";
      await dlpPermission.installDLPSandbox(bundleName, dlpFileAccess, userId, uri, async (err, sandboxInfo) => {
        expect(err).assertEqual(null);
        expect(typeof (sandboxInfo)).assertEqual("object");
        expect(sandboxInfo.tokenID).assertLarger(0);
        try {
          await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
          expect(true).assertTrue();
        } catch (err) {
          console.error(curTag, "uninstallDLPSandbox failed", err.code, err.message);
          expect(false).assertTrue();
        }
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_installDLPSandbox_003
     * @tc.name Test dlpPermission.installDLPSandbox
     * @tc.desc installDLPSandbox empty  bundleName (Promise).
     */
    it('Test_installDLPSandbox_003', 0, async function () {
      var curTag = TAG + "Test_installDLPSandbox_003";
      console.info(curTag, "start");
      var dlpFileAccess = dlpPermission.DLPFileAccess.READ_ONLY;
      var uri = "uri";
      try {
        var sandboxInfo = await dlpPermission.installDLPSandbox("", dlpFileAccess, userId, uri);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
      }
      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_installDLPSandbox_004
     * @tc.name Test dlpPermission.installDLPSandbox
     * @tc.desc installDLPSandbox empty  bundleName (Callback).
     */
    it('Test_installDLPSandbox_004', 0, async function (done) {
      var curTag = TAG + "Test_installDLPSandbox_004";
      console.info(curTag, "start");
      var dlpFileAccess = dlpPermission.DLPFileAccess.READ_ONLY;
      var uri = "uri";
      await dlpPermission.installDLPSandbox("", dlpFileAccess, userId, uri, async (err, sandboxInfo) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_installDLPSandbox_005
     * @tc.name Test dlpPermission.installDLPSandbox
     * @tc.desc installDLPSandbox NO_PERMISSION (Promise).
     */
    it('Test_installDLPSandbox_005', 0, async function () {
      var curTag = TAG + "Test_installDLPSandbox_005";
      console.info(curTag, "start");
      var uri = "uri";
      try {
        var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.NO_PERMISSION, userId, uri);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        console.info(curTag, "end");
        return;
      }
      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_installDLPSandbox_006
     * @tc.name Test dlpPermission.installDLPSandbox
     * @tc.desc installDLPSandbox NO_PERMISSION (Callback).
     */
    it('Test_installDLPSandbox_006', 0, async function (done) {
      var curTag = TAG + "Test_installDLPSandbox_006";
      console.info(curTag, "start");
      var uri = "uri";
      await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.NO_PERMISSION, userId, uri, async (err, sandboxInfo) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_installDLPSandbox_007
     * @tc.name Test dlpPermission.installDLPSandbox
     * @tc.desc installDLPSandbox invalid userId (Promise).
     */
    it('Test_installDLPSandbox_007', 0, async function () {
      var curTag = TAG + "Test_installDLPSandbox_007";
      console.info(curTag, "start");
      var dlpFileAccess = dlpPermission.DLPFileAccess.NO_PERMISSION;
      var uri = "uri";
      try {
        await dlpPermission.installDLPSandbox(bundleName, dlpFileAccess, -1, uri);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
      }
      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_installDLPSandbox_008
     * @tc.name Test dlpPermission.installDLPSandbox
     * @tc.desc installDLPSandbox invalid userId (Callback).
     */
    it('Test_installDLPSandbox_008', 0, async function (done) {
      var curTag = TAG + "Test_installDLPSandbox_008";
      console.info(curTag, "start");
      var dlpFileAccess = dlpPermission.DLPFileAccess.NO_PERMISSION;
      var uri = "uri";
      await dlpPermission.installDLPSandbox(bundleName, dlpFileAccess, -1, uri, async (err, sandboxInfo) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_installDLPSandbox_009
     * @tc.name Test dlpPermission.installDLPSandbox
     * @tc.desc installDLPSandbox invalid uri (Promise).
     */
    it('Test_installDLPSandbox_009', 0, async function () {
      var curTag = TAG + "Test_installDLPSandbox_009";
      console.info(curTag, "start");
      var dlpFileAccess = dlpPermission.DLPFileAccess.NO_PERMISSION;
      var uri = "uri";
      try {
        await dlpPermission.installDLPSandbox(bundleName, dlpFileAccess, userId, "");
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
      }
      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_installDLPSandbox_010
     * @tc.name Test dlpPermission.installDLPSandbox
     * @tc.desc installDLPSandbox invalid uri (Callback).
     */
    it('Test_installDLPSandbox_010', 0, async function (done) {
      var curTag = TAG + "Test_installDLPSandbox_010";
      console.info(curTag, "start");
      var dlpFileAccess = dlpPermission.DLPFileAccess.NO_PERMISSION;
      var uri = "uri";
      await dlpPermission.installDLPSandbox(bundleName, dlpFileAccess, userId, "", async (err, sandboxInfo) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_uninstallDLPSandbox_001
     * @tc.name Test dlpPermission.uninstallDLPSandbox
     * @tc.desc uninstallDLPSandbox success (Promise).
     */
    it('Test_uninstallDLPSandbox_001', 0, async function () {
      var curTag = TAG + "Test_uninstallDLPSandbox_001";
      console.info(curTag, "start");
      var dlpFileAccess = dlpPermission.DLPFileAccess.READ_ONLY;
      var uri = "uri";
      try {
        var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpFileAccess, userId, uri);
        expect(typeof (sandboxInfo)).assertEqual("object");
      } catch (err) {
        console.error(curTag, "installDLPSandbox failed", err.code, err.message);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        expect(true).assertTrue();
      } catch (err) {
        console.error(curTag, "uninstallDLPSandbox failed", err.code, err.message);
        expect(false).assertTrue();
      }
      console.info(curTag, "end");
      return;
    })
    /**
     * @tc.number Test_uninstallDLPSandbox_002
     * @tc.name Test dlpPermission.uninstallDLPSandbox
     * @tc.desc uninstallDLPSandbox  success (Callback).
     */
    it('Test_uninstallDLPSandbox_002', 0, async function (done) {
      var curTag = TAG + "Test_uninstallDLPSandbox_002";
      console.info(curTag, "start");
      var dlpFileAccess = dlpPermission.DLPFileAccess.READ_ONLY;
      var uri = "uri";
      try {
        var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpFileAccess, userId, uri);
        expect(typeof (sandboxInfo)).assertEqual("object");
      } catch (err) {
        console.error(curTag, "installDLPSandbox failed", err.code, err.message);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex, async (err, data) => {
        expect(err).assertEqual(null);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_uninstallDLPSandbox_003
     * @tc.name Test dlpPermission.uninstallDLPSandbox
     * @tc.desc uninstallDLPSandbox empty bundleName (Promise).
     */
    it('Test_uninstallDLPSandbox_003', 0, async function () {
      var curTag = TAG + "Test_uninstallDLPSandbox_003";
      console.info(curTag, "start");
      var appIndex = 1;
      try {
        await dlpPermission.uninstallDLPSandbox("", userId, appIndex);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
      }
      console.info(curTag, "end");
      return;
    })
    
    /**
     * @tc.number Test_uninstallDLPSandbox_004
     * @tc.name Test dlpPermission.uninstallDLPSandbox
     * @tc.desc uninstallDLPSandbox empty bundleName (Callback).
     */
    it('Test_uninstallDLPSandbox_004', 0, async function (done) {
      var curTag = TAG + "Test_uninstallDLPSandbox_002";
      console.info(curTag, "start");
      var appIndex = 1;
      dlpPermission.uninstallDLPSandbox("", userId, appIndex, async (err, data) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_uninstallDLPSandbox_005
     * @tc.name Test dlpPermission.uninstallDLPSandbox
     * @tc.desc uninstallDLPSandbox invalid userId (Promise).
     */
    it('Test_uninstallDLPSandbox_005', 0, async function () {
      var curTag = TAG + "Test_uninstallDLPSandbox_005";
      console.info(curTag, "start");
      var appIndex = 1;
      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, -1, appIndex);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);

      }
      console.info(curTag, "end");
      return;
    })
    
    /**
     * @tc.number Test_uninstallDLPSandbox_004
     * @tc.name Test dlpPermission.uninstallDLPSandbox
     * @tc.desc uninstallDLPSandbox invalid userId (Callback).
     */
    it('Test_uninstallDLPSandbox_006', 0, async function (done) {
      var curTag = TAG + "Test_uninstallDLPSandbox_002";
      console.info(curTag, "start");
      var appIndex = 1;
      dlpPermission.uninstallDLPSandbox(bundleName, -1, appIndex, async (err, data) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_uninstallDLPSandbox_007
     * @tc.name Test dlpPermission.uninstallDLPSandbox
     * @tc.desc uninstallDLPSandbox invalid appIndex (Promise).
     */
    it('Test_uninstallDLPSandbox_007', 0, async function () {
      var curTag = TAG + "Test_uninstallDLPSandbox_007";
      console.info(curTag, "start");
      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, -1);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        console.info(curTag, "end");
        return;
      }
      console.info(curTag, "end");
      return;
    })
    
    /**
     * @tc.number Test_uninstallDLPSandbox_008
     * @tc.name Test dlpPermission.uninstallDLPSandbox
     * @tc.desc uninstallDLPSandbox invalid appIndex (Callback).
     */
    it('Test_uninstallDLPSandbox_008', 0, async function (done) {
      var curTag = TAG + "Test_uninstallDLPSandbox_008";
      console.info(curTag, "start");
      dlpPermission.uninstallDLPSandbox(bundleName, userId, -1, async (err, data) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        console.info(curTag, "end");
        done();
      });
    })

    /*
     * * @tc.number Test_on_uninstallDLPSandbox_001
    * @tc.name Test dlpPermission.on('uninstallDLPSandbox')
    * @tc.desc on('uninstallDLPSandbox') success
    */
    it('Test_on_uninstallDLPSandbox_001', 0, async function () {
      var curTag = TAG + "Test_on_uninstallDLPSandbox_001";
      console.info(curTag, "start");
      try {
        dlpPermission.on("uninstallDLPSandbox", (date) => {
          console.info(curTag, "on callback");
        });
        expect(true).assertTrue();
      } catch (err) {
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      try {
        dlpPermission.off("uninstallDLPSandbox", (date) => {
          console.info(curTag, "off callback");
        });
        expect(true).assertTrue();
      } catch (err) {
        expect(false).assertTrue();
      }
      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_on_uninstallDLPSandbox_002
     * @tc.name Test dlpPermission.on('uninstallDLPSandbox')
     * @tc.desc on('uninstallDLPSandbox') invalid parameter
     */
    it('Test_on_uninstallDLPSandbox_002', 0, async function () {
      var curTag = TAG + "Test_on_uninstallDLPSandbox_002";
      console.info(curTag, "start");
      try {
        // @ts-ignore
        dlpPermission.on("uninstallDLPSandbox1", (date) => {
          console.info(curTag, "on callback");
        });
        expect(false).assertTrue();
      } catch (err) {
        expect(true).assertTrue();
        console.info(curTag, "end");
        return;
      }
    })

    /**
     * @tc.number Test_on_uninstallDLPSandbox_003
     * @tc.name Test dlpPermission.on('uninstallDLPSandbox')
     * @tc.desc on('uninstallDLPSandbox') double call error
     */
    it('Test_on_uninstallDLPSandbox_003', 0, async function () {
      var curTag = TAG + "Test_on_uninstallDLPSandbox_003";
      console.info(curTag, "start");
      try {
        dlpPermission.on("uninstallDLPSandbox", async (date) => {
          console.info(curTag, "on callback");
        });
        dlpPermission.on("uninstallDLPSandbox", async (date) => {
          console.info(curTag, "on callback");
        });
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        try {
          dlpPermission.off("uninstallDLPSandbox", (date) => {
            console.info(curTag, "off callback");
          });
          expect(true).assertTrue();
        } catch (err) {
          expect(false).assertTrue();
          console.info(curTag, "end");
          return;
        }
        console.info(curTag, "end");
        return;
      }
      try {
        dlpPermission.off("uninstallDLPSandbox", (date) => {
          console.info(curTag, "off callback");
        });
        expect(true).assertTrue();
      } catch (err) {
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_off_uninstallDLPSandbox_001
     * @tc.name Test dlpPermission.off('uninstallDLPSandbox')
     * @tc.desc off('uninstallDLPSandbox') success
     */
    it('Test_off_uninstallDLPSandbox_001', 0, async function () {
      var curTag = TAG + "Test_off_uninstallDLPSandbox_001";
      console.info(curTag, "start");

      try {
        dlpPermission.on("uninstallDLPSandbox", (date) => {
          console.info(curTag, "on callback");
        });
        expect(true).assertTrue();
      } catch (err) {
        expect(false).assertTrue();

        console.info(curTag, "end");
        return;
      }
      try {
        dlpPermission.off("uninstallDLPSandbox", (date) => {
          console.info(curTag, "off callback");
        });
        expect(true).assertTrue();
      } catch (err) {
        expect(false).assertTrue();

        console.info(curTag, "end");
        return;
      }

      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_off_uninstallDLPSandbox_002
     * @tc.name Test dlpPermission.off('uninstallDLPSandbox')
     * @tc.desc off('uninstallDLPSandbox') invalid parameter
     */
    it('Test_off_uninstallDLPSandbox_002', 0, async function () {
      var curTag = TAG + "Test_off_uninstallDLPSandbox_002";
      console.info(curTag, "start");

      try {
        // @ts-ignore
        dlpPermission.off("uninstallDLPSandbox1", (date) => {
          console.info(curTag, "off callback");
        });
        expect(false).assertTrue();
      } catch (err) {
        expect(true).assertTrue();

        console.info(curTag, "end");
        return;
      }

      console.info(curTag, "end");
      return;
    })


    /**
     * @tc.number Test_off_uninstallDLPSandbox_003
     * @tc.name Test dlpPermission.off('uninstallDLPSandbox')
     * @tc.desc off('uninstallDLPSandbox') double call error
     */
    it('Test_off_uninstallDLPSandbox_003', 0, async function () {
      var curTag = TAG + "Test_off_uninstallDLPSandbox_003";
      console.info(curTag, "start");

      try {
        dlpPermission.on("uninstallDLPSandbox", (date) => {
          console.info(curTag, "off callback");
        });
        expect(true).assertTrue();
      } catch (err) {
        console.error(curTag, "on uninstallDLPSandbox failed", err.code, err.message);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      try {
        dlpPermission.off("uninstallDLPSandbox", (date) => {
          console.info(curTag, "off callback");
        });
      } catch (err) {
        console.error(curTag, "off uninstallDLPSandbox failed", err.code, err.message);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      try {
        dlpPermission.off("uninstallDLPSandbox", (date) => {
          console.info(curTag, "off callback");
        });
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_SYSTEM_SERVICE_EXCEPTION);
      }

      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_isDLPFile_001
     * @tc.name Test dlpPermission.isDLPFile.
     * @tc.desc isDLPFile success (Promise).
     */
    it('Test_isDLPFile_001', 0, async function () {
      var curTag = TAG + "Test_isDLPFile_001";
      console.info(curTag, "start");

      let dlpInfo = await genTestDlpFile();

      try {
        await dlpPermission.isDLPFile(dlpInfo.ciphertextFd);
        expect(true).assertTrue();
      } catch (err) {
        console.error(curTag, "isDLPFile failed", err.code, err.message);
        expect(false).assertTrue();
        return;
      }

      await closeTestDlpFile(dlpInfo);
      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_isDLPFile_002
     * @tc.name Test dlpPermission.isDLPFile.
     * @tc.desc isDLPFile success (Callback).
     */
    it('Test_isDLPFile_002', 0, async function (done) {
      var curTag = TAG + "Test_isDLPFile_002";
      console.info(curTag, "start");
      let dlpInfo = await genTestDlpFile();

      dlpPermission.isDLPFile(dlpInfo.ciphertextFd, async (err, data) => {
        expect(err).assertEqual(null);
        await closeTestDlpFile(dlpInfo);
        console.info(curTag, "end");
        done();
      });
    })

    /*
     * @tc.number Test_isDLPFile_003
     * @tc.name Test dlpPermission.isDLPFile.
     * @tc.desc isDLPFile invalid fd (Promise).
     */
    it('Test_isDLPFile_003', 0, async function () {
      var curTag = TAG + "Test_isDLPFile_003";
      console.info(curTag, "start");

      try {
        await dlpPermission.isDLPFile(-1);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        expect(true).assertTrue();
      }

      console.info(curTag, "end");
      return;
    })

    /**
     * @tc.number Test_isDLPFile_004
     * @tc.name Test dlpPermission.isDLPFile.
     * @tc.desc isDLPFile success (Callback).
     */
    it('Test_isDLPFile_004', 0, async function (done) {
      var curTag = TAG + "Test_isDLPFile_004";
      console.info(curTag, "start");
      try {
        dlpPermission.isDLPFile(-1, (err, data) => {
        });
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        console.info(curTag, "end");
        done();
      }
    })

    /**
     * @tc.number Test_openDLPFile_001
     * @tc.name Test dlpPermission.openDLPFile.
     * @tc.desc openDLPFile dlp file success (Promise).
     */
    it('Test_openDLPFile_001', 0, async function () {
      /**
       * describe： 定义一个测试套件
       * it：定义一个测试用例
       * expect：断言的判断条件
       * toEqual：断言的比较结果
       * 1.生成一个dlp文件
       * 2.打开正确的dlp文件
       */
      var curTag = TAG + "Test_openDLPFile_001";
      console.info(curTag, "start");


      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
        await dlpFile.closeDLPFile();
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      // 打开dlp文件
      try {
        dlpFile = await dlpPermission.openDLPFile(ciphertextFd);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, "openDLPFile failed", err.code, err.message);
        expect(false).assertTrue();
      }
      await dlpFile.closeDLPFile();
      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);
      console.info(curTag, "end");
      return;
    })
    /**
     * @tc.number Test_openDLPFile_002
     * @tc.name Test dlpPermission.openDLPFile.
     * @tc.desc openDLPFile with invalid plaintextFd (Promise).
     */
    it('Test_openDLPFile_002', 0, async function () {
      /**
       * 1.打开不正确的dlp文件
       * 2.在catch中断言失败，需要根据code展示提示信息-ERR_JS_INVALID_PARAMETER-19100001
       */
      var curTag = TAG + "Test_openDLPFile_002";
      console.info(curTag, "start");

      // 打开dlp文件
      try {
        let dlpFile = await dlpPermission.openDLPFile(-1);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER)
      }
      console.info(curTag, "end");
      return;
    })
    /**
     * @tc.number Test_openDLPFile_003
     * @tc.name Test dlpPermission.openDLPFile.
     * @tc.desc openDLPFile with not DLPFile plaintextFd (Promise).
     */
    it('Test_openDLPFile_003', 0, async function () {
      /**
       * 1.打开非dlp文件
       * 2.在catch中断言失败，需要根据code展示提示信息-ERR_JS_NOT_DLP_FILE-19100008
       */
      var curTag = TAG + "Test_openDLPFile_003";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();

      // 打开dlp文件
      try {
        let dlpFile = await dlpPermission.openDLPFile(plaintextFd);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_NOT_DLP_FILE)
      }
      fs.closeSync(plaintextFd);
      fs.unlinkSync(plaintextPath);
      console.info(curTag, "end");
      return;
    })
    /**
     * @tc.number Test_openDLPFile_004
     * @tc.name Test dlpPermission.openDLPFile.
     * @tc.desc openDLPFile dlp file success (Callback).
     */
    it('Test_openDLPFile_004', 0, async function (done) {
      /**
       * 1.生成一个dlp文件
       * 2.打开dlp文件
       */
      var curTag = TAG + "Test_openDLPFile_004";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      try {
        let dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
        await dlpFile.closeDLPFile(); // 生成后关闭dlp文件
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      // 打开dlp文件
      dlpPermission.openDLPFile(ciphertextFd, async (err, dlpFile) => {
        expect(err).assertEqual(null);
        await dlpFile.closeDLPFile();
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        done();
      });
    })
    /**
     * @tc.number Test_openDLPFile_005
     * @tc.name Test dlpPermission.openDLPFile.
     * @tc.desc openDLPFile with invalid plaintextFd (Callback).
     */
    it('Test_openDLPFile_005', 0, async function (done) {
      /**
       * 1.传入一个非法参数
       */
      var curTag = TAG + "Test_openDLPFile_005";
      console.info(curTag, "start");

      // 打开dlp文件
      dlpPermission.openDLPFile(-1, async (err, dlpFile) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_openDLPFile_006
     * @tc.name Test dlpPermission.openDLPFile.
     * @tc.desc openDLPFile with not DLPFile plaintextFd (Callback).
     */
    it('Test_openDLPFile_006', 0, async function (done) {
      /**
       * 1.传入一个非dlp文件
       */
      var curTag = TAG + "Test_openDLPFile_006";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();

      // 打开dlp文件
      dlpPermission.openDLPFile(plaintextFd, async (err, dlpFile) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_NOT_DLP_FILE);
        fs.closeSync(plaintextFd);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_closeDLPFile_001
     * @tc.name Test dlpPermission.closeDLPFile.
     * @tc.desc closeDLPFile dlp file success (Promise).
     */
    it('Test_closeDLPFile_001', 0, async function () {
      /**
       * 1.生成一个dlp文件
       * 2.关闭dlp文件
       */
      var curTag = TAG + "Test_closeDLPFile_001";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      try {
        await dlpFile.closeDLPFile();
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, "closeDLPFile failed", err.code, err.message);
        expect(false).assertTrue();
      }

      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);
      console.info(curTag, "end");
      return;
    })
    /**
     * @tc.number Test_closeDLPFile_002
     * @tc.name Test dlpPermission.closeDLPFile.
     * @tc.desc closeDLPFile dlp file success (Callback).
     */
    it('Test_closeDLPFile_002', 0, async function (done) {
      /**
       * 1.生成一个dlp文件
       * 2.关闭dlp文件
       */
      var curTag = TAG + "Test_closeDLPFile_002";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      dlpFile.closeDLPFile(async (err, data) => {
        expect(err).assertEqual(null);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_recoverDLPFile_001
     * @tc.name Test dlpPermission.recoverDLPFile.
     * @tc.desc recoverDLPFile dlp file success (Promise).
     */
    it('Test_recoverDLPFile_001', 0, async function () {
      /**
       * 1.生成一个dlp文件
       * 2.生成一个临时空文件
       * 3.解密这个dlp文件
       */
      var curTag = TAG + "Test_recoverDLPFile_001";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      // 生成一个临时空文件
      let temporarilyPath = rootDir + "test_dlp1.txt";
      let temporarilyTextFd = genFile(temporarilyPath);
      // 解密dlp文件
      try {
        await dlpFile.recoverDLPFile(temporarilyTextFd);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, "recoverDLPFile failed", err.code, err.message);
        expect(false).assertTrue();
      }
      await dlpFile.closeDLPFile();
      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.closeSync(temporarilyTextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);
      fs.unlinkSync(temporarilyPath);
      console.info(curTag, "end");
      return;
    })
    /**
     * @tc.number Test_recoverDLPFile_00
     * @tc.name Test dlpPermission.recoverDLPFile.
     * @tc.desc recoverDLPFile with invalid plaintextFd (Promise).
     */
    it('Test_recoverDLPFile_002', 0, async function () {
      /**
       * 1.生成一个dlp文件
       * 2.解密这个dlp文件，传递一个非法参数
       */
      var curTag = TAG + "Test_recoverDLPFile_002";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }

      try {
        await dlpFile.recoverDLPFile(-1);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER)
        expect(true).assertTrue();
      }
      await dlpFile.closeDLPFile();
      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);
      console.info(curTag, "end");
      return;
    })
    /**
     * @tc.number Test_recoverDLPFile_003
     * @tc.name Test dlpPermission.recoverDLPFile.
     * @tc.desc recoverDLPFile READ ONLY fail (Promise).
     */
    it('Test_recoverDLPFile_003', 0, async function () {
      /**
       * 1.登录owner，生成一个dlp文件，然后关闭dlp，然后登出
       * 2.登录123账户，打开上面的dlp文件，然后解密这个dlp文件
       * 3.断言解密失败，expect(err.code).assertEqual(DLPErrCode.ERR_JS_DLP_FILE_READ_ONLY)
       */
      var curTag = TAG + "Test_recoverDLPFile_003";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      await dlpFile.closeDLPFile();
      await AccountLogin("123@ohos.com"); // 登入
      await timeOut();
      // 打开dlp文件
      let dlpFileReadOnly;
      try {
        dlpFileReadOnly = await dlpPermission.openDLPFile(ciphertextFd);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, "openDLPFile failed", err.code, err.message);
        expect(false).assertTrue();
      }

      // 生成一个只读临时空文件
      let temporarilyPath = rootDir + "test_dlp1.txt";
      let temporarilyTextFd = genFile(temporarilyPath);
      // 解密dlp文件
      try {
        await dlpFileReadOnly.recoverDLPFile(temporarilyTextFd);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_DLP_FILE_READ_ONLY)
        expect(true).assertTrue();
      }
      await dlpFile.closeDLPFile();
      await AccountLogin("owner@ohos.com");
      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.closeSync(temporarilyTextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);
      fs.unlinkSync(temporarilyPath);
      console.info(curTag, "end");
      return;
    })
    /**
     * @tc.number Test_recoverDLPFile_004
     * @tc.name Test dlpPermission.recoverDLPFile.
     * @tc.desc recoverDLPFile dlp file success (CallBack).
     */
    it('Test_recoverDLPFile_004', 0, async function (done) {
      var curTag = TAG + "Test_recoverDLPFile_004";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      // 生成一个临时空文件
      let temporarilyPath = rootDir + "test_dlp1.txt";
      let temporarilyTextFd = genFile(temporarilyPath);
      // 解密dlp文件
      dlpFile.recoverDLPFile(temporarilyTextFd, async (err, data) => {
        expect(err).assertEqual(null);
        await dlpFile.closeDLPFile();
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.closeSync(temporarilyTextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        fs.unlinkSync(temporarilyPath);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_recoverDLPFile_005
     * @tc.name Test dlpPermission.recoverDLPFile.
     * @tc.desc recoverDLPFile with invalid plaintextFd (CallBack).
     */
    it('Test_recoverDLPFile_005', 0, async function (done) {
      var curTag = TAG + "Test_recoverDLPFile_005";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      // 解密dlp文件
      dlpFile.recoverDLPFile(-1, async (err, data) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        await dlpFile.closeDLPFile();
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        done();
      });
    })
    /**
     * @tc.number Test_recoverDLPFile_006
     * @tc.name Test dlpPermission.recoverDLPFile.
     * @tc.desc recoverDLPFile READ ONLY fail (CallBack).
     */
    it('Test_recoverDLPFile_006', 0, async function (done) {
      /**
       * 1.登录owner，生成一个dlp文件，然后关闭dlp，然后登出
       * 2.登录123账户，打开上面的dlp文件，然后解密这个dlp文件
       * 3.断言解密失败，expect(err.code).assertEqual(DLPErrCode.ERR_JS_DLP_FILE_READ_ONLY)
       */
      var curTag = TAG + "Test_recoverDLPFile_006";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      await dlpFile.closeDLPFile();

      await AccountLogin("123@ohos.com"); // 登入
      await timeOut();

      // 打开dlp文件
      let dlpFileReadOnly;
      try {
        dlpFileReadOnly = await dlpPermission.openDLPFile(ciphertextFd);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, "openDLPFile failed", err.code, err.message);
        expect(false).assertTrue();
      }

      // 生成一个只读临时空文件
      let temporarilyPath = rootDir + "test_dlp1.txt";
      let temporarilyTextFd = genFile(temporarilyPath);
      expect(temporarilyTextFd >= 0).assertTrue();
      // 解密dlp文件
      dlpFileReadOnly.recoverDLPFile(temporarilyTextFd, async (err, data) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_DLP_FILE_READ_ONLY);
        await dlpFile.closeDLPFile();
        await AccountLogin("owner@ohos.com");
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.closeSync(temporarilyTextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        fs.unlinkSync(temporarilyPath);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_addDLPLinkFile_001
     * @tc.name Test dlpPermission.addDLPLinkFile.
     * @tc.desc addDLPLinkFile dlp file success (Promise).
     */
    it('Test_addDLPLinkFile_001', 0, async function () {
      /**
       * 1.生成一个dlp文件
       * 2.添加addDLPLinkFile
       */
      var curTag = TAG + "Test_addDLPLinkFile_001";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      let linkFileName = 'test_001.dlp.link';
      try {
        await dlpFile.addDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'addDLPLinkFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        await dlpFile.deleteDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'deleteDLPLinkFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      await dlpFile.closeDLPFile();
      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);
      console.info(curTag, "end");
      return;
    })
    /**
     * @tc.number Test_addDLPLinkFile_002
     * @tc.name Test dlpPermission.addDLPLinkFile.
     * @tc.desc addDLPLinkFile with Invalid parameter (Promise).
     */
    it('Test_addDLPLinkFile_002', 0, async function () {
      /**
       * 1.生成一个dlp文件
       * 2.添加addDLPLinkFile
       */
      var curTag = TAG + "Test_addDLPLinkFile_002";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      let linkFileName = '';
      try {
        await dlpFile.addDLPLinkFile(linkFileName);
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        expect(true).assertTrue();
      }
      await dlpFile.closeDLPFile();
      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);
      console.info(curTag, "end");
      return;
    })
    /**
     * @tc.number Test_addDLPLinkFile_003
     * @tc.name Test dlpPermission.addDLPLinkFile.
     * @tc.desc addDLPLinkFile dlp file success (Callback).
     */
    it('Test_addDLPLinkFile_003', 0, async function (done) {
      /**
       * 1.生成一个dlp文件
       * 2.添加addDLPLinkFile
       */
      var curTag = TAG + "Test_addDLPLinkFile_003";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      let linkFileName = 'test_addDLPLinkFile_003.dlp.link';
      dlpFile.addDLPLinkFile(linkFileName, async (err, data) => {
        expect(err).assertEqual(null);
        try {
          await dlpFile.deleteDLPLinkFile(linkFileName);
          expect(true).assertTrue();
        } catch (err) {
          console.error(TAG, 'deleteDLPLinkFile failed', err.code, err.message);
          expect(false).assertTrue();
        }
        await dlpFile.closeDLPFile();
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        done();
      });
    })
    /**
     * @tc.number Test_addDLPLinkFile_004
     * @tc.name Test dlpPermission.addDLPLinkFile.
     * @tc.desc addDLPLinkFile with Invalid parameter success (Callback).
     */
    it('Test_addDLPLinkFile_004', 0, async function (done) {
      /**
       * 1.生成一个dlp文件
       * 2.添加addDLPLinkFile
       */
      var curTag = TAG + "Test_addDLPLinkFile_004";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      let linkFileName = '';
      dlpFile.addDLPLinkFile(linkFileName, async (err, data) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        await dlpFile.closeDLPFile();
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_deleteDLPLinkFile_001
     * @tc.name Test dlpPermission.deleteDLPLinkFile.
     * @tc.desc deleteDLPLinkFile dlp file success (Promise).
     */
    it('Test_deleteDLPLinkFile_001', 0, async function () {
      /**
       * 1.生成一个dlp文件
       * 2.添加addDLPLinkFile
       * 3.删除deleteDLPLinkFile
       */
      var curTag = TAG + "Test_deleteDLPLinkFile_001";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      let linkFileName = 'test_001.dlp.link';
      try {
        await dlpFile.addDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'addDLPLinkFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        await dlpFile.deleteDLPLinkFile('');
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'deleteDLPLinkFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      await dlpFile.closeDLPFile();
      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);
      console.info(curTag, "end");
      return;
    })
    /**
     * @tc.number Test_deleteDLPLinkFile_002
     * @tc.name Test dlpPermission.deleteDLPLinkFile.
     * @tc.desc deleteDLPLinkFile with Invalid parameter (Promise).
     */
    it('Test_deleteDLPLinkFile_002', 0, async function () {
      /**
       * 1.生成一个dlp文件
       * 2.添加addDLPLinkFile
       */
      var curTag = TAG + "Test_deleteDLPLinkFile_002";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }

      try {
        await dlpFile.deleteDLPLinkFile('');
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_OPERATE_DLP_FILE_FAIL);
        expect(true).assertTrue();
      }
      await dlpFile.closeDLPFile();
      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);
      console.info(curTag, "end");
      return;
    })
    /**
     * @tc.number Test_deleteDLPLinkFile_003
     * @tc.name Test dlpPermission.deleteDLPLinkFile.
     * @tc.desc deleteDLPLinkFile dlp file success (CallBack).
     */
    it('Test_deleteDLPLinkFile_003', 0, async function (done) {
      /**
       * 1.生成一个dlp文件
       * 2.添加addDLPLinkFile
       * 3.删除deleteDLPLinkFile
       */
      var curTag = TAG + "Test_deleteDLPLinkFile_003";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      let linkFileName = 'test.dlp.link';
      try {
        await dlpFile.addDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'addDLPLinkFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      dlpFile.deleteDLPLinkFile(linkFileName, async (err, data) => {
        expect(err).assertEqual(null);
        await dlpFile.closeDLPFile();
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        done();
      });
    })
    /**
     * @tc.number Test_deleteDLPLinkFile_004
     * @tc.name Test dlpPermission.deleteDLPLinkFile.
     * @tc.desc deleteDLPLinkFile with Invalid parameter (Promise).
     */
    it('Test_deleteDLPLinkFile_004', 0, async function (done) {
      /**
       * 1.生成一个dlp文件
       * 2.添加addDLPLinkFile
       */
      var curTag = TAG + "Test_deleteDLPLinkFile_004";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      dlpFile.deleteDLPLinkFile('', async (err, data) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_OPERATE_DLP_FILE_FAIL);
        await dlpFile.closeDLPFile();
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_stopFuseLink_001
     * @tc.name Test dlpPermission.stopFuseLink.
     * @tc.desc stopFuseLink dlp file success (Promise).---停止DLP文件与链接文件之间的FUSE链接
     */
    it('Test_stopFuseLink_001', 0, async function () {
      /**
       * 1.生成一个dlp文件
       * 2.添加stopFuseLink
       */
      var curTag = TAG + "Test_stopFuseLink_001";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      let linkFileName = 'stopFuseLink_001.txt.dlp'
      try {
        await dlpFile.addDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'addDLPLinkFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        await dlpFile.stopFuseLink();
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'stopFuseLink failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        await dlpFile.deleteDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'deleteDLPLinkFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      await dlpFile.closeDLPFile();
      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);
      console.info(curTag, "end");
      return;
    })
    /**
     * @tc.number Test_stopFuseLink_002
     * @tc.name Test dlpPermission.stopFuseLink.
     * @tc.desc stopFuseLink dlp file success (Callback).
     */
    it('Test_stopFuseLink_002', 0, async function (done) {
      /**
       * 1.生成一个dlp文件
       * 2.添加addDLPLinkFile
       */
      var curTag = TAG + "Test_stopFuseLink_002";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      let linkFileName = 'test_dlp.txt.dlp'
      try {
        await dlpFile.addDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'addDLPLinkFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      dlpFile.stopFuseLink(async (err, data) => {
        expect(err).assertEqual(null);
        try {
          await dlpFile.deleteDLPLinkFile(linkFileName);
          expect(true).assertTrue();
        } catch (err) {
          console.error(TAG, 'deleteDLPLinkFile failed', err.code, err.message);
          expect(false).assertTrue();
        }
        await dlpFile.closeDLPFile();
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_resumeFuseLink_001
     * @tc.name Test dlpPermission.resumeFuseLink.
     * @tc.desc resumeFuseLink dlp file success (Promise).
     */
    it('Test_resumeFuseLink_001', 0, async function () {
      /**
       * 1.生成一个dlp文件
       * 2.添加addDLPLinkFile
       * 3.删除deleteDLPLinkFile
       */
      var curTag = TAG + "Test_resumeFuseLink_001";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      let linkFileName = 'test_dlp.txt.dlp'
      try {
        await dlpFile.addDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'addDLPLinkFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        await dlpFile.stopFuseLink();
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'stopFuseLink failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        await dlpFile.resumeFuseLink();
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'resumeFuseLink failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        await dlpFile.deleteDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'deleteDLPLinkFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      await dlpFile.closeDLPFile();
      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);
      console.info(curTag, "end");
      return;
    })
    /**
     * @tc.number Test_resumeFuseLink_002
     * @tc.name Test dlpPermission.resumeFuseLink.
     * @tc.desc resumeFuseLink dlp file success (Callback).
     */
    it('Test_resumeFuseLink_002', 0, async function (done) {
      /**
       * 1.生成一个dlp文件
       * 2.添加addDLPLinkFile
       */
      var curTag = TAG + "Test_resumeFuseLink_002";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      let linkFileName = 'test_dlp.txt.dlp'
      try {
        await dlpFile.addDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'addDLPLinkFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        await dlpFile.stopFuseLink();
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'stopFuseLink failed', err.code, err.message);
        expect(false).assertTrue();
      }
      dlpFile.resumeFuseLink(async (err, data) => {
        expect(err).assertEqual(null);
        try {
          await dlpFile.deleteDLPLinkFile(linkFileName);
          expect(true).assertTrue();
        } catch (err) {
          console.error(TAG, 'deleteDLPLinkFile failed', err.code, err.message);
          expect(false).assertTrue();
        }
        await dlpFile.closeDLPFile();
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_replaceDLPLinkFile_001
     * @tc.name Test dlpPermission.replaceDLPLinkFile.
     * @tc.desc replaceDLPLinkFile dlp file success (Promise).---替换DLP文件的链接文件
     */
    it('Test_replaceDLPLinkFile_001', 0, async function () {
      /**
       * 1.生成一个dlp文件
       * 2.添加addDLPLinkFile
       * 3.替换replaceDLPLinkFile
       */
      let curTag = TAG + "Test_replaceDLPLinkFile_001";
      console.info(curTag, "start");

      let plaintextPath = rootDir + "test_dlp.txt";
      let ciphertextPath = rootDir + "test_dlp.txt.dlp";
      let writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      let property = await genTestDlpProperty();
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        expect(false).assertTrue();
        return;
      }
      let linkFileName = 'replace_dlp.txt.dlp'
      try {
        await dlpFile.addDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'addDLPLinkFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        await dlpFile.stopFuseLink();
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'stopFuseLink failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        await dlpFile.replaceDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'replaceDLPLinkFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        await dlpFile.deleteDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'deleteDLPLinkFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      await dlpFile.closeDLPFile();
      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);
      console.info(curTag, "end");
      return;
    })
    /**
     * @tc.number Test_replaceDLPLinkFile_002
     * @tc.name Test dlpPermission.replaceDLPLinkFile.
     * @tc.desc replaceDLPLinkFile with Invalid parameter (Promise).
     */
    it('Test_replaceDLPLinkFile_002', 0, async function () {
      /**
       * 1.生成一个dlp文件
       * 2.添加addDLPLinkFile
       * 3.替换replaceDLPLinkFile
       */
      let curTag = TAG + "Test_replaceDLPLinkFile_002";
      console.info(curTag, "start");

      let plaintextPath = rootDir + "test_dlp.txt";
      let ciphertextPath = rootDir + "test_dlp.txt.dlp";
      let writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      let property = await genTestDlpProperty();

      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      let linkFileName = 'txt.dlp.link'
      try {
        await dlpFile.addDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_OPERATE_DLP_FILE_FAIL);
        expect(false).assertTrue();
      }
      try {
        await dlpFile.stopFuseLink();
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'stopFuseLink failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        await dlpFile.replaceDLPLinkFile('');
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER)
        expect(true).assertTrue();
      }
      try {
        await dlpFile.deleteDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'deleteDLPLinkFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      await dlpFile.closeDLPFile();
      fs.closeSync(plaintextFd);
      fs.closeSync(ciphertextFd);
      fs.unlinkSync(ciphertextPath);
      fs.unlinkSync(plaintextPath);
      console.info(curTag, "end");
      return;
    })
    /**
     * @tc.number Test_replaceDLPLinkFile_003
     * @tc.name Test dlpPermission.replaceDLPLinkFile.
     * @tc.desc replaceDLPLinkFile dlp file success (Callback).
     */
    it('Test_replaceDLPLinkFile_003', 0, async function (done) {
      /**
       * 1.生成一个dlp文件
       * 2.添加addDLPLinkFile
       */
      var curTag = TAG + "Test_replaceDLPLinkFile_003";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      let linkFileName = 'replace.txt.dlp.link'
      try {
        await dlpFile.addDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'addDLPLinkFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        await dlpFile.stopFuseLink();
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'stopFuseLink failed', err.code, err.message);
        expect(false).assertTrue();
      }
      dlpFile.replaceDLPLinkFile(linkFileName, async (err, data) => {
        expect(err).assertEqual(null);
        try {
          await dlpFile.deleteDLPLinkFile(linkFileName);
          expect(true).assertTrue();
        } catch (err) {
          console.error(TAG, 'deleteDLPLinkFile failed', err.code, err.message);
          expect(false).assertTrue();
        }
        await dlpFile.closeDLPFile();
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        done();
      });
    })
    /**
     * @tc.number Test_replaceDLPLinkFile_004
     * @tc.name Test dlpPermission.replaceDLPLinkFile.
     * @tc.desc replaceDLPLinkFile with Invalid parameter (Callback).
     */
    it('Test_replaceDLPLinkFile_004', 0, async function (done) {
      /**
       * 1.生成一个dlp文件
       * 2.添加addDLPLinkFile
       */
      var curTag = TAG + "Test_replaceDLPLinkFile_004";
      console.info(curTag, "start");

      var plaintextPath = rootDir + "test_dlp.txt";
      var ciphertextPath = rootDir + "test_dlp.txt.dlp";
      var writeContent = "123456";
      let plaintextFd = genFile(plaintextPath, writeContent);
      expect(plaintextFd >= 0).assertTrue();
      let ciphertextFd = genFile(ciphertextPath);
      expect(plaintextFd >= 0).assertTrue();

      var property = await genTestDlpProperty();
      // 生成dlp文件
      let linkFileName = 'replace.dlp.link'
      let dlpFile;
      try {
        dlpFile = await dlpPermission.generateDLPFile(plaintextFd, ciphertextFd, property);
        expect(typeof (dlpFile)).assertEqual("object");
      } catch (err) {
        console.error(TAG, "generateDLPFile failed", err.code, err.message);
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        expect(false).assertTrue();
        return;
      }
      try {
        await dlpFile.addDLPLinkFile(linkFileName);
        expect(true).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_OPERATE_DLP_FILE_FAIL);
      }
      try {
        await dlpFile.stopFuseLink();
        expect(true).assertTrue();
      } catch (err) {
        console.error(TAG, 'stopFuseLink failed', err.code, err.message);
        expect(false).assertTrue();
      }
      dlpFile.replaceDLPLinkFile('', async (err, data) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        try {
          await dlpFile.deleteDLPLinkFile(linkFileName);
          expect(true).assertTrue();
        } catch (err) {
          console.error(TAG, 'deleteDLPLinkFile failed', err.code, err.message);
          expect(false).assertTrue();
        }
        await dlpFile.closeDLPFile();
        fs.closeSync(plaintextFd);
        fs.closeSync(ciphertextFd);
        fs.unlinkSync(ciphertextPath);
        fs.unlinkSync(plaintextPath);
        console.info(curTag, "end");
        done();
      });
    })

    /**
     * @tc.number Test_getDLPPermissionInfo_001
     * @tc.name Test dlpPermission.getDLPPermissionInfo.
     * @tc.desc test getDLPPermissionInfo in sandbox (Promise).
     */
    it('Test_getDLPPermissionInfo_001', 0, async function () {
      var curTag = TAG + "Test_getDLPPermissionInfo_001";
      console.info(curTag, "start");

      var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, 'uri');
      let want: Want = {
        "abilityName": "GetDLPPermissionInfoPromise",
        "bundleName": bundleName,
        "parameters": {
          'ohos.dlp.params.index': sandboxInfo.appIndex,
        }
      }
      let result;
      try {
        result = await globalThis.context.startAbilityForResult(want);
      } catch (err) {
        console.info(curTag, "startAbility failed", err.code, err.message);
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      expect(result.want.parameters.info.flags).assertLargerOrEqual(dlpPermission.ActionFlagType.ACTION_VIEW);
      expect(result.want.parameters.info.dlpFileAccess).assertLargerOrEqual(dlpPermission.DLPFileAccess.READ_ONLY);
      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.info(curTag, "uninstallDLPSandbox failed", err.code, err.message);
      }
      expect(result.resultCode).assertEqual(0);

      console.info(curTag, "end");
    })

    /**
     * @tc.number Test_getDLPPermissionInfo_002
     * @tc.name Test dlpPermission.getDLPPermissionInfo.
     * @tc.desc test getDLPPermissionInfo in sandbox (Callback).
     */
    it('Test_getDLPPermissionInfo_002', 0, async function () {
      var curTag = TAG + "Test_getDLPPermissionInfo_002";
      console.info(curTag, "start");

      var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, 'uri');
      let want: Want = {
        "abilityName": "GetDLPPermissionInfoCallback",
        "bundleName": bundleName,
        "parameters": {
          'ohos.dlp.params.index': sandboxInfo.appIndex,
        }
      }
      let result;
      try {
        result = await globalThis.context.startAbilityForResult(want);
      } catch (err) {
        console.error(curTag, "startAbility failed", err.code, err.message);
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.info(curTag, "uninstallDLPSandbox failed", err.code, err.message);
      }
      expect(result.resultCode).assertEqual(0);

      console.info(curTag, "end");
    })

    /**
     * @tc.number Test_getDLPPermissionInfo_003
     * @tc.name Test dlpPermission.getDLPPermissionInfo.
     * @tc.desc test getDLPPermissionInfo in not sandbox (Promise)
     */
    it('Test_getDLPPermissionInfo_003', 0, async function () {
      var curTag = TAG + "Test_getDLPPermissionInfo_003";
      console.info(curTag, "start");

      try {
        var dlpPermInfo = await dlpPermission.getDLPPermissionInfo();
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_API_FOR_SANDBOX_ERROR);
      }

      console.info(curTag, "end");
    })

    /**
     * @tc.number Test_getDLPPermissionInfo_004
     * @tc.name Test dlpPermission.getDLPPermissionInfo.
     * @tc.desc test getDLPPermissionInfo in not sandbox (Callback)
     */
    it('Test_getDLPPermissionInfo_004', 0, async function () {
      var curTag = TAG + "Test_getDLPPermissionInfo_004";
      console.info(curTag, "start");

      dlpPermission.getDLPPermissionInfo(async (err, dlpPermInfo) => {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_API_FOR_SANDBOX_ERROR);
      });

      console.info(curTag, "end");
    })

    /**
     * @tc.number Test_getOriginalFileName_001
     * @tc.name Test dlpPermission.getOriginalFileName.
     * @tc.desc test getOriginalFileName
     */
    it('Test_getOriginalFileName_001', 0, async function () {
      var curTag = TAG + "Test_getOriginalFileName_001";
      console.info(curTag, "start");

      try {
        var name = dlpPermission.getOriginalFileName('1.txt.dlp');
        expect(name).assertEqual('1.txt');
      } catch (err) {
        console.error(curTag, "getOriginalFileName failed", err.code, err.message);
        expect(false).assertTrue();
      }

      console.info(curTag, "end");
    })

    /**
     * @tc.number Test_getOriginalFileName_002
     * @tc.name Test dlpPermission.getOriginalFileName.
     * @tc.desc test getOriginalFileName invalid fileName
     */
    it('Test_getOriginalFileName_002', 0, async function () {
      var curTag = TAG + "Test_getOriginalFileName_002";
      console.info(curTag, "start");

      try {
        var name = dlpPermission.getOriginalFileName('');
        expect(false).assertTrue();
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_INVALID_PARAMETER);
        expect(true).assertTrue();
      }

      console.info(curTag, "end");
    })

    /**
     * @tc.number Test_getDLPSuffix_001
     * @tc.name Test dlpPermission.getDLPSuffix.
     * @tc.desc test getDLPSuffix
     */
    it('Test_getDLPSuffix_001', 0, async function () {
      var curTag = TAG + "Test_getDLPSuffix_001";
      console.info(curTag, "start");

      try {
        var name = dlpPermission.getDLPSuffix();
        expect(name).assertEqual('.dlp');
      } catch (err) {
        console.error(curTag, "getDLPSuffix failed", err.code, err.message);
        expect(false).assertTrue();
      }

      console.info(curTag, "end");
    })

    /**
     * @tc.number Test_on_openDLPFile_001
     * @tc.name Test dlpPermission.on('openDLPFile').
     * @tc.desc test on('openDLPFile') success.
     */
    it('Test_on_openDLPFile_001', 0, async function () {
      var curTag = TAG + "Test_on_openDLPFile_001";
      console.info(curTag, "start");

      var called = false;
      var srcUri = '123456'
      try {
        dlpPermission.on('openDLPFile', (dlpFileInfo) => {
          expect(dlpFileInfo.uri).assertEqual(srcUri);
          called = true;
        });
      } catch (err) {
        console.error(curTag, 'on openDLPFile failed', err.code, err.message);
        expect(false).assertTrue();
      }

      try {
        var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, '123456');
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.error(curTag, 'installDLPSandbox failed', err.code, err.message);
        dlpPermission.off('openDLPFile');
        expect(false).assertTrue();
      }

      expect(called).assertEqual(true);
      dlpPermission.off('openDLPFile');
      console.info(curTag, "end");
    })

    /**
     * @tc.number Test_on_openDLPFile_002
     * @tc.name Test dlpPermission.on('openDLPFile').
     * @tc.desc test on('openDLPFile') in sandbox.
     */
    it('Test_on_openDLPFile_002', 0, async function () {
      var curTag = TAG + "Test_on_openDLPFile_002";
      console.info(curTag, "start");

      var sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, 'uri');
      let want: Want = {
        "abilityName": "OnOpenDlpFile",
        "bundleName": bundleName,
        "parameters": {
          'ohos.dlp.params.index': sandboxInfo.appIndex,
        }
      }
      let result;
      try {
        result = await globalThis.context.startAbilityForResult(want);
      } catch (err) {
        console.error(curTag, "startAbility failed", err.code, err.message);
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
        expect(false).assertTrue();
        console.info(curTag, "end");
        return;
      }
      try {
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.info(curTag, "uninstallDLPSandbox failed", err.code, err.message);
      }
      expect(result.resultCode).assertEqual(DLPErrCode.ERR_JS_API_NOT_FOR_SANDBOX_ERROR);

      console.info(curTag, "end");
    })

    /**
     * @tc.number Test_on_openDLPFile_003
     * @tc.name Test dlpPermission.on('openDLPFile').
     * @tc.desc test on('openDLPFile') invalid param.
     */
    it('Test_on_openDLPFile_003', 0, async function () {
      var curTag = TAG + "Test_on_openDLPFile_003";
      console.info(curTag, "start");

      try {
        // @ts-ignore
        dlpPermission.on('openDLPFile1', (dlpFileInfo) => {
        });
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_PARAMETER_ERROR);
      }

      console.info(curTag, "end");
    })


    /**
     * @tc.number Test_off_openDLPFile_001
     * @tc.name Test dlpPermission.off('openDLPFile').
     * @tc.desc test off('openDLPFile') success.
     */
    it('Test_off_openDLPFile_001', 0, async function () {
      var curTag = TAG + "Test_off_openDLPFile_001";
      console.info(curTag, "start");

      var called1 = 0;
      let func1 = (dlpFileInfo) => {
        expect(dlpFileInfo.uri).assertEqual(srcUri);
        called1++;
      }
      var called2 = 0;
      let func2 = (dlpFileInfo) => {
        expect(dlpFileInfo.uri).assertEqual(srcUri);
        called2++;
      }

      var srcUri = '123456'
      try {
        dlpPermission.on('openDLPFile', func1);
      } catch (err) {
        console.error(curTag, 'on openDLPFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        dlpPermission.on('openDLPFile', func2);
      } catch (err) {
        console.error(curTag, 'on openDLPFile failed', err.code, err.message);
        dlpPermission.off('openDLPFile');
        expect(false).assertTrue();
      }

      try {
        let sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, '123456');
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.error(curTag, 'installDLPSandbox failed', err.code, err.message);
        dlpPermission.off('openDLPFile');
        expect(false).assertTrue();
      }
      expect(called1).assertEqual(1);
      expect(called2).assertEqual(1);

      try {
        dlpPermission.off('openDLPFile', func1);
      } catch (err) {
        console.error(curTag, 'off openDLPFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        let sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, '123456');
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.error(curTag, 'installDLPSandbox failed', err.code, err.message);
        dlpPermission.off('openDLPFile');
        expect(false).assertTrue();
      }
      dlpPermission.off('openDLPFile');
      expect(called1).assertEqual(1);
      expect(called2).assertEqual(2);
      console.info(curTag, "end");
    })

    /**
     * @tc.number Test_off_openDLPFile_002
     * @tc.name Test dlpPermission.off('openDLPFile').
     * @tc.desc test off('openDLPFile') all callback success.
     */
    it('Test_off_openDLPFile_002', 0, async function () {
      var curTag = TAG + "Test_off_openDLPFile_002";
      console.info(curTag, "start");

      var called1 = 0;
      let func1 = (dlpFileInfo) => {
        expect(dlpFileInfo.uri).assertEqual(srcUri);
        called1++;
      }
      var called2 = 0;
      let func2 = (dlpFileInfo) => {
        expect(dlpFileInfo.uri).assertEqual(srcUri);
        called2++;
      }

      var srcUri = '123456'
      try {
        dlpPermission.on('openDLPFile', func1);
      } catch (err) {
        console.error(curTag, 'on openDLPFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        dlpPermission.on('openDLPFile', func2);
      } catch (err) {
        console.error(curTag, 'on openDLPFile failed', err.code, err.message);
        dlpPermission.off('openDLPFile');
        expect(false).assertTrue();
      }

      try {
        let sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, '123456');
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.error(curTag, 'installDLPSandbox failed', err.code, err.message);
        dlpPermission.off('openDLPFile');
        expect(false).assertTrue();
      }
      expect(called1).assertEqual(1);
      expect(called2).assertEqual(1);

      try {
        dlpPermission.off('openDLPFile');
      } catch (err) {
        console.error(curTag, 'off openDLPFile failed', err.code, err.message);
        expect(false).assertTrue();
      }
      try {
        let sandboxInfo = await dlpPermission.installDLPSandbox(bundleName, dlpPermission.DLPFileAccess.READ_ONLY, userId, '123456');
        await dlpPermission.uninstallDLPSandbox(bundleName, userId, sandboxInfo.appIndex);
      } catch (err) {
        console.error(curTag, 'installDLPSandbox failed', err.code, err.message);
        dlpPermission.off('openDLPFile');
        expect(false).assertTrue();
      }
      expect(called1).assertEqual(1);
      expect(called2).assertEqual(1);
      console.info(curTag, "end");
    })

    /**
     * @tc.number Test_off_openDLPFile_003
     * @tc.name Test dlpPermission.off('openDLPFile').
     * @tc.desc test off('openDLPFile') invalid param.
     */
    it('Test_off_openDLPFile_003', 0, async function () {
      var curTag = TAG + "Test_off_openDLPFile_003";
      console.info(curTag, "start");

      try {
        // @ts-ignore
        dlpPermission.off('openDLPFile1', (dlpFileInfo) => {
        });
      } catch (err) {
        expect(err.code).assertEqual(DLPErrCode.ERR_JS_PARAMETER_ERROR);
      }

      console.info(curTag, "end");
    })
  })
}
