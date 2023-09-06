# \@ohos.dlpPermission (数据防泄漏)


数据防泄漏（DLP）是OpenHarmony提供的系统级的数据防泄漏解决方案，提供跨设备的文件的权限管理、加密存储、授权访问等能力。


**起始版本：**10


## 导入模块

```
import dlpPermission from '@ohos.dlpPermission';
```


## ActionFlagType

可以对DLP文件进行的操作类型枚举。例如：DLP沙箱应用可以根据是否具有操作权限，对其按钮进行置灰

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**

| 名称 | 默认值 | 说明 | 
| -------- | -------- | -------- |
| ACTION_VIEW | 0x00000001 | 表示文件的查看权限。 | 
| ACTION_SAVE | 0x00000002 | 表示文件的保存权限。 | 
| ACTION_SAVE_AS | 0x00000004 | 表示文件的另存为权限。 | 
| ACTION_EDIT | 0x00000008 | 表示文件的编辑权限。 | 
| ACTION_SCREEN_CAPTURE | 0x00000010 | 表示文件的截屏权限。 | 
| ACTION_SCREEN_SHARE | 0x00000020 | 表示文件的共享屏幕权限。 | 
| ACTION_SCREEN_RECORD | 0x00000040 | 表示文件的录屏权限。 | 
| ACTION_COPY | 0x00000080 | 表示文件的复制权限。 | 
| ACTION_PRINT | 0x00000100 | 表示文件的打印权限。 | 
| ACTION_EXPORT | 0x00000200 | 表示文件的导出权限。 | 
| ACTION_PERMISSION_CHANGE | 0x00000400 | 表示文件的修改文件权限。 | 


## DLPFileAccess

DLP文件授权类型的枚举。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**

| 名称 | 默认值 | 说明 | 
| -------- | -------- | -------- |
| NO_PERMISSION | 0 | 表示无文件权限。 | 
| READ_ONLY | 1 | 表示文件的只读权限。 | 
| CONTENT_EDIT | 2 | 表示文件的编辑权限。 | 
| FULL_CONTROL | 3 | 表示文件的完全控制权限。 | 


## DLPPermissionInfo

表示DLP文件的权限信息。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

| 名称 | 类型 | 只读 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- | -------- |
| dlpFileAccess | [DLPFileAccess](#dlpfileaccess) | 否 | NA | 表示DLP文件针对用户的授权类型，例如：只读 | 
| flags | number | 否 | NA | 表示DLP文件的详细操作权限，是不同[ActionFlagType](#actionflagtype)的组合。 | 


## AccessedDLPFileInfo

表示被打开的DLP文件的信息。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

| 名称 | 类型 | 只读 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- | -------- |
| uri | string | 否 | 是 | 表示DLP文件的uri。 | 
| lastOpenTime | number | 否 | 是 | 表示DLP文最近打开时间。 | 


## RetentionSandboxInfo

保留沙箱的沙箱信息。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

| 名称 | 类型 | 只读 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- | -------- |
| appIndex | number | 否 | NA | 表示DLP沙箱应用索引。 | 
| bundleName | string | 否 | NA | 表示应用包名。 | 
| docUris | Array&lt;string&gt; | 否 | NA | 表示DLP文件的URI列表。 | 


## isDLPFile

isDLPFile(fd: number): Promise&lt;boolean&gt;

根据文件的fd，查询该文件是否是DLP文件，使用Promise方式异步返回结果。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| fd | number | 是 | 文件的fd(file descriptor, 文件描述符)。 | 

**返回值：**
| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;boolean&gt; | Promise对象。返回true表示是DLP文件，返回false表示非DLP文件。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission';
import fs from '@ohos.file.fs';

async func(uri) {
  let file = fs.openSync(uri);
  try {
    let res = await dlpPermission.isDLPFile(file.fd); // 是否加密DLP文件
    console.info('res', res);
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
  fs.closeSync(file);
}
```


## isDLPFile

isDLPFile(fd: number, callback: AsyncCallback&lt;boolean&gt;): void

根据文件的fd，查询该文件是否是DLP文件，使用callback方式异步返回结果。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| fd | number | 是 | 文件的fd。 | 
| callback | AsyncCallback&lt;boolean&gt; | 是 | 回调函数。true表示是DLP文件，返回false表示非DLP文件。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission';
import fs from '@ohos.file.fs';

async func(uri) {
  let file = fs.openSync(uri);
  try {
    dlpPermission.isDLPFile(file.fd, (err, res) => {
      if (err != undefined) {
        console.error('isDLPFile error,', err.code, err.message);
      } else {
        console.info('res', res);
      }
      fs.closeSync(file);
    });
  } catch (err) {
    console.error('isDLPFile error,', err.code, err.message);
    fs.closeSync(file);
  }
}
```


## getDLPPermissionInfo

getDLPPermissionInfo(): Promise&lt;DLPPermissionInfo&gt;

查询当前DLP沙箱的权限信息。使用Promise方式异步返回结果。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**返回值：**

| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;[DLPPermissionInfo](#dlppermissioninfo)&gt; | Promise对象。返回查询的DLP文件的权限信息，无异常则表明查询成功。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 19100001 | Invalid parameter value. | 
| 19100006 | No permission to invoke this API, which is for DLP sandbox application. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission';
async func() {
  try {
    let inSandbox = await dlpPermission.isInSandbox(); // 是否在沙箱内
    if (inSandbox) {
      let res: dlpPermission.DLPPermissionInfo = await dlpPermission.getDLPPermissionInfo(); // 获取当前权限信息
      console.info('res', JSON.stringify(res));
    }
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
```


## getDLPPermissionInfo

getDLPPermissionInfo(callback: AsyncCallback&lt;DLPPermissionInfo&gt;): void;

查询当前DLP沙箱的权限信息。使用callback方式异步返回结果。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**

| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| callback | AsyncCallback&lt;[DLPPermissionInfo](#dlppermissioninfo)&gt; | 是 | 查询当前DLP文件的权限。当查询成功时，err为undefined；否则为错误对象。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100006 | No permission to invoke this API, which is for DLP sandbox application. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission';
import fs from '@ohos.file.fs';

async func() {
  try {
    let inSandbox = await dlpPermission.isInSandbox(); // 是否在沙箱内
    if (inSandbox) {
      dlpPermission.getDLPPermissionInfo((err, res) => {
        if (err != undefined) {
          console.error('getDLPPermissionInfo error,', err.code, err.message);
        } else {
          console.info('res', JSON.stringify(res));
        }
      }); // 获取当前权限信息
    }
  } catch (err) {
    console.error('getDLPPermissionInfo error,', err.code, err.message);
  }
}
```


## getOriginalFileName

getOriginalFileName(fileName: string): string

获取指定DLP文件名的原始文件名。接口为同步接口。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**

| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| fileName | string | 是 | 指定要查询的文件名。 | 

**返回值：**

| 类型 | 说明 | 
| -------- | -------- |
| string | 返回DLP文件的原始文件名。例如：DLP文件名为test.txt.dlp，则返回的原始文件名为test.txt。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 19100001 | Invalid parameter value. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission';
async func() {
  try {
    let res = dlpPermission.getOriginalFileName('test.txt.dlp'); // 获取原始文件名
    console.info('res', res);
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
```


## getDLPSuffix

getDLPSuffix(): string

获取DLP文件扩展名。接口为同步接口。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**返回值：**

| 类型 | 说明 | 
| -------- | -------- |
| string | 返回DLP文件扩展名。例如：返回拓展名为".dlp"，加密后的DLP文件名为"test.txt.dlp"。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission';
async func() {
  try {
    let res = dlpPermission.getDLPSuffix(); // 获取DLP拓展名
    console.info('res', res);
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
```


## on('openDLPFile')

on(type: 'openDLPFile', listener: Callback&lt;AccessedDLPFileInfo&gt;): void

监听打开DLP文件。在当前应用的沙箱应用打开DLP文件时，通知当前应用。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| type | string | 是 | 监听事件类型。'openDLPFile'：打开DLP文件。 | 
| listener | Callback&lt;AccessedDLPFileInfo&gt; | 是 | DLP文件打开事件的回调。在当前应用的沙箱应用打开DLP文件时，通知当前应用。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100007 | No permission to invoke this API, which is not for DLP sandbox application. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission';
event(info: dlpPermission.VisitedDLPFileInfo) {
  console.info('openDlpFile event', info.uri, info.recentOpenTime)
}
subscribe() {
  try {
    dlpPermission.on('openDLPFile', this.event); // 订阅
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
async func() {
  this.subscribe();
}
```


## off('openDLPFile')

off(type: 'openDLPFile', listener?: Callback&lt;AccessedDLPFileInfo&gt;): void

取消监听打开DLP文件。在当前应用的沙箱应用打开DLP文件时，取消通知当前应用。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| type | string | 是 | 监听事件类型。'openDLPFile'：打开DLP文件。 | 
| listener | Callback&lt;AccessedDLPFileInfo&gt; | 否 | DLP文件被打开的事件的回调。在当前应用的沙箱应用打开DLP文件时，取消通知当前应用。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100007 | No permission to invoke this API, which is not for DLP sandbox application. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission';
event(info: dlpPermission.VisitedDLPFileInfo) {
  console.info('openDlpFile event', info.uri, info.recentOpenTime)
}
unSubscribe() {
  try {
    dlpPermission.off('openDLPFile', this.event); // 取消订阅
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
subscribe() {
  try {
    dlpPermission.on('openDLPFile', this.event); // 订阅
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
async func() {
  this.subscribe();
  this.unSubscribe();
}
```


## isInSandbox

isInSandbox(): Promise&lt;boolean&gt;

查询当前应用是否运行在DLP沙箱环境。使用Promise方式异步返回结果。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**返回值：**

| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;boolean&gt; | Promise对象。返回当前应用是否运行在沙箱中。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 19100001 | Invalid parameter value. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission';
async func() {
  try {
    let inSandbox = await dlpPermission.isInSandbox(); // 是否在沙箱内
    console.info('res', inSandbox);
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
```


## isInSandbox

isInSandbox(callback: AsyncCallback&lt;boolean&gt;): void

查询当前应用是否运行在DLP沙箱环境。使用callback方式异步返回结果。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**

| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| callback | AsyncCallback&lt;boolean&gt; | 是 | 查询当前应用是否运行在沙箱中。当查询成功时，err为undefined；否则为错误对象。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission';

try {
  dlpPermission.isInSandbox((err, data) => {
    if (err) {
        console.error('isInSandbox error,', err.code, err.message);
    } else {
        console.info('isInSandbox, data);
    }
  }); // 是否在沙箱内
} catch (err) {
  console.error('isInSandbox error,', err.code, err.message);
}
```


## getDLPSupportedFileTypes

getDLPSupportedFileTypes(): Promise&lt;Array&lt;string&gt;&gt;

查询当前可支持权限设置和校验的文件扩展名类型列表。使用Promise方式异步返回结果。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**返回值：**

| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;Array&lt;string&gt;&gt; | Promise对象。返回当前可支持权限设置和校验的文件扩展名类型列表。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 19100001 | Invalid parameter value. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission';
async func() {
  try {
    let res = await dlpPermission.getDLPSupportedFileTypes(); // 获取支持DLP的文件类型
    console.info('res', JSON.stringify(res));
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
```


## getDLPSupportedFileTypes

getDLPSupportedFileTypes(callback: AsyncCallback&lt;Array&lt;string&gt;&gt;): void

查询当前可支持权限设置和校验的文件扩展名类型列表。使用callback方式异步返回结果。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**

| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| callback | AsyncCallback&lt;Array&lt;string&gt;&gt; | 是 | 查询当前可支持权限设置和校验的文件扩展名类型列表。当查询成功时，err为undefined；否则为错误对象。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission';

async func() {
  try {
    dlpPermission.getDLPSupportedFileTypes((err, res) => {
      if (err != undefined) {
        console.error('getDLPSupportedFileTypes error,', err.code, err.message);
      } else {
        console.info('res', JSON.stringify(res));
      }
    }); // 获取支持DLP的文件类型
  } catch (err) {
    console.error('getDLPSupportedFileTypes error,', err.code, err.message);
  }
}
```



## setRetentionState

setRetentionState(docUris: Array&lt;string&gt;): Promise&lt;void&gt;

设置沙箱保留状态。使用Promise方式异步返回结果。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**数：**

| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| docUris | Array&lt;string&gt; | 是 | 表示需要设置保留状态的文件uri列表。 | 

**返回值：**

| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;void&gt; | Promise对象。无返回结果的Promise对象。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100006 | No permission to invoke this API, which is for DLP sandbox application. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission';
async func(uri) {
  try {
    let inSandbox = await dlpPermission.isInSandbox(); // 是否在沙箱内
    if (inSandbox) {
      await dlpPermission.setRetentionState([uri]); // 设置沙箱保留
    }
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
```


## setRetentionState

setRetentionState(docUris: Array&lt;string&gt;, callback: AsyncCallback&lt;void&gt;): void

设置沙箱保留状态。使用callback方式异步返回结果。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**

| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| docUris | Array&lt;string&gt; | 是 | 表示需要设置保留状态的文件uri列表。 | 
| callback | AsyncCallback&lt;void&gt; | 是 | 设置沙箱保留状态。当设置成功时，err为undefined；否则为错误对象。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100006 | No permission to invoke this API, which is for DLP sandbox application. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission';

async func(uri) {
  try {
    dlpPermission.setRetentionState([uri], (err, res) => {
      if (err != undefined) {
        console.error('setRetentionState error,', err.code, err.message);
      } else {
        console.info('setRetentionState success');
      }
    }); // 设置沙箱保留
  } catch (err) {
    console.error('setRetentionState error,', err.code, err.message);
  }
}
```



## cancelRetentionState

cancelRetentionState(docUris: Array&lt;string&gt;): Promise&lt;void&gt;

取消沙箱保留状态。使用Promise方式异步返回结果。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**返回值：**

| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;void&gt; | Promise对象。无返回结果的Promise对象。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
async func(uri) {
  try {
    await dlpPermission.cancelRetentionState([uri]); // 取消沙箱保留
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
```


## cancelRetentionState

cancelRetentionState(docUris: Array&lt;string&gt;, callback: AsyncCallback&lt;void&gt;): void

取消沙箱保留状态。使用callback方式异步返回结果。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**

| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| callback | AsyncCallback&lt;void&gt; | 是 | 取消沙箱保留状态。当设置成功时，err为undefined；否则为错误对象。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission';

async func(uri) {
  try {
    dlpPermission.cancelRetentionState([uri], (err, res) => {
      if (err != undefined) {
        console.error('cancelRetentionState error,', err.code, err.message);
      } else {
        console.info('cancelRetentionState success');
      }
    }); // 取消沙箱保留
  } catch (err) {
    console.error('cancelRetentionState error,', err.code, err.message);
  }
}
```



## getRetentionSandboxList

getRetentionSandboxList(bundleName?: string): Promise&lt;Array&lt;RetentionSandboxInfo&gt;&gt;

查询指定应用的保留沙箱信息列表。使用Promise方式异步返回结果。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**

| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| bundleName | string | 否 | 指定应用包名。默认为空，查询当前应用的保留沙箱信息列表。 | 

**返回值：**

| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;RetentionSandboxInfo&gt; | Promise对象。返回查询的沙箱信息列表。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100007 | No permission to invoke this API, which is not for DLP sandbox application. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
async func() {
  try {
    let res:Array<dlpPermission.RetentionSandboxInfo> = await dlpPermission.getRetentionSandboxList(); // 获取沙箱保留列表
    console.info('res', JSON.stringify(res))
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
```


## getRetentionSandboxList

getRetentionSandboxList(bundleName: string, callback: AsyncCallback&lt;Array&lt;RetentionSandboxInfo&gt;&gt;): void

查询指定应用的保留沙箱信息列表。使用callback方式异步返回结果。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**

| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| bundleName | string | 是 | 指定应用包名。 | 
| callback | AsyncCallback&lt;RetentionSandboxInfo&gt; | 是 | 查询指定应用的沙箱信息列表。当设置成功时，err为undefined；否则为错误对象。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100007 | No permission to invoke this API, which is not for DLP sandbox application. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission';

async func(bundleName) {
  try {
    dlpPermission.getRetentionSandboxList(bundleName, (err, res) => {
      if (err != undefined) {
        console.error('getRetentionSandboxList error,', err.code, err.message);
      } else {
        console.info('res', JSON.stringify(res));
      }
    }); // 获取沙箱保留列表
  } catch (err) {
    console.error('getRetentionSandboxList error,', err.code, err.message);
  }
}
```


## getRetentionSandboxList

getRetentionSandboxList(callback: AsyncCallback&lt;Array&lt;RetentionSandboxInfo&gt;&gt;): void

查询指定应用的保留沙箱信息列表。使用callback方式异步返回结果。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**

| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| callback | AsyncCallback&lt;RetentionSandboxInfo&gt; | 是 | 查询指定应用的沙箱信息列表。当设置成功时，err为undefined；否则为错误对象。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100007 | No permission to invoke this API, which is not for DLP sandbox application. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission';

async func() {
  try {
    dlpPermission.getRetentionSandboxList((err, res) => {
      if (err != undefined) {
        console.error('getRetentionSandboxList error,', err.code, err.message);
      } else {
        console.info('res', JSON.stringify(res));
      }
    }); // 获取沙箱保留列表
  } catch (err) {
    console.error('getRetentionSandboxList error,', err.code, err.message);
  }
}
```



## getDLPFileAccessRecords

getDLPFileAccessRecords(): Promise&lt;AccessedDLPFileInfo&gt;

查询最近访问的DLP文件列表。使用Promise方式异步返回结果。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**返回值：**

| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;AccessedDLPFileInfo&gt; | Promise对象。返回最近访问的DLP文件列表。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 19100001 | Invalid parameter value. | 
| 19100007 | No permission to invoke this API, which is not for DLP sandbox application. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
async func() {
  try {
    let res:Array<dlpPermission.VisitedDLPFileInfo> = await dlpPermission.getDLPFileAccessRecords(); // 获取DLP访问列表
    console.info('res', JSON.stringify(res))
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
```



## getDLPFileAccessRecords

getDLPFileAccessRecords(callback: AsyncCallback&lt;AccessedDLPFileInfo&gt;): void

查询最近访问的DLP文件列表。使用callback方式异步返回结果。

**起始版本：**10

**参数：**

| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| callback | AsyncCallback&lt;AccessedDLPFileInfo&gt; | 是 | 查询最近访问的DLP文件列表。当查询成功时，err为undefined；否则为错误对象。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100007 | No permission to invoke this API, which is not for DLP sandbox application. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission';

async func() {
  try {
    dlpPermission.getDLPFileAccessRecords((err, res) => {
      if (err != undefined) {
        console.error('getDLPFileAccessRecords error,', err.code, err.message);
      } else {
        console.info('res', JSON.stringify(res));
      }
    }); // 获取DLP访问列表
  } catch (err) {
    console.error('getDLPFileAccessRecords error,', err.code, err.message);
  }
}
```


## GatheringPolicyType

DLP沙箱聚合策略类型的枚举。沙箱聚合表示同一权限类型的DLP文件，在同一个沙箱内打开，例如在同一个沙箱内使用不同tab页打开；沙箱非聚合表示不同DLP文件在不同沙箱打开。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**

| 名称 | 默认值 | 说明 | 
| -------- | -------- | -------- |
| GATHERING | 1 | 表示沙箱聚合。 | 
| NON_GATHERING | 2 | 表示沙箱非聚合。 | 


## getDLPGatheringPolicy

getDLPGatheringPolicy(): Promise&lt;GatheringPolicyType&gt;

查询DLP沙箱聚合策略。使用Promise方式异步返回结果。

**系统接口：** 此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**返回值：**

| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;GatheringPolicyType&gt; | Promise对象。返回当前DLP沙箱聚合策略。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 19100001 | Invalid parameter value. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission'

async func() {
  try {
    let res: dlpPermission.GatheringPolicyType = await dlpPermission.getDLPGatheringPolicy(); // 获取沙箱聚合策略
    console.info('res', JSON.stringify(res));
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
```


## getDLPGatheringPolicy

getDLPGatheringPolicy(callback: AsyncCallback&lt;GatheringPolicyType&gt;): void

查询DLP沙箱聚合策略。使用callback方式异步返回结果。

**系统接口：** 此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**

| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| callback | AsyncCallback&lt;GatheringPolicyType&gt; | 是 | 查询当前DLP沙箱聚合策略。当查询成功时，err为undefined；否则为错误对象。 | 


**错误码：**


以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。


| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100011 | System service exception. | 


**示例：**
```
import dlpPermission from '@ohos.dlpPermission';

async func() {
  try {
    dlpPermission.getDLPGatheringPolicy((err, res) => {
      if (err != undefined) {
        console.error('getDLPGatheringPolicy error,', err.code, err.message);
      } else {
        console.info('res', JSON.stringify(res));
      }
    }); // 获取沙箱聚合策略
  } catch (err) {
    console.error('getDLPGatheringPolicy error,', err.code, err.message);
  }
}
```



## DLPSandboxInfo

表示DLP沙箱的信息。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

| 名称 | 类型 | 只读 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- | -------- |
| appIndex | number | 否 | 是 | 表示DLP沙箱号。 | 
| tokenID | number | 否 | 是 | 表示DLP沙箱应用的tokenID。 | 


## installDLPSandbox

installDLPSandbox(bundleName: string, dlpFileAccess: DLPFileAccess, userId: number, uri: string): Promise&lt;DLPSandboxInfo&gt;

安装一个应用的DLP沙箱。使用Promise方式异步返回结果返回应用沙箱信息。

**系统接口：** 此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| bundleName | string | 是 | 应用包名。 | 
| dlpFileAccess | [DLPFileAccess](#dlpfileaccess) | 是 | DLP文件授权类型。 | 
| userId | number | 是 | 当前的用户ID，通过帐号子系统获取的OS帐号ID，默认主用户ID：100。 | 
| uri | string | 是 | DLP文件的URI。 | 

**返回值：**
| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;[DLPSandboxInfo](#dlpsandboxinfo)&gt; | Promise对象。安装沙箱应用，返回应用沙箱信息。 | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
async func(uri) {
  try {
    let res: dlpPermission.DLPSandboxInfo = await dlpPermission.installDLPSandbox('com.ohos.note', dlpPermission.DLPFileAccess.READ_ONLY, 100, uri); // 安装DLP沙箱
    console.info('res', JSON.stringify(res));
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
```


## installDLPSandbox

installDLPSandbox(bundleName: string, dlpFileAccess: DLPFileAccess, userId: number, callback: AsyncCallback&lt;DLPSandboxInfo&gt;): void

安装一个应用的DLP沙箱。使用callback方式异步返回应用沙箱信息。

**系统接口：** 此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| bundleName | string | 是 | 应用包名。 | 
| dlpFileAccess | [DLPFileAccess](#dlpfileaccess) | 是 | DLP文件授权类型。 | 
| userId | number | 是 | 当前的用户ID，通过帐号子系统获取的系帐号ID，默认主用户ID：100。 | 
| uri | string | 是 | DLP文件的URI。 | 
| callback | AsyncCallback&lt;[DLPSandboxInfo](#dlpsandboxinfo)&gt; | 是 | 获取应用沙箱信息的回调。 | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission';

async func(uri) {
  try {
    dlpPermission.installDLPSandbox('com.ohos.note', dlpPermission.DLPFileAccess.READ_ONLY, 100, uri, (err, res) => {
      if (err != undefined) {
        console.error('installDLPSandbox error,', err.code, err.message);
      } else {
        console.info('res', JSON.stringify(res));
      }
    }); // 安装DLP沙箱
  } catch (err) {
    console.error('installDLPSandbox error,', err.code, err.message);
  }
}
```


## uninstallDLPSandbox

uninstallDLPSandbox(bundleName: string, userId: number, appIndex: number): Promise&lt;void&gt;

卸载一个应用的DLP沙箱。使用Promise方式异步返回结果。

**系统接口：** 此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| bundleName | string | 是 | 应用包名。 | 
| userId | number | 是 | 当前的用户ID，通过帐号子系统获取的系统帐号ID，默认主用户ID：100 | 
| appIndex | number | 是 | DLP沙箱号。 | 

**返回值：**
| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;void&gt; | Promise对象。无返回结果的Promise对象。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
async func(uri) {
  try {
    let res: dlpPermission.DLPSandboxInfo = await dlpPermission.installDLPSandbox('com.ohos.note', dlpPermission.DLPFileAccess.READ_ONLY, 100, uri); // 安装DLP沙箱
    console.info('res', JSON.stringify(res));
    await dlpPermission.uninstallDLPSandbox('com.ohos.note', 100, res.appIndex); // 卸载DLP沙箱
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
```


## uninstallDLPSandbox

uninstallDLPSandbox(bundleName: string, userId: number, appIndex: number, callback: AsyncCallback&lt;void&gt;): void

卸载一个应用的DLP沙箱。使用callback方式异步返回结果。

**系统接口：** 此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| bundleName | string | 是 | 应用包名。 | 
| userId | number | 是 | 当前的用户ID，通过帐号子系统获取的系统帐号ID，默认主用户ID：100。 | 
| appIndex | number | 是 | DLP沙箱号，即installDLPSandbox接口调用成功后的返回值。 | 
| callback | AsyncCallback&lt;void&gt; | 是 | 获取卸载结果的回调。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission';

async func(uri) {
  try {
    let res: dlpPermission.DLPSandboxInfo = await dlpPermission.installDLPSandbox('com.ohos.note', dlpPermission.DLPFileAccess.READ_ONLY, 100, uri); // 安装DLP沙箱
    console.info('res', JSON.stringify(res));
    dlpPermission.uninstallDLPSandbox('com.ohos.note', 100, res.appIndex, (err, res) => {
      if (err != undefined) {
        console.error('uninstallDLPSandbox error,', err.code, err.message);
      } else {
        console.info('res', JSON.stringify(res));
      }
    });
  } catch (err) {
    console.error('uninstallDLPSandbox error,', err.code, err.message);
  }
}
```


## DLPSandboxState

DLP沙箱状态。

**系统接口：** 此接口为系统接口。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

| 名称 | 类型 | 只读 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- | -------- |
| bundleName | string | 否 | NA | 表示应用包名。 | 
| userId | number | 否 | NA | 当前的用户ID，通过帐号子系统获取的OS帐号ID，默认主用户ID：100。 | 
| appIndex | number | 否 | NA | 表示DLP沙箱应用索引。 | 


## on('uninstallDLPSandbox')

on(type: 'uninstallDLPSandbox', listener: Callback&lt;DLPSandboxState&gt;): void

注册监听DLP沙箱卸载事件。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| type | 'uninstallDLPSandbox' | 是 | 监听事件类型。 | 
| listener | Callback&lt;DLPSandboxState&gt; | 是 | 沙箱应用卸载事件的回调。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
event(info: dlpPermission.DLPSandboxState) {
  console.info('uninstallDLPSandbox event', info.appIndex, info.bundleName)
}
subscribe() {
  try {
    dlpPermission.on('uninstallDLPSandbox', this.event); // 订阅
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
async func() {
  this.subscribe();
}
```



## off('uninstallDLPSandbox')

off(type: 'uninstallDLPSandbox', listener?: Callback&lt;DLPSandboxState&gt;): void

取消监听DLP沙箱卸载事件。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| type | 'uninstallDLPSandbox' | 是 | 监听事件类型。 | 
| listener | Callback&lt;DLPSandboxState&gt; | 否 | 沙箱应用卸载事件的回调。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
event(info: dlpPermission.DLPSandboxState) {
  console.info('uninstallDLPSandbox event', info.appIndex, info.bundleName)
}
subscribe() {
  try {
    dlpPermission.on('uninstallDLPSandbox', this.event); // 订阅
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
unSubscribe() {
  try {
    dlpPermission.off('uninstallDLPSandbox', this.event); // 取消订阅
  } catch (err) {
    console.error('error', err.code, err.message); // 失败报错
  }
}
async func() {
  this.subscribe();
  this.unSubscribe();
}
```



## AccountType

授权帐号类型的枚举。

**系统接口：**此接口为系统接口。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

| 名称 | 默认值 | 说明 | 
| -------- | -------- | -------- |
| CLOUD_ACCOUNT | 1 | 表示云帐号。 | 
| DOMAIN_ACCOUNT | 2 | 表示域帐号。 | 


## AuthUser

表示授权用户数据。

**系统接口：**此接口为系统接口。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

| 名称 | 类型 | 只读 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- | -------- |
| authAccount | string | 否 | 是 | 表示被授权用户帐号。 | 
| authAccountType | [AccountType](#accounttype) | 否 | 是 | 表示被授权用户帐号类型。 | 
| dlpFileAccess | [DLPFileAccess](#dlpfileaccess) | 否 | 是 | 表示被授予的权限。 | 
| permExpiryTime | number | 否 | 是 | 表示授权到期时间。 | 


## DLPProperty

表示授权相关信息。

**系统接口：**此接口为系统接口。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

| 名称 | 类型 | 只读 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- | -------- |
| ownerAccount | string | 否 | 是 | 表示权限设置者帐号。 | 
| ownerAccountID | string | 否 | 是 | 表示权限设置者帐号的ID。 | 
| ownerAccountType | [AccountType](#accounttype) | 否 | 是 | 表示权限设置者帐号类型。 | 
| authUserList | Array&lt;[AuthUser](#authuser)&gt; | 否 | 否 | 表示授权用户列表。 | 
| contractAccount | string | 否 | 是 | 表示联系人帐号。 | 
| offlineAccess | boolean | 否 | 是 | 表示是否是离线打开。 | 
| everyoneAccessList | Array&lt;[DLPFileAccess](#dlpfileaccess)&gt; | 否 | 否 | 表示授予所有人的权限。 | 


## DLPFile

管理DLPFile的实例，表示一个DLP文件对象，需要通过generateDLPFile/openDLPFile 获取 DLPFile的示例。

**系统接口：**此接口为系统接口。

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**属性：**

| 名称 | 类型 | 只读 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- | -------- |
| dlpProperty | [DLPProperty](#dlpproperty) | 否 | 是 | 表示DLP文件授权相关信息 | 


### addDLPLinkFile

addDLPLinkFile(linkFileName: string): Promise&lt;void&gt;

在FUSE文件系统(Filesystem in Userspace)添加link文件(FUSE文件系统中映射到密文的虚拟文件，对该文件的读写操作会同步到DLP文件)。使用Promise方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| linkFileName | string | 是 | 用于fuse文件系统的link文件名。 | 

**返回值：**
| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;void&gt; | Promise对象。无返回结果的Promise对象。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100009 | Operate DLP file fail. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
import fs from '@ohos.file.fs';
async func(uri) {
  let file = fs.openSync(uri);
  try {
    let dlpFile: dlpPermission.DLPFile = await dlpPermission.openDLPFile(file.fd); // 打开DLP文件
    await dlpFile.addDLPLinkFile('test.txt.dlp.link'); // 添加link文件
    await dlpFile.closeDLPFile(); //关闭DLP对象
  } catch(err) {
    console.error('error', err.code, err.message); // 失败报错
  }
  fs.closeSync(file);
}
```


### addDLPLinkFile

addDLPLinkFile(linkFileName: string, callback: AsyncCallback&lt;void&gt;): void

在FUSE中添加link文件，使用callback方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| linkFileName | string | 是 | 用于fuse文件系统的link文件名。 | 
| callback | AsyncCallback&lt;void&gt; | 是 | 获取添加结果的回调。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100009 | Operate DLP file fail. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission';
import fs from '@ohos.file.fs';
async func(uri) {
  let file = fs.openSync(uri);
  try {
    let dlpFile: dlpPermission.DLPFile = await dlpPermission.openDLPFile(file.fd); // 打开DLP文件
    dlpFile.addDLPLinkFile('test.txt.dlp.link', (err, res) => {
      if (err != undefined) {
        console.error('addDLPLinkFile error,', err.code, err.message);
        await dlpFile.closeDLPFile(); //关闭DLP对象
      } else {
        console.info('res', JSON.stringify(res));
      }
    });
  } catch (err) {
    console.error('addDLPLinkFile error,', err.code, err.message);
  }
}
```



### stopFuseLink

stopFuseLink(): Promise&lt;void&gt;;

停止FUSE关联读写。使用Promise方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**返回值：**
| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;void&gt; | Promise对象。无返回结果的Promise对象。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100009 | Operate DLP file fail. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
import fs from '@ohos.file.fs';
async func(uri) {
  let file = fs.openSync(uri);
  try {
    let dlpFile: dlpPermission.DLPFile = await dlpPermission.openDLPFile(file.fd); // 打开DLP文件
    await dlpFile.addDLPLinkFile('test.txt.dlp.link'); // 添加link文件
    await dlpFile.stopFuseLink(); // 暂停link读写
    await dlpFile.closeDLPFile(); //关闭DLP对象
  } catch(err) {
    console.error('error', err.code, err.message); // 失败报错
  }
  fs.closeSync(file);
}
```


### stopFuseLink

stopFuseLink(callback: AsyncCallback&lt;void&gt;): void

停止FUSE关联读写，使用callback方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| callback | AsyncCallback&lt;void&gt; | 是 | 获取添加结果的回调。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100009 | Operate DLP file fail. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission';
import fs from '@ohos.file.fs';
async func(uri) {
  let file = fs.openSync(uri);
  try {
    let dlpFile: dlpPermission.DLPFile = await dlpPermission.openDLPFile(file.fd); // 打开DLP文件
    await dlpFile.addDLPLinkFile('test.txt.dlp.link'); // 添加link文件
    dlpFile.stopFuseLink((err, res) => {
      if (err != undefined) {
        console.error('stopFuseLink error,', err.code, err.message);
        await dlpFile.closeDLPFile(); //关闭DLP对象
      } else {
        console.info('res', JSON.stringify(res));
      }
    });
  } catch (err) {
    console.error('stopFuseLink error,', err.code, err.message);
  }
}
```



### resumeFuseLink

resumeFuseLink(): Promise&lt;void&gt;

恢复FUSE关联读写。使用Promise方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**返回值：**
| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;void&gt; | Promise对象。无返回结果的Promise对象。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100009 | Operate DLP file fail. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
import fs from '@ohos.file.fs';
async func(uri) {
  let file = fs.openSync(uri);
  try {
    let dlpFile: dlpPermission.DLPFile = await dlpPermission.openDLPFile(file.fd); // 打开DLP文件
    await dlpFile.addDLPLinkFile('test.txt.dlp.link'); // 添加link文件
    await dlpFile.stopFuseLink(); // 暂停link读写
    await dlpFile.resumeFuseLink(); // 恢复link读写
    await dlpFile.closeDLPFile(); //关闭DLP对象
  } catch(err) {
    console.error('error', err.code, err.message); // 失败报错
  }
  fs.closeSync(file);
}
```


### resumeFuseLink

resumeFuseLink(callback: AsyncCallback&lt;void&gt;): void

恢复FUSE关联读写，使用callback方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| linkFileName | string | 是 | 用于fuse文件系统的link文件名。 | 
| callback | AsyncCallback&lt;void&gt; | 是 | 获取添加结果的回调。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100009 | Operate DLP file fail. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission';
import fs from '@ohos.file.fs';
async func(uri) {
  let file = fs.openSync(uri);
  try {
    let dlpFile: dlpPermission.DLPFile = await dlpPermission.openDLPFile(file.fd); // 打开DLP文件
    await dlpFile.addDLPLinkFile('test.txt.dlp.link'); // 添加link文件
    await dlpFile.stopFuseLink(); // 暂停link读写
    dlpFile.resumeFuseLink((err, res) => {
      if (err != undefined) {
        console.error('resumeFuseLink error,', err.code, err.message);
        await dlpFile.closeDLPFile(); //关闭DLP对象
      } else {
        console.info('res', JSON.stringify(res));
      }
    });
  } catch (err) {
    console.error('resumeFuseLink error,', err.code, err.message);
  }
}
```



### replaceDLPLinkFile

replaceDLPLinkFile(linkFileName: string): Promise&lt;void&gt;

替换link文件。使用Promise方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| linkFileName | string | 是 | 用于fuse文件系统的link文件名。 | 

**返回值：**
| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;void&gt; | Promise对象。无返回结果的Promise对象。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100009 | Operate DLP file fail. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
import fs from '@ohos.file.fs';
async func(uri) {
  let file = fs.openSync(uri);
  try {
    let dlpFile: dlpPermission.DLPFile = await dlpPermission.openDLPFile(file.fd); // 打开DLP文件
    await dlpFile.addDLPLinkFile('test.txt.dlp.link'); // 添加link文件
    await dlpFile.stopFuseLink(); // 暂停link读写
    await dlpFile.replaceDLPLinkFile('test_new.txt.dlp.link'); // 替换link文件
    await dlpFile.resumeFuseLink(); // 恢复link读写
    await dlpFile.closeDLPFile(); //关闭DLP对象
  } catch(err) {
    console.error('error', err.code, err.message); // 失败报错
  }
  fs.closeSync(file);
}
```



### replaceDLPLinkFile

replaceDLPLinkFile(linkFileName: string, callback: AsyncCallback&lt;void&gt;): void

替换link文件，使用callback方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| linkFileName | string | 是 | 用于fuse文件系统的link文件名。 | 
| callback | AsyncCallback&lt;void&gt; | 是 | 获取添加结果的回调。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100009 | Operate DLP file fail. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission';
import fs from '@ohos.file.fs';
async func(uri) {
  let file = fs.openSync(uri);
  try {
    let dlpFile: dlpPermission.DLPFile = await dlpPermission.openDLPFile(file.fd); // 打开DLP文件
    await dlpFile.addDLPLinkFile('test.txt.dlp.link'); // 添加link文件
    await dlpFile.stopFuseLink(); // 暂停link读写
    dlpFile.replaceDLPLinkFile('test_new.txt.dlp.link', (err, res) => { // 替换link文件
      if (err != undefined) {
        console.error('replaceDLPLinkFile error,', err.code, err.message);
        await dlpFile.closeDLPFile(); //关闭DLP对象
      } else {
        console.info('res', JSON.stringify(res));
        await dlpFile.resumeFuseLink(); // 恢复link读写
      }
    });
  } catch (err) {
    console.error('error,', err.code, err.message);
  }
}
```



### deleteDLPLinkFile

deleteDLPLinkFile(linkFileName: string): Promise&lt;void&gt;

删除fuse文件系统中创建的link文件。使用Promise方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| linkFileName | string | 是 | 用于fuse文件系统的link文件名。 | 

**返回值：**
| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;void&gt; | Promise对象。无返回结果的Promise对象。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100009 | Operate DLP file fail. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
import fs from '@ohos.file.fs';
async func(uri) {
  let file = fs.openSync(uri);
  try {
    let dlpFile: dlpPermission.DLPFile = await dlpPermission.openDLPFile(file.fd); // 打开DLP文件
    await dlpFile.addDLPLinkFile('test.txt.dlp.link'); // 添加link文件
    await dlpFile.deleteDLPLinkFile('test.txt.dlp.link'); // 删除link文件
    await dlpFile.closeDLPFile(); //关闭DLP对象
  } catch(err) {
    console.error('error', err.code, err.message); // 失败报错
  }
  fs.closeSync(file);
}
```


### deleteDLPLinkFile

deleteDLPLinkFile(linkFileName: string, callback: AsyncCallback&lt;void&gt;): void

删除link文件，使用callback方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| linkFileName | string | 是 | 用于fuse文件系统的link文件名。 | 
| callback | AsyncCallback&lt;void&gt; | 是 | 获取添加结果的回调。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100009 | Operate DLP file fail. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission';
import fs from '@ohos.file.fs';
async func(uri) {
  let file = fs.openSync(uri);
  try {
    let dlpFile: dlpPermission.DLPFile = await dlpPermission.openDLPFile(file.fd); // 打开DLP文件
    await dlpFile.addDLPLinkFile('test.txt.dlp.link'); // 添加link文件
    dlpFile.deleteDLPLinkFile('test.txt.dlp.link', (err, res) => { // 删除link文件
      if (err != undefined) {
        console.error('replaceDLPLinkFile error,', err.code, err.message);
        await dlpFile.closeDLPFile(); //关闭DLP对象
      } else {
        console.info('res', JSON.stringify(res));
      }
    });
  } catch (err) {
    console.error('error,', err.code, err.message);
  }
}
```



### recoverDLPFile

recoverDLPFile(plaintextFd: number): Promise&lt;void&gt;;

移除DLP文件的权限控制，恢复成明文文件。使用Promise方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| plaintextFd | number | 是 | 目标明文文件的fd。 | 

**返回值：**
| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;void&gt; | Promise对象。无返回结果的Promise对象。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100002 | Credential task error. | 
| 19100003 | Credential task timeout. | 
| 19100004 | Credential service error. | 
| 19100005 | Credential remote server error. | 
| 19100008 | Not DLP file. | 
| 19100009 | Operate DLP file fail. | 
| 19100010 | DLP file is read only. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
import fs from '@ohos.file.fs';
async func(uri, destUri) {
  let file = fs.openSync(uri);
  let destFile = fs.openSync(destUri);
  try {
    let dlpFile: dlpPermission.DLPFile = await dlpPermission.openDLPFile(file.fd); // 打开DLP文件
    await dlpFile.recoverDLPFile(destFile.fd); // 还原DLP文件
    await dlpFile.closeDLPFile(); //关闭DLP对象
  } catch(err) {
    console.error('error', err.code, err.message); // 失败报错
  }
  fs.closeSync(file);
  fs.closeSync(destFile);
}
```


### recoverDLPFile

recoverDLPFile(plaintextFd: number, callback: AsyncCallback&lt;void&gt;): void

移除DLP文件的权限控制，恢复成明文文件，使用callback方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| plaintextFd | number | 是 | 目标明文文件的fd。 | 
| callback | AsyncCallback&lt;void&gt; | 是 | 获取添加结果的回调。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100002 | Credential task error. | 
| 19100003 | Credential task timeout. | 
| 19100004 | Credential service error. | 
| 19100005 | Credential remote server error. | 
| 19100008 | Not DLP file. | 
| 19100009 | Operate DLP file fail. | 
| 19100010 | DLP file is read only. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
import fs from '@ohos.file.fs';
async func(uri, destUri) {
  let file = fs.openSync(uri);
  let destFile = fs.openSync(destUri);
  try {
    let dlpFile: dlpPermission.DLPFile = await dlpPermission.openDLPFile(file.fd); // 打开DLP文件
    dlpFile.recoverDLPFile(destFile.fd, (err, res) => { // 还原DLP文件
      if (err != undefined) {
        console.error('recoverDLPFile error,', err.code, err.message);
        await dlpFile.closeDLPFile(); //关闭DLP对象
      } else {
        console.info('res', JSON.stringify(res));
      }
    });
  } catch (err) {
    console.error('error,', err.code, err.message);
  }
}
```


### closeDLPFile

closeDLPFile(): Promise&lt;void&gt;

关闭DLPFile，释放对象。使用Promise方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

> **说明：**
> dlpFile不再使用，应该关闭释放内存，且对象不应继续使用。

**返回值：**
| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;void&gt; | Promise对象。无返回结果的Promise对象。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 19100009 | Operate DLP file fail. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
import fs from '@ohos.file.fs';
async func(uri) {
  let file = fs.openSync(uri);
  try {
    let dlpFile: dlpPermission.DLPFile = await dlpPermission.openDLPFile(file.fd); // 打开DLP文件
    await dlpFile.closeDLPFile(); //关闭DLP对象
  } catch(err) {
    console.error('error', err.code, err.message); // 失败报错
  }
  fs.closeSync(file);
}
```


### closeDLPFile

closeDLPFile(callback: AsyncCallback&lt;void&gt;): void

关闭DLPFile，释放对象，使用callback方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

> **说明：**
> dlpFile不再使用，应该关闭释放内存，且对象不应继续使用。

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| callback | AsyncCallback&lt;void&gt; | 是 | 获取添加结果的回调。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 19100001 | Invalid parameter value. | 
| 19100009 | Operate DLP file fail. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
import fs from '@ohos.file.fs';
async func(uri) {
  let file = fs.openSync(uri);
  try {
    let dlpFile: dlpPermission.DLPFile = await dlpPermission.openDLPFile(file.fd); // 打开DLP文件
    dlpFile.closeDLPFile((err, res) => { // 还原DLP文件
      if (err != undefined) {
        console.error('closeDLPFile error,', err.code, err.message);
      } else {
        console.info('res', JSON.stringify(res));
      }
      fs.closeSync(file);
    });
  } catch (err) {
    console.error('error,', err.code, err.message);
    fs.closeSync(file);
  }
}
```


## generateDLPFile

generateDLPFile(plaintextFd: number, ciphertextFd: number, property: DLPProperty): Promise&lt;DLPFile&gt;

将明文文件加密生成权限受控文件，仅在授权列表内的用户可以打开，授权又分为完全控制权限和只读权限。获取DLPFile管理对象，使用Promise方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| plaintextFd | number | 是 | 待加密明文文件的fd。 | 
| ciphertextFd | number | 是 | 目标加密文件的fd。 | 
| property | [DLPProperty](#dlpproperty) | 是 | 授权用户信息：授权用户列表、owner帐号、联系人帐号。 | 

**返回值：**
| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;[DLPFile](#dlpfile)&gt; | Promise对象。返回对象表示成功生成DLP文件，返回null表示失败。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100002 | Credential task error. | 
| 19100003 | Credential task timeout. | 
| 19100004 | Credential service error. | 
| 19100005 | Credential remote server error. | 
| 19100009 | Operate DLP file fail. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
import fs from '@ohos.file.fs';
async func(uri, dlpUri) {
  let file = fs.openSync(uri);
  let dlp = fs.openSync(dlpUri);
  try {
    let dlpProperty: dlpPermission.DLPProperty = {
      ownerAccount: 'zhangsan',
      ownerAccountType: dlpPermission.AccountType.DOMAIN_ACCOUNT,
      authUserList: [],
      contactAccount: 'zhangsan',
      offlineAccess: true,
      ownerAccountID: 'xxxxxxx',
      everyoneAccessList: []
    };
    let dlpFile: dlpPermission.DLPFile = await dlpPermission.generateDLPFile(file.fd, dlp.fd, dlpProperty); // 生成DLP文件
    await dlpFile.closeDLPFile(); //关闭DLP对象
  } catch(err) {
    console.error('error', err.code, err.message); // 失败报错
  }
  fs.closeSync(file);
  fs.closeSync(dlp);
}
```


## generateDLPFile

generateDLPFile(plaintextFd: number, ciphertextFd: number, property: DLPProperty, callback: AsyncCallback&lt;DLPFile&gt;): void

DLP管理应用调用该接口，将明文文件加密生成权限受控文件，仅在授权列表内的用户可以打开，授权又分为完全控制权限和只读权限。获取DLPFile管理对象，使用callback方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| plaintextFd | number | 是 | 待加密明文文件的fd。 | 
| ciphertextFd | number | 是 | 目标加密文件的fd。 | 
| property | [DLPProperty](#dlpproperty) | 是 | 授权用户信息：授权用户列表、owner帐号、联系人帐号。 | 
| callback | AsyncCallback&lt;[DLPFile](#dlpfile)&gt; | 是 | 回调函数。返回DLPFile对象。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100002 | Credential task error. | 
| 19100003 | Credential task timeout. | 
| 19100004 | Credential service error. | 
| 19100005 | Credential remote server error. | 
| 19100009 | Operate DLP file fail. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
import fs from '@ohos.file.fs';
async func(uri, dlpUri) {
  let file = fs.openSync(uri);
  let dlp = fs.openSync(dlpUri);
  try {
    let dlpProperty: dlpPermission.DLPProperty = {
      ownerAccount: 'zhangsan',
      ownerAccountType: dlpPermission.AccountType.DOMAIN_ACCOUNT,
      authUserList: [],
      contactAccount: 'zhangsan',
      offlineAccess: true,
      ownerAccountID: 'xxxxxxx',
      everyoneAccessList: []
    };
    dlpPermission.generateDLPFile(file.fd, dlp.fd, dlpProperty, (err, res) => { // 生成DLP文件
      if (err != undefined) {
        console.error('generateDLPFile error,', err.code, err.message);
      } else {
        console.info('res', JSON.stringify(res));
      }
    });
  } catch (err) {
    console.error('error,', err.code, err.message);
    fs.closeSync(file);
  }
}
```


## openDLPFile

openDLPFile(ciphertextFd: number): Promise&lt;DLPFile&gt;

打开DLP文件。获取DLPFile管理对象，使用Promise方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| ciphertextFd | number | 是 | 加密文件的fd。 | 

**返回值：**
| 类型 | 说明 | 
| -------- | -------- |
| Promise&lt;[DLPFile](#dlpfile)&gt; | Promise对象。返回对象表示成功生成DLP文件，返回null表示失败。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100002 | Credential task error. | 
| 19100003 | Credential task timeout. | 
| 19100004 | Credential service error. | 
| 19100005 | Credential remote server error. | 
| 19100008 | Not DLP file. | 
| 19100009 | Operate DLP file fail. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
import fs from '@ohos.file.fs';
async func(uri) {
  let file = fs.openSync(uri);
  try {
    let dlpFile: dlpPermission.DLPFile = await dlpPermission.openDLPFile(file.fd); // 打开DLP文件
    await dlpFile.closeDLPFile(); //关闭DLP对象
  } catch(err) {
    console.error('error', err.code, err.message); // 失败报错
  }
  fs.closeSync(file);
}
```


## openDLPFile

openDLPFile(ciphertextFd: number, callback: AsyncCallback&lt;DLPFile&gt;): void

DLP管理应用调用该接口，打开DLP文件。获取DLPFile管理对象，使用callback方式异步返回结果。

**系统接口：**此接口为系统接口。

**需要权限：**ohos.permission.ACCESS_DLP_FILE

**系统能力：**SystemCapability.Security.DataLossPrevention

**起始版本：**10

**参数：**
| 参数名 | 类型 | 必填 | 说明 | 
| -------- | -------- | -------- | -------- |
| ciphertextFd | number | 是 | 加密文件的fd。 | 
| callback | AsyncCallback&lt;[DLPFile](#dlpfile)&gt; | 是 | 回调函数。返回DLPFile对象。 | 

**错误码：**

以下错误码的详细介绍请参见[DLP服务错误码](errorcodes-dlp.md)。

| 错误码ID | 错误信息 | 
| -------- | -------- |
| 201 | Permission denied. | 
| 202 | Non-system applications use system APIs. | 
| 401 | Parameter error. | 
| 19100001 | Invalid parameter value. | 
| 19100002 | Credential task error. | 
| 19100003 | Credential task timeout. | 
| 19100004 | Credential service error. | 
| 19100005 | Credential remote server error. | 
| 19100008 | Not DLP file. | 
| 19100009 | Operate DLP file fail. | 
| 19100011 | System service exception. | 

**示例：**
```
import dlpPermission from '@ohos.dlpPermission'
import fs from '@ohos.file.fs';
async func(uri) {
  let file = fs.openSync(uri);
  try {
    dlpPermission.openDLPFile(file.fd, (err, res) => { // 打开DLP文件
      if (err != undefined) {
        console.error('openDLPFile error,', err.code, err.message);
      } else {
        console.info('res', JSON.stringify(res));
      }
    });
  } catch (err) {
    console.error('error,', err.code, err.message);
    fs.closeSync(file);
  }
}
```


