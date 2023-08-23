# DLP权限管理部件

## 简介

数据防泄漏（DLP）是通过一系列安全保护技术，实现文档的权限管理功能，保证权限文档的安全性。

## 架构图

**图 1**   DLP权限管理部件架构图

![](figures/zh-cn_image_dlp_struct.png)

## 目录

```
/base/security/dlp_permission_service
├── figures                     # README图片存放目录
├── frameworks                  # 框架层，基础功能代码存放目录
│   ├── access_config           # 访问权限配置存放目录
│   ├── common                  # 框架公共代码存放目录
│   ├── dlp_permission          # DLP权限管理框架代码存放目录
│   └── test                    # 框架层测试代码存放目录
├── interfaces                  # 接口层
│   ├── inner_api               # 内部接口层
│   │   ├── dlp_fuse            # link文件及用户态文件系统实现代码存放目录
│   │   ├── dlp_parse           # dlp文件代码存放目录
│   │   └── dlp_permission      # DLP权限管理内部接口代码存放目录
│   └── kits                    # 外部接口层
│       ├── dlp_permission      # DLP权限管理外部接口代码存放目录
│       └── napi_common         # 外部接口公共代码存放目录
├── services                    # 服务层
│   └── dlp_permission          # 服务层代码存放目录
│       └── sa                  # 服务层代码存放目录
│           ├── adapt           # 数据适配相关代码存放目录
│           ├── callback        # 监听回调代码存放目录
│           ├── etc             # 配置文件存放目录
│           ├── sa_common       # 服务层公共代码存放目录
│           ├── sa_main         # DLP权限管理服务代码存放目录
│           ├── sa_profile      # DLP权限管理SA配置文件定义存放目录
│           └── test            # 服务层单元测试代码存放目录
└── test                        # 模糊测试代码存放目录
```

## 说明

### 接口说明

**表 1**  DLP权限管理模块说明
| **模块名** | **模块描述** |
| --- | --- |
|dlpPermission &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; |提供dlp权限管理模块方法|
|||

**表 2**  DLP权限管理模块类说明

| **类名** | **描述** |
| --- | --- |
|ActionFlagType &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;|枚举DLP文件执行的操作类型|
|DLPFileAccess|枚举DLP文件的访问权限|
|DLPPermissionInfo|DLP文件的权限信息|
|AccessedDLPFileInfo|访问的DLP文件信息|
|RetentionSandboxInfo|保留沙箱信息|
|GatheringPolicyType|枚举DLP文件的收集策略类型|
|DLPSandboxInfo|已安装的DLP沙盒应用程序信息|
|DLPSandboxState|DLP沙箱状态|
|AccountType|枚举生成DLP文件时的帐户类型|
|AuthUser|授权用户信息|
|DLPProperty|DLP文件属性|
|DLPFile|DLP文件对象|
|||

**表 3**  DLP权限管理模块方法说明
| **方法** | **描述** |
| --- | --- |
|isDLPFile(fd: number): Promise\<boolean\>;<br>isDLPFile(fd: number, callback: AsyncCallback\<boolean\>): void;|检查文件是否为DLP文件|
|getDLPPermissionInfo(): Promise\<DLPPermissionInfo\>;<br>getDLPPermissionInfo(callback: AsyncCallback\<DLPPermissionInfo\>): void;|获取该DLP文件的权限信息|
|getOriginalFileName(fileName: string): string;|从DLP文件名中获取原始文件名，此方法从DLP文件名中删除DLP文件扩展名|
|getDLPSuffix(): string;|获取DLP文件扩展名|
|on(type: 'openDLPFile', listener: Callback\<AccessedDLPFileInfo\>): void;|订阅当前应用程序打开DLP文件时报告的事件|
|off(type: 'openDLPFile', listener?: Callback\<AccessedDLPFileInfo\>): void;|取消订阅当前应用程序打开DLP文件时报告的事件|
|isInSandbox(): Promise\<boolean\>;<br>isInSandbox(callback: AsyncCallback\<boolean\>): void;|检查当前应用程序是否在DLP沙箱中|
|getDLPSupportedFileTypes(): Promise<Array\<string\>>;<br>getDLPSupportedFileTypes(callback: AsyncCallback<Array\<string\>>): void;|获取DLP支持的文件类型|
|setRetentionState(docUris: Array\<string\>): Promise\<void\>;<br>setRetentionState(docUris: Array\<string\>, callback: AsyncCallback\<void\>): void;|根据URI列表设置对应的文件的沙箱保留状态|
|cancelRetentionState(docUris: Array\<string\>): Promise\<void\>;<br>cancelRetentionState(docUris: Array\<string\>, callback: AsyncCallback\<void\>): void;|根据URI列表取消对应的文件的沙箱保留状态|
|getRetentionSandboxList(bundleName?: string): Promise<Array\<RetentionSandboxInfo\>>;<br>getRetentionSandboxList(bundleName: string, callback: AsyncCallback<Array\<RetentionSandboxInfo\>>): void;<br>getRetentionSandboxList(callback: AsyncCallback<Array\<RetentionSandboxInfo\>>): void;|获取DLP保留的沙箱应用信息|
|getDLPFileAccessRecords(): Promise<Array\<AccessedDLPFileInfo\>>;<br>getDLPFileAccessRecords(callback: AsyncCallback<Array\<AccessedDLPFileInfo\>>): void;|获取DLP文件的访问记录|
|getDLPGatheringPolicy(): Promise\<GatheringPolicyType\>;<br>getDLPGatheringPolicy(callback: AsyncCallback\<GatheringPolicyType\>): void;|获取DLP沙箱收集策略|
|installDLPSandbox(bundleName: string, access: DLPFileAccess, userId: number, uri: string): Promise\<DLPSandboxInfo\>;<br>installDLPSandbox(bundleName: string, access: DLPFileAccess, userId: number, uri: string, callback: AsyncCallback\<DLPSandboxInfo\>): void;|安装DLP沙箱应用程序|
|uninstallDLPSandbox(bundleName: string, userId: number, appIndex: number): Promise\<void\>;<br>uninstallDLPSandbox(bundleName: string, userId: number, appIndex: number, callback: AsyncCallback\<void\>): void;|卸载DLP沙箱应用程序|
|on(type: 'uninstallDLPSandbox', listener: Callback\<DLPSandboxState\>): void;|订阅DLP沙箱应用卸载时上报的事件|
|off(type: 'uninstallDLPSandbox', listener?: Callback\<DLPSandboxState\>): void;|取消订阅DLP沙箱应用卸载时上报的事件|
|generateDLPFile(plaintextFd: number, ciphertextFd: number, property: DLPProperty): Promise\<DLPFile\>;<br>generateDLPFile(plaintextFd: number, ciphertextFd: number, property: DLPProperty, callback: AsyncCallback\<DLPFile\>): void;|生成DLP文件|
|openDLPFile(ciphertextFd: number): Promise\<DLPFile\>;<br>openDLPFile(ciphertextFd: number, callback: AsyncCallback\<DLPFile\>): void;|打开DLP文件|
|||

**表 3** DLPFile方法说明
| **方法** | **描述** |
| --- | --- |
|addDLPLinkFile(linkFileName: string): Promise\<void\>;<br>addDLPLinkFile(linkFileName: string, callback: AsyncCallback\<void\>): void;|为DLP文件添加link文件|
|stopFuseLink(): Promise\<void\>;<br>stopFuseLink(callback: AsyncCallback\<void\>): void;|停止DLP文件与link文件之间的FUSE链接|
|resumeFuseLink(): Promise\<void\>;<br>resumeFuseLink(callback: AsyncCallback\<void\>): void;|恢复DLP文件与link文件之间的FUSE链接|
|replaceDLPLinkFile(linkFileName: string): Promise\<void\>;<br>replaceDLPLinkFile(linkFileName: string, callback: AsyncCallback\<void\>): void;|替换DLP文件的link文件|
|deleteDLPLinkFile(linkFileName: string): Promise\<void\>;<br>deleteDLPLinkFile(linkFileName: string, callback: AsyncCallback\<void\>): void;|删除DLP文件的link文件|
|recoverDLPFile(plaintextFd: number): Promise\<void\>;<br>recoverDLPFile(plaintextFd: number, callback: AsyncCallback\<void\>): void;|从DLP文件恢复明文文件|
|closeDLPFile(): Promise\<void\>;<br>closeDLPFile(callback: AsyncCallback\<void\>): void;|关闭DLP文件|
|||

## 相关仓

DLP权限管理部件

**security\_dlp\_permission\_service**