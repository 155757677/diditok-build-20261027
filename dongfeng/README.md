# 奕派解码器（东风 S73 工程模式）· iOS 版

扫车机工程模式弹窗上的二维码 → 识别到就自动算出应输密码，显示在屏幕底部 → 点一下数字即复制。
算法与 `计算方法.md` / `DongfengDecoder.cs` / Android 版 `Decoder.java` 逐行一致，全程不联网、不读写车机。

界面只有一个页面：顶部标题「奕派解码器」、中间尽量大的摄像头预览、底部大号密码，别的一个都不要。
没有手动输入框，没有计算按钮，没有复制按钮。

## 目录内容

| 文件 | 作用 |
|---|---|
| `Sources/DongfengDecoder.swift` | 解码核心：SHA1PRNG 密钥派生 + AES-256-CBC + PKCS5 + 每位 ASCII +2 |
| `Sources/ScanViewController.swift` | 界面：AVFoundation 实时扫码，识别到自动出结果 |
| `Sources/AppDelegate.swift` | 无 storyboard 的 UIKit 入口，锁竖屏 |
| `Assets.xcassets/AppIcon.appiconset/` | 桌面图标：奕派 eπ 标识（1024 universal） |
| `tools/make-icon.py` | 从官方 logo 重上色生成图标的脚本 |
| `Info.plist` | 显示名「奕派解码器」、`CFBundleIconName`、相机用途说明 |
| `SelfTest/main.swift` | 打包前的算法自检（黄金样本比对，不通过就不出包） |
| `project.yml` | XcodeGen 工程定义 |
| `dongfeng-ipa.yml` | GitHub Actions：自检 → xcodegen → xcodebuild → 打 IPA |
| `build-ipa.py` | 一键脚本：推源码 → 触发构建 → 轮询 → 下载 → 解出 IPA |

## 重新出包

```
pip install requests
python build-ipa.py            # token 取环境变量 GH_TOKEN，或本目录 token.txt
python build-ipa.py --no-push  # 只重编，不推源码
```

产物落在本目录 `DongfengDecoder.ipa`。

也可以直接在 GitHub 网页上手动跑：Actions → **Build Dongfeng Decoder IPA** → Run workflow。

## 安装

CI 出的包是**未签名**的（GitHub runner 上没有你的证书），装之前要走你自己的通道：

- TrollStore：直接装（iOS 9–16.x 部分版本 / 17.0 Dopamine）。
- SideStore / AltStore / 宽松签工具：把 IPA 丢进去用你自己的 Apple ID 重签再装。

装完打开，允许相机权限。

## 算法自检

CI 第一步就会跑 `SelfTest`，用 Python 移植生成的 7 组黄金样本核对：

- 派生密钥（seed `" S73daiqnlsxrqt"`，32 字节）必须是
  `3098af3228f188128290821b1ff61ff2433f416de1efc14aea5597197f188bac`
- 裸 base64 / 整段 JSON（字面 `\n` 和真换行两种）/ 首尾空白 四种输入形式都要算对
- 空输入、长度非 16 倍数、密文被改 必须报错

任一条不过，构建直接失败，不会出包。

## 用法提醒

- 扫到码就自动出结果，底部那串就是要在车机上输的密码；点一下它即复制到剪贴板。
- 随机码只在工程模式 Activity 重建时更换，弹窗关闭重开不换码，扫一次可反复用。
- 失败次数会累计、按日重置，**输错一次就停手**。
- 若随机码里有 `8`/`9`，对应位 +2 后是 `:`/`;` 而不是数字，这是算法本身如此（无回绕），照抄输入即可。
