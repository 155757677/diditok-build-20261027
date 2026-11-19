# 奕派解码器（东风 S73 工程模式）· iOS 版

扫车机工程模式弹窗上的二维码 → 自动算出应输密码 → 点一下数字即复制。
算法与 `计算方法.md` / `DongfengDecoder.cs` / Android 版 `Decoder.java` 逐行一致，全程不联网、不读写车机、画面和图片不出设备。

## 界面

- **主界面**：标题「奕派解码器」，中间大号密码，下面两个按钮「扫描二维码」「导入二维码」。
  点密码 = 复制；长按密码 = 显示随机码 / 车型串 / 结果来源（排查用）。
  **左边缘向右滑 = 关闭程序。**
- **扫码页**：整屏摄像头，识别到就自动算，算完自动回主界面显示结果。
  只认 QR / microQR，且识别区域锁在预览可见范围内，画面外的码不会被误读；屏幕里有多张时取最大那张。
  **左边缘向右滑 = 返回主界面。**
- **导入二维码**：从相册选一张二维码截图离线解码（iOS 16+ 走 Vision，支持 microQR；更低版本走 CIDetector）。
  扫不准、车机在另一台设备上、或者只想翻截图时用这条，最稳。

## 目录内容

| 文件 | 作用 |
|---|---|
| `Sources/DongfengDecoder.swift` | 解码核心：车型串取用 + SHA1PRNG 密钥派生 + AES-256-CBC + PKCS5 + 每位 ASCII +2 |
| `Sources/HomeViewController.swift` | 主界面、相册导入、左边缘关闭 |
| `Sources/ScanViewController.swift` | 实时扫码页，识别到自动出结果 |
| `Sources/AppDelegate.swift` | 无 storyboard 的 UIKit 入口，锁竖屏 |
| `Assets.xcassets/AppIcon.appiconset/` | 桌面图标：奕派 eπ 标识（1024 universal） |
| `tools/make-icon.py` | 从官方 logo 重上色生成图标的脚本 |
| `Info.plist` | 显示名「奕派解码器」、`CFBundleIconName`、相机 / 相册用途说明 |
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
页面里有个 `用哪台 macOS 构建机` 选项：`macos-26` / `macos-15` 排队久了换 `macos-26-intel`（Intel 池子通常有空机器）。

## 安装

CI 出的包是**未签名**的（GitHub runner 上没有你的证书），装之前要走你自己的通道：

- TrollStore：直接装（iOS 9–16.x 部分版本 / 17.0 Dopamine）。
- SideStore / AltStore / 宽松签工具：把 IPA 丢进去用你自己的 Apple ID 重签再装。

装完打开，允许相机权限（用相册导入才需要相册权限）。

## 算法自检

CI 第一步就会跑 `SelfTest`，用 Python 移植生成的样本核对，任一条不过直接不出包：

- 派生密钥（seed `" S73daiqnlsxrqt"`，32 字节）必须是
  `3098af3228f188128290821b1ff61ff2433f416de1efc14aea5597197f188bac`
- 裸 base64 / 整段 JSON（字面 `\n` 和真换行两种）/ 首尾空白 四种输入形式都要算对
- **车型串取自二维码**：`S09_`、`S73_EN`→`S73_`、` S73` 三组各自用对应密钥加密的密文都要解对
  （用错车型串必然 PKCS5 校验失败，所以这三组能过就说明 seed 前缀真是从二维码里取的）
- `getSecretKey()` 归一化：空 → `" S73"`、`S73` → `" S73"`（补空格）、`S73_EN` → `S73_`（截 4 位）、`eπ007` → `eπ00`
- 空输入、长度非 16 倍数、密文被改 必须报错

## 用法提醒

- 扫到码就自动出结果，那串就是要在车机上输的密码；点一下即复制到剪贴板。
- 随机码只在工程模式 Activity 重建时更换，弹窗关闭重开不换码，扫一次可反复用。
- 失败次数会累计、按日重置，**输错一次就停手**。
- 若随机码里有 `8`/`9`，对应位 +2 后是 `:`/`;` 而不是数字，这是算法本身如此（无回绕），照抄输入即可。
- 结果对不上时长按数字看「随机码 / 车型串 / 来源」：车型串不对就是读错了码或换了车型，不是算法问题。
