import Foundation

// 解码器自检：黄金样本由本地 Python 移植（与 DongfengDecoder.cs 同算法）生成。
// 打包前先跑这个，证明 Swift 版 SHA1PRNG 派生 / AES-256-CBC / PKCS5 / 每位+2 全部对齐。
setbuf(stdout, nil)   // 崩溃时也能看到已打印的进度

let expectedKeyHex = "3098af3228f188128290821b1ff61ff2433f416de1efc14aea5597197f188bac"

let golden: [(ct: String, code: String, pwd: String)] = [
    ("WVuTtQl4cAH65JSdf7N+zA==", "000000", "222222"),
    ("lNVMJMNnta6QP0PiOkwnlw==", "123456", "345678"),
    ("z+fKTqCvyABg5v85RAb44w==", "908123", ";2:345"),
    ("5gilyxGoaqitrVOU4ZIe+Q==", "583092", "7:52;4"),
    ("gdWp0x4e7yLKFm8ZmeTb8w==", "777777", "999999"),
    ("xaTct8ZcQw+xcIul4JyHjA==", "480295", "6:24;7"),
    ("NNWuwd/EHlxufzSYH19dKQ==", "619084", "83;2:6"),
]

var failures = 0

func check(_ name: String, _ ok: Bool, _ detail: String = "") {
    if ok {
        print("PASS  \(name)")
    } else {
        failures += 1
        print("FAIL  \(name)  \(detail)")
    }
}

print("phase 1: deriveKey")
let key = DongfengDecoder.deriveKey(seed: Array(" S73daiqnlsxrqt".utf8), keySize: 32)
let hex = key.map { String(format: "%02x", Int($0)) }.joined()
print("       key = \(hex)")
check("deriveKey == 车机内置派生结果", hex == expectedKeyHex, hex)

print("phase 2: base64 x\(golden.count)")
for (idx, g) in golden.enumerated() {
    print("       [\(idx)] \(g.ct)")
    do {
        let r = try DongfengDecoder.compute(g.ct)
        check("base64 \(g.code)", r.code == g.code && r.password == g.pwd,
              "got \(r.code)/\(r.password)")
    } catch {
        check("base64 \(g.code)", false, "\(error)")
    }
}

print("phase 3: 整段 JSON（字面 \\n）")
let json1 = "{\"content\":\"" + golden[1].ct + "\\n S73\",\"encrypt_signal\":\"true\"}"
do {
    let r = try DongfengDecoder.compute(json1)
    check("json 字面\\n", r.code == golden[1].code && r.password == golden[1].pwd, "\(r.code)/\(r.password)")
} catch {
    check("json 字面\\n", false, "\(error)")
}

print("phase 4: 整段 JSON（真换行）")
let json2 = "{\"content\":\"" + golden[2].ct + "\n S73\",\"encrypt_signal\":\"true\"}"
do {
    let r = try DongfengDecoder.compute(json2)
    check("json 真换行", r.code == golden[2].code && r.password == golden[2].pwd, "\(r.code)/\(r.password)")
} catch {
    check("json 真换行", false, "\(error)")
}

print("phase 5: 首尾空白")
do {
    let r = try DongfengDecoder.compute("  \(golden[3].ct)  \n")
    check("首尾空白", r.code == golden[3].code, "\(r.code)")
} catch {
    check("首尾空白", false, "\(error)")
}

print("phase 6: 车型串取自二维码（不再硬编码 S73）")
// 这三组密文是用「别的车型串」派生的密钥加密的，只有正确取用二维码里那段才能解开
let tagVectors: [(json: String, code: String, pwd: String, tag: String)] = [
    ("{\"content\":\"NtWgCiBf95Njcu/Bou7HCQ==\\nS09_\",\"encrypt_signal\":\"true\"}", "480295", "6:24;7", "S09_"),
    ("{\"content\":\"ocCAnBjj/yLydgqF1RWWCQ==\\nS73_EN\",\"encrypt_signal\":\"true\"}", "619084", "83;2:6", "S73_"),
    ("{\"content\":\"Aqoy0X38Ccp5EGO2yi7fKg==\\n S73\",\"encrypt_signal\":\"true\"}", "362631", "584853", " S73"),
]
for v in tagVectors {
    print("       \(v.json)")
    do {
        let r = try DongfengDecoder.compute(v.json)
        check("车型串 \(v.tag)", r.code == v.code && r.password == v.pwd && r.tag == v.tag,
              "got \(r.code)/\(r.password)/\"\(r.tag)\"")
    } catch {
        check("车型串 \(v.tag)", false, "\(error)")
    }
}

print("phase 7: getSecretKey 归一化（补空格 / 截 4 位）")
let norm: [(raw: String, want: String)] = [
    ("", " S73"), (" S73", " S73"), ("S73", " S73"), ("S73_EN", "S73_"),
    ("S09_", "S09_"), ("S09_EN", "S09_"), (" S73 ", " S73"), ("eπ007", "eπ00"),
]
for n in norm {
    let got = DongfengDecoder.normalizedTag(n.raw)
    check("tag \"\(n.raw)\" → \"\(n.want)\"", got == n.want, "got \"\(got)\"")
}
print("phase 8: 补空格后的车型串能解出真样本")
do {
    // 车型串少一位时补空格：这条密文用的就是 " S73"
    let r = try DongfengDecoder.compute("{\"content\":\"Aqoy0X38Ccp5EGO2yi7fKg==\\nS73\",\"encrypt_signal\":\"true\"}")
    check("S73 补空格后解出真样本", r.code == "362631" && r.password == "584853", "\(r.code)/\(r.password)")
} catch {
    check("S73 补空格后解出真样本", false, "\(error)")
}

print("phase 9: 负例")
do {
    _ = try DongfengDecoder.compute("")
    check("空输入报错", false, "没抛错")
} catch {
    check("空输入报错", true)
}
do {
    _ = try DongfengDecoder.compute("AAAAAAAA")
    check("长度非16倍数报错", false, "没抛错")
} catch let e as DongfengDecoder.Error {
    check("长度非16倍数报错", e.errorDescription == "密文长度不是16的倍数", e.errorDescription ?? "")
} catch {
    check("长度非16倍数报错", false, "\(error)")
}
do {
    _ = try DongfengDecoder.compute(golden[0].ct + "AAAAAAAAAAAAAAAAAAAAAAAA")
    check("密钥不符报错", false, "没抛错")
} catch {
    check("密钥不符报错", true)
}

if failures == 0 {
    print("SELFTEST OK")
    exit(0)
} else {
    print("SELFTEST FAILED: \(failures)")
    exit(1)
}
