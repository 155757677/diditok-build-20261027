import Foundation

// 解码器自检：黄金样本由本地 Python 移植（与 DongfengDecoder.cs 同算法）生成。
// 打包前先跑这个，证明 Swift 版 SHA1PRNG 派生 / AES-256-CBC / PKCS5 / 每位+2 全部对齐。

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

// 1. 密钥派生（32 字节）
let key = DongfengDecoder.deriveKey(seed: Array(" S73daiqnlsxrqt".utf8), keySize: 32)
let hex = key.map { String(format: "%02x", $0) }.joined()
check("deriveKey == 车机内置派生结果", hex == expectedKeyHex, hex)

// 2. 裸 base64
for g in golden {
    do {
        let r = try DongfengDecoder.compute(g.ct)
        check("base64 \(g.code)", r.code == g.code && r.password == g.pwd,
              "got \(r.code)/\(r.password)")
    } catch {
        check("base64 \(g.code)", false, "\(error)")
    }
}

// 3. 整段 JSON：content 里是字面反斜杠 + n
let json1 = "{\"content\":\"" + golden[1].ct + "\\n S73\",\"encrypt_signal\":\"true\"}"
do {
    let r = try DongfengDecoder.compute(json1)
    check("json 字面\\n", r.code == golden[1].code && r.password == golden[1].pwd, "\(r.code)/\(r.password)")
} catch {
    check("json 字面\\n", false, "\(error)")
}

// 4. 整段 JSON：content 里是真换行
let json2 = "{\"content\":\"" + golden[2].ct + "\n S73\",\"encrypt_signal\":\"true\"}"
do {
    let r = try DongfengDecoder.compute(json2)
    check("json 真换行", r.code == golden[2].code && r.password == golden[2].pwd, "\(r.code)/\(r.password)")
} catch {
    check("json 真换行", false, "\(error)")
}

// 5. 首尾空白
do {
    let r = try DongfengDecoder.compute("  \(golden[3].ct)  \n")
    check("首尾空白", r.code == golden[3].code, "\(r.code)")
} catch {
    check("首尾空白", false, "\(error)")
}

// 6. 负例
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
