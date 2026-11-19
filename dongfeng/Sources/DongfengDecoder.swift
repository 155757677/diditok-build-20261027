import Foundation
import CommonCrypto

/// 东风车机工程模式「加密项」解码。
/// 算法与 DongfengDecoder.cs / apk Decoder.java 逐行对齐（AOSP InsecureSHA1PRNGKeyDerivator + AES-256-CBC）。
/// 纯离线：不联网、不读写车机。
enum DongfengDecoder {

    struct Output {
        /// QR 里的 6 位随机码明文
        let code: String
        /// 应输密码（随机码每位 ASCII +2，无回绕）
        let password: String
    }

    enum Error: LocalizedError {
        case empty
        case badBase64
        case badCipherLength
        case badPkcs5
        case badPlainLength(String)
        case nonDigit(String)

        var errorDescription: String? {
            switch self {
            case .empty:            return "输入为空"
            case .badBase64:        return "base64 解析失败"
            case .badCipherLength:  return "密文长度不是16的倍数"
            case .badPkcs5:         return "PKCS5 填充异常，密钥或密文不对"
            case .badPlainLength(let p): return "明文不是6位: [\(p)]"
            case .nonDigit(let p):  return "明文含非数字: [\(p)]"
            }
        }
    }

    // MARK: - 入口

    /// 接受整段二维码 JSON（{"content":"<base64>\n S73",...}）或裸 base64。
    static func compute(_ raw: String) throws -> Output {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)

        if let g = firstMatch(s, pattern: "\"content\"\\s*:\\s*\"([^\"]*)\"") {
            s = g
        }
        s = s.replacingOccurrences(of: "\\n", with: "\n")
             .replacingOccurrences(of: "\\/", with: "/")
        if let nl = s.firstIndex(of: "\n") {
            s = String(s[..<nl])
        }
        s = s.trimmingCharacters(in: .whitespacesAndNewlines)
        if s.isEmpty { throw Error.empty }

        guard let ct = Data(base64Encoded: s, options: []) else { throw Error.badBase64 }
        if ct.isEmpty || ct.count % 16 != 0 { throw Error.badCipherLength }

        let key = deriveKey(seed: Array(" S73daiqnlsxrqt".utf8), keySize: 32)
        guard let pt = aesCBCCrypt(key: key, iv: [UInt8](repeating: 0, count: 16), data: [UInt8](ct), decrypt: true) else {
            throw Error.badPkcs5
        }
        guard let last = pt.last else { throw Error.badPkcs5 }
        let pad = Int(last)
        if pad < 1 || pad > 16 { throw Error.badPkcs5 }
        if pt.count < pad { throw Error.badPkcs5 }

        let body = Array(pt[0..<(pt.count - pad)])
        guard let plain = String(bytes: body, encoding: .ascii) else { throw Error.badPkcs5 }
        if plain.count != 6 { throw Error.badPlainLength(plain) }
        if plain.contains(where: { $0 < "0" || $0 > "9" }) { throw Error.badPlainLength(plain) }

        let pwd = String(plain.unicodeScalars.map { Character(UnicodeScalar($0.value + 2)!) })
        return Output(code: plain, password: pwd)
    }

    private static func firstMatch(_ s: String, pattern: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern) else { return nil }
        let ns = s as NSString
        guard let m = re.firstMatch(in: s, range: NSRange(location: 0, length: ns.length)) else { return nil }
        guard m.numberOfRanges > 1 else { return nil }
        let r = m.range(at: 1)
        if r.location == NSNotFound { return nil }
        return ns.substring(with: r)
    }

    // MARK: - AES-256-CBC，NoPadding（填充由调用方按 PKCS5 校验）

    private static func aesCBCCrypt(key: [UInt8], iv: [UInt8], data: [UInt8], decrypt: Bool) -> [UInt8]? {
        var out = [UInt8](repeating: 0, count: data.count + kCCBlockSizeAES128)
        var n = 0
        let status: CCCryptorStatus = data.withUnsafeBytes { dptr in
            key.withUnsafeBytes { kptr in
                iv.withUnsafeBytes { vptr in
                    CCCrypt(
                        decrypt ? CCOperation(kCCDecrypt) : CCOperation(kCCEncrypt),
                        CCAlgorithm(kCCAlgorithmAES),
                        CCOptions(0),                       // 0 = 不做 PKCS7 填充，与车机 NoPadding 一致
                        kptr.baseAddress, key.count,
                        vptr.baseAddress,
                        dptr.baseAddress, data.count,
                        &out, out.count,
                        &n)
                }
            }
        }
        return status == kCCSuccess ? Array(out[0..<n]) : nil
    }

    // MARK: - InsecureSHA1PRNGKeyDerivator（含 extraBytes = 7 历史 bug）

    private static let Hs: [UInt32] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    private static let EndFlags: [UInt32] = [0x8000_0000, 0x0080_0000, 0x0000_8000, 0x0000_0080]
    private static let Right1 = [0, 40, 48, 56]
    private static let Right2 = [0, 8, 16, 24]
    private static let LeftArr = [0, 24, 16, 8]
    private static let Mask: [UInt32] = [0xFFFF_FFFF, 0x00FF_FFFF, 0x0000_FFFF, 0x0000_00FF]

    static func deriveKey(seed seedBytes: [UInt8], keySize: Int) -> [UInt8] {
        var seed = [UInt32](repeating: 0, count: 87)
        for z in 0..<5 { seed[82 + z] = Hs[z] }
        var copies = [UInt32](repeating: 0, count: 37)
        var nextBuf = [UInt8](repeating: 0, count: 20)

        let seedLength = UInt64(seedBytes.count)
        updateHash(&seed, seedBytes, 0, seedBytes.count - 1)

        let extraBytes = 7
        let lastWord = seed[81] == 0 ? 0 : Int((seed[81] + UInt32(extraBytes)) >> 2)
        for i in (lastWord + 3)..<18 { seed[i] = 0 }

        let bits = (seedLength << 3) + 64
        if seed[81] < 48 {
            seed[14] = UInt32(truncatingIfNeeded: bits >> 32)
            seed[15] = UInt32(truncatingIfNeeded: bits)
        } else {
            copies[19] = UInt32(truncatingIfNeeded: bits >> 32)
            copies[20] = UInt32(truncatingIfNeeded: bits)
        }

        var counter: UInt64 = 0
        var key = [UInt8](repeating: 0, count: keySize)
        var next = 0
        let n = Int(seed[81] & 3)

        while true {
            if n == 0 {
                seed[lastWord]     = UInt32(truncatingIfNeeded: counter >> 32)
                seed[lastWord + 1] = UInt32(truncatingIfNeeded: counter)
                seed[lastWord + 2] = EndFlags[0]
            } else {
                seed[lastWord] |= UInt32(truncatingIfNeeded: (counter >> UInt64(Right1[n])) & UInt64(Mask[n]))
                seed[lastWord + 1] = UInt32(truncatingIfNeeded: counter >> UInt64(Right2[n]))
                seed[lastWord + 2] = UInt32(truncatingIfNeeded: (counter << UInt64(LeftArr[n])) | UInt64(EndFlags[n]))
            }
            if seed[81] > 48 {
                copies[5] = seed[16]
                copies[6] = seed[17]
            }
            computeHash(&seed)
            if seed[81] > 48 {
                for z in 0..<16 { copies[21 + z] = seed[z] }
                for z in 0..<16 { seed[z] = copies[5 + z] }
                computeHash(&seed)
                for z in 0..<16 { seed[z] = copies[21 + z] }
            }
            counter += 1

            var j = 0
            for i in 0..<5 {
                // Swift 的 UInt8(UInt32) 会做溢出检查（C# 的 (byte) 是截断），必须用 truncatingIfNeeded
                let k = seed[82 + i]
                nextBuf[j]     = UInt8(truncatingIfNeeded: k >> 24)
                nextBuf[j + 1] = UInt8(truncatingIfNeeded: k >> 16)
                nextBuf[j + 2] = UInt8(truncatingIfNeeded: k >> 8)
                nextBuf[j + 3] = UInt8(truncatingIfNeeded: k)
                j += 4
            }
            let take = min(20, keySize - next)
            for z in 0..<take { key[next + z] = nextBuf[z] }
            next += take
            if next >= keySize { break }
        }
        return key
    }

    private static func rotl(_ x: UInt32, _ n: UInt32) -> UInt32 {
        return (x << n) | (x >> (32 - n))
    }

    private static func computeHash(_ w: inout [UInt32]) {
        var a = w[82], b = w[83], c = w[84], d = w[85], e = w[86]
        for t in 16..<80 {
            w[t] = rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1)
        }
        for t in 0..<20 {
            let temp = rotl(a, 5) &+ ((b & c) | (~b & d)) &+ e &+ w[t] &+ 0x5A82_7999
            e = d; d = c; c = rotl(b, 30); b = a; a = temp
        }
        for t in 20..<40 {
            let temp = rotl(a, 5) &+ (b ^ c ^ d) &+ e &+ w[t] &+ 0x6ED9_EBA1
            e = d; d = c; c = rotl(b, 30); b = a; a = temp
        }
        for t in 40..<60 {
            let temp = rotl(a, 5) &+ ((b & c) | (b & d) | (c & d)) &+ e &+ w[t] &+ 0x8F1B_BCDC
            e = d; d = c; c = rotl(b, 30); b = a; a = temp
        }
        for t in 60..<80 {
            let temp = rotl(a, 5) &+ (b ^ c ^ d) &+ e &+ w[t] &+ 0xCA62_C1D6
            e = d; d = c; c = rotl(b, 30); b = a; a = temp
        }
        w[82] = w[82] &+ a
        w[83] = w[83] &+ b
        w[84] = w[84] &+ c
        w[85] = w[85] &+ d
        w[86] = w[86] &+ e
    }

    private static func updateHash(_ arr: inout [UInt32], _ bin: [UInt8], _ fromByte: Int, _ toByte: Int) {
        let base = arr[81]
        var i = fromByte
        var wordIndex = Int(base >> 2)
        var byteIndex = Int(base & 3)
        arr[81] = (base + UInt32(toByte - fromByte + 1)) & 63

        if byteIndex != 0 {
            while i <= toByte && byteIndex < 4 {
                arr[wordIndex] |= UInt32(bin[i] & 0xFF) << UInt32((3 - byteIndex) * 8)
                byteIndex += 1
                i += 1
            }
            if byteIndex == 4 {
                wordIndex += 1
                if wordIndex == 16 {
                    computeHash(&arr)
                    wordIndex = 0
                }
            }
            if i > toByte { return }
        }
        let maxWord = (toByte - i + 1) >> 2
        for _ in 0..<maxWord {
            arr[wordIndex] = UInt32(bin[i] & 0xFF) << 24
                | UInt32(bin[i + 1] & 0xFF) << 16
                | UInt32(bin[i + 2] & 0xFF) << 8
                | UInt32(bin[i + 3] & 0xFF)
            i += 4
            wordIndex += 1
            if wordIndex == 16 {
                computeHash(&arr)
                wordIndex = 0
            }
        }
        let nBytes = toByte - i + 1
        if nBytes != 0 {
            var w = UInt32(bin[i] & 0xFF) << 24
            if nBytes != 1 {
                w |= UInt32(bin[i + 1] & 0xFF) << 16
                if nBytes != 2 { w |= UInt32(bin[i + 2] & 0xFF) << 8 }
            }
            arr[wordIndex] = w
        }
    }
}
