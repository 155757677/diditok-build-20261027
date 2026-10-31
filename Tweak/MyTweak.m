// MyTweak.m —— 滴滴 iOS Diditok Tweak
//
// 菜单（点右下角悬浮 "T" 按钮）：
//   1. 🔐 复制密文            免密码，AES-CBC 与 Android TkHook 逐字节一致
//   2. 👁️ 查看/复制明文       必须输密码 18075893937，错密码拒绝；明文只显示不写盘
//   3. 💾 保存密文到沙盒       只写密文 diditok.txt，绝不写明文
//   4. 📡 抓包控制            子菜单：开始抓包 / 停止抓包 / 分享导出（导出即清空缓冲）
//   5. ❌ 取消
//
// 加密格式（与 Android TkHook 完全一致）：
//   JSON {Phone, token, auToken, ddfp}
//   AES-128-CBC / PKCS7 / key="MFY-TK-ENC-2026!"(16B UTF-8) / IV=0x00×16
//   Base64 NO_WRAP
//
// 沙盒 Documents/ 输出（无明文！）：
//   diditok.txt       — 密文一行
//   diditok_full.har  — Proxyman HAR 1.2 抓包

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonCryptor.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <string.h>
#import <dlfcn.h>

// ═══════════════════════════════════════════════════════════════════════
// 自研 hook（不依赖 Cydia Substrate / MobileSubstrate）
// 非越狱（TrollStore）设备上没有 libsubstrate，调用 MSHookMessageEx
// 会在 dyld 加载阶段符号解析失败 → App 启动即闪退。
// 这里改用 Objective-C runtime 的 method_setImplementation。
// ═══════════════════════════════════════════════════════════════════════
static BOOL DidiHook(Class cls, SEL sel, IMP newImp, IMP *outOld) {
    if (!cls || !sel || !newImp) return NO;
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return NO;
    if (outOld) *outOld = method_getImplementation(m);
    method_setImplementation(m, newImp);
    return YES;
}


// ═══════════════════════════════════════════════════════════════════════
// 常量
// ═══════════════════════════════════════════════════════════════════════
static const char *kAesKey   = "MFY-TK-ENC-2026!";
static const int   kAesKeyLen = 16;
static const int   kAesIvLen  = 16;
#define DIDITOK_PASSWORD   @"18075893937"

// ═══════════════════════════════════════════════════════════════════════
// 状态
// ═══════════════════════════════════════════════════════════════════════
static NSString *g_lastAuToken   = nil;
static NSString *g_lastDdfp      = nil;
static NSString *g_lastDeviceId  = nil;
static NSString *g_lastToken     = nil;
static NSString *g_lastPhone     = nil;

static BOOL       g_captureEnabled = NO;
static NSMutableArray *g_harEntries;
static NSLock     *g_harLock;
static int        g_harSeq = 0;

static NSRegularExpression *g_reAu;

static UIWindow   *g_floatWindow = nil;
static UIButton   *g_floatButton = nil;
static UILabel    *g_toastLabel  = nil;

static IMP g_origDataTask1 = NULL;
static IMP g_origDataTask2 = NULL;
static IMP g_origUserToken = NULL;
static IMP g_origUserPhone = NULL;

static NSMutableDictionary *g_pendingHarMap;

static id g_launchObserver = nil;

// ═══════════════════════════════════════════════════════════════════════
// HAR response forward declaration
// ═══════════════════════════════════════════════════════════════════════
static NSDictionary *harResponseFrom(NSURLResponse *resp, NSData *body, NSTimeInterval timingMs);

// ═══════════════════════════════════════════════════════════════════════
// KVO 接收
// ═══════════════════════════════════════════════════════════════════════
@interface DiditokKvo : NSObject
+ (instancetype)shared;
@end
@implementation DiditokKvo
+ (instancetype)shared {
    static DiditokKvo *inst; static dispatch_once_t t;
    dispatch_once(&t, ^{ inst = [DiditokKvo new]; });
    return inst;
}
- (void)observeValueForKeyPath:(NSString *)kp ofObject:(id)obj
                        change:(NSDictionary *)change context:(void *)ctx {
    if (![obj isKindOfClass:[NSURLSessionTask class]]) return;
    NSURLSessionTask *task = obj;
    NSValue *k = [NSValue valueWithPointer:(__bridge const void *)task];
    NSDictionary *entry = g_pendingHarMap[k];
    if (!entry) return;

    if ([kp isEqualToString:@"response"] && task.response) {
        [entry setValue:harResponseFrom(task.response, nil, 0) forKey:@"response"];
    }
    if ([kp isEqualToString:@"state"] && task.state == NSURLSessionTaskStateCompleted) {
        @try { [task removeObserver:self forKeyPath:@"response"]; } @catch (NSException *e) {}
        @try { [task removeObserver:self forKeyPath:@"state"];    } @catch (NSException *e) {}
        [g_pendingHarMap removeObjectForKey:k];
        double ms = [[NSDate date] timeIntervalSinceDate:
                     (task.earliestBeginDate ?: [NSDate date])] * 1000.0;
        [entry setValue:@((int)(ms + 0.5)) forKey:@"time"];
        [entry setValue:@{@"send":@0, @"wait":@((int)(ms+0.5)), @"receive":@0,
                          @"dns":@-1, @"connect":@-1, @"ssl":@-1, @"blocked":@-1}
                 forKey:@"timings"];
    }
}
@end

// ═══════════════════════════════════════════════════════════════════════
// AES 工具
// ═══════════════════════════════════════════════════════════════════════
static NSData *pkcs7Pad(NSData *data, int bs) {
    NSUInteger len = data.length;
    int pad = bs - ((int)len % bs);
    if (pad == 0) pad = bs;
    NSMutableData *out = [NSMutableData dataWithData:data];
    unsigned char b = (unsigned char)pad;
    for (int i = 0; i < pad; i++) [out appendBytes:&b length:1];
    return out;
}
static NSString *aesEncryptString(NSString *plaintext) {
    NSData *plain = [plaintext dataUsingEncoding:NSUTF8StringEncoding];
    NSData *padded = pkcs7Pad(plain, 16);
    unsigned char k[kAesKeyLen]; memcpy(k, kAesKey, kAesKeyLen);
    unsigned char iv[kAesIvLen];  memset(iv, 0, kAesIvLen);
    NSUInteger outSize = padded.length + 16;
    void *outBuf = malloc(outSize);
    size_t moved = 0;
    // ⚠️ CCCrypt 是 3 个 C！不是 4 个
    CCCrypt(kCCEncrypt, kCCAlgorithmAES, kCCOptionPKCS7Padding,
            k, kAesKeyLen, iv, padded.bytes, padded.length,
            outBuf, outSize, &moved);
    NSData *ct = [NSData dataWithBytes:outBuf length:moved];
    free(outBuf);
    return [ct base64EncodedStringWithOptions:0];
}

// ═══════════════════════════════════════════════════════════════════════
// 凭据 JSON
// ═══════════════════════════════════════════════════════════════════════
static NSString *buildPlainJSON(void) {
    NSMutableDictionary *d = [NSMutableDictionary new];
    d[@"Phone"]   = g_lastPhone.length ? [@"苹果端" stringByAppendingString:g_lastPhone] : @"";
    d[@"token"]   = g_lastToken   ?: @"";
    d[@"auToken"] = g_lastAuToken ?: @"";
    d[@"ddfp"]    = g_lastDdfp    ?: (g_lastDeviceId ?: @"");
    NSError *err;
    NSData *data = [NSJSONSerialization dataWithJSONObject:d options:0 error:&err];
    if (!data) return @"{}";
    return [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
}
static NSString *buildCipherText(void) { return aesEncryptString(buildPlainJSON()); }
static NSString *documentsDir(void) {
    return NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0];
}
static void writeCipherOnly(void) {
    @autoreleasepool {
        NSString *ct = buildCipherText();
        [ct writeToFile:[documentsDir() stringByAppendingPathComponent:@"diditok.txt"]
             atomically:YES encoding:NSUTF8StringEncoding error:nil];
        NSLog(@"[Diditok] ✓ 密文写入 Documents/diditok.txt");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Toast + 按钮颜色
// ═══════════════════════════════════════════════════════════════════════
static void showToast(NSString *msg) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!g_toastLabel) return;
        g_toastLabel.text = msg; g_toastLabel.alpha = 1; g_toastLabel.hidden = NO;
        [NSObject cancelPreviousPerformRequestsWithTarget:g_toastLabel];
        [g_toastLabel performSelector:@selector(setAlpha:) withObject:@(0) afterDelay:2.5];
    });
}
static void setButtonColor(UIColor *c) {
    dispatch_async(dispatch_get_main_queue(), ^{ g_floatButton.backgroundColor = c; });
}

// ═══════════════════════════════════════════════════════════════════════
// 密码门控
// ═══════════════════════════════════════════════════════════════════════
static void requirePassword(UIViewController *presenter, void (^onOk)(void)) {
    UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"🔐 请输入密码"
                                                                  message:@"此操作需要密码验证"
                                                           preferredStyle:UIAlertControllerStyleAlert];
    [ac addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.secureTextEntry = YES; tf.placeholder = @"密码";
    }];
    [ac addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [ac addAction:[UIAlertAction actionWithTitle:@"确认" style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
        NSString *input = ac.textFields.firstObject.text ?: @"";
        if ([input isEqualToString:DIDITOK_PASSWORD]) onOk();
        else showToast(@"❌ 密码错误");
    }]];
    [presenter presentViewController:ac animated:YES completion:nil];
}

// ═══════════════════════════════════════════════════════════════════════
// HAR 构建
// ═══════════════════════════════════════════════════════════════════════
static NSDictionary *harResponseFrom(NSURLResponse *resp, NSData *body, NSTimeInterval timingMs) {
    NSMutableDictionary *r = [NSMutableDictionary new];
    NSHTTPURLResponse *hr = (NSHTTPURLResponse *)resp;
    int status = hr.statusCode ?: 0;
    r[@"status"] = @(status);
    r[@"statusText"] = @"";
    r[@"httpVersion"] = @"HTTP/1.1";
    NSMutableArray *hdrs = [NSMutableArray new];
    [hr.allHeaderFields enumerateKeysAndObjectsUsingBlock:^(id k, id v, BOOL *s) {
        [hdrs addObject:@{@"name": k, @"value": v}];
    }];
    r[@"headers"] = hdrs;
    NSMutableDictionary *content = [NSMutableDictionary new];
    if (body) {
        NSData *trunc = body.length > 32768 ? [body subdataWithRange:NSMakeRange(0, 32768)] : body;
        content[@"size"] = @(body.length);
        content[@"mimeType"] = hr.MIMEType ?: @"";
        content[@"text"] = [trunc base64EncodedStringWithOptions:0];
        content[@"encoding"] = @"base64";
        if (body.length > 32768) content[@"_truncated"] = @YES;
    } else { content[@"size"] = @0; content[@"mimeType"] = @""; }
    r[@"content"] = content;
    r[@"redirectURL"] = @""; r[@"headersSize"] = @-1; r[@"bodySize"] = @(body ? body.length : 0);
    r[@"time"] = @((int)(timingMs + 0.5));
    return r;
}

static NSDictionary *buildHarEntry(NSURLRequest *req, NSURLResponse *resp,
                                    NSTimeInterval startTime) {
    g_harSeq++;
    NSMutableDictionary *entry = [NSMutableDictionary new];
    entry[@"startedDateTime"] = [@(startTime) description];
    entry[@"_seq"] = @(g_harSeq);

    NSMutableDictionary *rq = [NSMutableDictionary new];
    rq[@"method"] = req.HTTPMethod ?: @"GET";
    rq[@"url"]    = req.URL.absoluteString ?: @"";
    rq[@"httpVersion"] = @"HTTP/1.1";
    NSMutableArray *hdrs = [NSMutableArray new];
    [req.allHTTPHeaderFields enumerateKeysAndObjectsUsingBlock:^(id k, id v, BOOL *s) {
        [hdrs addObject:@{@"name": k, @"value": v}];
    }];
    rq[@"headers"] = hdrs;
    NSURLComponents *uc = [NSURLComponents componentsWithURL:req.URL resolvingAgainstBaseURL:NO];
    NSMutableArray *qs = [NSMutableArray new];
    for (NSURLQueryItem *qi in uc.queryItems) {
        [qs addObject:@{@"name": qi.name ?: @"", @"value": qi.value ?: @""}];
    }
    rq[@"queryString"] = qs;
    NSMutableDictionary *pd = [NSMutableDictionary new];
    if (req.HTTPBody && req.HTTPBody.length) {
        NSData *trunc = req.HTTPBody.length > 16384 ?
            [req.HTTPBody subdataWithRange:NSMakeRange(0, 16384)] : req.HTTPBody;
        pd[@"mimeType"] = req.allHTTPHeaderFields[@"Content-Type"] ?:
                         req.allHTTPHeaderFields[@"content-type"] ?: @"application/octet-stream";
        pd[@"text"] = [[NSString alloc] initWithData:trunc encoding:NSUTF8StringEncoding]
                      ?: [trunc base64EncodedStringWithOptions:0];
        pd[@"encoding"] = @"utf-8"; pd[@"size"] = @(req.HTTPBody.length);
        if (req.HTTPBody.length > 16384) pd[@"_truncated"] = @YES;
    } else { pd[@"mimeType"] = @""; pd[@"text"] = @""; pd[@"size"] = @0; }
    rq[@"postData"] = pd;
    rq[@"cookies"] = @[]; rq[@"headersSize"] = @-1; rq[@"bodySize"] = @(req.HTTPBody ? req.HTTPBody.length : 0);
    entry[@"request"] = rq;

    entry[@"response"] = resp ? harResponseFrom(resp, nil, 0) :
        @{@"status":@0, @"statusText":@"Pending", @"httpVersion":@"",
          @"headers":@[], @"content":@{@"size":@0}, @"redirectURL":@"",
          @"headersSize":@0, @"bodySize":@0, @"_pending":@YES};
    entry[@"cache"] = @{};
    entry[@"timings"] = @{@"send":@0, @"wait":@0, @"receive":@0, @"dns":@-1,
                          @"connect":@-1, @"ssl":@-1, @"blocked":@-1};
    return entry;
}

// 导出 HAR → 写盘 → 弹系统分享面板 → 清空缓冲（避免误触重复导出）
static UIViewController *topVC(void);   // 定义在后面，这里先声明
static void exportHarAndShare(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [g_harLock lock]; NSArray *snap = [g_harEntries copy]; [g_harLock unlock];
        if (snap.count == 0) { showToast(@"⚠️ 还没有抓到请求"); return; }

        NSDictionary *har = @{@"log": @{
            @"version": @"1.2",
            @"creator": @{@"name": @"Diditok", @"version": @"0.4"},
            @"entries": snap,
            @"_proxyman": @{@"appName": @"滴滴", @"platform": @"iOS", @"tweak": @"Diditok"}}};
        NSError *err;
        NSData *data = [NSJSONSerialization dataWithJSONObject:har options:NSJSONWritingPrettyPrinted error:&err];
        if (!data) { showToast([NSString stringWithFormat:@"❌ HAR 失败: %@", err]); return; }

        NSString *path = [documentsDir() stringByAppendingPathComponent:@"diditok_full.har"];
        [data writeToFile:path atomically:YES];
        NSLog(@"[Diditok] HAR %d → %@", (int)snap.count, path);

        // 导出即清空缓冲
        [g_harLock lock]; g_harEntries = [NSMutableArray new]; g_harSeq = 0; [g_harLock unlock];

        showToast([NSString stringWithFormat:@"📤 已导出 %d 条，选「存储到文件」可存到 iCloud/本地", (int)snap.count]);

        // 等子菜单收起后再弹分享面板
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(300000000)),
                       dispatch_get_main_queue(), ^{
            UIViewController *p = topVC();
            if (!p) { showToast(@"❌ 找不到可用窗口"); return; }
            UIActivityViewController *av =
                [[UIActivityViewController alloc] initWithActivityItems:@[[NSURL fileURLWithPath:path]]
                                                  applicationActivities:nil];
            if (av.popoverPresentationController) {
                av.popoverPresentationController.sourceView = g_floatButton ?: p.view;
                av.popoverPresentationController.sourceRect = g_floatButton ? g_floatButton.bounds : p.view.bounds;
            }
            [p presentViewController:av animated:YES completion:nil];
        });
    });
}

static void captureRequest(NSURLRequest *req, NSURLSessionTask *task) {
    if (!g_captureEnabled) return;
    @autoreleasepool {
        NSTimeInterval now = [[NSDate date] timeIntervalSince1970] * 1000.0;
        NSDictionary *entry = buildHarEntry(req, nil, now);
        [g_harLock lock]; [g_harEntries addObject:entry]; [g_harLock unlock];
        NSValue *k = [NSValue valueWithPointer:(__bridge const void *)task];
        if (!g_pendingHarMap) g_pendingHarMap = [NSMutableDictionary new];
        g_pendingHarMap[k] = entry;
        @try { [task addObserver:[DiditokKvo shared] forKeyPath:@"response"
                          options:NSKeyValueObservingOptionNew context:(__bridge void *)k]; }
        @catch (NSException *e) {}
        @try { [task addObserver:[DiditokKvo shared] forKeyPath:@"state"
                          options:NSKeyValueObservingOptionNew context:(__bridge void *)k]; }
        @catch (NSException *e) {}
    }
}

static NSString* matchHeader(NSRegularExpression *re, NSString *s) {
    NSTextCheckingResult *m = [re firstMatchInString:s options:0 range:NSMakeRange(0, s.length)];
    if (m && m.numberOfRanges > 1) return [s substringWithRange:[m rangeAtIndex:1]];
    return nil;
}

// header 名大小写不敏感取值（allHTTPHeaderFields 的键大小写不保证）
static NSString *headerValue(NSDictionary *hdrs, NSString *name) {
    NSString *v = hdrs[name];
    if (v.length) return v;
    for (NSString *k in hdrs) {
        if ([k caseInsensitiveCompare:name] == NSOrderedSame) return hdrs[k];
    }
    return nil;
}

// 从 URL query 取字段（ddfp / device_id / token / tkn 都在这里）
static NSString *urlQueryValue(NSURLRequest *req, NSString *name) {
    NSString *q = req.URL.query;
    if (!q.length) return nil;
    for (NSString *pair in [q componentsSeparatedByString:@"&"]) {
        NSRange eq = [pair rangeOfString:@"="];
        if (eq.location == NSNotFound) continue;
        if (![[pair substringToIndex:eq.location] isEqualToString:name]) continue;
        NSString *v = [pair substringFromIndex:eq.location + 1];
        return [v stringByRemovingPercentEncoding] ?: v;
    }
    return nil;
}

// 递归在 JSON 里按 key 找字符串值
static id DidiJSONFind(id obj, NSArray *keys, int depth) {
    if (depth > 8 || !obj) return nil;
    if ([obj isKindOfClass:[NSDictionary class]]) {
        for (NSString *k in keys) {
            id v = ((NSDictionary *)obj)[k];
            if ([v isKindOfClass:[NSString class]] && [(NSString *)v length]) return v;
        }
        for (id v in [(NSDictionary *)obj allValues]) {
            id r = DidiJSONFind(v, keys, depth + 1);
            if (r) return r;
        }
    } else if ([obj isKindOfClass:[NSArray class]]) {
        for (id v in (NSArray *)obj) {
            id r = DidiJSONFind(v, keys, depth + 1);
            if (r) return r;
        }
    }
    return nil;
}

static id bodyJSONValue(NSData *body, NSArray *keys) {
    if (!body.length || body.length > 512 * 1024) return nil;
    id obj = [NSJSONSerialization JSONObjectWithData:body options:0 error:nil];
    if (!obj) return nil;
    return DidiJSONFind(obj, keys, 0);
}

// 只从响应体里补「手机号」，且仅在尚未拿到时执行（避免每次请求都解析）
static void onCredsFound(void);   // 定义在后面，这里先声明
static void scanResponseBodyForPhone(NSData *data) {
    if (g_lastPhone.length || !data.length || data.length > 512 * 1024) return;
    @autoreleasepool {
        id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
        if (!obj) return;
        static NSRegularExpression *rePhone; static dispatch_once_t once;
        dispatch_once(&once, ^{
            rePhone = [NSRegularExpression regularExpressionWithPattern:@"1[3-9]\\d{9}" options:0 error:nil];
        });
        id v = DidiJSONFind(obj,
                            @[@"phone", @"cell", @"phone_num", @"mobile",
                              @"user_phone", @"passenger_phone"], 0);
        if (![v isKindOfClass:[NSString class]]) return;
        NSString *s = v;
        NSTextCheckingResult *m = [rePhone firstMatchInString:s options:0
                                                        range:NSMakeRange(0, s.length)];
        if (m && m.range.length > 0) {
            g_lastPhone = s;
            onCredsFound();
        }
    }
}

static void onCredsFound(void) {
    setButtonColor([UIColor colorWithRed:0.1 green:0.7 blue:0.2 alpha:0.9]);
    writeCipherOnly();
    showToast([NSString stringWithFormat:@"✓ 新凭据  ddfp=%@",
               g_lastDdfp.length ? [g_lastDdfp substringToIndex:MIN(g_lastDdfp.length, 12)] : @"—"]);
}

static void scanHeaders(NSURLRequest *req, NSString *src, NSURLSessionTask *task) {
    @autoreleasepool {
        // ── 实测（HAR 207 条 + 主二进制扫描）：
        //   auToken : 请求头 secdd-authentication（94 条请求，值稳定，120 字符 hex）
        //   token   : 196 字符，出现在 query "token=" / body "token" / 请求头 "token" / query "tkn="
        //   ddfp    : 64 hex，出现在 query "ddfp="（68 次），device_id= 同值
        //   ❌ 旧代码用的 didi-header-ssuuid / didi-header-deviceid 在 App 与流量里都是 0 次
        NSDictionary *hdrs = req.allHTTPHeaderFields;

        NSString *au = headerValue(hdrs, @"secdd-authentication")
                    ?: (hdrs.count ? matchHeader(g_reAu, hdrs.description) : nil);

        NSString *ddfp = urlQueryValue(req, @"ddfp")
                      ?: urlQueryValue(req, @"device_id")
                      ?: headerValue(hdrs, @"ddfp")
                      ?: bodyJSONValue(req.HTTPBody, @[@"ddfp", @"device_id"]);

        NSString *tok = headerValue(hdrs, @"token")
                     ?: urlQueryValue(req, @"token")
                     ?: urlQueryValue(req, @"tkn")
                     ?: bodyJSONValue(req.HTTPBody, @[@"token"]);

        NSString *dev = urlQueryValue(req, @"device_id");

        // 空串/占位值不写入（token 未登录时可能是 ""，别把已拿到的覆盖掉）
        if (au.length   < 16) au   = nil;
        if (ddfp.length < 8)  ddfp = nil;
        if (tok.length  < 8)  tok  = nil;
        if (dev.length  < 8)  dev  = nil;

        BOOL changed = NO;
        if (au   && ![au   isEqualToString:g_lastAuToken])  { g_lastAuToken  = au;   changed = YES; }
        if (ddfp && ![ddfp isEqualToString:g_lastDdfp])     { g_lastDdfp     = ddfp; changed = YES; }
        if (dev  && ![dev  isEqualToString:g_lastDeviceId]) { g_lastDeviceId = dev;  changed = YES; }
        if (tok  && ![tok  isEqualToString:g_lastToken])    { g_lastToken    = tok;  changed = YES; }

        if (changed && (g_lastAuToken || g_lastDdfp || g_lastToken)) onCredsFound();
        if (g_captureEnabled) captureRequest(req, task);
    }
}


static UIWindow *appWindow(void);
static UIViewController *topVC(void);
// ═══════════════════════════════════════════════════════════════════════
// UI 事件 target（ObjC 方法，避免 addTarget:nil 野指针）
// ═══════════════════════════════════════════════════════════════════════
@interface DiditokActionTarget : NSObject
+ (instancetype)shared;
- (void)onFloatTap;
- (void)onPan:(UIPanGestureRecognizer *)g;
@end
@implementation DiditokActionTarget
+ (instancetype)shared {
    static DiditokActionTarget *inst; static dispatch_once_t t;
    dispatch_once(&t, ^{ inst = [DiditokActionTarget new]; });
    return inst;
}
- (void)onFloatTap {

    dispatch_async(dispatch_get_main_queue(), ^{
        UIViewController *vc = topVC();
        if (!vc || !vc.view.window) vc = appWindow().rootViewController;
        UIAlertController *ac = [UIAlertController alertControllerWithTitle:@"Diditok"
                                                                    message:nil
                                                             preferredStyle:UIAlertControllerStyleActionSheet];

        [ac addAction:[UIAlertAction actionWithTitle:@"🔐 复制密文（AES-CBC）"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
            UIPasteboard.generalPasteboard.string = buildCipherText();
            writeCipherOnly();
            showToast(@"密文已复制");
        }]];

        [ac addAction:[UIAlertAction actionWithTitle:@"👁️ 查看明文（需密码）"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
            requirePassword(vc, ^{
                NSString *plain = buildPlainJSON();
                UIAlertController *a2 = [UIAlertController alertControllerWithTitle:@"📄 明文凭据"
                                                                            message:plain
                                                                     preferredStyle:UIAlertControllerStyleAlert];
                [a2 addAction:[UIAlertAction actionWithTitle:@"复制明文" style:UIAlertActionStyleDefault handler:^(UIAlertAction *b) {
                    UIPasteboard.generalPasteboard.string = plain;
                    showToast(@"明文已复制（内存中，未写盘）");
                }]];
                [a2 addAction:[UIAlertAction actionWithTitle:@"好" style:UIAlertActionStyleCancel handler:nil]];
                [vc presentViewController:a2 animated:YES completion:nil];
            });
        }]];

        [ac addAction:[UIAlertAction actionWithTitle:@"💾 保存密文"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
            writeCipherOnly();
            showToast(@"diditok.txt 已写入 Documents/");
        }]];

        [ac addAction:[UIAlertAction actionWithTitle:@"📡 抓包控制"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
            UIAlertController *sub = [UIAlertController alertControllerWithTitle:@"📡 抓包控制"
                                                                         message:g_captureEnabled ? @"🔴 正在抓包…" : @"⚪ 未开启"
                                                                  preferredStyle:UIAlertControllerStyleAlert];

            UIAlertAction *start = [UIAlertAction actionWithTitle:@"▶️ 开始抓包"
                                                            style:UIAlertActionStyleDefault
                                                          handler:^(UIAlertAction *b) {
                [g_harLock lock]; g_harEntries = [NSMutableArray new]; g_harSeq = 0; [g_harLock unlock];
                g_captureEnabled = YES;
                setButtonColor([UIColor redColor]);
                showToast(@"🔴 开始抓包");
            }];
            start.enabled = !g_captureEnabled;
            [sub addAction:start];

            UIAlertAction *stop = [UIAlertAction actionWithTitle:@"⏹ 停止抓包"
                                                           style:UIAlertActionStyleDefault
                                                         handler:^(UIAlertAction *b) {
                g_captureEnabled = NO;
                setButtonColor([UIColor colorWithRed:0.1 green:0.7 blue:0.2 alpha:0.9]);
                showToast(@"⏹ 已停止抓包（已抓到的仍在内存，可点分享导出）");
            }];
            stop.enabled = g_captureEnabled;
            [sub addAction:stop];

            [sub addAction:[UIAlertAction actionWithTitle:@"📤 分享导出"
                                                    style:UIAlertActionStyleDefault
                                                  handler:^(UIAlertAction *b) {
                exportHarAndShare();
            }]];

            [sub addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
            [vc presentViewController:sub animated:YES completion:nil];
        }]];

        [ac addAction:[UIAlertAction actionWithTitle:@"❌ 取消" style:UIAlertActionStyleCancel handler:nil]];
        if (ac.popoverPresentationController) {
            ac.popoverPresentationController.sourceView = g_floatButton;
            ac.popoverPresentationController.sourceRect = g_floatButton.bounds;
        }
        [vc presentViewController:ac animated:YES completion:nil];
    });
}
- (void)onPan:(UIPanGestureRecognizer *)g {

    static CGPoint g_dragStart, g_btnStart;
    CGPoint pt = [g translationInView:g_floatWindow.superview];
    if (g.state == UIGestureRecognizerStateBegan) { g_dragStart = pt; g_btnStart = g_floatButton.center; }
    else if (g.state == UIGestureRecognizerStateChanged) {
        CGPoint t = CGPointMake(g_btnStart.x + pt.x - g_dragStart.x,
                                g_btnStart.y + pt.y - g_dragStart.y);
        CGRect b = [UIScreen mainScreen].bounds;
        CGFloat h = g_floatButton.bounds.size.width / 2;
        t.x = MAX(h, MIN(b.size.width - h, t.x));
        t.y = MAX(h + 20, MIN(b.size.height - h - 40, t.y));
        g_floatButton.center = t;
    }
}
@end

// ═══════════════════════════════════════════════════════════════════════
// NSURLSession hook
// ═══════════════════════════════════════════════════════════════════════
static id hookedDataTask1(id self, SEL _cmd, NSURLRequest *req, id handler) {
    typedef id (*o_t)(id, SEL, NSURLRequest *, id);
    // 包一层 completionHandler，顺手拿到响应体（只有这样才能补手机号）
    id wrapped = handler;
    if (handler) {
        void (^orig)(NSData *, NSURLResponse *, NSError *) =
            (void (^)(NSData *, NSURLResponse *, NSError *))handler;
        wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
            @try { scanResponseBodyForPhone(data); } @catch (NSException *e) {}
            orig(data, resp, err);
        };
    }
    id task = nil;
    if (g_origDataTask1) {
        task = ((o_t)g_origDataTask1)(self, _cmd, req, wrapped);
    } else {
        task = ((o_t)[NSURLSession instanceMethodForSelector:_cmd])(self, _cmd, req, wrapped);
    }
    scanHeaders(req, @"NSURLSession#dataTaskWithRequest:completionHandler:", task);
    return task;
}
static id hookedDataTask2(id self, SEL _cmd, NSURLRequest *req) {
    typedef id (*o_t)(id, SEL, NSURLRequest *);
    id task = nil;
    if (g_origDataTask2) {
        task = ((o_t)g_origDataTask2)(self, _cmd, req);
    } else {
        task = ((o_t)[NSURLSession instanceMethodForSelector:_cmd])(self, _cmd, req);
    }
    scanHeaders(req, @"NSURLSession#dataTaskWithRequest:", task);
    return task;
}

static NSString* hookedUserToken(id self, SEL _cmd) {
    NSString *t = g_origUserToken ? ((NSString*(*)(id,SEL))g_origUserToken)(self, _cmd) : @"";
    if (t.length && ![t isEqualToString:g_lastToken]) { g_lastToken = t; onCredsFound(); }
    return t;
}
static NSString* hookedUserPhone(id self, SEL _cmd) {
    NSString *p = g_origUserPhone ? ((NSString*(*)(id,SEL))g_origUserPhone)(self, _cmd) : @"";
    if (p.length && ![p isEqualToString:g_lastPhone]) { g_lastPhone = p; onCredsFound(); }
    return p;
}

// ═══════════════════════════════════════════════════════════════════════
// 悬浮 UI
// ═══════════════════════════════════════════════════════════════════════

@interface DiditokFloatWindow : UIWindow
@end

@implementation DiditokFloatWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    return (v == self) ? nil : v;
}
@end

static UIWindow *appWindow(void) {
    UIApplication *app = [UIApplication sharedApplication];
    if (@available(iOS 13.0, *)) {
        for (UIScene *s in app.connectedScenes) {
            if (![s isKindOfClass:[UIWindowScene class]]) continue;
            if (s.activationState != UISceneActivationStateForegroundActive) continue;
            for (UIWindow *w in ((UIWindowScene *)s).windows) {
                if (w != g_floatWindow && w.isKeyWindow) return w;
            }
        }
        for (UIScene *s in app.connectedScenes) {
            if (![s isKindOfClass:[UIWindowScene class]]) continue;
            for (UIWindow *w in ((UIWindowScene *)s).windows) {
                if (w != g_floatWindow) return w;
            }
        }
    }
    return app.keyWindow;
}

static UIViewController *topVC(void) {
    UIWindow *kw = appWindow();
    UIViewController *vc = kw.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}


static void setupFloatUI(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        if (g_floatWindow) return;
        UIScreen *sc = [UIScreen mainScreen];
        g_floatWindow = [[DiditokFloatWindow alloc] initWithFrame:sc.bounds];
        g_floatWindow.windowLevel = UIWindowLevelStatusBar + 1;
        g_floatWindow.backgroundColor = [UIColor clearColor];
        g_floatWindow.hidden = NO;

        CGFloat size = 60;
        CGFloat x = sc.bounds.size.width  - size - 20;
        CGFloat y = sc.bounds.size.height - size - 120;
        g_floatButton = [UIButton buttonWithType:UIButtonTypeCustom];
        g_floatButton.frame = CGRectMake(x, y, size, size);
        g_floatButton.layer.cornerRadius = size / 2;
        g_floatButton.layer.borderWidth  = 2;
        g_floatButton.layer.borderColor  = [UIColor whiteColor].CGColor;
        g_floatButton.backgroundColor    = [UIColor colorWithRed:0.2 green:0.4 blue:0.9 alpha:0.9];
        [g_floatButton setTitle:@"梦" forState:UIControlStateNormal];
        [g_floatButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        g_floatButton.titleLabel.font = [UIFont boldSystemFontOfSize:28];
        [g_floatButton addTarget:[DiditokActionTarget shared] action:@selector(onFloatTap) forControlEvents:UIControlEventTouchUpInside];
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc] initWithTarget:[DiditokActionTarget shared] action:@selector(onPan:)];
        [g_floatButton addGestureRecognizer:pan];
        [g_floatWindow addSubview:g_floatButton];

        CGFloat tw = 280, th = 44;
        g_toastLabel = [[UILabel alloc] initWithFrame:CGRectMake((sc.bounds.size.width - tw)/2,
                                                                 sc.bounds.size.height - 260, tw, th)];
        g_toastLabel.backgroundColor = [UIColor colorWithWhite:0 alpha:0.75];
        g_toastLabel.textColor = [UIColor whiteColor];
        g_toastLabel.textAlignment = NSTextAlignmentCenter;
        g_toastLabel.font = [UIFont systemFontOfSize:14];
        g_toastLabel.layer.cornerRadius = 22;
        g_toastLabel.layer.masksToBounds = YES;
        g_toastLabel.alpha = 0;
        g_toastLabel.userInteractionEnabled = NO;
        [g_floatWindow addSubview:g_toastLabel];
        NSLog(@"[Diditok] ✓ 悬浮 UI ready");
    });
}

// ═══════════════════════════════════════════════════════════════════════
// 反检测：把自己从 dyld 的镜像表里抹掉
//
// 滴滴安全组件通过公开 API 枚举已加载镜像：
//   _dyld_image_count / _dyld_get_image_name / _dyld_get_image_header
//   _dyld_get_image_vmaddr_slide / _dyld_register_func_for_add_image
// 它们全部读同一份全局表 _dyld_all_image_infos.infoArray。
// 所以不用 fishhook、不用改任何函数，直接改表里"我们这一条"的路径和 header，
// 让所有枚举者看到的都是一个系统库，看不到 Diditok.dylib。
// dyld 之后 dlopen 新镜像可能重建这张表，所以在新增镜像回调里再刷一次。
//
// 表结构（64 位）：
//   +0  uint32 version
//   +4  uint32 infoArrayCount
//   +8  const dyld_image_info *infoArray   // 每项：loadAddr / path / modDate
// ═══════════════════════════════════════════════════════════════════════

typedef struct {
    const void *imageLoadAddress;
    const char *imageFilePath;
    uintptr_t   imageFileModDate;
} DidiImageInfo;

static uint32_t    g_hideIndex = UINT32_MAX;
static const void *g_spoofAddr = NULL;
static const char *g_spoofPath = NULL;
static BOOL        g_hiding    = NO;
static void       *g_ai        = NULL;   // _dyld_all_image_infos 地址（固定不变，只解析一次）

static void DidiApplyHide(void) {
    if (!g_hiding || !g_spoofPath || !g_ai) return;
    void *ai = g_ai;
    uint32_t count = *(uint32_t *)((char *)ai + 4);
    DidiImageInfo *arr = *(DidiImageInfo **)((char *)ai + 8);
    if (!arr || count == 0) return;

    // 表可能被 dyld 重建，先按真实路径重新定位自己
    int idx = -1;
    for (uint32_t i = 0; i < count; i++) {
        const char *p = arr[i].imageFilePath;
        if (p && (strstr(p, "Diditok") || strstr(p, "diditok"))) { idx = (int)i; break; }
    }
    if (idx < 0) idx = (int)g_hideIndex;
    if ((uint32_t)idx >= count) return;

    arr[idx].imageFilePath    = g_spoofPath;
    arr[idx].imageLoadAddress = g_spoofAddr;
}

static void DidiOnImageAdded(const struct mach_header *mh, intptr_t slide) {
    DidiApplyHide();
}

static void DidiHideSelf(void) {
    int n = _dyld_image_count();
    for (int i = n - 1; i >= 0; i--) {
        const char *nm = _dyld_get_image_name(i);
        if (nm && (strstr(nm, "Diditok") || strstr(nm, "diditok"))) {
            g_hideIndex = (uint32_t)i;
            break;
        }
    }
    if (g_hideIndex == UINT32_MAX) {
        NSLog(@"[Diditok] ⚠️ 镜像表里没找到自己，跳过隐藏");
        return;
    }

    // 替身：优先挑 /usr/lib 下的系统库
    for (int i = 0; i < n; i++) {
        if ((uint32_t)i == g_hideIndex) continue;
        const char *nm = _dyld_get_image_name(i);
        if (!nm) continue;
        if (strncmp(nm, "/usr/lib/", 9) == 0) {
            g_spoofPath = nm;
            g_spoofAddr = _dyld_get_image_header((uint32_t)i);
            break;
        }
    }
    if (!g_spoofPath) {
        g_spoofPath = _dyld_get_image_name(0);
        g_spoofAddr = _dyld_get_image_header(0);
    }
    if (!g_spoofPath) return;

    g_ai = dlsym(RTLD_DEFAULT, "_dyld_all_image_infos");
    if (!g_ai) {
        NSLog(@"[Diditok] ⚠️ _dyld_all_image_infos 不可用，跳过隐藏");
        return;
    }
    g_hiding = YES;
    DidiApplyHide();
    _dyld_register_func_for_add_image(DidiOnImageAdded);
    NSLog(@"[Diditok] ✓ 已隐藏自身镜像 idx=%u → %s", g_hideIndex, g_spoofPath);
}

// ═══════════════════════════════════════════════════════════════════════
// 反检测（「非官方或低版本」）
// 实测依据：
//   · SecCodeCheckValidity / SecStaticCodeCheckValidity / SecCodeCopySigningInformation
//     在整个 IPA 里 0 处引用 → 不是本地验签
//   · 主二进制有 WSGAppAttestManager / WSGDeviceCheckManager / isAppAttestEnabled /
//     isAppAttestEntitlementPresent / isAppCracked / isJailbroken、DeviceCheck 的
//     attestKey:clientDataHash:completionHandler: → 重签后 App Attest 必然失败
//   · 提示文案不在包内（服务端下发）→ 只能削弱客户端上报的完整性信号
// ═══════════════════════════════════════════════════════════════════════
static BOOL DidiReturnNO(id self, SEL _cmd) { return NO; }

// 把「是否破解/越狱/可证明」这类布尔方法统一改成 NO（只认 BOOL 返回，避免误伤）
static void DidiSuppressIntegrityFlags(void) {
    static const char *names[] = {
        "isAppAttestEnabled", "isAppAttestEntitlementPresent",
        "isAppCracked", "isCracked", "isJailbroken", "isJailBreak", "isJailBroken",
        "isDeviceJailbroken", "isDeviceCracked", "hasCydia", "isPiracy"
    };
    int n = (int)(sizeof(names) / sizeof(names[0]));
    int total = objc_getClassList(NULL, 0);
    if (total <= 0) return;
    Class *classes = (Class *)malloc(sizeof(Class) * (size_t)total);
    if (!classes) return;
    total = objc_getClassList(classes, total);
    int hooked = 0;
    for (int i = 0; i < total; i++) {
        Class c = classes[i];
        for (int j = 0; j < n; j++) {
            SEL s = sel_registerName(names[j]);
            Method m = class_getInstanceMethod(c, s);
            if (m) {
                const char *t = method_getTypeEncoding(m);
                if (t && t[0] == 'c') {                 // 'c' = BOOL / char
                    method_setImplementation(m, (IMP)DidiReturnNO);
                    hooked++;
                }
            }
            Method cm = class_getClassMethod(c, s);
            if (cm) {
                const char *t = method_getTypeEncoding(cm);
                if (t && t[0] == 'c') {
                    method_setImplementation(cm, (IMP)DidiReturnNO);
                    hooked++;
                }
            }
        }
    }
    free(classes);
    NSLog(@"[Diditok] ✓ 完整性开关已压平 %d 处", hooked);
}

// DCAppAttestService 在重签包里一定不可用，直接让它自报不支持（SDK 会走降级路径）
static void DidiDisableAppAttest(void) {
    Class att = NSClassFromString(@"DCAppAttestService");
    if (!att) { NSLog(@"[Diditok] ⚠️ DCAppAttestService 不存在"); return; }
    Method m = class_getInstanceMethod(att, @selector(isSupported));
    if (m) {
        method_setImplementation(m, (IMP)DidiReturnNO);
        NSLog(@"[Diditok] ✓ DCAppAttestService.isSupported → NO");
    }
}

// 让本 dylib 在文件系统枚举里「不存在」（in-memory 隐藏之前做过，对磁盘扫描无效）
static IMP g_origContentsOfDir = NULL;
static IMP g_origFileExists     = NULL;

static BOOL DidiIsOurName(NSString *s) {
    if (!s.length) return NO;
    NSString *low = s.lowercaseString;
    return [low containsString:@"diditok"];
}
// 只隐藏「App 包内」的痕迹；Documents 里的 diditok.txt / diditok_full.har 必须照常可见（分享要用）
static BOOL DidiInAppBundle(NSString *path) {
    return path.length && [path.lowercaseString containsString:@".app"];
}
static NSArray *hookedContentsOfDir(id self, SEL _cmd, NSString *path, NSError **err) {
    typedef NSArray *(*o_t)(id, SEL, NSString *, NSError **);
    NSArray *arr = ((o_t)g_origContentsOfDir)(self, _cmd, path, err);
    if (!arr.count || !DidiInAppBundle(path)) return arr;
    NSMutableArray *out = [NSMutableArray arrayWithCapacity:arr.count];
    for (id x in arr) {
        if ([x isKindOfClass:[NSString class]] && DidiIsOurName(x)) continue;
        [out addObject:x];
    }
    return out.count == arr.count ? arr : out;
}
static BOOL hookedFileExists(id self, SEL _cmd, NSString *path) {
    typedef BOOL (*o_t)(id, SEL, NSString *);
    if (DidiInAppBundle(path) && DidiIsOurName(path)) return NO;
    return ((o_t)g_origFileExists)(self, _cmd, path);
}
static void DidiHideDylibFromFS(void) {
    Class fm = NSClassFromString(@"NSFileManager");
    if (!fm) return;
    DidiHook(fm, NSSelectorFromString(@"contentsOfDirectoryAtPath:error:"),
             (IMP)hookedContentsOfDir, &g_origContentsOfDir);
    DidiHook(fm, NSSelectorFromString(@"fileExistsAtPath:"),
             (IMP)hookedFileExists, &g_origFileExists);
    NSLog(@"[Diditok] ✓ 文件系统枚举已过滤 Diditok");
}

// ═══════════════════════════════════════════════════════════════════════
// constructor
// ═══════════════════════════════════════════════════════════════════════
__attribute__((constructor))
static void diditok_init(void) {
    @autoreleasepool {
      @try {
        NSLog(@"[Diditok] ▶ constructor fired");
        DidiHideSelf();
        DidiHideDylibFromFS();
        DidiDisableAppAttest();
        DidiSuppressIntegrityFlags();

        g_harLock    = [NSLock new];
        g_harEntries = [NSMutableArray new];
        g_reAu       = [NSRegularExpression regularExpressionWithPattern:@"secdd-authentication:\\s*(\\S+)" options:0 error:nil];

                // hook NSURLSession（ObjC runtime 交换，无需 Substrate）
        Class sessCls = NSClassFromString(@"NSURLSession");
        if (sessCls) {
            SEL s1 = NSSelectorFromString(@"dataTaskWithRequest:completionHandler:");
            SEL s2 = NSSelectorFromString(@"dataTaskWithRequest:");
            @try {
                DidiHook(sessCls, s1, (IMP)hookedDataTask1, &g_origDataTask1);
                NSLog(@"[Diditok] ✓ hooked NSURLSession.dataTaskWithRequest:completionHandler:");
            } @catch (NSException *e) { NSLog(@"[Diditok] ✗ hook s1 failed: %@", e); }
            @try {
                DidiHook(sessCls, s2, (IMP)hookedDataTask2, &g_origDataTask2);
                NSLog(@"[Diditok] ✓ hooked NSURLSession.dataTaskWithRequest:");
            } @catch (NSException *e) { NSLog(@"[Diditok] ✗ hook s2 failed: %@", e); }
        } else {
            NSLog(@"[Diditok] ⚠️ NSURLSession not found (shouldn't happen)");
        }

        // ✅ 修 2: UserInfoCallback — 多候选类名，逐个试
        for (NSString *name in @[@"UserInfoCallback",
                                 @"com.didi.carhailing.component.mapflow.util.UserInfoCallback"]) {
            Class c = NSClassFromString(name);
            if (!c) continue;
            NSLog(@"[Diditok] ✓ UserInfoCallback class = %@", name);
            @try {
                DidiHook(c, @selector(getToken), (IMP)hookedUserToken, &g_origUserToken);
            } @catch (NSException *e) { NSLog(@"[Diditok] ✗ hook getToken: %@", e); }
            @try {
                DidiHook(c, @selector(getPhoneNumber), (IMP)hookedUserPhone, &g_origUserPhone);
            } @catch (NSException *e) { NSLog(@"[Diditok] ✗ hook getPhoneNumber: %@", e); }
            break;
        }

        // ✅ 修 3: AES 自验（CCCrypt 3 个 C）
        @try {
            NSString *demo = @"{\"Phone\":\"13800000000\",\"token\":\"demo\",\"auToken\":\"demoA\",\"ddfp\":\"demoD\"}";
            NSString *enc = aesEncryptString(demo);
            NSLog(@"[Diditok] ✓ AES self-test OK  len=%lu", (unsigned long)enc.length);
        } @catch (NSException *e) {
            NSLog(@"[Diditok] ✗ AES self-test FAILED: %@", e);
        }

        // 等 App 完全启动后再建 UIWindow
        g_launchObserver = [[NSNotificationCenter defaultCenter] addObserverForName:UIApplicationDidFinishLaunchingNotification
                                                          object:nil
                                                           queue:[NSOperationQueue mainQueue]
                                                      usingBlock:^(NSNotification *note) {
            NSLog(@"[Diditok] ▶ UIApplicationDidFinishLaunching → setupFloatUI");
            setupFloatUI();
        }];

        // 兜底：如果通知没触发（罕见），3 秒后强制
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3000000000)),
                       dispatch_get_main_queue(), ^{ setupFloatUI(); });

        NSLog(@"[Diditok] ✅ constructor done  password=%@", DIDITOK_PASSWORD);
      } @catch (NSException *e) {
        NSLog(@"[Diditok] ✗ constructor exception: %@", e);
      }
    }
}
