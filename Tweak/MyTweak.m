// MyTweak.m —— Diditok Tweak（纯抓包版，通用 App）
//
// 悬浮球「抓」（右下角，可拖动），点开菜单：
//   ▶️ 开始抓包    清空记录，重写 diditok_capture.txt 重新开始
//   ⏹ 停止抓包    停止记录（进行中的请求会记完整条再落盘）
//   📤 分享导出    把 diditok_capture.txt 弹系统分享面板（微信/AirDrop/存储到文件…）
//   ❌ 取消
//
// 抓包内容（全量，TXT 逐条追加，UTF-8）：
//   · 请求：方法 / URL / HTTP 版本 / 超时 / 全部请求头（含 User-Agent）/ 请求体
//   · 响应：状态码 / 全部响应头 / MIME / 响应体
//   · 其他：耗时、错误、重定向链、下载落盘路径、流式上传提示
//   · 响应体三条路都覆盖：completionHandler 包装 / session 代理回调 / KVO 兜底
//   · 单个体上限 16 MB，超出截断并标注（防撑爆内存/文件）
//
// 沙盒 Documents/ 输出：
//   diditok_capture.txt —— 全量抓包记录；「分享导出」直接分享这个文件
//
// 实现要点：
//   · 不依赖 Cydia Substrate，全部用 ObjC runtime method_setImplementation
//   · session 代理用 NSProxy 包装转发，不 hook 任何业务类
//   · 反检测保留（镜像隐藏 / 完整性开关压平 / 文件枚举过滤），保证 App 正常运行
//   · 已移除：凭据提取、AES 加密、密码门控、NSJSONSerialization / UserInfoCallback 钩子

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
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
// 常量与状态
// ═══════════════════════════════════════════════════════════════════════
#define DIDITOK_CAPTURE_FILE @"diditok_capture.txt"
static const NSUInteger kMaxBodyBytes = 16 * 1024 * 1024;   // 单条请求/响应体上限

static BOOL  g_captureEnabled = NO;
static int   g_seq   = 0;
static int   g_count = 0;
static NSLock *g_stateLock;      // g_captureEnabled / g_seq / g_count
static NSLock *g_mapLock;        // g_pendingMap / g_bodyMap / entry 收尾标记

static NSMutableDictionary *g_pendingMap;  // task指针 → entry（进行中的请求）
static NSMutableDictionary *g_bodyMap;     // task指针 → NSMutableData（代理路径响应体累积）

static dispatch_queue_t g_writeQueue;      // 串行写文件，保证条目顺序

static UIWindow *g_floatWindow = nil;
static UIButton *g_floatButton = nil;
static UILabel  *g_toastLabel  = nil;

static IMP g_origDataTaskCH     = NULL;  // dataTaskWithRequest:completionHandler:
static IMP g_origDataTaskNH     = NULL;  // dataTaskWithRequest:
static IMP g_origDataTaskURLCH  = NULL;  // dataTaskWithURL:completionHandler:
static IMP g_origDataTaskURLNH  = NULL;  // dataTaskWithURL:
static IMP g_origUploadDataCH   = NULL;  // uploadTaskWithRequest:fromData:completionHandler:
static IMP g_origUploadDataNH   = NULL;  // uploadTaskWithRequest:fromData:
static IMP g_origUploadStream   = NULL;  // uploadTaskWithStreamedRequest:
static IMP g_origDownloadCH     = NULL;  // downloadTaskWithRequest:completionHandler:
static IMP g_origDownloadURLCH  = NULL;  // downloadTaskWithURL:completionHandler:
static IMP g_origDownloadNH     = NULL;  // downloadTaskWithRequest:
static IMP g_origSessionDQ      = NULL;  // sessionWithConfiguration:delegate:delegateQueue:
static IMP g_origSessionD       = NULL;  // sessionWithConfiguration:delegate:
static IMP g_origBgSessionDQ    = NULL;  // backgroundSessionWithConfiguration:delegate:delegateQueue:

static id g_launchObserver = nil;

// 前置声明
static NSMutableDictionary *maybeCapture(NSURLRequest *req, NSURLSessionTask *task,
                                         NSData *uploadBody, NSString *note, BOOL willSelfFinalize);
static void finalizeEntry(NSMutableDictionary *entry, NSData *respBody, NSError *err, NSString *extra);
static void noteEntry(NSURLSessionTask *task, NSString *note);
static void setRespFromResponse(NSMutableDictionary *entry, NSURLResponse *resp);
static UIWindow *appWindow(void);
static UIViewController *topVC(void);

// ═══════════════════════════════════════════════════════════════════════
// 基础工具
// ═══════════════════════════════════════════════════════════════════════
static NSString *documentsDir(void) {
    return NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES)[0];
}
static NSString *captureFilePath(void) {
    return [documentsDir() stringByAppendingPathComponent:DIDITOK_CAPTURE_FILE];
}
static NSString *tsStr(NSDate *d) {
    static NSDateFormatter *df; static dispatch_once_t once;
    dispatch_once(&once, ^{
        df = [NSDateFormatter new];
        df.dateFormat = @"yyyy-MM-dd HH:mm:ss";
        df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    });
    if (!d) return @"—";
    NSTimeInterval ti = d.timeIntervalSince1970;
    int ms = (int)((ti - floor(ti)) * 1000.0);
    return [NSString stringWithFormat:@"%@.%03d", [df stringFromDate:d], ms];
}
static NSString *sizeStr(NSUInteger n) {
    if (n >= 1024 * 1024) return [NSString stringWithFormat:@"%.1f MB", n / 1024.0 / 1024.0];
    if (n >= 1024)        return [NSString stringWithFormat:@"%.1f KB", n / 1024.0];
    return [NSString stringWithFormat:@"%lu B", (unsigned long)n];
}
// header 名大小写不敏感取值（allHTTPHeaderFields 的键大小写不保证）
static NSString *headerValue(NSDictionary *hdrs, NSString *name) {
    NSString *v = hdrs[name];
    if (v.length) return [v isKindOfClass:[NSString class]] ? v : [v description];
    for (NSString *k in hdrs) {
        if ([k caseInsensitiveCompare:name] == NSOrderedSame) {
            id o = hdrs[k];
            return [o isKindOfClass:[NSString class]] ? o : [o description];
        }
    }
    return nil;
}
static NSString *headersText(NSDictionary *hdrs) {
    NSMutableString *s = [NSMutableString new];
    NSArray *keys = [hdrs.allKeys sortedArrayUsingSelector:@selector(caseInsensitiveCompare:)];
    for (NSString *k in keys) {
        id v = hdrs[k];
        [s appendFormat:@"  %@: %@\n", k, [v isKindOfClass:[NSString class]] ? v : [v description]];
    }
    return s;
}
// 请求/响应体渲染：能转 UTF-8 就直接放文本，二进制给 Base64 预览
static NSString *bodyText(NSData *body, BOOL truncated) {
    if (!body.length) return @"（无）";
    NSMutableString *s = [NSMutableString new];
    NSString *asText = [[NSString alloc] initWithData:body encoding:NSUTF8StringEncoding];
    if (asText) {
        [s appendString:asText];
    } else {
        NSUInteger preview = MIN(body.length, (NSUInteger)262144);
        NSData *p = [body subdataWithRange:NSMakeRange(0, preview)];
        [s appendFormat:@"【二进制数据，Base64 预览 %@ / 完整 %@】\n%@",
            sizeStr(preview), sizeStr(body.length), [p base64EncodedStringWithOptions:0]];
    }
    if (truncated) [s appendFormat:@"\n⚠️ 超过 %@ 上限，已截断", sizeStr(kMaxBodyBytes)];
    return s;
}

// ═══════════════════════════════════════════════════════════════════════
// TXT 条目渲染
// ═══════════════════════════════════════════════════════════════════════
static NSString *renderEntry(NSDictionary *e) {
    NSMutableString *s = [NSMutableString new];
    NSDictionary *reqH = e[@"reqHeaders"] ?: @{};
    NSDictionary *rspH = e[@"respHeaders"] ?: @{};
    NSData *reqB = e[@"reqBody"];
    NSData *rspB = e[@"respBody"];

    [s appendString:@"════════════════════════════════════════════════\n"];
    [s appendFormat:@"[#%d] %@  %@  %@\n",
        [e[@"seq"] intValue], tsStr(e[@"start"]), e[@"method"], e[@"url"]];
    NSString *ua = headerValue(reqH, @"User-Agent");
    if (ua.length) [s appendFormat:@"UA  : %@\n", ua];
    [s appendFormat:@"耗时: %.0f ms   结束: %@\n", [e[@"ms"] doubleValue], tsStr(e[@"end"])];
    if ([e[@"statusCode"] intValue] > 0)
        [s appendFormat:@"状态: %@   MIME: %@\n", e[@"statusCode"], e[@"respMime"] ?: @""];

    [s appendFormat:@"────────────── 请求头 (%lu 个) ──────────────\n", (unsigned long)reqH.count];
    [s appendString:headersText(reqH)];
    if (reqB.length) {
        [s appendFormat:@"────────────── 请求体 (%@) ──────────────\n", sizeStr(reqB.length)];
        [s appendString:bodyText(reqB, [e[@"reqTruncated"] boolValue])];
        [s appendString:@"\n"];
    } else {
        [s appendString:@"────────────── 请求体（无） ──────────────\n"];
    }
    NSString *reqNote = e[@"reqNote"];
    if (reqNote.length) [s appendFormat:@"请求备注: %@\n", reqNote];

    if (rspH.count) {
        [s appendFormat:@"────────────── 响应头 (%lu 个) ──────────────\n", (unsigned long)rspH.count];
        [s appendString:headersText(rspH)];
    }
    if (rspB.length) {
        [s appendFormat:@"────────────── 响应体 (%@) ──────────────\n", sizeStr(rspB.length)];
        [s appendString:bodyText(rspB, [e[@"respTruncated"] boolValue])];
        [s appendString:@"\n"];
    } else {
        [s appendString:@"────────────── 响应体（无） ──────────────\n"];
    }
    for (NSString *nt in e[@"notes"]) if (nt.length) [s appendFormat:@"备注: %@\n", nt];
    NSString *err = e[@"error"];
    if (err.length) [s appendFormat:@"错误: %@\n", err];
    [s appendString:@"════════════════════════════════════════════════\n\n"];
    return s;
}

static void appendCaptureText(NSString *text) {
    @autoreleasepool {
        NSString *path = captureFilePath();
        NSData *d = [text dataUsingEncoding:NSUTF8StringEncoding];
        NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:path];
        if (!fh) {
            [@"" writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:nil];
            fh = [NSFileHandle fileHandleForWritingAtPath:path];
        }
        if (!fh) { NSLog(@"[Diditok] ✗ 抓包文件打不开: %@", path); return; }
        [fh seekToEndOfFile];
        [fh writeData:d];
        [fh closeFile];
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
// 抓包核心：key / 截断 / 响应提取
// ═══════════════════════════════════════════════════════════════════════
static NSValue *keyFor(id task) {
    return [NSValue valueWithPointer:(__bridge const void *)task];
}
static NSData *capBody(NSData *body, BOOL *trunc) {
    if (trunc) *trunc = NO;
    if (!body.length) return body;
    if (body.length <= kMaxBodyBytes) return body;
    if (trunc) *trunc = YES;
    return [body subdataWithRange:NSMakeRange(0, kMaxBodyBytes)];
}

static void setRespFromResponse(NSMutableDictionary *e, NSURLResponse *resp) {
    if (!resp) return;
    if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
        NSHTTPURLResponse *hr = (NSHTTPURLResponse *)resp;
        e[@"statusCode"]  = @(hr.statusCode);
        e[@"respHeaders"] = hr.allHeaderFields ?: @{};
    }
    e[@"respMime"] = resp.MIMEType ?: @"";
    if (resp.suggestedFilename.length) e[@"respFile"] = resp.suggestedFilename;
}

// ═══════════════════════════════════════════════════════════════════════
// KVO 兜底：观察 task 的 response / state
//   · response → 补响应头/状态码（无 completionHandler 的任务靠这个）
//   · state    → Completed/Canceling 时收尾（代理回调路径优先，这里兜底）
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
    NSValue *k = keyFor(task);

    if ([kp isEqualToString:@"response"]) {
        if (!task.response) return;
        [g_mapLock lock];
        NSMutableDictionary *e = g_pendingMap[k];
        if (e && ![e[@"finalized"] boolValue]) setRespFromResponse(e, task.response);
        [g_mapLock unlock];
        return;
    }

    if (![kp isEqualToString:@"state"]) return;
    if (task.state != NSURLSessionTaskStateCompleted &&
        task.state != NSURLSessionTaskStateCanceling) return;

    // 收尾：先摘观察器，再合并累积的响应体
    @try { [task removeObserver:self forKeyPath:@"response"]; } @catch (NSException *ex) {}
    @try { [task removeObserver:self forKeyPath:@"state"]; }    @catch (NSException *ex) {}

    [g_mapLock lock];
    NSMutableDictionary *e    = g_pendingMap[k];
    NSMutableData      *acc   = g_bodyMap[k];
    [g_bodyMap removeObjectForKey:k];
    BOOL staleCH = NO;
    if (e) {
        if ([e[@"finalized"] boolValue]) {
            e = nil;
        } else if ([e[@"willSelfFinalize"] boolValue] &&
                   task.state == NSURLSessionTaskStateCompleted) {
            // completionHandler 路径：handler 大概率马上回调，兜底延迟收尾，
            // 避免抢在 handler 之前收尾导致响应体丢失
            staleCH = YES;
        } else {
            [g_pendingMap removeObjectForKey:k];
        }
    }
    [g_mapLock unlock];

    if (e) {
        setRespFromResponse(e, task.response);
        NSMutableArray *extras = [NSMutableArray new];
        if (task.state == NSURLSessionTaskStateCanceling) [extras addObject:@"任务被取消"];
        if (!acc.length) [extras addObject:@"响应体未捕获（无 completionHandler 且无代理回调）"];
        finalizeEntry(e, acc, nil, extras.count ? [extras componentsJoinedByString:@"；"] : nil);
    }
    if (staleCH) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(500 * NSEC_PER_MSEC)),
                       dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            [g_mapLock lock];
            NSMutableDictionary *still = g_pendingMap[k];
            [g_pendingMap removeObjectForKey:k];
            [g_mapLock unlock];
            if (still) {
                setRespFromResponse(still, task.response);
                finalizeEntry(still, nil, nil, @"completionHandler 未回调，KVO 兜底收尾");
            }
        });
    }
}
@end

// 请求创建时登记 entry；未开启抓包返回 nil
static NSMutableDictionary *maybeCapture(NSURLRequest *req, NSURLSessionTask *task,
                                         NSData *uploadBody, NSString *note, BOOL willSelfFinalize) {
    if (!g_captureEnabled) return nil;
    @autoreleasepool {
        [g_stateLock lock]; int seq = ++g_seq; [g_stateLock unlock];
        NSMutableDictionary *e = [NSMutableDictionary new];
        e[@"seq"]         = @(seq);
        e[@"start"]       = [NSDate date];
        e[@"method"]      = req.HTTPMethod ?: @"GET";
        e[@"url"]         = req.URL.absoluteString ?: @"";
        e[@"httpVersion"] = req.HTTPVersion ?: @"";
        e[@"timeout"]     = @(req.timeoutInterval);
        e[@"reqHeaders"]  = req.allHTTPHeaderFields ?: @{};
        NSData *raw = uploadBody ?: req.HTTPBody;
        BOOL tr = NO;
        e[@"reqBody"]      = capBody(raw, &tr);
        e[@"reqTruncated"] = @(tr);
        e[@"reqMime"]      = headerValue(req.allHTTPHeaderFields, @"Content-Type") ?: @"";
        if (!raw && req.HTTPBodyStream) {
            e[@"reqNote"] = @"请求体为 HTTPBodyStream 流式上传，未读取（读流会破坏原请求）";
        } else if (note.length) {
            e[@"reqNote"] = note;
        }
        e[@"finalized"]        = @NO;
        e[@"willSelfFinalize"] = @(willSelfFinalize);
        e[@"notes"]            = [NSMutableArray new];

        if (task) {
            NSValue *k = keyFor(task);
            [g_mapLock lock]; g_pendingMap[k] = e; [g_mapLock unlock];
            @try { [task addObserver:[DiditokKvo shared] forKeyPath:@"response"
                                     options:NSKeyValueObservingOptionNew context:NULL]; }
            @catch (NSException *ex) {}
            @try { [task addObserver:[DiditokKvo shared] forKeyPath:@"state"
                                     options:NSKeyValueObservingOptionNew context:NULL]; }
            @catch (NSException *ex) {}
        }
        return e;
    }
}

// 请求完成：算耗时 → 串行队列追加写盘
static void finalizeEntry(NSMutableDictionary *e, NSData *respBody, NSError *err, NSString *extra) {
    if (!e) return;
    @autoreleasepool {
        BOOL proceed = NO;
        [g_mapLock lock];
        if (![e[@"finalized"] boolValue]) { e[@"finalized"] = @YES; proceed = YES; }
        [g_mapLock unlock];
        if (!proceed) return;

        NSDate *start = e[@"start"];
        double ms = start ? [[NSDate date] timeIntervalSinceDate:start] * 1000.0 : 0;
        e[@"ms"]  = @(ms);
        e[@"end"] = [NSDate date];
        BOOL tr = NO;
        e[@"respBody"]      = capBody(respBody, &tr);
        e[@"respTruncated"] = @(tr);
        e[@"error"]         = err.localizedDescription ?: @"";
        if (extra.length) [(NSMutableArray *)e[@"notes"] addObject:extra];

        NSString *text = renderEntry(e);
        [g_stateLock lock]; g_count++; [g_stateLock unlock];
        dispatch_async(g_writeQueue, ^{ appendCaptureText(text); });
    }
}

static void noteEntry(NSURLSessionTask *task, NSString *note) {
    if (!task || !note.length) return;
    NSValue *k = keyFor(task);
    [g_mapLock lock];
    NSMutableDictionary *e = g_pendingMap[k];
    if (e && ![e[@"finalized"] boolValue]) [(NSMutableArray *)e[@"notes"] addObject:note];
    [g_mapLock unlock];
}

// ═══════════════════════════════════════════════════════════════════════
// session 代理包装（NSProxy）：
//   拦截 4 个 delegate 回调做抓包，其余全部转发给原 delegate。
//   好处：不用扫描/hook 任何业务类，对 App 完全透明。
// ═══════════════════════════════════════════════════════════════════════
static NSString *const kSelData     = @"URLSession:dataTask:didReceiveData:";
static NSString *const kSelComplete = @"URLSession:task:didCompleteWithError:";
static NSString *const kSelDownFile = @"URLSession:downloadTask:didFinishDownloadingToURL:";
static NSString *const kSelRedirect = @"URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:";

@interface DiditokSessionProxy : NSProxy
- (instancetype)initWithTarget:(id)target;
@end

@implementation DiditokSessionProxy {
    __strong id _target;
}
- (instancetype)initWithTarget:(id)target {
    _target = target;
    return self;
}
- (BOOL)respondsToSelector:(SEL)s {
    if (s == NSSelectorFromString(kSelData) ||
        s == NSSelectorFromString(kSelComplete) ||
        s == NSSelectorFromString(kSelDownFile) ||
        s == NSSelectorFromString(kSelRedirect)) return YES;
    return [_target respondsToSelector:s];
}
- (BOOL)conformsToProtocol:(Protocol *)p { return [_target conformsToProtocol:p]; }
- (BOOL)isKindOfClass:(Class)cls {
    if ([super isKindOfClass:cls]) return YES;
    return [_target isKindOfClass:cls];
}
- (NSMethodSignature *)methodSignatureForSelector:(SEL)s {
    NSMethodSignature *sig = [_target methodSignatureForSelector:s];
    if (!sig) sig = [NSMethodSignature signatureWithObjCTypes:"v@:@"];
    return sig;
}
- (void)forwardInvocation:(NSInvocation *)inv {
    if ([_target respondsToSelector:inv.selector]) [inv invokeWithTarget:_target];
}
// —— 数据块：累积到该 task 的 entry ——
- (void)URLSession:(NSURLSession *)session dataTask:(NSURLSessionDataTask *)task
        didReceiveData:(NSData *)data {
    @try {
        if ([task isKindOfClass:[NSURLSessionTask class]] && [data isKindOfClass:[NSData class]]) {
            NSValue *k = keyFor(task);
            [g_mapLock lock];
            NSMutableDictionary *e = g_pendingMap[k];
            if (e && ![e[@"finalized"] boolValue]) {
                NSMutableData *acc = g_bodyMap[k];
                if (!acc) { acc = [NSMutableData data]; g_bodyMap[k] = acc; }
                if (acc.length < kMaxBodyBytes) {
                    NSUInteger room = kMaxBodyBytes - acc.length;
                    [acc appendData:(data.length > room ?
                        [data subdataWithRange:NSMakeRange(0, room)] : data)];
                }
            }
            [g_mapLock unlock];
        }
    } @catch (NSException *ex) { NSLog(@"[Diditok] ✗ didReceiveData: %@", ex); }
    if ([_target respondsToSelector:@selector(URLSession:dataTask:didReceiveData:)]) {
        void (*fp)(id, SEL, NSURLSession *, NSURLSessionDataTask *, NSData *) =
            (void (*)(id, SEL, NSURLSession *, NSURLSessionDataTask *, NSData *))[_target methodForSelector:_cmd];
        fp(_target, _cmd, session, task, data);
    }
}
// —— 完成：合并累积响应体并收尾 ——
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
        didCompleteWithError:(NSError *)error {
    @try {
        if ([task isKindOfClass:[NSURLSessionTask class]]) {
            NSValue *k = keyFor(task);
            [g_mapLock lock];
            NSMutableDictionary *e  = g_pendingMap[k];
            NSMutableData      *acc = g_bodyMap[k];
            [g_bodyMap removeObjectForKey:k];
            BOOL mine = e && ![e[@"finalized"] boolValue] && ![e[@"willSelfFinalize"] boolValue];
            if (mine) [g_pendingMap removeObjectForKey:k];
            [g_mapLock unlock];
            if (mine) {
                setRespFromResponse(e, task.response);
                finalizeEntry(e, acc, error, nil);
            }
        }
    } @catch (NSException *ex) { NSLog(@"[Diditok] ✗ didComplete: %@", ex); }
    if ([_target respondsToSelector:@selector(URLSession:task:didCompleteWithError:)]) {
        void (*fp)(id, SEL, NSURLSession *, NSURLSessionTask *, NSError *) =
            (void (*)(id, SEL, NSURLSession *, NSURLSessionTask *, NSError *))[_target methodForSelector:_cmd];
        fp(_target, _cmd, session, task, error);
    }
}
// —— 下载落盘 ——
- (void)URLSession:(NSURLSession *)session downloadTask:(NSURLSessionDownloadTask *)task
        didFinishDownloadingToURL:(NSURL *)location {
    @try { noteEntry(task, [NSString stringWithFormat:@"下载落盘: %@", location.path ?: @""]); }
    @catch (NSException *ex) {}
    if ([_target respondsToSelector:@selector(URLSession:downloadTask:didFinishDownloadingToURL:)]) {
        void (*fp)(id, SEL, NSURLSession *, NSURLSessionDownloadTask *, NSURL *) =
            (void (*)(id, SEL, NSURLSession *, NSURLSessionDownloadTask *, NSURL *))[_target methodForSelector:_cmd];
        fp(_target, _cmd, session, task, location);
    }
}
// —— 重定向：记一条备注，跟随原语义 ——
- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task
        willPerformHTTPRedirection:(NSHTTPURLResponse *)response
        newRequest:(NSURLRequest *)request
        completionHandler:(void (^)(NSURLRequest *))completionHandler {
    @try {
        noteEntry(task, [NSString stringWithFormat:@"↪️ 重定向 %ld → %@",
            (long)response.statusCode, request.URL.absoluteString ?: @""]);
    } @catch (NSException *ex) {}
    SEL s = @selector(URLSession:task:willPerformHTTPRedirection:newRequest:completionHandler:);
    if ([_target respondsToSelector:s]) {
        void (*fp)(id, SEL, NSURLSession *, NSURLSessionTask *, NSHTTPURLResponse *,
                   NSURLRequest *, void (^)(NSURLRequest *)) =
            (void (*)(id, SEL, NSURLSession *, NSURLSessionTask *, NSHTTPURLResponse *,
                      NSURLRequest *, void (^)(NSURLRequest *)))[_target methodForSelector:s];
        fp(_target, s, session, task, response, request, completionHandler);
    } else if (completionHandler) {
        completionHandler(request);   // 目标没实现 → 走默认：跟随重定向
    }
}
@end

// ═══════════════════════════════════════════════════════════════════════
// hook 安装工具
// ═══════════════════════════════════════════════════════════════════════
static void hookInstanceMethod(Class c, const char *selName, IMP newImp, IMP *slot, const char *label) {
    SEL s = NSSelectorFromString(@(selName));
    @try {
        if (DidiHook(c, s, newImp, slot)) NSLog(@"[Diditok] ✓ hooked %@", @(label));
        else NSLog(@"[Diditok] ⚠️ 未找到 %@", @(label));
    } @catch (NSException *e) { NSLog(@"[Diditok] ✗ hook %@ 失败: %@", @(label), e); }
}
static void hookClassMethod(Class c, const char *selName, IMP newImp, IMP *slot, const char *label) {
    SEL s = NSSelectorFromString(@(selName));
    @try {
        Method m = class_getClassMethod(c, s);
        if (!m) { NSLog(@"[Diditok] ⚠️ 未找到类方法 %@", @(label)); return; }
        if (slot) *slot = method_getImplementation(m);
        method_setImplementation(m, newImp);
        NSLog(@"[Diditok] ✓ hooked %@", @(label));
    } @catch (NSException *e) { NSLog(@"[Diditok] ✗ hook %@ 失败: %@", @(label), e); }
}

// 下载落盘文件预览（最多 1 MB，完整文件在备注里的路径）
static NSData *previewFile(NSURL *loc) {
    @autoreleasepool {
        NSString *p = loc.path;
        if (!p.length) return nil;
        NSDictionary *at = [[NSFileManager defaultManager] attributesOfItemAtPath:p error:nil];
        unsigned long long sz = at ? [at fileSize] : 0;
        if (!sz) return nil;
        NSUInteger n = (NSUInteger)MIN((unsigned long long)(1024 * 1024), sz);
        NSFileHandle *fh = [NSFileHandle fileHandleForReadingAtPath:p];
        NSData *d = [fh readDataOfLength:n];
        [fh closeFile];
        return d;
    }
}

// ═══════════════════════════════════════════════════════════════════════
// NSURLSession 任务创建 hook（10 个入口全覆盖）
//   completionHandler 路径 → 包一层 handler 拿响应体，自己收尾
//   无 handler 路径        → 交给 session 代理回调 / KVO 兜底
// ═══════════════════════════════════════════════════════════════════════

// 1. dataTaskWithRequest:completionHandler:
static id hookedDataTaskCH(id self, SEL _cmd, NSURLRequest *req, id handler) {
    typedef id (*o_t)(id, SEL, NSURLRequest *, id);
    __block NSMutableDictionary *entry = nil;
    id wrapped = handler;
    if (handler) {
        void (^orig)(NSData *, NSURLResponse *, NSError *) =
            (void (^)(NSData *, NSURLResponse *, NSError *))handler;
        wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
            @try {
                if (entry) {
                    setRespFromResponse(entry, resp);
                    finalizeEntry(entry, data, err, nil);
                }
            } @catch (NSException *ex) { NSLog(@"[Diditok] ✗ CH: %@", ex); }
            orig(data, resp, err);
        };
    }
    id task = g_origDataTaskCH
        ? ((o_t)g_origDataTaskCH)(self, _cmd, req, wrapped)
        : ((o_t)[NSURLSession instanceMethodForSelector:_cmd])(self, _cmd, req, wrapped);
    if (task) entry = maybeCapture(req, task, nil, nil, YES);
    return task;
}

// 2. dataTaskWithRequest:（无 handler → 代理/KVO 路径）
static id hookedDataTaskNH(id self, SEL _cmd, NSURLRequest *req) {
    typedef id (*o_t)(id, SEL, NSURLRequest *);
    id task = g_origDataTaskNH
        ? ((o_t)g_origDataTaskNH)(self, _cmd, req)
        : ((o_t)[NSURLSession instanceMethodForSelector:_cmd])(self, _cmd, req);
    if (task) maybeCapture(req, task, nil, nil, NO);
    return task;
}

// 3. dataTaskWithURL:completionHandler:
static id hookedDataTaskURLCH(id self, SEL _cmd, NSURL *url, id handler) {
    typedef id (*o_t)(id, SEL, NSURL *, id);
    __block NSMutableDictionary *entry = nil;
    id wrapped = handler;
    if (handler) {
        void (^orig)(NSData *, NSURLResponse *, NSError *) =
            (void (^)(NSData *, NSURLResponse *, NSError *))handler;
        wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
            @try {
                if (entry) {
                    setRespFromResponse(entry, resp);
                    finalizeEntry(entry, data, err, nil);
                }
            } @catch (NSException *ex) { NSLog(@"[Diditok] ✗ URLCH: %@", ex); }
            orig(data, resp, err);
        };
    }
    id task = g_origDataTaskURLCH
        ? ((o_t)g_origDataTaskURLCH)(self, _cmd, url, wrapped)
        : ((o_t)[NSURLSession instanceMethodForSelector:_cmd])(self, _cmd, url, wrapped);
    if (task) {
        NSURLRequest *req = [NSURLRequest requestWithURL:url];
        entry = maybeCapture(req, task, nil, nil, YES);
    }
    return task;
}

// 4. dataTaskWithURL:
static id hookedDataTaskURLNH(id self, SEL _cmd, NSURL *url) {
    typedef id (*o_t)(id, SEL, NSURL *);
    id task = g_origDataTaskURLNH
        ? ((o_t)g_origDataTaskURLNH)(self, _cmd, url)
        : ((o_t)[NSURLSession instanceMethodForSelector:_cmd])(self, _cmd, url);
    if (task) {
        NSURLRequest *req = [NSURLRequest requestWithURL:url];
        maybeCapture(req, task, nil, nil, NO);
    }
    return task;
}

// 5. uploadTaskWithRequest:fromData:completionHandler:
static id hookedUploadCH(id self, SEL _cmd, NSURLRequest *req, NSData *upData, id handler) {
    typedef id (*o_t)(id, SEL, NSURLRequest *, NSData *, id);
    __block NSMutableDictionary *entry = nil;
    id wrapped = handler;
    if (handler) {
        void (^orig)(NSData *, NSURLResponse *, NSError *) =
            (void (^)(NSData *, NSURLResponse *, NSError *))handler;
        wrapped = ^(NSData *data, NSURLResponse *resp, NSError *err) {
            @try {
                if (entry) {
                    setRespFromResponse(entry, resp);
                    finalizeEntry(entry, data, err, nil);
                }
            } @catch (NSException *ex) { NSLog(@"[Diditok] ✗ UPCH: %@", ex); }
            orig(data, resp, err);
        };
    }
    id task = g_origUploadDataCH
        ? ((o_t)g_origUploadDataCH)(self, _cmd, req, upData, wrapped)
        : ((o_t)[NSURLSession instanceMethodForSelector:_cmd])(self, _cmd, req, upData, wrapped);
    if (task) entry = maybeCapture(req, task, upData, @"上传任务（请求体=fromData）", YES);
    return task;
}

// 6. uploadTaskWithRequest:fromData:
static id hookedUploadNH(id self, SEL _cmd, NSURLRequest *req, NSData *upData) {
    typedef id (*o_t)(id, SEL, NSURLRequest *, NSData *);
    id task = g_origUploadDataNH
        ? ((o_t)g_origUploadDataNH)(self, _cmd, req, upData)
        : ((o_t)[NSURLSession instanceMethodForSelector:_cmd])(self, _cmd, req, upData);
    if (task) maybeCapture(req, task, upData, @"上传任务（请求体=fromData）", NO);
    return task;
}

// 7. uploadTaskWithStreamedRequest:
static id hookedUploadStream(id self, SEL _cmd, NSURLRequest *req) {
    typedef id (*o_t)(id, SEL, NSURLRequest *);
    id task = g_origUploadStream
        ? ((o_t)g_origUploadStream)(self, _cmd, req)
        : ((o_t)[NSURLSession instanceMethodForSelector:_cmd])(self, _cmd, req);
    if (task) maybeCapture(req, task, nil, @"流式上传（请求体在流里，未读取）", NO);
    return task;
}

// 8. downloadTaskWithRequest:completionHandler:
static id hookedDownloadCH(id self, SEL _cmd, NSURLRequest *req, id handler) {
    typedef id (*o_t)(id, SEL, NSURLRequest *, id);
    __block NSMutableDictionary *entry = nil;
    id wrapped = handler;
    if (handler) {
        void (^orig)(NSURL *, NSURLResponse *, NSError *) =
            (void (^)(NSURL *, NSURLResponse *, NSError *))handler;
        wrapped = ^(NSURL *loc, NSURLResponse *resp, NSError *err) {
            @try {
                if (entry) {
                    setRespFromResponse(entry, resp);
                    NSString *extra = nil;
                    NSData *body = nil;
                    if (loc) {
                        extra = [NSString stringWithFormat:@"下载落盘: %@", loc.path ?: @""];
                        body = previewFile(loc);
                    }
                    finalizeEntry(entry, body, err, extra);
                }
            } @catch (NSException *ex) { NSLog(@"[Diditok] ✗ DLCH: %@", ex); }
            orig(loc, resp, err);
        };
    }
    id task = g_origDownloadCH
        ? ((o_t)g_origDownloadCH)(self, _cmd, req, wrapped)
        : ((o_t)[NSURLSession instanceMethodForSelector:_cmd])(self, _cmd, req, wrapped);
    if (task) entry = maybeCapture(req, task, nil, @"下载任务（响应体=落盘文件预览）", YES);
    return task;
}

// 9. downloadTaskWithURL:completionHandler:
static id hookedDownloadURLCH(id self, SEL _cmd, NSURL *url, id handler) {
    typedef id (*o_t)(id, SEL, NSURL *, id);
    __block NSMutableDictionary *entry = nil;
    id wrapped = handler;
    if (handler) {
        void (^orig)(NSURL *, NSURLResponse *, NSError *) =
            (void (^)(NSURL *, NSURLResponse *, NSError *))handler;
        wrapped = ^(NSURL *loc, NSURLResponse *resp, NSError *err) {
            @try {
                if (entry) {
                    setRespFromResponse(entry, resp);
                    NSString *extra = nil;
                    NSData *body = nil;
                    if (loc) {
                        extra = [NSString stringWithFormat:@"下载落盘: %@", loc.path ?: @""];
                        body = previewFile(loc);
                    }
                    finalizeEntry(entry, body, err, extra);
                }
            } @catch (NSException *ex) { NSLog(@"[Diditok] ✗ DLURLCH: %@", ex); }
            orig(loc, resp, err);
        };
    }
    id task = g_origDownloadURLCH
        ? ((o_t)g_origDownloadURLCH)(self, _cmd, url, wrapped)
        : ((o_t)[NSURLSession instanceMethodForSelector:_cmd])(self, _cmd, url, wrapped);
    if (task) {
        NSURLRequest *req = [NSURLRequest requestWithURL:url];
        entry = maybeCapture(req, task, nil, @"下载任务（响应体=落盘文件预览）", YES);
    }
    return task;
}

// 10. downloadTaskWithRequest:（无 handler → didFinishDownloadingToURL 记路径）
static id hookedDownloadNH(id self, SEL _cmd, NSURLRequest *req) {
    typedef id (*o_t)(id, SEL, NSURLRequest *);
    id task = g_origDownloadNH
        ? ((o_t)g_origDownloadNH)(self, _cmd, req)
        : ((o_t)[NSURLSession instanceMethodForSelector:_cmd])(self, _cmd, req);
    if (task) maybeCapture(req, task, nil, @"下载任务（内容看落盘文件）", NO);
    return task;
}

// ═══════════════════════════════════════════════════════════════════════
// session 工厂 hook：把 delegate 包成 NSProxy，其余参数原样透传
// ═══════════════════════════════════════════════════════════════════════
static id hookedSessionDQ(id self, SEL _cmd, NSURLSessionConfiguration *cfg,
                          id delegate, NSOperationQueue *q) {
    typedef id (*o_t)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *);
    id wrapped = delegate ? [[DiditokSessionProxy alloc] initWithTarget:delegate] : nil;
    if (!g_origSessionDQ) return nil;
    return ((o_t)g_origSessionDQ)(self, _cmd, cfg, wrapped, q);
}
static id hookedSessionD(id self, SEL _cmd, NSURLSessionConfiguration *cfg, id delegate) {
    typedef id (*o_t)(id, SEL, NSURLSessionConfiguration *, id);
    id wrapped = delegate ? [[DiditokSessionProxy alloc] initWithTarget:delegate] : nil;
    if (!g_origSessionD) return nil;
    return ((o_t)g_origSessionD)(self, _cmd, cfg, wrapped);
}
static id hookedBgSessionDQ(id self, SEL _cmd, NSURLSessionConfiguration *cfg,
                            id delegate, NSOperationQueue *q) {
    typedef id (*o_t)(id, SEL, NSURLSessionConfiguration *, id, NSOperationQueue *);
    id wrapped = delegate ? [[DiditokSessionProxy alloc] initWithTarget:delegate] : nil;
    if (!g_origBgSessionDQ) return nil;
    return ((o_t)g_origBgSessionDQ)(self, _cmd, cfg, wrapped, q);
}

// ═══════════════════════════════════════════════════════════════════════
// 抓包控制
// ═══════════════════════════════════════════════════════════════════════
static void startCapture(void) {
    [g_stateLock lock]; g_captureEnabled = YES; g_seq = 0; g_count = 0; [g_stateLock unlock];
    [g_mapLock lock]; [g_pendingMap removeAllObjects]; [g_bodyMap removeAllObjects]; [g_mapLock unlock];
    NSString *header = [NSString stringWithFormat:
        @"════════ Diditok 全量抓包  开始 %@ ════════\n", tsStr([NSDate date])];
    [header writeToFile:captureFilePath() atomically:YES encoding:NSUTF8StringEncoding error:nil];
    setButtonColor([UIColor redColor]);
    showToast(@"🔴 开始抓包 → diditok_capture.txt");
}
static void stopCapture(void) {
    [g_stateLock lock]; g_captureEnabled = NO; int cnt = g_count; [g_stateLock unlock];
    setButtonColor([UIColor colorWithRed:0.2 green:0.4 blue:0.9 alpha:0.9]);
    showToast([NSString stringWithFormat:@"⏹ 已停止（共 %d 条，可分享导出）", cnt]);
}
// 分享导出：把 diditok_capture.txt 弹系统分享面板
static void shareCaptureFile(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *path = captureFilePath();
        NSDictionary *at = [[NSFileManager defaultManager] attributesOfItemAtPath:path error:nil];
        unsigned long long sz = at ? [at fileSize] : 0;
        if (sz == 0) { showToast(@"⚠️ 还没有抓到内容"); return; }
        UIViewController *p = topVC();
        if (!p) { showToast(@"❌ 找不到可用窗口"); return; }
        UIActivityViewController *av = [[UIActivityViewController alloc]
            initWithActivityItems:@[[NSURL fileURLWithPath:path]] applicationActivities:nil];
        if (av.popoverPresentationController) {
            av.popoverPresentationController.sourceView = g_floatButton ?: p.view;
            av.popoverPresentationController.sourceRect = g_floatButton ? g_floatButton.bounds : p.view.bounds;
        }
        showToast([NSString stringWithFormat:@"📤 分享 diditok_capture.txt（%@）", sizeStr((NSUInteger)sz)]);
        [p presentViewController:av animated:YES completion:nil];
    });
}

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
        if (!vc) { showToast(@"❌ 找不到可用窗口"); return; }

        [g_stateLock lock]; BOOL cap = g_captureEnabled; int cnt = g_count; [g_stateLock unlock];
        UIAlertController *ac = [UIAlertController
            alertControllerWithTitle:@"抓包"
            message:cap ? [NSString stringWithFormat:@"🔴 正在抓包…（已记录 %d 条）", cnt]
                        : [NSString stringWithFormat:@"⚪ 未开启（已记录 %d 条）", cnt]
            preferredStyle:UIAlertControllerStyleActionSheet];

        UIAlertAction *start = [UIAlertAction actionWithTitle:@"▶️ 开始抓包"
            style:UIAlertActionStyleDefault
            handler:^(UIAlertAction *a) { startCapture(); }];
        start.enabled = !cap;
        [ac addAction:start];

        UIAlertAction *stop = [UIAlertAction actionWithTitle:@"⏹ 停止抓包"
            style:UIAlertActionStyleDefault
            handler:^(UIAlertAction *a) { stopCapture(); }];
        stop.enabled = cap;
        [ac addAction:stop];

        [ac addAction:[UIAlertAction actionWithTitle:@"📤 分享导出 TXT"
            style:UIAlertActionStyleDefault
            handler:^(UIAlertAction *a) { shareCaptureFile(); }]];

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
// 悬浮 UI
// ═══════════════════════════════════════════════════════════════════════
@interface DiditokFloatWindow : UIWindow
@end
@implementation DiditokFloatWindow
- (UIView *)hitTest:(CGPoint)point withEvent:(UIEvent *)event {
    UIView *v = [super hitTest:point withEvent:event];
    return (v == self) ? nil : v;   // 空白区域穿透，只吃按钮
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
        [g_floatButton setTitle:@"抓" forState:UIControlStateNormal];
        [g_floatButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
        g_floatButton.titleLabel.font = [UIFont boldSystemFontOfSize:28];
        [g_floatButton addTarget:[DiditokActionTarget shared] action:@selector(onFloatTap)
                 forControlEvents:UIControlEventTouchUpInside];
        UIPanGestureRecognizer *pan = [[UIPanGestureRecognizer alloc]
            initWithTarget:[DiditokActionTarget shared] action:@selector(onPan:)];
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
// 滴滴/哈啰等安全组件通过公开 API 枚举已加载镜像：
//   _dyld_image_count / _dyld_get_image_name / _dyld_get_image_header
//   _dyld_get_image_vmaddr_slide / _dyld_register_func_for_add_image
// 它们全部读同一份全局表 _dyld_all_image_infos.infoArray。
// 所以不用 fishhook、不用改任何函数，直接改表里"我们这一条"的路径和 header，
// 让所有枚举者看到的都是一个系统库，看不到 Diditok.dylib。
// dyld 之后 dlopen 新镜像可能重建这张表，所以在新增镜像回调里再刷一次。
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
//   · DCAppAttestService.isSupported → NO（重签后必然失败，让它走降级）
//   · isAppAttestEnabled / isAppCracked / isJailbroken 等布尔开关压平为 NO
//   · App 包内 Diditok 相关文件在 NSFileManager 枚举里隐藏
// ═══════════════════════════════════════════════════════════════════════
static BOOL DidiReturnNO(id self, SEL _cmd) { return NO; }

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

static void DidiDisableAppAttest(void) {
    Class att = NSClassFromString(@"DCAppAttestService");
    if (!att) { NSLog(@"[Diditok] ⚠️ DCAppAttestService 不存在"); return; }
    Method m = class_getInstanceMethod(att, @selector(isSupported));
    if (m) {
        method_setImplementation(m, (IMP)DidiReturnNO);
        NSLog(@"[Diditok] ✓ DCAppAttestService.isSupported → NO");
    }
}

// 让本 dylib 在文件系统枚举里「不存在」（in-memory 隐藏对磁盘扫描无效）
static IMP g_origContentsOfDir = NULL;
static IMP g_origFileExists     = NULL;

static BOOL DidiIsOurName(NSString *s) {
    if (!s.length) return NO;
    NSString *low = s.lowercaseString;
    return [low containsString:@"diditok"];
}
// 只隐藏「App 包内」的痕迹；Documents 里的 diditok_capture.txt 必须照常可见（分享要用）
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

// ⚠️ 这些必须等 App 启动完再装。
// 在 dyld 初始化阶段调用 class_getInstanceMethod 会触发任意类的 +initialize，
// 那些类里再用 dispatch_once / mutex，会在 objc 运行时锁持有的情况下判定死锁，
// 抛 std::system_error → _objc_terminate → abort。
static void DidiInstallGuards(void) {
    static BOOL done = NO;
    if (done) return;
    done = YES;
    @try { DidiHideDylibFromFS();  } @catch (NSException *e) { NSLog(@"[Diditok] ✗ hideFS: %@", e); }
    @try { DidiDisableAppAttest(); } @catch (NSException *e) { NSLog(@"[Diditok] ✗ attest: %@", e); }
    @try { DidiSuppressIntegrityFlags(); } @catch (NSException *e) { NSLog(@"[Diditok] ✗ flags: %@", e); }
}

// ═══════════════════════════════════════════════════════════════════════
// constructor
// ═══════════════════════════════════════════════════════════════════════
__attribute__((constructor))
static void diditok_init(void) {
    @autoreleasepool {
      @try {
        NSLog(@"[Diditok] ▶ constructor fired (capture-only)");
        DidiHideSelf();

        g_stateLock  = [NSLock new];
        g_mapLock    = [NSLock new];
        g_pendingMap = [NSMutableDictionary new];
        g_bodyMap    = [NSMutableDictionary new];
        g_writeQueue = dispatch_queue_create("diditok.capture.write", DISPATCH_QUEUE_SERIAL);

        Class sessCls = NSClassFromString(@"NSURLSession");
        if (sessCls) {
            hookInstanceMethod(sessCls, "dataTaskWithRequest:completionHandler:",
                               (IMP)hookedDataTaskCH, &g_origDataTaskCH, "dataTaskWithRequest:completionHandler:");
            hookInstanceMethod(sessCls, "dataTaskWithRequest:",
                               (IMP)hookedDataTaskNH, &g_origDataTaskNH, "dataTaskWithRequest:");
            hookInstanceMethod(sessCls, "dataTaskWithURL:completionHandler:",
                               (IMP)hookedDataTaskURLCH, &g_origDataTaskURLCH, "dataTaskWithURL:completionHandler:");
            hookInstanceMethod(sessCls, "dataTaskWithURL:",
                               (IMP)hookedDataTaskURLNH, &g_origDataTaskURLNH, "dataTaskWithURL:");
            hookInstanceMethod(sessCls, "uploadTaskWithRequest:fromData:completionHandler:",
                               (IMP)hookedUploadCH, &g_origUploadDataCH, "uploadTaskWithRequest:fromData:completionHandler:");
            hookInstanceMethod(sessCls, "uploadTaskWithRequest:fromData:",
                               (IMP)hookedUploadNH, &g_origUploadDataNH, "uploadTaskWithRequest:fromData:");
            hookInstanceMethod(sessCls, "uploadTaskWithStreamedRequest:",
                               (IMP)hookedUploadStream, &g_origUploadStream, "uploadTaskWithStreamedRequest:");
            hookInstanceMethod(sessCls, "downloadTaskWithRequest:completionHandler:",
                               (IMP)hookedDownloadCH, &g_origDownloadCH, "downloadTaskWithRequest:completionHandler:");
            hookInstanceMethod(sessCls, "downloadTaskWithURL:completionHandler:",
                               (IMP)hookedDownloadURLCH, &g_origDownloadURLCH, "downloadTaskWithURL:completionHandler:");
            hookInstanceMethod(sessCls, "downloadTaskWithRequest:",
                               (IMP)hookedDownloadNH, &g_origDownloadNH, "downloadTaskWithRequest:");
            hookClassMethod(sessCls, "sessionWithConfiguration:delegate:delegateQueue:",
                            (IMP)hookedSessionDQ, &g_origSessionDQ, "+sessionWithConfiguration:delegate:delegateQueue:");
            hookClassMethod(sessCls, "sessionWithConfiguration:delegate:",
                            (IMP)hookedSessionD, &g_origSessionD, "+sessionWithConfiguration:delegate:");
            hookClassMethod(sessCls, "backgroundSessionWithConfiguration:delegate:delegateQueue:",
                            (IMP)hookedBgSessionDQ, &g_origBgSessionDQ, "+backgroundSessionWithConfiguration:delegate:delegateQueue:");
        } else {
            NSLog(@"[Diditok] ⚠️ NSURLSession not found (shouldn't happen)");
        }

        // 等 App 完全启动后再建 UIWindow + 装反检测
        g_launchObserver = [[NSNotificationCenter defaultCenter]
            addObserverForName:UIApplicationDidFinishLaunchingNotification
                        object:nil
                         queue:[NSOperationQueue mainQueue]
                    usingBlock:^(NSNotification *note) {
            NSLog(@"[Diditok] ▶ UIApplicationDidFinishLaunching → setupFloatUI");
            DidiInstallGuards();
            setupFloatUI();
        }];

        // 兜底：如果通知没触发（罕见），3 秒后强制
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(3000000000)),
                       dispatch_get_main_queue(), ^{
            DidiInstallGuards();
            setupFloatUI();
        });

        NSLog(@"[Diditok] ✅ constructor done (capture-only)");
      } @catch (NSException *e) {
        NSLog(@"[Diditok] ✗ constructor exception: %@", e);
      }
    }
}
