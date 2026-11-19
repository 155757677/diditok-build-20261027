# -*- coding: utf-8 -*-
"""
东风解码 iOS 包 · 一键构建（GitHub Actions macOS runner）

流程：推送 dongfeng 源码 + workflow → 触发 dongfeng-ipa.yml → 轮询 → 下载产物 → 解出 IPA

用法：
    python build-ipa.py                 # 用本目录 token.txt 或环境变量 GH_TOKEN
    python build-ipa.py --no-push       # 不推源码，只用云端现有代码重新构建
产物：
    ./DongfengDecoder.ipa               （未签名，装之前需用你自己的方式签名）

注意：本脚本只写 dongfeng/ 目录和 .github/workflows/dongfeng-ipa.yml，
不动仓库里其它任何文件，也不会触发其它 workflow。
"""
import base64
import os
import sys
import time
import zipfile

import requests

REPO = "155757677/diditok-build-20261027"
WORKFLOW = "dongfeng-ipa.yml"
BRANCH = "main"
ARTIFACT = "dongfeng-decoder-ipa"
OUT = "DongfengDecoder.ipa"

HERE = os.path.dirname(os.path.abspath(__file__))

# 本地路径 → 仓库路径
FILES = {
    "project.yml": "dongfeng/project.yml",
    "Info.plist": "dongfeng/Info.plist",
    "dongfeng-ipa.yml": ".github/workflows/dongfeng-ipa.yml",
    "README.md": "dongfeng/README.md",
    "build-ipa.py": "dongfeng/build-ipa.py",
    "Sources/DongfengDecoder.swift": "dongfeng/Sources/DongfengDecoder.swift",
    "Sources/AppDelegate.swift": "dongfeng/Sources/AppDelegate.swift",
    "Sources/ScanViewController.swift": "dongfeng/Sources/ScanViewController.swift",
    "SelfTest/main.swift": "dongfeng/SelfTest/main.swift",
}


def token():
    t = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not t:
        p = os.path.join(HERE, "token.txt")
        if os.path.exists(p):
            t = open(p, encoding="utf-8").read().strip()
    if not t:
        sys.exit("找不到 token：设 GH_TOKEN 环境变量，或在本目录放 token.txt")
    return t


H = {}


def log(m):
    print(m, flush=True)


def api(path, method="GET", **kw):
    r = requests.request(method, "https://api.github.com" + path, headers=H, timeout=60, **kw)
    if r.status_code >= 400:
        log("  !! %s %s -> %s %s" % (method, path, r.status_code, r.text[:300]))
    return r


def put_file(repo_path, local_path, msg):
    data = open(local_path, "rb").read()
    sha = None
    r = api("/repos/%s/contents/%s" % (REPO, repo_path))
    if r.status_code == 200 and isinstance(r.json(), dict):
        sha = r.json().get("sha")
    body = {"message": msg, "content": base64.b64encode(data).decode(), "branch": BRANCH}
    if sha:
        body["sha"] = sha
    for attempt in range(3):
        r2 = api("/repos/%s/contents/%s" % (REPO, repo_path), "PUT", json=body)
        log("  PUT %-46s %s" % (repo_path, r2.status_code))
        if r2.status_code in (200, 201):
            return True
        if r2.status_code == 409:
            r = api("/repos/%s/contents/%s" % (REPO, repo_path))
            if r.status_code == 200:
                body["sha"] = r.json().get("sha")
        time.sleep(3)
    return False


def push():
    log("[1/4] 推送源码")
    ok = True
    for rel, repo_path in FILES.items():
        local = os.path.join(HERE, rel)
        if not os.path.exists(local):
            log("  跳过缺失文件 %s" % rel)
            continue
        ok = put_file(repo_path, local, "dongfeng: update " + os.path.basename(rel)) and ok
    if not ok:
        sys.exit("推送失败（workflow 文件需要 token 具备 workflow 权限）")


def dispatch_and_wait():
    log("[2/4] 触发构建")
    before = api("/repos/%s/actions/workflows/%s/runs?per_page=1" % (REPO, WORKFLOW)).json()
    prev = (before.get("workflow_runs") or [{}])[0].get("run_number", 0)

    r = api("/repos/%s/actions/workflows/%s/dispatches" % (REPO, WORKFLOW), "POST",
            json={"ref": BRANCH})
    if r.status_code != 204:
        sys.exit("dispatch 失败 %s" % r.status_code)

    run = None
    for _ in range(30):
        time.sleep(5)
        runs = api("/repos/%s/actions/workflows/%s/runs?per_page=5" % (REPO, WORKFLOW)).json()
        for c in runs.get("workflow_runs", []):
            if c.get("run_number", 0) > prev:
                run = c
                break
        if run:
            break
    if not run:
        sys.exit("查不到本次 run（上一条是 #%s）" % prev)
    rid = run["id"]
    log("  Run #%s  #%s" % (rid, run["run_number"]))
    log("  https://github.com/%s/actions/runs/%s" % (REPO, rid))

    start = time.time()
    while True:
        if time.time() - start > 1800:
            sys.exit("轮询超时")
        time.sleep(15)
        run = api("/repos/%s/actions/runs/%s" % (REPO, rid)).json()
        jobs = api("/repos/%s/actions/runs/%s/jobs" % (REPO, rid)).json().get("jobs", [])
        cur = ""
        if jobs:
            for s in jobs[0].get("steps", []):
                if s["status"] == "in_progress":
                    cur = s["name"]
        log("  [%4ds] %s / %s  %s" % (time.time() - start, run["status"], run.get("conclusion") or "", cur))
        if run["status"] == "completed":
            break

    if run["conclusion"] != "success":
        if jobs:
            for s in jobs[0]["steps"]:
                log("    [%s] %s" % (s.get("conclusion"), s.get("name")))
        sys.exit("构建失败：https://github.com/%s/actions/runs/%s" % (REPO, rid))
    log("  ✅ 构建成功")
    return rid


def download(rid):
    log("[3/4] 下载产物")
    arts = api("/repos/%s/actions/runs/%s/artifacts" % (REPO, rid)).json().get("artifacts", [])
    if not arts:
        sys.exit("没有产物")
    a = next((x for x in arts if x["name"] == ARTIFACT), arts[0])
    url = "/repos/%s/actions/artifacts/%s/zip" % (REPO, a["id"])
    s = requests.Session()
    if os.name == "nt":
        s.trust_env = False      # Windows 上绕开系统代理，与 构建.py 行为一致
    r = s.get("https://api.github.com" + url, headers=H, allow_redirects=False, timeout=120)
    loc = r.headers.get("Location")
    if not loc:
        sys.exit("拿不到下载直链")
    tmp = os.path.join(HERE, "_artifact.zip")
    with open(tmp, "wb") as f:
        for chunk in s.get(loc, stream=True, timeout=300).iter_content(1 << 16):
            f.write(chunk)
    size = a["size_in_bytes"]
    got = os.path.getsize(tmp)
    log("  %s 字节（云端 %s）" % (got, size))
    if got != size:
        log("  ⚠️ 大小与云端记录不一致，仍按 zip 内容处理")
    return tmp


def unpack(zp):
    log("[4/4] 解出 IPA 并自检")
    with zipfile.ZipFile(zp) as z:
        names = z.namelist()
        ipa = next((n for n in names if n.endswith(".ipa")), None)
        if not ipa:
            sys.exit("产物里没有 .ipa：%s" % names[:10])
        data = z.read(ipa)
    out = os.path.join(HERE, OUT)
    with open(out, "wb") as f:
        f.write(data)
    os.remove(zp)

    with zipfile.ZipFile(out) as z:
        n = z.namelist()
        app = next((x for x in n if x.endswith(".app/Info.plist")), None)
        if not app:
            sys.exit("IPA 结构不对，没找到 .app/Info.plist")
        info = z.read(app).decode("utf-8", "replace")
        binname = app.replace("Info.plist", "DongfengDecoder")
        ok_bin = binname in n
        log("  %s  %.2f MB" % (OUT, os.path.getsize(out) / 1048576))
        for k in ("东风解码", "com.df.dongfengdecoder", "NSCameraUsageDescription"):
            log("  %-26s %s" % (k, "✅" if k in info else "❌"))
        log("  %-26s %s" % ("主二进制", "✅" if ok_bin else "❌"))
    log("\n✅ 完成：%s" % out)


if __name__ == "__main__":
    H.update({"Authorization": "token " + token(),
              "Accept": "application/vnd.github+json",
              "User-Agent": "dongfeng-ipa-build"})
    if "--no-push" not in sys.argv:
        push()
    rid = dispatch_and_wait()
    unpack(download(rid))
