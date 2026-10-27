#!/usr/bin/env python3
"""注入 Diditok.dylib 到目标 Mach-O 二进制"""
import sys, os, lief

def inject(binary_path, dylib_path):
    print(f"[inject] parsing {binary_path}")
    b = lief.MachO.parse(binary_path)
    if isinstance(b, list):
        # fat binary (arm64 + arm64e)，需要对每个 slice 注入
        for binary in b:
            libs = [lib.name for lib in binary.libraries]
            target = "@executable_path/Frameworks/Diditok.dylib"
            if target in libs:
                print(f"[inject] already has {target}, skip")
            else:
                binary.add_library(target)
                print(f"[inject] added {target} to slice")
        # 写回 fat binary
        b.write(binary_path)
    else:
        binary = b
        libs = [lib.name for lib in binary.libraries]
        target = "@executable_path/Frameworks/Diditok.dylib"
        if target not in libs:
            binary.add_library(target)
        binary.write(binary_path)
    print(f"[inject] ✅ injected into {binary_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: inject.py <binary_path> [dylib_path]")
        sys.exit(1)
    inject(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "Diditok.dylib")
