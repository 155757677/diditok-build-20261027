#!/usr/bin/env python3
"""注入 Diditok.dylib 到目标 Mach-O 二进制"""
import sys, os, lief

TARGET_LIB = "@executable_path/Frameworks/Diditok.dylib"

def inject(binary_path):
    print(f"[inject] parsing {binary_path}")
    parsed = lief.MachO.parse(binary_path)
    
    if isinstance(parsed, lief.MachO.FatBinary):
        # Fat binary (arm64 + arm64e)
        print(f"[inject] FatBinary with {parsed.size} slices")
        for i in range(parsed.size):
            binary = parsed.at(i)
            libs = [lib.name for lib in binary.libraries]
            if TARGET_LIB in libs:
                print(f"[inject] slice {i}: already has {TARGET_LIB}")
            else:
                binary.add_library(TARGET_LIB)
                print(f"[inject] slice {i}: added {TARGET_LIB}")
        parsed.write(binary_path)
    elif isinstance(parsed, list):
        # 多个独立 binary（不太常见）
        for binary in parsed:
            libs = [lib.name for lib in binary.libraries]
            if TARGET_LIB not in libs:
                binary.add_library(TARGET_LIB)
        parsed[0].write(binary_path) if hasattr(parsed[0], 'write') else None
        # 用第一个 binary 写回
        binary0 = parsed[0]
        if isinstance(binary0, lief.MachO.Binary):
            binary0.write(binary_path)
    elif isinstance(parsed, lief.MachO.Binary):
        libs = [lib.name for lib in parsed.libraries]
        if TARGET_LIB not in libs:
            parsed.add_library(TARGET_LIB)
        parsed.write(binary_path)
    else:
        print(f"[inject] unexpected type: {type(parsed)}")
        sys.exit(1)
    
    print(f"[inject] ✅ injected into {binary_path}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: inject.py <binary_path>")
        sys.exit(1)
    inject(sys.argv[1])
