#!/usr/bin/env python3
"""Windows CRT regression using pinned GFXReconstruct function bodies; no Vulkan."""
import argparse
import difflib
import hashlib
import json
import os
from pathlib import Path
import subprocess

PIN = "f9b0fb0d7c8b3293c7ec3edec5115da877831d18"
CPP = "framework/decode/vulkan_replay_consumer_base.cpp"
PLATFORM = "framework/util/platform.h"


def block(text, marker):
    start = text.index(marker)
    opening = text.index("{", start)
    depth = 1
    end = opening + 1
    while depth:
        depth += (text[end] == "{") - (text[end] == "}")
        end += 1
    return text[start:end]


HARNESS = r'''
#include <windows.h>
#include <fcntl.h>
#include <cassert>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#define GFXRECON_ASSERT(x) assert(x)
#define GFXRECON_LOG_ERROR(...) ((void)0)
#define GFXRECON_LOG_WARNING(...) ((void)0)
#define GFXRECON_LOG_FATAL(...) ((void)0)
#define GFXRECON_LOG_INFO(...) ((void)0)
#define VK_NULL_HANDLE 0
namespace format { using HandleId = uint64_t; }
namespace util::platform {
enum FileSeekOrigin { FileSeekCurrent = SEEK_CUR, FileSeekEnd = SEEK_END, FileSeekSet = SEEK_SET };
@PLATFORM@
}
// Only options, device-call data supply and logging are stubbed. Container code is verbatim.
struct VulkanDeviceInfo { int handle = 1; };
struct VulkanReplayConsumerBase {
    struct Options { std::string load_pipeline_cache_filename, save_pipeline_cache_filename; } options_;
    struct TrackedPipelineCache {
        const VulkanDeviceInfo* device_info{ nullptr };
        uint64_t vk_cache{ VK_NULL_HANDLE };
        bool write_to_file{ false };
    };
    bool save_pipeline_caches_to_file = true;
    bool load_pipeline_caches_from_file = false;
    bool load_save_caches_in_same_file = false;
    std::vector<std::vector<uint8_t>> payloads;
    struct Calls {
        const std::vector<std::vector<uint8_t>>* payloads;
        Calls* Open() { return this; }
        void GetPipelineCacheData(int, uint64_t cache, size_t* size, void* data) {
            const auto& bytes = payloads->at(cache - 1);
            if (data) { assert(*size >= bytes.size()); memcpy(data, bytes.data(), bytes.size()); }
            *size = bytes.size();
        }
    };
    Calls GetInjectedDeviceCalls(int) { return { &payloads }; }
    void InitializeCacheFile() { @INITIALIZE@ }
    bool LoadPipelineCacheFromFile(format::HandleId, std::vector<uint8_t>&);
    void SavePipelineCache(format::HandleId, const TrackedPipelineCache&);
};
@LOAD@
@SAVE@
// Independent oracle: explicitly encode the documented native little-endian record layout.
static void record(std::vector<uint8_t>& out, uint64_t id, const std::vector<uint8_t>& data) {
    for (auto value : {id, uint64_t(data.size())})
        for (unsigned n = 0; n != 8; ++n) out.push_back(uint8_t(value >> (8 * n)));
    out.insert(out.end(), data.begin(), data.end());
}
static void raw_write(const char* path, const std::vector<uint8_t>& data) {
    FILE* f = fopen(path, "wb"); assert(f);
    assert(fwrite(data.data(), 1, data.size(), f) == data.size()); assert(fclose(f) == 0);
}
static std::vector<uint8_t> raw_read(const char* path) {
    FILE* f = fopen(path, "rb"); assert(f);
    std::vector<uint8_t> data;
    for (int c; (c = fgetc(f)) != EOF;) data.push_back(uint8_t(c));
    assert(!ferror(f)); assert(fclose(f) == 0); return data;
}
int main() {
    int mode = 0; assert(_get_fmode(&mode) == 0);
    FILE* probe = nullptr;
    assert(util::platform::FileOpen(&probe, "crt-probe.bin", "w") == 0);
    assert(fputc(0x0a, probe) == 0x0a); assert(fclose(probe) == 0);
    const bool text_default = raw_read("crt-probe.bin") == std::vector<uint8_t>({0x0d, 0x0a});
    assert(remove("crt-probe.bin") == 0);
    printf("CRT default=%d unqualified write=%s; no mode override\n", mode, text_default ? "TEXT" : "OTHER");
    if (!text_default) return 90; // Refuse an environment that masks the original defect.
    VulkanReplayConsumerBase c;
    const std::vector<uint64_t> ids{17, 260, 4096};
    c.payloads = {{0x41, 0x0a, 0x42, 0x0d, 0x0a, 0x1a, 0x43},
                  {0x00, 0x0a, 0x0d, 0x0a, 0x1a, 0xff, 0x42, 0x00},
                  {0x7f, 0x1a, 0x0d, 0x0a, 0x0a, 0x55}};
    std::vector<uint8_t> expected;
    for (size_t n = 0; n != ids.size(); ++n) record(expected, ids[n], c.payloads[n]);
    raw_write("authored-input.bin", expected);
    c.options_.load_pipeline_cache_filename = "authored-input.bin";
    unsigned failures = 0;
    // Start with ID260, requiring the real loader to skip ID17 before selecting it.
    for (size_t n : {size_t(1), size_t(0), size_t(2)}) {
        std::vector<uint8_t> got;
        const bool found = c.LoadPipelineCacheFromFile(ids[n], got);
        const bool equal = found && got == c.payloads[n];
        printf("load id=%llu found=%d bytes=%zu expected=%zu oracle=%s\n",
               (unsigned long long)ids[n], int(found), got.size(), c.payloads[n].size(), equal ? "PASS" : "FAIL");
        if (!equal) failures |= 1;
    }
    // Actual constructor block truncates junk, actual writer appends three separate records.
    c.options_.save_pipeline_cache_filename = "authored-output.bin";
    raw_write("authored-output.bin", std::vector<uint8_t>(31, 0xee));
    c.InitializeCacheFile();
    if (!raw_read("authored-output.bin").empty()) failures |= 4;
    VulkanDeviceInfo device;
    for (size_t n = 0; n != ids.size(); ++n)
        c.SavePipelineCache(ids[n], {&device, n + 1, true});
    const auto actual = raw_read("authored-output.bin");
    printf("write three records bytes=%zu expected=%zu full oracle=%s\n",
           actual.size(), expected.size(), actual == expected ? "PASS" : "FAIL");
    if (actual != expected) failures |= 2;
    // Same-file load+save must preserve every appended byte, then absent-file initialization creates empty.
    c.load_pipeline_caches_from_file = c.load_save_caches_in_same_file = true;
    c.InitializeCacheFile();
    if (raw_read("authored-output.bin") != actual) failures |= 4;
    assert(remove("authored-output.bin") == 0);
    c.InitializeCacheFile();
    if (!raw_read("authored-output.bin").empty()) failures |= 4;
    printf("initialization truncate/preserve/create=%s; failure_mask=%u\n", (failures & 4) ? "FAIL" : "PASS", failures);
    assert(remove("authored-output.bin") == 0);
    assert(remove("authored-input.bin") == 0);
    return int(failures);
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--cxx", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent / "run")
    args = parser.parse_args()
    if os.name != "nt":
        parser.error("requires the Windows CRT; POSIX text mode cannot reproduce this defect")
    args.out.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, PATH=str(args.cxx.parent) + os.pathsep + os.environ.get("PATH", ""))
    def run(command, *, cwd=args.out, timeout=10):
        return subprocess.run([str(x) for x in command], cwd=cwd, env=env, capture_output=True,
                              text=True, timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW)
    def show(path):
        p = run(["git", "-c", "gc.auto=0", "-c", "maintenance.auto=false", "show", PIN + ":" + path], cwd=args.source_repo)
        if p.returncode: raise RuntimeError(p.stderr)
        return p.stdout
    source, platform = show(CPP), show(PLATFORM)
    replacements = {
        'options_.save_pipeline_cache_filename.c_str(), "r")': 'options_.save_pipeline_cache_filename.c_str(), "rb")',
        'options_.save_pipeline_cache_filename.c_str(), "w")': 'options_.save_pipeline_cache_filename.c_str(), "wb")',
        'options_.load_pipeline_cache_filename.c_str(), "r")': 'options_.load_pipeline_cache_filename.c_str(), "rb")',
        'options_.save_pipeline_cache_filename.c_str(), "a")': 'options_.save_pipeline_cache_filename.c_str(), "ab")',
    }
    patched = source
    for old, new in replacements.items():
        assert patched.count(old) == 1, old
        patched = patched.replace(old, new)
    patch = ''.join(difflib.unified_diff(source.splitlines(True), patched.splitlines(True), fromfile='a/'+CPP, tofile='b/'+CPP))
    (args.out.parent / "pipeline-cache-binary.patch").write_text(patch, encoding="utf-8", newline="\n")
    helpers = [block(platform, marker) for marker in [
        'inline std::wstring ToWString(const char* str)',
        'inline int32_t FileOpen(FILE** stream, const char* filename, const char* mode)',
        'inline bool FileSeek(FILE* stream, int64_t offset, FileSeekOrigin origin)',
        'inline bool FileWrite(const void* buffer, size_t bytes, FILE* stream)',
        'inline size_t FileReadBytes(void* buffer, size_t bytes, FILE* stream)',
        'inline bool FileRead(void* buffer, size_t bytes, FILE* stream)',
        'inline int32_t FileClose(FILE* stream)',
    ]]
    results = []
    for name, text, expected_exit in [('original', source, 3), ('binary', patched, 0)]:
        generated = source[:source.index('*/')+2] + '\n' + platform[:platform.index('*/')+2] + '\n' + HARNESS
        for marker, value in {
            '@PLATFORM@': '\n'.join(helpers),
            '@INITIALIZE@': block(text, 'if (save_pipeline_caches_to_file)'),
            '@LOAD@': block(text, 'bool VulkanReplayConsumerBase::LoadPipelineCacheFromFile('),
            '@SAVE@': block(text, 'void VulkanReplayConsumerBase::SavePipelineCache('),
        }.items(): generated = generated.replace(marker, value)
        cpp, exe = args.out / (name+'.cpp'), args.out / (name+'.exe')
        cpp.write_text(generated, encoding="utf-8", newline="\n")
        command = [args.cxx, '-std=c++20', '-O0', '-Wall', '-Wextra', '-Werror', cpp.resolve(), '-o', exe.resolve()]
        built = run(command, timeout=40)
        if built.returncode: raise RuntimeError(name+' COMPILE FAILURE (not a red control):\n'+built.stdout+built.stderr)
        tested = run([exe.resolve()])
        print(name+' exit='+str(tested.returncode)+'\n'+tested.stdout+tested.stderr, flush=True)
        results.append({'variant':name, 'cpp_sha256':hashlib.sha256(cpp.read_bytes()).hexdigest(), 'compile_command':[str(x) for x in command], 'compile_exit':built.returncode, 'run_exit':tested.returncode, 'stdout':tested.stdout, 'stderr':tested.stderr})
        if tested.returncode != expected_exit: raise RuntimeError(name+' did not meet intended behavioral oracle')
    (args.out.parent / "results.json").write_text(json.dumps({'pin':PIN,'paths':[CPP,PLATFORM],'results':results}, indent=2)+'\n', encoding='utf-8')
    (args.out.parent / "LICENSE-GFXReconstruct.txt").write_text(show('LICENSES/LICENSE.txt'), encoding='utf-8')
    print('PASS original read/write behavioral red; binary read/write green')


if __name__ == '__main__':
    main()
