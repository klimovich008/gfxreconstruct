# Windows CRT pipeline-cache container reproducer

This standalone test uses authored bytes and real Windows CRT I/O. It extracts the actual cache reader/writer, constructor cache-file initialization block and seven stdio/platform helpers from GFXReconstruct commit f9b0fb0d7c8b3293c7ec3edec5115da877831d18. It does not compile or run GFXReconstruct itself or use Vulkan, a capture, game data or a real pipeline cache.

Requirements: Windows x64, Python 3, Git, and llvm-mingw clang++ with its runtime DLLs available. No Python packages are required. The source checkout must contain the pinned commit object; a shallow checkout without it is insufficient. MSVC and POSIX execution are not covered.

Copy the supplied script and license into a writable GFXReconstruct checkout, then run:

```
python -I -B test_pipeline_cache_binary.py --source-repo . --cxx clang++
```

Alternatively run the script from a separate writable folder and pass your clone as --source-repo. Use --cxx with the llvm-mingw compiler's full path if it is not on PATH. The script writes its adjacent run/ generated C++/executables and patch/result/license files. Use a dedicated test location, never a real cache directory. Normal successful completion removes its authored binary input/output files. Git/native subprocess timeouts are 10 seconds and each sequential compile timeout is 40 seconds.

The independent byte oracle contains IDs 17, 260, 4096 with LF, CRLF, 0x1a, NUL and 0xff payload bytes. ID 260 is requested first, requiring the actual loader to skip ID 17. The actual writer appends three records; every header and payload byte is compared against an independent 69-byte container. A real unqualified Windows FileOpen("w") probe must emit CRLF before the test proceeds; no global mode override is applied.

Observed with llvm-mingw 23.1.5/UCRT: both variants compile with -Wall -Wextra -Werror. Original read/write byte checks fail (75 written bytes instead of 69); changing only the four open-mode literals passes all byte checks. RESULT.txt contains the observed aggregate output.

Two limits are deliberate. Fatal logging is stubbed to collect all failures; real fatal logging can terminate or throw at the first corrupt payload, so fixture exit 3 is not the real tool's exit sequence. Initialization flags are injected; those cases test the extracted block given flags, not the full constructor's filename-equality classification.

This is a frozen-source red/green reproducer, not a test of an arbitrary current worktree or a registered CI test. Its exercised source bodies and complete platform.h are byte-identical in dev 860627562a6256a3a61fc55559b0c633322362fa, but no whole current-dev build, Vulkan cache acceptance, replay, Linux or MSVC run is claimed. The short payloads are not valid Vulkan cache blobs.

Upstream source and notices remain under the included MIT license. Both upstream source-file notices are retained in generated C++. See the [pinned upstream source](https://github.com/LunarG/gfxreconstruct/tree/f9b0fb0d7c8b3293c7ec3edec5115da877831d18).
