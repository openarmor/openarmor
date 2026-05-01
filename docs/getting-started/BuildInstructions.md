# Build Instructions

This guide explains how to compile OpenArmor from source using Microsoft Visual Studio and the Windows Driver Kit (WDK). Building from source is recommended for contributors, security researchers, and organizations that require custom builds or need to integrate OpenArmor into an existing CI/CD pipeline.

## What You Are Building

| Output | Description |
|---|---|
| `edrdrv.sys` | Kernel-mode driver — captures OS-level events via kernel callbacks |
| `edrsvc.exe` | User-space Windows service — core agent, event processing, telemetry output |
| `edrpm.dll` | User-space injected DLL — API interception in monitored processes |
| `edrcon.exe` | Command-line control and diagnostics utility |
| `edrmm.dll` | Memory monitoring module |
| `edrext.dll` | Extension module for additional event sources |
| `OpenArmor-Setup-x64.msi` | Windows installer package (requires WiX Toolset) |

**Why build from source instead of using a release binary?**

- Audit and verify every line of code that runs on your endpoints
- Apply custom patches or detection logic
- Integrate with internal build and signing infrastructure
- Develop and test new event sources or policy engine features
- Build with modified configurations (custom output paths, embedded policy, etc.)

---

## Prerequisites

All prerequisites must be installed before opening the solution. Missing components will cause build failures that are difficult to diagnose after the fact.

### Summary Table

| Tool | Version | Required | Notes |
|---|---|---|---|
| Visual Studio 2019 | 16.x (any update) | Recommended | See workloads below |
| Visual Studio 2017 | 15.x | Alternative | Use if VS2019 unavailable |
| Windows Driver Kit (WDK) | Matching SDK version | Required | Must match Windows 10 SDK version |
| Windows 10 SDK | 10.0.18362.0 or later | Required | Installed via VS installer |
| Git | 2.x | Required | With Git LFS enabled |
| Git LFS | Any current | Required | Large binary assets in repo |
| Python | 3.6 or later | Required | Used by build scripts |
| CMake | 3.14 or later | Required | Used by external dependency builds |
| WiX Toolset | 3.11 or later | Required for MSI | Installer build only |

### Visual Studio 2019 — Required Workloads and Components

Open the Visual Studio Installer and ensure the following are installed:

**Workloads:**
- Desktop development with C++
- (Optional) Linux development with C++ — only if cross-compiling for test tools

**Individual Components** (under the "Individual components" tab):
- Windows 10 SDK (10.0.18362.0 or the latest available)
- MSVC v142 — VS 2019 C++ x64/x86 build tools
- C++ ATL for latest v142 build tools (x86 & x64)
- C++ MFC for latest v142 build tools (x86 & x64)
- C++ Clang tools for Windows (optional, used by some scripts)
- .NET Framework 4.7.2 targeting pack (required for installer build)

### Windows Driver Kit (WDK) Installation

The WDK version **must match** the Windows 10 SDK version installed with Visual Studio. A mismatch is the most common cause of driver project build failures.

1. Open Visual Studio Installer and note the exact Windows 10 SDK version installed (e.g., `10.0.18362.0`).
2. Navigate to the WDK download page:
   ```
   https://docs.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
   ```
3. Download the WDK installer corresponding to your SDK version.
4. Run the WDK installer. It will automatically integrate with Visual Studio.
5. Verify integration: open Visual Studio 2019, create a new project, and confirm that **Driver** project templates appear under the Windows category.

> **Version matching rule:** WDK 10.0.18362 pairs with SDK 10.0.18362.0. Always use the WDK that matches your SDK's build number exactly.

### Git LFS

The repository uses Git Large File Storage (LFS) for binary assets. Install it before cloning:

```bash
# Download from https://git-lfs.github.com/
# Or via winget:
winget install GitHub.GitLFS

# Enable LFS globally
git lfs install
```

### WiX Toolset (Installer Build Only)

Required only if you intend to build the `.msi` installer:

1. Download WiX Toolset 3.11 from `https://wixtoolset.org/releases/`
2. Install the WiX Toolset build tools
3. Install the WiX Toolset Visual Studio 2019 Extension (provides project templates)

---

## Cloning the Repository

```bash
git clone --recursive https://github.com/openarmor/openarmor.git
cd openarmor
git submodule update --init --recursive
```

The `--recursive` flag is essential. OpenArmor depends on approximately 20 external libraries that are managed as Git submodules under `edrav2/eprj/`. Without recursive initialization, the build will fail with missing header errors.

**External dependencies included as submodules:**

| Submodule | Purpose |
|---|---|
| `awssdkcpp` | AWS SDK for C++ — cloud backend communication |
| `boost` | Boost C++ Libraries — utilities, ASIO, filesystem |
| `c-ares` | Asynchronous DNS resolver |
| `Catch2` | Unit testing framework |
| `crashpad` | Google Crashpad — crash reporting and dump collection |
| `detours` | Microsoft Detours — API hooking for `edrpm.dll` |
| `googleapis` | Google API protocol definitions |
| `grpc` | gRPC — remote procedure call framework |
| `jsoncpp` | JSON parsing and serialization |
| `libcurl` | HTTP client library |
| `libjson-rpc-cpp` | JSON-RPC protocol support |
| `libmicrohttpd` | Embedded HTTP server |
| `log4cplus` | C++ logging framework |
| `nlohmann/json` | Header-only modern JSON library |
| `openssl` | TLS and cryptographic primitives |
| `protobuf` | Google Protocol Buffers |
| `tiny-AES-c` | AES encryption implementation |
| `uri` | C++ URI parsing library |
| `utfcpp` | UTF-8 encoding/decoding |
| `xxhash_cpp` | Fast hashing |
| `zlib` | Data compression |

After cloning, verify all submodules are present:

```bash
git submodule status
```

All entries should show a commit hash without a leading `-` (which would indicate an uninitialized submodule).

---

## Building with Visual Studio 2019

Visual Studio 2019 is the recommended build environment.

### Step 1 — Open the Solution as Administrator

Opening as Administrator is required for the post-build steps that register the kernel driver during development builds.

1. Right-click the Visual Studio 2019 shortcut and select **Run as administrator**.
2. In Visual Studio, select **File** > **Open** > **Project/Solution**.
3. Navigate to:
   ```
   edrav2\build\vs2019\edrav2.sln
   ```
4. Click **Open**.

### Step 2 — Set the Build Configuration

In the toolbar dropdowns:

- **Configuration:** `Release`
- **Platform:** `x64`

> **Do not build Debug configurations** for production use. Debug builds include additional logging and assertions that significantly affect performance. Use Debug builds only for local development and debugging sessions.

### Step 3 — Build the Solution

Select **Build** > **Build Solution** (or press `Ctrl+Shift+B`).

The build process compiles the following in dependency order:

1. External libraries (Boost, OpenSSL, gRPC, protobuf, etc.) — this takes the longest on a first build
2. Core shared libraries (`edrmm.dll`, `edrext.dll`)
3. Kernel driver (`edrdrv.sys`)
4. Injected DLL (`edrpm.dll`)
5. Service binary (`edrsvc.exe`)
6. Control utility (`edrcon.exe`)

First-time builds typically take 20–60 minutes depending on hardware. Subsequent incremental builds are much faster.

### Step 4 — Locate Build Outputs

All build artifacts are placed in:

```
edrav2\build\vs2019\x64\Release\
```

**Expected output files:**

| File | Description |
|---|---|
| `edrsvc.exe` | Windows service binary |
| `edrdrv.sys` | Kernel driver |
| `edrpm.dll` | Process monitor DLL (injected) |
| `edrcon.exe` | Control utility |
| `edrmm.dll` | Memory monitoring module |
| `edrext.dll` | Extension module |
| `edrsvc.pdb` | Service debug symbols |
| `edrdrv.pdb` | Driver debug symbols |

> Retain the `.pdb` files. They are required for crash dump analysis and kernel debugging.

---

## Building with Visual Studio 2017

The process is identical to VS2019. Use the VS2017 solution file instead:

1. Open Visual Studio 2017 **as Administrator**.
2. Open:
   ```
   edrav2\build\vs2017\edrav2.sln
   ```
3. Set configuration to `Release | x64`.
4. Build with **Build** > **Build Solution**.

Build outputs are placed in:

```
edrav2\build\vs2017\x64\Release\
```

> **Note:** VS2017 uses the MSVC v141 toolset. If your WDK was installed for VS2019 (v142), you may need to install the separate WDK for VS2017. See the WDK download page for multi-version installation instructions.

---

## Building the Installer (MSI)

The MSI installer requires WiX Toolset 3.11 or later to be installed before opening the installer solution.

### Step 1 — Build the Main Solution First

The installer project references the built binaries. Ensure `edrav2.sln` has been fully compiled to `Release | x64` before proceeding.

### Step 2 — Open the Installer Solution

1. Open Visual Studio 2019 **as Administrator**.
2. Open:
   ```
   edrav2\iprj\installation\build\vs2019\installation.wixproj
   ```
   or open the installer solution file in the same directory.

### Step 3 — Build the Installer

1. Set configuration to `Release | x64`.
2. Build with **Build** > **Build Solution**.

The resulting installer is placed at:

```
edrav2\iprj\installation\build\vs2019\x64\Release\OpenArmor-Setup-x64.msi
```

---

## Driver Signing

Windows requires that kernel-mode drivers be signed. The signing approach depends on your deployment target.

### Development and Testing — Test Signing Mode

For development machines only. This mode allows drivers signed with self-signed or untrusted certificates to load.

**Enable test signing (requires Administrator, requires reboot):**

```cmd
bcdedit /set testsigning on
shutdown /r /t 0
```

After reboot, a "Test Mode" watermark will appear on the desktop.

**Create a self-signed test certificate:**

```cmd
# Create a self-signed certificate
MakeCert -r -pe -ss PrivateCertStore -n "CN=OpenArmor Test Signing" -eku 1.3.6.1.5.5.7.3.3 OpenArmorTest.cer

# Sign the driver
SignTool sign /fd sha256 /a /s PrivateCertStore /n "OpenArmor Test Signing" /t http://timestamp.digicert.com edrdrv.sys
```

**Disable test signing when done:**

```cmd
bcdedit /set testsigning off
shutdown /r /t 0
```

### Production Deployment — EV Code Signing Certificate

Production deployments require a driver signed with an Extended Validation (EV) code signing certificate from a Microsoft-trusted Certificate Authority (e.g., DigiCert, Sectigo, GlobalSign).

**Sign the driver for production:**

```cmd
signtool sign /a /fd sha256 /tr http://timestamp.digicert.com /td sha256 edrdrv.sys
```

Verify the signature after signing:

```cmd
signtool verify /pa /v edrdrv.sys
```

### Enterprise Deployment — WHQL Submission

For the broadest enterprise compatibility (including systems with strict Secure Boot policies), submit `edrdrv.sys` to Microsoft for WHQL (Windows Hardware Quality Labs) certification via the Windows Hardware Dev Center:

```
https://partner.microsoft.com/en-us/dashboard/hardware/
```

WHQL-certified drivers are signed by Microsoft directly and load on all Windows configurations without additional certificate trust configuration.

---

## Dependencies Reference

Full reference of all external libraries included as submodules under `edrav2/eprj/`:

| Library | Version | License | Purpose |
|---|---|---|---|
| AWS SDK for C++ | 1.7.x | Apache 2.0 | Cloud backend communication, S3/SQS/Firehose |
| Boost C++ Libraries | 1.72+ | BSL-1.0 | ASIO, filesystem, string algorithms, variant |
| c-ares | 1.15+ | MIT | Asynchronous DNS resolution |
| Catch2 | 2.x | BSL-1.0 | C++ unit testing framework |
| Clara | 1.1.x | BSL-1.0 | Command-line argument parsing |
| CLI11 | 1.9+ | BSD-3-Clause | Alternative command-line parser |
| Crashpad | HEAD | Apache 2.0 | Crash reporting and minidump collection |
| libcurl | 7.x | MIT/curl | HTTP and HTTPS client |
| Microsoft Detours | 4.0+ | MIT | Win32 API hooking for `edrpm.dll` |
| googleapis | HEAD | Apache 2.0 | Google Cloud API protocol definitions |
| gRPC | 1.26+ | Apache 2.0 | Remote procedure call framework |
| JsonCpp | 1.9+ | MIT | JSON parsing (legacy interfaces) |
| libjson-rpc-cpp | 1.2+ | MIT | JSON-RPC 2.0 protocol support |
| libmicrohttpd | 0.9.x | LGPL-2.1 | Embedded HTTP server for local API |
| log4cplus | 2.0+ | Apache 2.0 | C++ logging framework |
| nlohmann JSON | 3.x | MIT | Header-only JSON library (modern interfaces) |
| OpenSSL | 1.1.x | OpenSSL/SSLeay | TLS, X.509, cryptographic primitives |
| protobuf | 3.11+ | BSD-3-Clause | Protocol Buffers serialization |
| tiny-AES-c | HEAD | Unlicense | AES-128/192/256 ECB/CBC/CTR |
| URI | HEAD | BSL-1.0 | C++ Network URI parsing |
| UTF8-CPP | 3.x | BSL-1.0 | UTF-8 encoding and decoding |
| xxhash_cpp | HEAD | BSD-2-Clause | Fast non-cryptographic hashing |
| zlib | 1.2.x | zlib | Deflate compression |

---

## Running Tests

OpenArmor includes a reference test suite using the Catch2 framework.

### Running via Visual Studio Test Explorer

1. Open `edrav2.sln` in Visual Studio 2019.
2. Select **Test** > **Configure Run Settings** > **Select Solution Wide runsettings File**.
3. Navigate to:
   ```
   edrav2\build\vs2019\ReferenceTests.runsettings
   ```
4. Select **Test** > **Run All Tests** or open the **Test Explorer** panel (View > Test Explorer).

### Running via Command Line

```cmd
# Build the test project first (it is included in edrav2.sln)
# Then run the test binary directly:
cd edrav2\build\vs2019\x64\Release
ReferenceTests.exe

# Run with verbose output
ReferenceTests.exe -v high

# Run a specific test by name or tag
ReferenceTests.exe "[process]"
ReferenceTests.exe "TestProcessCreation"
```

### Test Run Settings

The `.runsettings` file at `edrav2\build\vs2019\ReferenceTests.runsettings` configures:

- Test output directory
- Timeout per test (default: 30 seconds)
- Parallel execution settings
- Code coverage collection (if enabled)

> **Note:** Some tests require the kernel driver to be loaded and the service to be running. Run tests as Administrator on a system with the driver installed (test signing mode for development builds).

---

## Common Build Errors and Fixes

### WDK Version Mismatch

**Error:** `The Windows Driver Kit (WDK) was not found` or `error MSB8020: The build tools for Visual Studio 20xx (Platform Toolset = 'WindowsKernelModeDriver10.0') cannot be found.`

**Fix:** Ensure the WDK version matches the Windows 10 SDK installed with Visual Studio. Open Visual Studio Installer, check the SDK version, then download and install the matching WDK from the Microsoft documentation site.

### Missing SDK Components

**Error:** `error C1083: Cannot open include file: 'atlbase.h'` or `'afxwin.h'`

**Fix:** Open Visual Studio Installer, select Modify for VS2019, and install:
- C++ ATL for latest v142 build tools
- C++ MFC for latest v142 build tools

### Submodule Not Initialized

**Error:** `fatal error C1083: Cannot open include file: 'boost/asio.hpp'` or similar missing headers for external libraries.

**Fix:**
```bash
git submodule update --init --recursive
```

Verify with `git submodule status` — no entries should start with `-`.

### Boost Compilation Errors

**Error:** Boost compilation fails with template depth errors or internal compiler errors.

**Fix:**
1. Ensure you are using the MSVC v142 toolset (VS2019), not an older one.
2. Increase available heap for the compiler by adding `/Zm200` to the project's Additional Options if you see `C1060` (compiler out of heap space).
3. Build on a machine with at least 8 GB of RAM.

### Driver Certificate / Signing Errors

**Error:** `SignTool Error: No certificates were found that met all the given criteria.`

**Fix:**
1. Verify the certificate store name is correct: `PrivateCertStore`.
2. List available certificates: `certutil -store PrivateCertStore`.
3. If using an EV hardware token, ensure the token driver is installed and the token is inserted.

**Error:** Driver loads in test mode but fails on a production machine.

**Fix:** The driver must be signed with a trusted EV code signing certificate. Test-mode signatures are not accepted by production Windows installs with standard security settings.

### Out of Memory During Link

**Error:** `LINK : fatal error LNK1102: out of memory` or `LNK1248`

**Fix:**
1. Close other applications during the build.
2. Ensure the build machine has at least 8 GB of RAM (16 GB recommended for parallel builds).
3. Reduce parallel build degree: go to **Tools** > **Options** > **Projects and Solutions** > **Build and Run**, and set the maximum number of parallel project builds to 2.
4. If linking `edrsvc.exe` specifically, check for excessively large static link libraries being included.

### CMake Version Too Old

**Error:** `CMake 3.14 or higher is required.`

**Fix:** Download and install the latest CMake from `https://cmake.org/download/`. Ensure the new version is on your `PATH` before the old one: `cmake --version`.

---

## Next Steps

After a successful build, proceed to installation and configuration:

| Guide | Description |
|---|---|
| [Installation Instructions](InstallationInstructions.md) | Install your freshly built binaries on a Windows endpoint |
| [Docker Installation](DockerInstallation.md) | Stand up the Elasticsearch + Logstash + Kibana backend for receiving telemetry |
