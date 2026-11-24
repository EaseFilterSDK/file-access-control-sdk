# EaseFilter File Control Filter Driver SDK

[![Platform](https://img.shields.io/badge/Platform-Windows-0078D6?logo=windows&logoColor=white)](https://www.easefilter.com/kb/file-control-file-security-sdk.htm)
[![Architecture](https://img.shields.io/badge/Driver-Windows%20Minifilter-blue)](https://www.easefilter.com/kb/file-control-file-security-sdk.htm)
[![Languages](https://img.shields.io/badge/SDK-C%23%20%7C%20C%2B%2B%20%7C%20Python%20%7C%20Java%20%7C%20Go%20%7C%20Rust-informational)](https://www.easefilter.com/kb/file-control-file-security-sdk.htm)
[![Trial](https://img.shields.io/badge/Trial-30--Day%20Free%20Trial-brightgreen)](https://www.easefilter.com/kb/file-control-file-security-sdk.htm)

The **EaseFilter File Control SDK** is a kernel-level development toolkit for building file security, access control, anti-ransomware, and data protection solutions on Windows. Powered by a high-performance Windows file system minifilter driver, it intercepts and manages file I/O operations in real time—providing granular control far beyond standard Windows APIs or Access Control Lists (ACLs).

With the SDK, developers can control file operations at every stage of the I/O lifecycle. Before an I/O request reaches the underlying file system, you can block or allow file access either natively in the kernel using static filter rules or dynamically at runtime through user-mode callbacks. Additionally, after the file system processes the request, you can intercept and modify the I/O data returned from the file system—enabling advanced capabilities such as transparent encryption, data redaction, and virtualized file views.

> **Documentation & Official Guide:** [EaseFilter File Control Filter Driver SDK](https://www.easefilter.com/kb/file-control-file-security-sdk.htm)

---

## Table of Contents

- [Core Architecture](#core-architecture)
- [Key Capabilities](#key-capabilities)
- [Filter Rule Configuration](#filter-rule-configuration)
  - [Rule Matching Criteria](#rule-matching-criteria)
  - [Access Control Flags](#access-control-flags)
- [Code Examples (C#)](#code-examples-c)
  - [1. Tamper-Proof Audit Log Protection (Static Rule)](#1-tamper-proof-audit-log-protection-static-rule)
  - [2. Real-Time Blocking & Auditing (Pre/Post-IO Callbacks)](#2-real-time-blocking--auditing-prepost-io-callbacks)
  - [3. Dynamic Sandboxing & Path Redirection](#3-dynamic-sandboxing--path-redirection)
  - [4. Transparent AES-256 File Encryption (TFE)](#4-transparent-aes-256-file-encryption-tfe)
- [Supported Languages & Integrations](#supported-languages--integrations)
- [Getting Started](#getting-started)
- [License & Support](#License)

---

## Core Architecture

The SDK bridges your user-mode application and the Windows kernel by integrating directly into the Windows I/O stack—positioned between the **Windows I/O Manager** and underlying file system drivers (such as NTFS and FAT).

![File Control](https://www.easefilter.com/Images/file-control-sdk-color.jpg)

The driver uses a **dual-layered interception mechanism**:

- **Pre-Operation Callbacks (`PRE-IO`):** Intercepts I/O requests (`CreateFile`, `ReadFile`, `WriteFile`, rename, delete) *before* they reach the file system. Allows synchronous evaluation, modification, redirection, or immediate denial (`StatusAccessDenied`).
- **Post-Operation Callbacks (`POST-IO`):** Triggers *after* the file system processes the request but before returning results to the calling application. Ideal for auditing, logging, and on-the-fly encryption/decryption.

---

## Key Capabilities

- **Real-Time Interception & Access Control:** Enforce allow/deny policies on create, open, read, write, rename, and delete operations at the kernel level before requests touch the disk.
- **Pre- and Post-Operation Filtering:** Combine synchronous blocking in `PRE-IO` callbacks with asynchronous monitoring and security dashboard logging in `POST-IO` callbacks.
- **Tamper-Proof File Protection:** Lock down critical binaries, configurations, and logs against unauthorized modification or deletion—even from compromised administrator accounts or ransomware.
- **Virtual File Systems & Sandboxing:** Dynamically redirect write operations from protected directories (e.g., `C:\Program Files`) to isolated sandbox folders using `StatusReparse`.
- **Transparent File Encryption (TFE) Integration:** Enforce automatic, on-the-fly AES-256 encryption and decryption for designated folders or removable drives without user intervention.
- **Low-Level Kernel-Mode Performance:** Built on the native Windows minifilter framework to handle thousands of file I/O operations per second with minimal latency and CPU overhead.

---

## Filter Rule Configuration

### Rule Matching Criteria

Filter rules define what the driver monitors and how policies are enforced. You can combine multiple matching criteria:

- **File/Folder Path Masks:** Target files using wildcards (e.g., `C:\SensitiveData\*`, `*.docx`) and define exclude masks to bypass trusted paths and reduce overhead.
- **Process Verification & Trusted Paths:** Filter by originating process name/path, or enforce Zero Trust by verifying digital certificate signatures and SHA-256 binary hashes.
- **User Security Identifiers (SIDs):** Grant or restrict privileges per local or domain Windows user account and group.
- **Time-Based Rules:** Restrict file access permissions to specific hours of the day or calendar dates.

### Access Control Flags

Static access control is enforced directly inside the kernel via bitwise integer flags with zero user-mode round-trip overhead:

| Access Flag | Description |
| :--- | :--- |
| `ALLOW_MAX_ACCESS_RIGHT` | Grants full privileges (read, write, delete, execute, modify). |
| `LEAST_ACCESS_RIGHT` | Denies all access, effectively locking or hiding the target. |
| `ALLOW_READ_ACCESS` | Allows the file to be opened and read. |
| `ALLOW_WRITE_ACCESS` | Allows data to be written to the file. |
| `ALLOW_FILE_RENAME` | Permits the file or directory to be renamed. |
| `ALLOW_FILE_DELETE` | Permits the file or directory to be deleted. |

---

## Code Examples (C#)

### 1. Tamper-Proof Audit Log Protection (Static Rule)

Allow general processes to read and write audit logs while blocking deletion and renaming globally—granting full rotation privileges only to `LoggingService.exe`:

```csharp
using EaseFilter.FilterControl;

// 1. Target the audit logs directory
FileFilterRule auditLogRule = new FileFilterRule(@"C:\AuditLogs\*");

// 2. Grant max access, but strip delete and rename rights globally at the kernel level
auditLogRule.AccessFlags = FilterAPI.ALLOW_MAX_ACCESS_RIGHT
    & ~FilterAPI.ALLOW_FILE_DELETE
    & ~FilterAPI.ALLOW_FILE_RENAME;

// Optional: Receive notifications whenever the filter driver blocks an I/O request
auditLogRule.BooleanConfig |= FilterAPI.BooleanConfig.ENABLE_SEND_DENIED_EVENT;
auditLogRule.NotifiyFileIOWasBlocked += (sender, e) =>
{
    Console.WriteLine($"Blocked {e.EventName} by {e.ProcessName} ({e.UserName}) on {e.FileName}: {e.Description}");
};

// 3. Grant the trusted logging service full control for log rotation
auditLogRule.AddProcessRight("LoggingService.exe", FilterAPI.ALLOW_MAX_ACCESS_RIGHT);

// 4. Register the rule
filterControl.AddFilter(auditLogRule);
```

### 2. Real-Time Blocking & Auditing (Pre/Post-IO Callbacks)

Synchronously block unauthorized writes in `PRE-IO` when a threat is detected, while asynchronously logging authorized reads in `POST-IO`:

```csharp
using EaseFilter.FilterControl;

FileFilterRule ioRule = new FileFilterRule(@"C:\SensitiveData\*");
ioRule.AccessFlags = FilterAPI.ALLOW_MAX_ACCESS_RIGHT;
ioRule.ControlFileIOEventFilter = ControlFileIOEvents.OnPreFileWrite;
ioRule.MonitorFileIOEventFilter = (uint)FileIOEvents.OnPostFileRead;

// Note: PRE-IO callbacks must execute synchronously
ioRule.OnPreWrite += (sender, e) =>
{
    if (ExfiltrationEngine.IsThreatDetected(e.ProcessName))
    {
        e.ReturnStatus = NtStatus.StatusAccessDenied;
    }
};

ioRule.OnFileRead += (sender, e) =>
{
    SecurityDashboard.LogRead(e.FileName, e.UserName);
};

filterControl.AddFilter(ioRule);
```

### 3. Dynamic Sandboxing & Path Redirection

Transparently redirect write requests from a protected application folder to an isolated sandbox directory:

```csharp
using EaseFilter.FilterControl;

FileFilterRule sandboxRule = new FileFilterRule(@"C:\Program Files\LegacyApp\*");
sandboxRule.ControlFileIOEventFilter = ControlFileIOEvents.OnPreFileCreate;

sandboxRule.OnPreCreate += (sender, e) =>
{
    if (e.DesiredAccess.HasFlag(FileAccess.Write))
    {
        e.FileName = e.FileName.Replace(@"C:\Program Files\", @"C:\Sandbox\");
        e.ReturnStatus = NtStatus.StatusReparse;
    }
};

filterControl.AddFilter(sandboxRule);
```

### 4. Transparent AES-256 File Encryption (TFE)

Automatically encrypt and decrypt files on the fly inside a protected directory:

```csharp
using System.Text;
using EaseFilter.FilterControl;

FileFilterRule tfeRule = new FileFilterRule(@"C:\SecureProjects\*");
tfeRule.EnableEncryption = true;

// Use a securely managed 256-bit AES key in production
tfeRule.EncryptionKey = Encoding.UTF8.GetBytes("YourSecure256BitEncryptionKey123");

filterControl.AddFilter(tfeRule);
```

---

## Supported Languages & Integrations

- **Languages:** C#, C++, Python, Java, Go, and Rust
- **Common Use Cases:** Endpoint Security, Zero Trust File Access, Data Loss Prevention (DLP), Ransomware Protection, Folder Lockers, Secure Sandboxes, and Cloud Storage Tiering
- **Ecosystem Integrations:** AI Decision Engines, SIEM Platforms, and YARA Rule Scanning

---

## Getting Started

1. Download the **30-day free trial SDK** (`.exe` installer or `.zip` archive) from the [EaseFilter File Control SDK page](https://www.easefilter.com/kb/file-control-file-security-sdk.htm).
2. Open one of the pre-built Zero Trust, File Protector, File Monitor, or Sandbox templates in your preferred language (C#, C++, Python, Java, Go, or Rust).
3. Configure your `FileFilterRule` policies and run the application with Administrator privileges to load the minifilter driver.

---


## EaseFilter File System Filter Driver SDK Reference
| Product Name | Description |
| --- | --- |
| [Cloud File System SDK](https://www.easefilter.com/cloud/cloud-file-system-sdk.htm) | EaseFilter Cloud File System SDK Introduction. |
| [CloudTier Storage Tiering SDK](https://www.easefilter.com/cloud/storage-tiering-sdk.htm) | EaseFilter Storage Tiering Filter Driver SDK Introduction. |
| [File Monitor SDK](https://www.easefilter.com/kb/file-monitor-filter-driver-sdk.htm) | EaseFilter File Monitor Filter Driver SDK Introduction. |
| [File Control SDK](https://www.easefilter.com/kb/file-control-file-security-sdk.htm) | EaseFilter File Control Filter Driver SDK Introduction. |
| [File Encryption SDK](https://www.easefilter.com/kb/transparent-file-encryption-filter-driver-sdk.htm) | EaseFilter Transparent File Encryption Filter Driver SDK Introduction. |
| [Registry Filter SDK](https://www.easefilter.com/kb/registry-filter-drive-sdk.htm) | EaseFilter Registry Filter Driver SDK Introduction. |
| [Process Filter SDK](https://www.easefilter.com/kb/process-filter-driver-sdk.htm) | EaseFilter Process Filter Driver SDK Introduction. |
| [EaseFilter SDK Programming](https://www.easefilter.com/kb/programming.htm) | EaseFilter Filter Driver SDK Programming. |

## EaseFilter SDK Sample Projects
| Sample Project | Description |
| --- | --- |
| [CloudTier Storage Tiering Demo](https://www.easefilter.com/cloud/cloudtier-storage-tiering-demo.htm) | A HSM File System Filter Driver Demo. |
| [CloudTier S3 Tiering Demo](https://www.easefilter.com/cloud/cloudtier-s3-intelligent-tiering-demo.htm) | CloudTier S3 Intelligent Tiering Demo. |
| [Cloud File DR S3 Demo](https://www.easefilter.com/cloud/cloud-file-dr-demo.htm) | Cloud File DR S3 Demo. |
| [Amazon S3 File Explorer Demo](https://www.easefilter.com/cloud/s3-browser-demo.htm) | Amazon S3 File Explorer Demo. |
| [Auto File DRM Encryption](https://www.easefilter.com/kb/auto-file-drm-encryption-tool.htm) | Auto file encryption with DRM data embedded. |
| [Transparent File Encrypt](https://www.easefilter.com/kb/AutoFileEncryption.htm) | Transparent on access file encryption. |
| [Secure File Sharing with DRM](https://www.easefilter.com/kb/DRM_Secure_File_Sharing.htm) | Secure encrypted file sharing with digital rights management. |
| [File Monitor Example](https://www.easefilter.com/kb/file-monitor-demo.htm) | Monitor file system I/O in real time, tracking file changes. |
| [File Protector Example](https://www.easefilter.com/kb/file-protector-demo.htm) | Prevent sensitive files from being accessed by unauthorized users or processes. |
| [FolderLocker Example](https://www.easefilter.com/kb/FolderLocker.htm) | Lock file automatically in a FolderLocker. |
| [Process Monitor](https://www.easefilter.com/kb/Process-Monitor.htm) | Monitor the process creation and termination, block unauthorized process running. |
| [Registry Monitor](https://www.easefilter.com/kb/RegMon.htm) | Monitor the Registry activities, block the modification of the Registry keys. |
| [Secure Sandbox Example](https://www.easefilter.com/kb/Secure-Sandbox.htm) |A secure sandbox example, block the processes accessing the files out of the box. |
| [FileSystemWatcher Example](https://www.easefilter.com/kb/FileSystemWatcher.htm) | File system watcher, logging the file I/O events. |
| [ZeroTrust Example](https://www.easefilter.com/kb/zero-trust-file-access-control-demo.htm) | Zero trust file access control with encryption feature. |

## Filter Driver Reference

* [Understand MiniFilter Driver](https://www.easefilter.com/kb/understand-minifilter.htm)
* [Understand File I/O](https://www.easefilter.com/kb/File_IO.htm)
* [Understand I/O Request Packets(IRPs)](https://www.easefilter.com/kb/understand-irps.htm)
* [Filter Driver Developer Guide](https://www.easefilter.com/kb/DeveloperGuide.htm)
* [MiniFilter Filter Driver Framework](https://www.easefilter.com/kb/minifilter-framework.htm)
* [Isolation Filter Driver](https://www.easefilter.com/kb/Isolation_Filter_Driver.htm)

## Support
If you have questions or need help, please contact support@easefilter.com 

## License

This repository contains two distinct licensing categories:

1. **Wrapper/Implementation Code (MIT License):** 
   The source code, scripts, and configuration files provided directly in this repository are licensed under the [MIT License](LICENSE). You are free to modify, distribute, and use this specific integration code.

2. **EaseFilter SDK (Commercial License):**
   This project requires the EaseFilter SDK (including its binaries, filter drivers, and core libraries) to function. The EaseFilter SDK is **proprietary commercial software** and is strictly excluded from the MIT License. 
   
   To use the EaseFilter SDK for commercial purposes or in a production environment, you must obtain a valid commercial license directly from [EaseFilter](https://www.easefilter.com/License.pdf).

[Home](https://www.easefilter.com/) | [Solution](https://www.easefilter.com/solutions.htm) | [Download](https://www.easefilter.com/download.htm) | [Demos](https://www.easefilter.com/online-fileio-test.aspx) | [Blog](https://blog.easefilter.com/) | [Programming](https://www.easefilter.com/kb/programming.htm)
