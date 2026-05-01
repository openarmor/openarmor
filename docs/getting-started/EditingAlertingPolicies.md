# Editing Alerting Policies

## Overview

OpenArmor's policy engine determines which endpoint activities generate alerts. Understanding how the engine works helps you write precise, high-fidelity detection rules with minimal false positives.

### How the Policy Engine Works

Events originate in the kernel driver (`edrdrv.sys`), which intercepts system calls for process creation, file I/O, registry access, network connections, and other activity classes. Each raw kernel event is handed off to the user-mode service (`edrsvc.exe`), which runs it through a declarative QSC pipeline:

```
edrdrv.sys (kernel)
    │
    ▼
filter.qsc          — drops noise (system idle, known-good paths)
    │
    ▼
enrich.qsc          — adds process ancestry, file hashes, user context
    │
    ▼
match_patterns.qsc  — evaluates named pattern rules against enriched fields
    │
    ▼
apply_policy.qsc    — maps matched patterns to alert types via event rules
    │
    ▼
output.qsc          — serialises and forwards alerts to the configured SIEM
```

The policy file (`evm.local.src`) controls the last two stages. It defines:

- **Lists** — reusable collections of strings (process names, file paths, registry keys) referenced by match conditions.
- **Patterns** — named, reusable field-matching rules evaluated during `match_patterns.qsc`.
- **Events** — detection rules that map matched patterns (or raw conditions) to alert types, severities, and MITRE ATT&CK metadata.

When `edrsvc.exe` starts it compiles the policy into an in-memory rule set. Changes to `evm.local.src` are picked up either by restarting the service or by issuing a hot-reload command through `edrcon.exe`.

---

## Policy File Location

| Item | Path |
|---|---|
| Main policy file | `C:\Program Files\OpenArmor\evm.local.src` |
| Control utility | `C:\Program Files\OpenArmor\edrcon.exe` |
| Service binary | `C:\Program Files\OpenArmor\edrsvc.exe` |

The file is plain JSON. Any text editor that can save UTF-8 without a byte-order mark works: VS Code, Notepad++, and standard Notepad are all fine.

### Before You Edit — Always Take a Backup

```powershell
Copy-Item "C:\Program Files\OpenArmor\evm.local.src" `
          "C:\Program Files\OpenArmor\evm.local.src.bak"
```

### Applying Changes

**Restart the service (clean reload):**

```powershell
Restart-Service OpenArmorEDR
```

**Hot-reload without dropping coverage:**

```cmd
edrcon run
```

The hot-reload path recompiles the policy while the service continues monitoring. A failed compilation leaves the previous rule set active and writes an error to the event log.

---

## Validating Policy Changes

Always validate the policy file before restarting or hot-reloading the service. A syntax error in the JSON or an invalid operator will cause the reload to fail.

```cmd
edrcon compile --policy "C:\Program Files\OpenArmor\evm.local.src"
```

A successful validation prints:

```
Policy compiled successfully. 0 errors, 0 warnings.
```

Fix all reported errors before proceeding. Common mistakes include:

- Trailing commas after the last element in a JSON array or object.
- Referencing a list name in a condition that does not exist in the `lists` section.
- A regex pattern with an unescaped backslash (use `\\\\` in JSON for a literal `\`).

---

## Top-Level Policy Structure

```json
{
  "version": "2.5",
  "lists": {
    "emailClients": ["outlook.exe", "thunderbird.exe", "msedge.exe"],
    "browsers": ["chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe"],
    "infectibleExtensions": [".exe", ".dll", ".bat", ".ps1", ".vbs", ".js", ".hta"],
    "regWhiteList": [
      "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
      "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
    ],
    "fileWhiteList": [
      "C:\\Windows\\System32\\*",
      "C:\\Program Files\\OpenArmor\\*"
    ]
  },
  "patterns": {
  },
  "events": {
  }
}
```

The three top-level sections are evaluated in dependency order: `lists` first, then `patterns` (which may reference lists), then `events` (which reference patterns).

---

## Lists

Lists are named arrays of strings. They are referenced by name inside pattern match conditions and adaptive event conditions, making it easy to maintain a single authoritative set of values rather than repeating strings across many rules.

### Built-In List Types

| List Name | Purpose |
|---|---|
| `emailClients` | Processes treated as email clients. Membership affects phishing and attachment-execution detections. |
| `browsers` | Web browsers. Membership affects download-execution and drive-by detections. |
| `infectibleExtensions` | File extensions monitored when written to disk. Add custom script extensions your environment uses. |
| `regWhiteList` | Registry key paths (glob) excluded from registry-write alerting. |
| `fileWhiteList` | File paths (glob) excluded from file-write and file-create alerting. |

### Adding Custom Entries

Append new entries to the relevant list. Order does not matter within a list.

```json
"lists": {
  "browsers": [
    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "iexplore.exe",
    "brave.exe",
    "vivaldi.exe"
  ],
  "fileWhiteList": [
    "C:\\Windows\\System32\\*",
    "C:\\Program Files\\OpenArmor\\*",
    "C:\\Program Files\\YourApp\\*"
  ]
}
```

### Lists vs. Inline Conditions

Use a **list** when the same set of values is referenced in multiple rules or when the set is expected to grow over time (for example, the browsers list). Use an **inline condition value** when a value is specific to a single rule and unlikely to change.

---

## Patterns

A pattern is a named, reusable matching rule evaluated during the `match_patterns.qsc` stage. Defining patterns separately from events keeps individual event rules short and promotes reuse across multiple detection rules.

### Structure

```json
"patterns": {
  "pattern_name": {
    "match": {
      "fieldName": "regex_or_value",
      "anotherField": "another_value"
    }
  }
}
```

All fields listed inside `match` must match simultaneously (logical AND). A pattern matches an event only when every field condition is satisfied.

### Match Operators

| Operator | Syntax | Description |
|---|---|---|
| `match` (default) | `"field": "regex"` | Regex match, case-insensitive by default |
| `equals` | `"field": {"equals": "value"}` | Exact string or number equality |
| `contains` | `"field": {"contains": "substr"}` | Substring present anywhere in the field |
| `startsWith` | `"field": {"startsWith": "prefix"}` | Field begins with the given prefix |
| `endsWith` | `"field": {"endsWith": "suffix"}` | Field ends with the given suffix |
| `in` | `"field": {"in": "listName"}` | Field value is a member of the named list |
| `not` | `"field": {"not": {...}}` | Logical negation of the inner operator |

### Pattern Examples

**Detect PowerShell with an encoded command argument:**

```json
"powershell_encoded": {
  "match": {
    "imageFile": ".*\\\\powershell\\.exe$",
    "cmdLine": ".*(-[Ee][Nn][Cc]|-[Ee]ncoded[Cc]ommand).*"
  }
}
```

**Detect an Office application spawning a command interpreter:**

```json
"office_spawning_shell": {
  "match": {
    "parentImageFile": ".*(winword|excel|powerpnt|outlook)\\.exe$",
    "imageFile": ".*(cmd|powershell|wscript|cscript|mshta)\\.exe$"
  }
}
```

**Detect a process opening a handle to LSASS with read access:**

```json
"lsass_access": {
  "match": {
    "targetProcessName": "lsass\\.exe",
    "accessMask": "0x[01][0].*"
  }
}
```

**Detect execution from a user's Temp directory:**

```json
"exec_from_temp": {
  "match": {
    "imageFile": ".*\\\\(Temp|tmp)\\\\.*\\.(exe|dll|bat|ps1|vbs|js|hta)$"
  }
}
```

**Detect a file with an infectible extension being written by a browser:**

```json
"browser_file_drop": {
  "match": {
    "processName": {"in": "browsers"},
    "extension": {"in": "infectibleExtensions"}
  }
}
```

---

## Events (Detection Rules)

Event rules map matched patterns (or raw conditions) to alert types. Each rule specifies which kernel event type it applies to, which patterns must match, the alert severity, and optional MITRE ATT&CK metadata.

### Structure

```json
"events": {
  "rule_name": {
    "baseType": 1,
    "conditions": ["pattern_name_1", "pattern_name_2"],
    "conditionOperator": "and",
    "severity": "high",
    "mitre": {
      "tactic": "Execution",
      "technique": "T1059.001"
    },
    "description": "Human-readable description of what this rule detects."
  }
}
```

| Field | Required | Description |
|---|---|---|
| `baseType` | Yes | LLE event code that triggers evaluation of this rule (see LLE Event Type Reference). |
| `conditions` | Yes | Array of pattern names. All must match (when `conditionOperator` is `and`) or at least one (when `or`). |
| `conditionOperator` | No | `"and"` (default) or `"or"`. |
| `severity` | Yes | `"high"`, `"medium"`, `"low"`, or `"info"`. |
| `mitre` | No | MITRE ATT&CK tactic and technique for enriching alert context. |
| `description` | No | Free-text description shown in the alert. |

---

## Adaptive Event (Advanced)

The adaptive event system allows fine-grained control over whether an event is logged and what type is assigned to it, based on runtime field values that may not be available at pattern-match time (for example, verdicts computed by enrichment steps).

### Structure

```json
{
  "BaseEventType": 3,
  "EventType": null,
  "Condition": {
    "Field": "parentVerdict",
    "Operator": "!Equal",
    "Value": 1
  }
}
```

| Field | Description |
|---|---|
| `BaseEventType` | LLE event code for the kernel event class this rule applies to. |
| `EventType` | GUID string that overrides the event type sent to the SIEM, or `null` to use the default for `BaseEventType`. |
| `Condition` | A condition object (see Condition Operators Reference). If omitted, the condition is treated as always matching. |

Multiple adaptive events for the same `BaseEventType` are supplied as an ordered array. Evaluation is sequential — the first matching adaptive event wins and the rest are skipped.

---

## Condition Operators Reference

### Field Conditions

| Operator | Value Type | Description |
|---|---|---|
| `Equal` | Number, String, Boolean, null | True when the field exactly equals the value. |
| `!Equal` | Number, String, Boolean, null | True when the field does not equal the value. |
| `Match` | String (glob: `*` and `?`) | True when the field matches the glob pattern. Environment variables in the pattern are expanded before comparison. |
| `!Match` | String | True when the field does not match the glob pattern. |
| `MatchInList` | String (list name) | True when the field matches any entry in the named list. Entries are treated as glob patterns; environment variables are expanded. |
| `!MatchInList` | String | True when the field matches none of the entries in the named list. |

### Boolean Operators

Conditions can be nested to arbitrary depth using `And` and `Or`.

```json
{
  "BooleanOperator": "And",
  "Conditions": [
    {
      "Field": "parentProcessPath",
      "Operator": "!Match",
      "Value": "*\\explorer.exe"
    },
    {
      "BooleanOperator": "Or",
      "Conditions": [
        { "Field": "path", "Operator": "Match", "Value": "*\\powershell.exe" },
        { "Field": "path", "Operator": "Match", "Value": "*\\cmd.exe" },
        { "Field": "path", "Operator": "Match", "Value": "*\\wscript.exe" }
      ]
    }
  ]
}
```

This example matches any process creation where the parent is not `explorer.exe` **and** the new process is one of `powershell.exe`, `cmd.exe`, or `wscript.exe`.

---

## Adaptive Event Ordering

When a kernel event arrives, `edrsvc.exe` iterates the adaptive event array for the matching `BaseEventType` in order. The first adaptive event whose condition evaluates to `true` is applied: its `BaseEventType` and `EventType` are written into the event record and the event is forwarded to the output stage. Remaining adaptive events in the array are not evaluated.

If no condition matches, no alert is generated. This is intentional — it allows you to define a catch-all "do not log" case by placing a final adaptive event with no `Condition` field (which always matches) and an `EventType` of `null`.

**Rule of thumb:** Place the most specific (narrowest) conditions first and the broadest conditions last.

---

## LLE Event Type Reference

Use these codes as the `BaseEventType` (or `baseType`) value when writing rules.

| Code | Name | Description |
|---|---|---|
| 1 | `LLE_PROCESS_CREATE` | A new process was created. |
| 2 | `LLE_PROCESS_TERMINATE` | A process exited. |
| 3 | `LLE_PROCESS_OPEN` | A handle was opened to an existing process. |
| 10 | `LLE_FILE_CREATE` | A file was created. |
| 11 | `LLE_FILE_WRITE` | A file was written. |
| 12 | `LLE_FILE_RENAME` | A file was renamed. |
| 13 | `LLE_FILE_DELETE` | A file was deleted. |
| 20 | `LLE_REGISTRY_KEY_CREATE` | A registry key was created. |
| 21 | `LLE_REGISTRY_VALUE_WRITE` | A registry value was written. |
| 22 | `LLE_REGISTRY_KEY_DELETE` | A registry key was deleted. |
| 30 | `LLE_NETWORK_CONNECT_OUT` | An outbound network connection was initiated. |
| 31 | `LLE_NETWORK_CONNECT_IN` | An inbound network connection was accepted. |
| 32 | `LLE_NETWORK_LISTEN` | A process opened a listening port. |
| 33 | `LLE_NETWORK_DNS_REQUEST` | A DNS query was issued. |
| 40 | `LLE_INPUT_KEYBOARD_STATE` | A process read keyboard state (potential keylogger). |
| 41 | `LLE_CLIPBOARD_GET` | Clipboard contents were read. |
| 42 | `LLE_SCREEN_CAPTURE` | A screenshot was taken. |

---

## 10 Ready-to-Use Detection Rules

The following rules are production-ready starting points. Add them to your `patterns` and `events` sections, validate with `edrcon compile`, and tune as needed for your environment.

### 1. PowerShell Encoded Command

Detects PowerShell invoked with `-EncodedCommand` or `-Enc`, a common technique to bypass command-line logging.

```json
"patterns": {
  "powershell_encoded_cmd": {
    "match": {
      "imageFile": ".*\\\\powershell\\.exe$",
      "cmdLine": ".*(-[Ee][Nn][Cc]|-[Ee]ncoded[Cc]ommand).*"
    }
  }
},
"events": {
  "detect_powershell_encoded": {
    "baseType": 1,
    "conditions": ["powershell_encoded_cmd"],
    "severity": "high",
    "mitre": { "tactic": "Execution", "technique": "T1059.001" },
    "description": "PowerShell launched with an encoded command argument."
  }
}
```

### 2. Office Macro Spawning a Shell

Detects Microsoft Office applications (Word, Excel, PowerPoint, Outlook) launching a command interpreter, which is a common initial-access technique via malicious macros.

```json
"patterns": {
  "office_macro_shell": {
    "match": {
      "parentImageFile": ".*(winword|excel|powerpnt|outlook)\\.exe$",
      "imageFile": ".*(cmd|powershell|wscript|cscript|mshta)\\.exe$"
    }
  }
},
"events": {
  "detect_office_macro_shell": {
    "baseType": 1,
    "conditions": ["office_macro_shell"],
    "severity": "high",
    "mitre": { "tactic": "Execution", "technique": "T1566.001" },
    "description": "Office application spawned a command interpreter — possible macro execution."
  }
}
```

### 3. LSASS Memory Access (Credential Dumping)

Detects process-open calls targeting `lsass.exe` with memory-read access masks, indicative of credential-dumping tools such as Mimikatz.

```json
"patterns": {
  "lsass_memory_read": {
    "match": {
      "targetProcessName": "lsass\\.exe",
      "accessMask": "0x[0-9a-fA-F]*(10|20|40|1000|1010|1038)[0-9a-fA-F]*"
    }
  }
},
"events": {
  "detect_lsass_dump": {
    "baseType": 3,
    "conditions": ["lsass_memory_read"],
    "severity": "high",
    "mitre": { "tactic": "Credential Access", "technique": "T1003.001" },
    "description": "Process opened LSASS with memory-read access — possible credential dump."
  }
}
```

### 4. Registry Run Key Modification

Detects writes to the standard autorun registry keys used by malware to establish persistence.

```json
"patterns": {
  "run_key_write": {
    "match": {
      "keyPath": ".*(HKLM|HKCU)\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run(Once)?.*"
    }
  }
},
"events": {
  "detect_run_key_persistence": {
    "baseType": 21,
    "conditions": ["run_key_write"],
    "severity": "medium",
    "mitre": { "tactic": "Persistence", "technique": "T1547.001" },
    "description": "Registry Run key written — possible persistence mechanism."
  }
}
```

### 5. Mass File Rename (Ransomware Indicator)

Detects rapid file-rename activity, which is a strong indicator of ransomware encrypting files and appending a new extension.

```json
"patterns": {
  "mass_rename_suspicious_ext": {
    "match": {
      "newExtension": "\\.(locked|encrypted|enc|crypt|crypted|[a-z0-9]{4,8})$"
    }
  }
},
"events": {
  "detect_mass_rename": {
    "baseType": 12,
    "conditions": ["mass_rename_suspicious_ext"],
    "severity": "high",
    "mitre": { "tactic": "Impact", "technique": "T1486" },
    "description": "File renamed to suspicious extension — possible ransomware activity."
  }
}
```

### 6. Suspicious Network Connection from PowerShell

Detects PowerShell establishing outbound TCP connections, which may indicate download cradles, C2 beaconing, or data exfiltration.

```json
"patterns": {
  "powershell_network_out": {
    "match": {
      "processName": "powershell\\.exe",
      "direction": "out"
    }
  }
},
"events": {
  "detect_powershell_network": {
    "baseType": 30,
    "conditions": ["powershell_network_out"],
    "severity": "medium",
    "mitre": { "tactic": "Command and Control", "technique": "T1059.001" },
    "description": "PowerShell initiated an outbound network connection."
  }
}
```

### 7. WMI Spawning a Child Process

Detects the WMI host (`WmiPrvSE.exe`) creating child processes, a common technique for lateral movement and persistence without touching disk in a traditional way.

```json
"patterns": {
  "wmi_child_process": {
    "match": {
      "parentImageFile": ".*\\\\WmiPrvSE\\.exe$"
    }
  }
},
"events": {
  "detect_wmi_spawn": {
    "baseType": 1,
    "conditions": ["wmi_child_process"],
    "severity": "medium",
    "mitre": { "tactic": "Execution", "technique": "T1047" },
    "description": "WMI host spawned a child process — review for lateral movement or persistence."
  }
}
```

### 8. Net.exe Lateral Movement

Detects `net.exe` or `net1.exe` being used with user-enumeration or share-enumeration arguments, which are common reconnaissance and lateral movement precursors.

```json
"patterns": {
  "net_lateral_recon": {
    "match": {
      "imageFile": ".*\\\\net1?\\.exe$",
      "cmdLine": ".*(user|localgroup|group|use|view|share|accounts).*"
    }
  }
},
"events": {
  "detect_net_recon": {
    "baseType": 1,
    "conditions": ["net_lateral_recon"],
    "severity": "medium",
    "mitre": { "tactic": "Discovery", "technique": "T1087.001" },
    "description": "net.exe used for user or share enumeration — possible lateral movement recon."
  }
}
```

### 9. Credential Tool by Name or Known Path

Detects execution of Mimikatz and other common credential-access tools by process name.

```json
"patterns": {
  "credential_tool_name": {
    "match": {
      "imageFile": ".*(mimikatz|pwdump|fgdump|gsecdump|lsadump|wce\\.exe|procdump).*"
    }
  }
},
"events": {
  "detect_credential_tool": {
    "baseType": 1,
    "conditions": ["credential_tool_name"],
    "severity": "high",
    "mitre": { "tactic": "Credential Access", "technique": "T1003" },
    "description": "Known credential-access tool name detected in process image path."
  }
}
```

### 10. Unsigned Executable from a Temp Directory

Detects process creation where the image file resides in a Temp or temporary-upload directory, which is a common staging area for malware droppers.

```json
"patterns": {
  "exec_from_temp_dir": {
    "match": {
      "imageFile": ".*\\\\(Temp|tmp|AppData\\\\Local\\\\Temp|Downloads)\\\\.*\\.(exe|dll|bat|ps1|vbs|js|hta)$",
      "signed": {"equals": "false"}
    }
  }
},
"events": {
  "detect_temp_exec": {
    "baseType": 1,
    "conditions": ["exec_from_temp_dir"],
    "severity": "high",
    "mitre": { "tactic": "Execution", "technique": "T1204.002" },
    "description": "Unsigned executable launched from a temporary directory."
  }
}
```

---

## Whitelisting False Positives

Legitimate software sometimes triggers detection rules. The recommended approach is to use the most specific suppression mechanism available rather than broadly disabling a rule.

### Suppress by File Path

Add a glob pattern to `fileWhiteList` to exclude a specific application or directory from file-event alerting:

```json
"fileWhiteList": [
  "C:\\Windows\\System32\\*",
  "C:\\Program Files\\OpenArmor\\*",
  "C:\\Program Files\\YourSoftware\\*"
]
```

### Suppress by Registry Path

Add a pattern to `regWhiteList` to exclude a known-good registry location:

```json
"regWhiteList": [
  "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
  "HKCU\\SOFTWARE\\Microsoft\\Windows Defender\\*"
]
```

### Suppress by Process Classification

If a legitimate application is detected because it resembles a browser or email client, add it to the appropriate list:

```json
"browsers": ["chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "slack.exe"]
```

### Suppress via Rule Condition

For narrow suppressions that only apply to a specific rule, use a `!Match` or `!MatchInList` condition in the adaptive event rather than modifying a shared list:

```json
{
  "BaseEventType": 1,
  "EventType": null,
  "Condition": {
    "BooleanOperator": "And",
    "Conditions": [
      {
        "Field": "imageFile",
        "Operator": "Match",
        "Value": "*\\powershell.exe"
      },
      {
        "Field": "parentProcessPath",
        "Operator": "!Match",
        "Value": "*\\YourTrustedOrchestrator.exe"
      }
    ]
  }
}
```

---

## Testing Your Rules

### Validate Syntax

Run the compiler before every reload:

```cmd
edrcon compile --policy "C:\Program Files\OpenArmor\evm.local.src"
```

### Debug Mode — Full Policy Trace

Debug mode logs every policy evaluation decision to the console, including which conditions matched or failed:

```cmd
edrcon debug --policy-trace
```

### Filter to a Specific Event Class

Narrow the debug output to one event type to reduce noise while testing a specific rule:

```cmd
edrcon debug --policy-trace --filter LLE_PROCESS_CREATE
```

### Reload After Successful Validation

```cmd
edrcon run
```

Or restart the service for a clean state:

```powershell
Restart-Service OpenArmorEDR
```

### What to Check After Enabling a New Rule

1. Trigger the targeted behaviour in a test environment (for example, run `powershell -EncodedCommand <base64>` to test rule 1).
2. Confirm an alert appears in your SIEM or log output.
3. Verify no unexpected false positives appear in the debug trace for normal workloads.
4. If false positives appear, add suppression conditions before promoting to production.

---

## Community Rules

The OpenArmor project maintains a growing library of community-contributed detection rules:

**https://github.com/openarmor/openarmor/tree/main/edrav2/iprj/edrdata**

This repository contains ready-to-use pattern and event definitions organised by MITRE ATT&CK tactic. You can copy individual rules directly into your `evm.local.src` file or use them as reference when writing your own.

Contributions are welcome. If you develop a useful detection rule, please open a pull request against that repository so the broader community can benefit.

---

## Next Steps

- [Installation Instructions](InstallationInstructions.md) — initial setup, service configuration, and agent deployment.
- [Setting Up FileBeat](SettingFileBeat.md) — configure FileBeat to ship OpenArmor alerts to Elasticsearch.
