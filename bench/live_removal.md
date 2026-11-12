# Live removal verification

Each row planted a real entry, ran the real removal, checked the entry was gone from the authoritative source (the registry, the Startup folder, `schtasks /query`), ran the real undo, and checked it came back unchanged. Nothing here is monkeypatched.

- Host: Windows 11, Python 3.13.14
- Administrator: no
- Run: 2026-11-11 21:32

| Test | Outcome | Note |
|---|---|---|
| a run key is really removed and really restored | pass |  |
| a startup file is really moved and really restored | pass |  |
| removing a startup shortcut leaves its target alone | pass |  |
| a task is really deleted and really re created | pass |  |
| the journal is append only and parses as jsonl | pass |  |
| a service is disabled not deleted and is re enabled | skipped | creating a service needs Administrator |

## Coverage of the removal paths

| Removal path | Status | Note |
|---|---|---|
| `run-key` | covered | HKCU Run value, planted and restored |
| `startup-folder (plain file)` | covered | quarantined and restored |
| `startup-folder (.lnk)` | covered | destructive bug (A): the target must survive |
| `scheduled-task` | covered | destructive bug (B): XML captured before deletion |
| `service / service-dll` | needs Administrator | disabled not deleted, then re-enabled |
| `hidden-task` | not covered | needs a task written straight into the Tasks folder as SYSTEM |
| `active-setup, netsh-helper, appcert-dll` | not covered — deliberately | system-wide load points; planting one to watch it go is how you lose the machine |
| `lsa-package, print-monitor, gpo-script, office-addin, accessibility-swap, pam-module` | n/a | these refuse by design; the refusal is unit-tested |

The paths marked *deliberately* not covered are system-wide load points: an AppCertDll is loaded into every process that starts one, and an LSA package into `lsass` at boot. Planting one on a working machine to watch it being removed is not a test. Their removal either refuses by design or is a plain registry value whose deletion is the same code path the `run-key` row exercises.
