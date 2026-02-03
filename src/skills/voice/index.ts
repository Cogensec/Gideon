/**
 * Voice Skill
 *
 * Speech-to-speech AI capabilities using NVIDIA PersonaPlex.
 * Provides voice input/output for hands-free security operations.
 */

import {
  Skill,
  SkillCommand,
  SkillCommandContext,
  SkillCommandResult,
  SkillStatus,
} from '../types.js';

import {
  getPersonaPlexConfig,
  speakText,
  VOICE_OPTIONS,
  PersonaPlexConfig,
} from '../../utils/personaplex.js';

// Current voice settings
let currentVoice = 'NATM0';
let voiceEnabled = true;

// ============================================================================
// Command Implementations
// ============================================================================

async function handleSpeak(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const text = args.join(' ');

  if (!text) {
    return {
      success: false,
      output: '',
      error: 'Usage: speak <text>\nConvert text to speech.',
    };
  }

  if (!voiceEnabled) {
    return {
      success: false,
      output: '',
      error: 'Voice output is disabled. Use `voice-enable` to turn it on.',
    };
  }

  try {
    await speakText(text, { voice: currentVoice });
    return {
      success: true,
      output: `Speaking: "${text}"`,
    };
  } catch (error) {
    return {
      success: false,
      output: '',
      error: `Speech failed: ${error}`,
    };
  }
}

async function handleVoiceSet(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const voice = args[0]?.toUpperCase();

  if (!voice) {
    return {
      success: false,
      output: '',
      error: `Usage: voice-set <voice-id>\n\nAvailable voices:\n${formatVoiceList()}`,
    };
  }

  if (!VOICE_OPTIONS.includes(voice)) {
    return {
      success: false,
      output: '',
      error: `Unknown voice: ${voice}\n\nAvailable voices:\n${formatVoiceList()}`,
    };
  }

  currentVoice = voice;

  return {
    success: true,
    output: `Voice set to: ${voice}`,
  };
}

async function handleVoiceList(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  return {
    success: true,
    output: `# Available Voices

${formatVoiceList()}

**Current voice:** ${currentVoice}

Use \`voice-set <voice-id>\` to change.`,
  };
}

async function handleVoiceEnable(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  voiceEnabled = true;
  return {
    success: true,
    output: 'Voice output enabled.',
  };
}

async function handleVoiceDisable(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  voiceEnabled = false;
  return {
    success: true,
    output: 'Voice output disabled.',
  };
}

async function handleVoiceStatus(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  const config = getPersonaPlexConfig();

  return {
    success: true,
    output: `# Voice Status

**Enabled:** ${voiceEnabled ? 'Yes' : 'No'}
**Current Voice:** ${currentVoice}
**Service URL:** ${config.url}
**CPU Offload:** ${config.cpuOffload ? 'Yes' : 'No'}

## Service Configuration
- Model: PersonaPlex-7B
- Latency: ~170ms (GPU), ~500ms (CPU)
- Full-duplex: Supported`,
  };
}

async function handleVoiceHelp(args: string[], ctx: SkillCommandContext): Promise<SkillCommandResult> {
  return {
    success: true,
    output: `# Voice Skill

Speech-to-speech AI powered by NVIDIA PersonaPlex-7B.

## Commands

| Command | Description |
|---------|-------------|
| \`speak <text>\` | Convert text to speech |
| \`voice-set <id>\` | Change voice |
| \`voice-list\` | Show available voices |
| \`voice-enable\` | Enable voice output |
| \`voice-disable\` | Disable voice output |
| \`voice-status\` | Show voice configuration |

## Voice Categories

### Natural Voices (NAT)
- NATM0-3: Male voices
- NATF0-3: Female voices

### Variable Voices (VAR)
- VARM0-4: Male voices with more variation
- VARF0-4: Female voices with more variation

## Performance
- 170ms latency with GPU
- 500ms latency with CPU offload
- Full-duplex conversation support

## Requirements
- NVIDIA PersonaPlex service (PERSONAPLEX_URL)
- GPU recommended, CPU fallback available`,
  };
}

function formatVoiceList(): string {
  const voices = [
    { id: 'NATM0', desc: 'Natural Male 1' },
    { id: 'NATM1', desc: 'Natural Male 2' },
    { id: 'NATM2', desc: 'Natural Male 3' },
    { id: 'NATM3', desc: 'Natural Male 4' },
    { id: 'NATF0', desc: 'Natural Female 1' },
    { id: 'NATF1', desc: 'Natural Female 2' },
    { id: 'NATF2', desc: 'Natural Female 3' },
    { id: 'NATF3', desc: 'Natural Female 4' },
    { id: 'VARM0', desc: 'Variable Male 1' },
    { id: 'VARM1', desc: 'Variable Male 2' },
    { id: 'VARM2', desc: 'Variable Male 3' },
    { id: 'VARM3', desc: 'Variable Male 4' },
    { id: 'VARM4', desc: 'Variable Male 5' },
    { id: 'VARF0', desc: 'Variable Female 1' },
    { id: 'VARF1', desc: 'Variable Female 2' },
    { id: 'VARF2', desc: 'Variable Female 3' },
    { id: 'VARF3', desc: 'Variable Female 4' },
    { id: 'VARF4', desc: 'Variable Female 5' },
  ];

  return voices.map(v => `- **${v.id}**: ${v.desc}`).join('\n');
}

// ============================================================================
// Skill Definition
// ============================================================================

const commands: SkillCommand[] = [
  {
    name: 'speak',
    description: 'Convert text to speech',
    usage: 'speak <text>',
    execute: handleSpeak,
  },
  {
    name: 'voice-set',
    description: 'Set voice for speech output',
    usage: 'voice-set <voice-id>',
    execute: handleVoiceSet,
  },
  {
    name: 'voice-list',
    description: 'List available voices',
    usage: 'voice-list',
    execute: handleVoiceList,
  },
  {
    name: 'voice-enable',
    description: 'Enable voice output',
    usage: 'voice-enable',
    execute: handleVoiceEnable,
  },
  {
    name: 'voice-disable',
    description: 'Disable voice output',
    usage: 'voice-disable',
    execute: handleVoiceDisable,
  },
  {
    name: 'voice-status',
    description: 'Show voice configuration',
    usage: 'voice-status',
    execute: handleVoiceStatus,
  },
  {
    name: 'voice-help',
    description: 'Show voice skill help',
    usage: 'voice-help',
    execute: handleVoiceHelp,
  },
];

export const voiceSkill: Skill = {
  metadata: {
    id: 'voice',
    name: 'Voice',
    description: 'Speech-to-speech AI using NVIDIA PersonaPlex',
    version: '1.0.0',
    author: 'Gideon',
    category: 'voice',
    capabilities: {
      providesTools: false,
      requiresGpu: true,
      supportsCpuFallback: true,
      stateful: true,
      requiresExternalService: true,
    },
    optionalEnvVars: ['PERSONAPLEX_URL'],
  },

  commands,

  async isAvailable(): Promise<boolean> {
    const config = getPersonaPlexConfig();
    if (!config.enabled) return false;

    try {
      const response = await fetch(`${config.url}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      });
      return response.ok;
    } catch {
      return true; // Still available with limited functionality
    }
  },

  async getStatus(): Promise<SkillStatus> {
    const config = getPersonaPlexConfig();

    if (!config.enabled) {
      return {
        healthy: false,
        message: 'PersonaPlex integration disabled',
        checkedAt: new Date(),
      };
    }

    try {
      const response = await fetch(`${config.url}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(5000),
      });

      return {
        healthy: response.ok,
        message: response.ok ? 'PersonaPlex service available' : 'PersonaPlex service unhealthy',
        checkedAt: new Date(),
        details: {
          url: config.url,
          currentVoice,
          voiceEnabled,
        },
      };
    } catch (error) {
      return {
        healthy: false,
        message: `PersonaPlex service unavailable: ${error}`,
        checkedAt: new Date(),
        details: {
          url: config.url,
          currentVoice,
          voiceEnabled,
        },
      };
    }
  },

  async shutdown(): Promise<void> {
    voiceEnabled = false;
  },
};
