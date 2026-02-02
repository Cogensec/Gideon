import { Agent } from '../agent/agent.js';
import { CommandContext, CommandResult } from './types.js';
import {
  isPersonaPlexAvailable,
  PersonaPlexSession,
  getPersonaPlexConfig,
  PERSONAPLEX_VOICES,
  VoiceId,
} from '../utils/personaplex.js';

export interface VoiceCommandOptions {
  voiceId?: VoiceId;
  listVoices?: boolean;
}

/**
 * Parse voice command arguments
 */
function parseArgs(args: string[]): VoiceCommandOptions {
  const options: VoiceCommandOptions = {};

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--voice' && args[i + 1]) {
      options.voiceId = args[i + 1] as VoiceId;
      i++;
    } else if (arg === '--list-voices') {
      options.listVoices = true;
    }
  }

  return options;
}

/**
 * Voice command - Start interactive voice conversation with Gideon
 *
 * Usage:
 *   gideon voice                    Start voice mode with default voice
 *   gideon voice --voice NATF1      Use specific voice
 *   gideon voice --list-voices      List available voices
 */
export async function voiceCommand(
  args: string[],
  context: CommandContext
): Promise<CommandResult> {
  const options = parseArgs(args);

  // List available voices
  if (options.listVoices) {
    let output = 'Available PersonaPlex voices:\n\n';
    output += 'Natural voices:\n';
    for (const [id, name] of Object.entries(PERSONAPLEX_VOICES)) {
      if (id.startsWith('NAT')) {
        output += `  ${id}: ${name}\n`;
      }
    }
    output += '\nVaried voices:\n';
    for (const [id, name] of Object.entries(PERSONAPLEX_VOICES)) {
      if (id.startsWith('VAR')) {
        output += `  ${id}: ${name}\n`;
      }
    }
    return { success: true, output };
  }

  // Check if PersonaPlex is available
  const available = await isPersonaPlexAvailable();
  if (!available) {
    const config = getPersonaPlexConfig();
    return {
      success: false,
      output: '',
      error: `PersonaPlex server not available at ${config.serverUrl}

To start PersonaPlex server:
  1. Install: pip install moshi
  2. Run: python -m moshi.server --cpu-offload

Or set PERSONAPLEX_URL in .env to point to your PersonaPlex server.`,
    };
  }

  // Create PersonaPlex session
  const session = new PersonaPlexSession({
    voiceId: options.voiceId,
  });

  try {
    await session.connect();

    const agent = Agent.create(context);
    const config = getPersonaPlexConfig();

    let output = `Voice mode activated using ${config.voiceId} voice.\n`;
    output += 'PersonaPlex full-duplex conversation enabled.\n';
    output += 'Speak naturally - Gideon is listening.\n\n';
    output += 'Note: This is a CLI demonstration. For full voice interaction,\n';
    output += 'use the PersonaPlex WebUI at the server URL.\n';

    // Set up transcript handler to pipe to agent
    session.onTranscript(async (transcript) => {
      if (transcript.confidence > 0.7) {
        // Run agent with transcribed text
        for await (const event of agent.run(transcript.text)) {
          if (event.type === 'answer_chunk') {
            // In a full implementation, this would be sent back through PersonaPlex TTS
            process.stdout.write(event.text);
          }
        }
      }
    });

    return {
      success: true,
      output,
      artifacts: {
        json: {
          mode: 'voice',
          voiceId: config.voiceId,
          serverUrl: config.serverUrl,
          cpuOffload: config.cpuOffload,
        },
      },
    };
  } catch (error) {
    session.disconnect();
    return {
      success: false,
      output: '',
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

/**
 * Speak text using PersonaPlex TTS
 * Utility function for other commands to vocalize their output
 */
export async function speakText(text: string, voiceId?: VoiceId): Promise<void> {
  const available = await isPersonaPlexAvailable();
  if (!available) {
    console.error('PersonaPlex not available - cannot speak');
    return;
  }

  const session = new PersonaPlexSession({ voiceId });

  try {
    await session.connect();

    // Send text for TTS
    // In full implementation, this would stream audio to speakers
    console.log(`[Speaking]: ${text.substring(0, 100)}...`);

    session.disconnect();
  } catch (error) {
    console.error('Speech failed:', error);
    session.disconnect();
  }
}
