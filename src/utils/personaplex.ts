/**
 * NVIDIA PersonaPlex Client
 *
 * Client for connecting to PersonaPlex server for speech-to-speech
 * conversational AI with customizable voice and persona.
 *
 * PersonaPlex is a full-duplex model that can listen and speak simultaneously,
 * supporting natural turn-taking, interruptions, and backchanneling.
 */

export interface PersonaPlexConfig {
  serverUrl: string;
  voiceId: string;
  textPrompt: string;
  cpuOffload: boolean;
}

export interface SpeakOptions {
  text: string;
  voiceId?: string;
}

export interface TranscriptResult {
  text: string;
  confidence: number;
}

// Available voice options in PersonaPlex
export const PERSONAPLEX_VOICES = {
  // Natural voices
  NATF0: 'Natural Female 0',
  NATF1: 'Natural Female 1',
  NATF2: 'Natural Female 2',
  NATF3: 'Natural Female 3',
  NATM0: 'Natural Male 0',
  NATM1: 'Natural Male 1',
  NATM2: 'Natural Male 2',
  NATM3: 'Natural Male 3',
  // Varied voices
  VARF0: 'Varied Female 0',
  VARF1: 'Varied Female 1',
  VARF2: 'Varied Female 2',
  VARF3: 'Varied Female 3',
  VARF4: 'Varied Female 4',
  VARM0: 'Varied Male 0',
  VARM1: 'Varied Male 1',
  VARM2: 'Varied Male 2',
  VARM3: 'Varied Male 3',
  VARM4: 'Varied Male 4',
} as const;

export type VoiceId = keyof typeof PERSONAPLEX_VOICES;

// Default Gideon security analyst persona
export const GIDEON_PERSONA = `You are Gideon, a professional cybersecurity analyst assistant.
You provide clear, concise security briefings and threat intelligence analysis.
Speak with authority but remain approachable and helpful.
When discussing vulnerabilities, be precise about severity levels and remediation steps.
You focus exclusively on defensive security - never provide offensive guidance,
exploitation techniques, or help with attacking systems.
Keep responses focused and actionable for security defenders.`;

/**
 * Gets PersonaPlex configuration from environment
 */
export function getPersonaPlexConfig(): PersonaPlexConfig {
  return {
    serverUrl: process.env.PERSONAPLEX_URL || 'http://localhost:8998',
    voiceId: process.env.PERSONAPLEX_VOICE || 'NATM1',
    textPrompt: process.env.PERSONAPLEX_PERSONA || GIDEON_PERSONA,
    cpuOffload: process.env.PERSONAPLEX_CPU_OFFLOAD !== 'false',
  };
}

/**
 * Checks if PersonaPlex server is available
 */
export async function isPersonaPlexAvailable(): Promise<boolean> {
  const config = getPersonaPlexConfig();

  try {
    // PersonaPlex server exposes a health endpoint
    const response = await fetch(`${config.serverUrl}/health`, {
      method: 'GET',
      signal: AbortSignal.timeout(5000),
    });
    return response.ok;
  } catch {
    return false;
  }
}

/**
 * Text-to-speech using PersonaPlex
 * Sends text to PersonaPlex server and returns audio data
 */
export async function textToSpeech(options: SpeakOptions): Promise<ArrayBuffer> {
  const config = getPersonaPlexConfig();
  const voiceId = options.voiceId || config.voiceId;

  const response = await fetch(`${config.serverUrl}/api/tts`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      text: options.text,
      voice_id: voiceId,
      persona: config.textPrompt,
    }),
  });

  if (!response.ok) {
    throw new Error(`PersonaPlex TTS failed: ${response.statusText}`);
  }

  return response.arrayBuffer();
}

/**
 * Speech-to-text using PersonaPlex
 * Sends audio data to PersonaPlex server and returns transcript
 */
export async function speechToText(audioData: ArrayBuffer): Promise<TranscriptResult> {
  const config = getPersonaPlexConfig();

  const response = await fetch(`${config.serverUrl}/api/stt`, {
    method: 'POST',
    headers: {
      'Content-Type': 'audio/wav',
    },
    body: audioData,
  });

  if (!response.ok) {
    throw new Error(`PersonaPlex STT failed: ${response.statusText}`);
  }

  return response.json() as Promise<TranscriptResult>;
}

/**
 * WebSocket connection for full-duplex voice conversation
 */
export class PersonaPlexSession {
  private ws: WebSocket | null = null;
  private config: PersonaPlexConfig;

  constructor(config?: Partial<PersonaPlexConfig>) {
    this.config = { ...getPersonaPlexConfig(), ...config };
  }

  /**
   * Connect to PersonaPlex server via WebSocket
   */
  async connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const wsUrl = this.config.serverUrl.replace(/^http/, 'ws') + '/ws';
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        // Send initial configuration
        this.ws?.send(JSON.stringify({
          type: 'config',
          voice_id: this.config.voiceId,
          persona: this.config.textPrompt,
        }));
        resolve();
      };

      this.ws.onerror = (error) => {
        reject(new Error(`WebSocket connection failed: ${error}`));
      };
    });
  }

  /**
   * Send audio chunk to PersonaPlex
   */
  sendAudio(audioData: ArrayBuffer): void {
    if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket not connected');
    }
    this.ws.send(audioData);
  }

  /**
   * Set callback for receiving audio responses
   */
  onAudioResponse(callback: (audioData: ArrayBuffer) => void): void {
    if (!this.ws) {
      throw new Error('WebSocket not connected');
    }
    this.ws.onmessage = (event) => {
      if (event.data instanceof ArrayBuffer) {
        callback(event.data);
      }
    };
  }

  /**
   * Set callback for receiving text transcripts
   */
  onTranscript(callback: (transcript: TranscriptResult) => void): void {
    if (!this.ws) {
      throw new Error('WebSocket not connected');
    }
    const existingHandler = this.ws.onmessage;
    this.ws.onmessage = (event) => {
      if (typeof event.data === 'string') {
        try {
          const data = JSON.parse(event.data);
          if (data.type === 'transcript') {
            callback({ text: data.text, confidence: data.confidence });
          }
        } catch {
          // Not JSON, ignore
        }
      }
      // Call existing handler if set
      if (existingHandler) {
        existingHandler.call(this.ws, event);
      }
    };
  }

  /**
   * Disconnect from PersonaPlex server
   */
  disconnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  /**
   * Check if connected
   */
  isConnected(): boolean {
    return this.ws !== null && this.ws.readyState === WebSocket.OPEN;
  }
}
