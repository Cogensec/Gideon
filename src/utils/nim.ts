/**
 * NVIDIA NIM API utilities
 *
 * NIM (NVIDIA Inference Microservices) provides OpenAI-compatible API
 * for GPU-accelerated LLM inference, enabling self-hosted deployments.
 */

interface NimModel {
  id: string;
  object: string;
  created?: number;
  owned_by?: string;
}

interface NimModelsResponse {
  object: string;
  data: NimModel[];
}

/**
 * Gets the NIM base URL from environment or returns default
 */
export function getNimBaseUrl(): string {
  return process.env.NIM_BASE_URL || 'http://localhost:8000/v1';
}

/**
 * Fetches available models from the NIM API
 * NIM uses OpenAI-compatible /v1/models endpoint
 */
export async function getNimModels(): Promise<string[]> {
  const baseUrl = getNimBaseUrl();

  try {
    const response = await fetch(`${baseUrl}/models`, {
      headers: {
        'Authorization': `Bearer ${process.env.NIM_API_KEY || 'not-required'}`,
      },
    });

    if (!response.ok) {
      return [];
    }

    const data = (await response.json()) as NimModelsResponse;
    return data.data.map((m) => m.id);
  } catch {
    // NIM not running or unreachable
    return [];
  }
}

/**
 * Checks if NIM is available and responding
 */
export async function isNimAvailable(): Promise<boolean> {
  const baseUrl = getNimBaseUrl();

  try {
    const response = await fetch(`${baseUrl}/models`, {
      headers: {
        'Authorization': `Bearer ${process.env.NIM_API_KEY || 'not-required'}`,
      },
    });
    return response.ok;
  } catch {
    return false;
  }
}
