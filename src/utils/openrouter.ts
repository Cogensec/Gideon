/**
 * OpenRouter API utilities
 */
declare const process: { env: Record<string, string | undefined> };

interface OpenRouterModel {
  id: string;
  name: string;
}

interface OpenRouterModelsResponse {
  data: OpenRouterModel[];
}

/**
 * Fetches available models from the OpenRouter API
 */
export async function getOpenRouterModels(): Promise<string[]> {
  try {
    const headers: Record<string, string> = {};
    const apiKey = process.env.OPENROUTER_API_KEY;
    
    if (apiKey) {
      headers['Authorization'] = `Bearer ${apiKey}`;
    }

    const response = await fetch('https://openrouter.ai/api/v1/models', {
      headers
    });
    
    if (!response.ok) {
      return [];
    }
    
    const data = (await response.json()) as OpenRouterModelsResponse;
    // Sort models alphabetically for better UX
    const models = data.data.map((m) => m.id).sort();
    return models;
  } catch {
    // API unreachable or other error
    return [];
  }
}
