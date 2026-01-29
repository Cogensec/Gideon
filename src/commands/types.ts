export interface CommandContext {
  model: string;
  modelProvider: string;
  maxIterations: number;
  signal?: AbortSignal;
}

export interface CommandResult {
  success: boolean;
  output: string;
  artifacts?: {
    markdown?: string;
    json?: any;
    stix?: any;
  };
  error?: string;
}

export type CommandHandler = (
  args: string[],
  context: CommandContext
) => Promise<CommandResult>;
