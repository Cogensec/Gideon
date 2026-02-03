import { StructuredToolInterface } from '@langchain/core/tools';
import {
  Skill,
  SkillCommand,
  SkillConfig,
  SkillSession,
  RegisteredSkill,
  SkillLoadResult,
  SkillStatus,
  SkillCategory,
  SkillCommandContext,
  SkillCommandResult,
} from './types.js';

// ============================================================================
// Skill Registry - Central management for all Gideon skills
// ============================================================================

class SkillRegistry {
  private skills: Map<string, RegisteredSkill> = new Map();
  private sessions: Map<string, SkillSession> = new Map();
  private initialized: boolean = false;

  /**
   * Register a skill with the registry
   */
  async register(skill: Skill, config?: SkillConfig): Promise<SkillLoadResult> {
    const skillId = skill.metadata.id;

    // Check if already registered
    if (this.skills.has(skillId)) {
      return {
        success: false,
        skillId,
        error: `Skill '${skillId}' is already registered`,
      };
    }

    // Validate skill availability
    const available = await skill.isAvailable();
    if (!available && config?.enabled !== false) {
      console.warn(`Skill '${skillId}' dependencies not met, registering as disabled`);
    }

    // Initialize if enabled
    if (config?.enabled !== false && skill.initialize) {
      try {
        await skill.initialize(config);
      } catch (error) {
        return {
          success: false,
          skillId,
          error: `Failed to initialize skill '${skillId}': ${error}`,
        };
      }
    }

    // Register the skill
    this.skills.set(skillId, {
      skill,
      enabled: config?.enabled !== false && available,
      loadedAt: new Date(),
      config,
    });

    return { success: true, skillId };
  }

  /**
   * Unregister a skill
   */
  async unregister(skillId: string): Promise<boolean> {
    const registered = this.skills.get(skillId);
    if (!registered) {
      return false;
    }

    // Shutdown skill if needed
    if (registered.skill.shutdown) {
      await registered.skill.shutdown();
    }

    // Remove any sessions for this skill
    for (const [sessionId, session] of this.sessions) {
      if (session.skillId === skillId) {
        this.sessions.delete(sessionId);
      }
    }

    this.skills.delete(skillId);
    return true;
  }

  /**
   * Get a registered skill by ID
   */
  getSkill(skillId: string): Skill | undefined {
    return this.skills.get(skillId)?.skill;
  }

  /**
   * Get all registered skills
   */
  getAllSkills(): RegisteredSkill[] {
    return Array.from(this.skills.values());
  }

  /**
   * Get enabled skills only
   */
  getEnabledSkills(): Skill[] {
    return Array.from(this.skills.values())
      .filter(r => r.enabled)
      .map(r => r.skill);
  }

  /**
   * Get skills by category
   */
  getSkillsByCategory(category: SkillCategory): Skill[] {
    return Array.from(this.skills.values())
      .filter(r => r.skill.metadata.category === category)
      .map(r => r.skill);
  }

  /**
   * Enable a skill
   */
  async enableSkill(skillId: string): Promise<boolean> {
    const registered = this.skills.get(skillId);
    if (!registered) {
      return false;
    }

    if (!registered.enabled) {
      const available = await registered.skill.isAvailable();
      if (!available) {
        return false;
      }

      if (registered.skill.initialize) {
        await registered.skill.initialize(registered.config);
      }

      registered.enabled = true;
    }

    return true;
  }

  /**
   * Disable a skill
   */
  async disableSkill(skillId: string): Promise<boolean> {
    const registered = this.skills.get(skillId);
    if (!registered) {
      return false;
    }

    if (registered.enabled) {
      if (registered.skill.shutdown) {
        await registered.skill.shutdown();
      }
      registered.enabled = false;
    }

    return true;
  }

  /**
   * Get all commands from all enabled skills
   */
  getAllCommands(): Map<string, { skill: Skill; command: SkillCommand }> {
    const commands = new Map<string, { skill: Skill; command: SkillCommand }>();

    for (const registered of this.skills.values()) {
      if (!registered.enabled) continue;

      for (const command of registered.skill.commands) {
        // Primary command name
        commands.set(command.name, { skill: registered.skill, command });

        // Aliases
        if (command.aliases) {
          for (const alias of command.aliases) {
            commands.set(alias, { skill: registered.skill, command });
          }
        }
      }
    }

    return commands;
  }

  /**
   * Get all LangChain tools from all enabled skills
   */
  getAllTools(): StructuredToolInterface[] {
    const tools: StructuredToolInterface[] = [];

    for (const registered of this.skills.values()) {
      if (!registered.enabled) continue;
      if (registered.skill.tools) {
        tools.push(...registered.skill.tools);
      }
    }

    return tools;
  }

  /**
   * Execute a skill command
   */
  async executeCommand(
    commandName: string,
    args: string[],
    context: Partial<SkillCommandContext> = {}
  ): Promise<SkillCommandResult> {
    const commands = this.getAllCommands();
    const entry = commands.get(commandName);

    if (!entry) {
      return {
        success: false,
        output: '',
        error: `Unknown command: ${commandName}`,
      };
    }

    const fullContext: SkillCommandContext = {
      cwd: context.cwd ?? process.cwd(),
      env: context.env ?? process.env as Record<string, string | undefined>,
      sessions: this.sessions,
      signal: context.signal,
    };

    try {
      return await entry.command.execute(args, fullContext);
    } catch (error) {
      return {
        success: false,
        output: '',
        error: `Command '${commandName}' failed: ${error}`,
      };
    }
  }

  /**
   * Get status of all skills
   */
  async getStatus(): Promise<Map<string, SkillStatus>> {
    const statuses = new Map<string, SkillStatus>();

    for (const [skillId, registered] of this.skills) {
      if (registered.skill.getStatus) {
        statuses.set(skillId, await registered.skill.getStatus());
      } else {
        statuses.set(skillId, {
          healthy: registered.enabled,
          message: registered.enabled ? 'Enabled' : 'Disabled',
          checkedAt: new Date(),
        });
      }
    }

    return statuses;
  }

  /**
   * Create a session for a skill
   */
  createSession(skillId: string, initialState: Record<string, unknown> = {}): SkillSession | null {
    const skill = this.skills.get(skillId);
    if (!skill || !skill.enabled) {
      return null;
    }

    const session: SkillSession = {
      id: `${skillId}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      skillId,
      startedAt: new Date(),
      state: initialState,
    };

    this.sessions.set(session.id, session);
    return session;
  }

  /**
   * Get a session by ID
   */
  getSession(sessionId: string): SkillSession | undefined {
    return this.sessions.get(sessionId);
  }

  /**
   * End a session
   */
  endSession(sessionId: string): boolean {
    return this.sessions.delete(sessionId);
  }

  /**
   * Get all active sessions
   */
  getActiveSessions(): SkillSession[] {
    return Array.from(this.sessions.values());
  }

  /**
   * Clear all skills and sessions (for testing)
   */
  clear(): void {
    this.skills.clear();
    this.sessions.clear();
    this.initialized = false;
  }
}

// Singleton instance
export const skillRegistry = new SkillRegistry();

// Export for testing
export { SkillRegistry };
