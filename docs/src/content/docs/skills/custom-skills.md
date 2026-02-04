---
title: Extending Gideon (Skills)
description: Learn how to build and integrate custom modular skills into the Gideon agent loop.
---

Gideon's power comes from its **Modular Skill System**. A skill is a standalone capability that the agent can "learn" and use during task execution.

## Anatomy of a Skill

A skill consists of three parts:
1.  **Definition**: The metadata that tells the agent what the skill does and what arguments it needs.
2.  **Implementation**: The actual TypeScript code that performs the action.
3.  **Validation**: Rules for ensuring the skill was executed correctly (Self-Reflection).

## Creating Your First Skill

### 1. Define the Skill
Create a new file in `src/skills/custom-skill.ts`:

```typescript
export const MyCustomSkill = {
  name: 'analyze_pcap',
  description: 'Analyzes a PCAP file for suspicious network traffic',
  parameters: {
    type: 'object',
    properties: {
      filePath: { type: 'string', description: 'Path to the .pcap file' },
    },
    required: ['filePath'],
  },
  
  async execute({ filePath }) {
    // Your implementation here
    return { status: 'success', data: 'No threats found' };
  }
};
```

### 2. Register the Skill
Export your skill from the index file in `src/skills/index.ts`. Gideon will automatically pick it up and present it to the LLM during the planning phase.

## Best Practices

-   **Be Descriptive**: The LLM relies on the `description` field to decide when to use a skill. Be very specific about its use cases.
-   **Defensive Focus**: All skills should align with Gideon's **defensive-only** mission.
-   **Return Structured Data**: Always return data that the agent can easily parse and summarize for the final report.
-   **Error Handling**: Gideon's "Self-Reflection" loop can recover from errors if your skill returns descriptive error messages instead of just crashing.
