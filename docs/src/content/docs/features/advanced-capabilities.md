---
title: Advanced Capabilities
description: Learn about Gideon's advanced features like Voice AI and RAPIDS-accelerated data processing.
---

Gideon extends beyond standard security research with specialized features for data analytics and human-agent interaction.

## Voice AI (NVIDIA PersonaPlex)

Gideon can provide professional security briefings using high-fidelity AI-generated voice.

-   **Persona**: Gideon speaks as a professional security analyst—precise, authoritative, and helpful.
-   **Hardware**: Uses NVIDIA GPU acceleration for real-time text-to-speech.
-   **Configuration**:
    ```yaml
    voice:
      enabled: true
      voice_id: NATM1
      cpu_offload: true # Lower GPU memory usage
    ```

## Data Analytics (NVIDIA RAPIDS)

For large-scale security data (SIEM logs, packet captures), Gideon leverages **NVIDIA RAPIDS** to perform GPU-accelerated analysis.

### Features
-   **Batch IOC Analysis**: Process 10,000+ indicators in seconds using `cuDF`.
-   **Link Correlation**: Build threat relationship graphs using `cuGraph`.
-   **Threat Clustering**: Use `cuML` to group similar alerts into a single incident.

### Configuration
```yaml
rapids:
  enabled: true
  processing:
    batch_size: 10000
    memory_limit: 8GB
```

## CLI Reference

Gideon provides a powerful command-line interface for daily security operations.

| Command | Description |
| :--- | :--- |
| `gideon brief` | Generate a daily security briefing summary. |
| `gideon cve <id>` | Analyze a specific CVE and generate hardening steps. |
| `gideon ioc <value>` | Perform reputation and threat analysis on an IP, domain, or hash. |
| `gideon policy` | Generate a hardening checklist based on a target technology. |
| `gideon chat` | Enter an interactive session with the Gideon assistant. |
