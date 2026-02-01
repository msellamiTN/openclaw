# OpenClaw Architecture Analysis
## Comprehensive System Architecture with Mermaid Diagrams

---

## 1. HIGH-LEVEL SYSTEM ARCHITECTURE

```mermaid
flowchart TB
    subgraph External["External Interfaces"]
        Users["👥 Users<br/>CLI / Mobile / Web"]
        LLM["🧠 LLM Providers<br/>Anthropic/OpenAI/Gemini/Local"]
        Channels["📱 Messaging Channels<br/>Telegram/Signal/Discord/Slack/iMessage"]
    end

    subgraph Core["OpenClaw Core"]
        CLI["CLI Engine<br/>src/cli/"]
        Gateway["🏛️ Gateway Server<br/>WebSocket + HTTP API"]
        AgentRunner["🤖 Agent Runner<br/>pi-embedded-runner"]
        Config["⚙️ Configuration<br/>YAML + Runtime"]
    end

    subgraph AI["AI/Agent Layer"]
        AgentCore["Agent Core<br/>@mariozechner/pi-agent-core"]
        Tools["🔧 Tool System<br/>50+ Tools"]
        Subagents["Subagent Registry<br/>Parallel Execution"]
        Memory["🧠 Memory System<br/>Search + Recall"]
    end

    subgraph ChannelsLayer["Channel Adapters"]
        ChannelPlugins["Channel Plugins<br/>Core + Extensions"]
        MessageRouter["Message Router"]
        AuthProfiles["Auth Profiles<br/>Per-channel credentials"]
    end

    subgraph Infra["Infrastructure"]
        SessionStore["💾 Session Store<br/>JSON/Filesystem"]
        Sandbox["🏖️ Sandbox System<br/>Docker/Browser"]
        MediaPipeline["📹 Media Pipeline"]
        Skills["📚 Skills System<br/>SKILL.md files"]
    end

    Users --> CLI
    CLI --> Gateway
    Gateway --> AgentRunner
    AgentRunner --> AgentCore
    AgentCore --> Tools
    AgentCore --> Subagents
    AgentCore --> Memory
    Tools --> Sandbox
    Tools --> Infra
    Gateway --> ChannelPlugins
    ChannelPlugins --> Channels
    MessageRouter --> ChannelPlugins
    AgentRunner --> LLM
```

---

## 2. AGENT ARCHITECTURE - DEEP DIVE

```mermaid
flowchart TB
    subgraph AgentConfig["Agent Configuration"]
        AgentScope["agent-scope.ts<br/>- Agent ID resolution<br/>- Workspace management<br/>- Model fallbacks"]
        AgentDefaults["types.agent-defaults.ts<br/>- Model selection<br/>- Timeout config<br/>- Human delay"]
        AgentIdentity["identity.ts<br/>- Persona management<br/>- Avatar/ack reactions"]
    end

    subgraph AgentExecution["Agent Execution Pipeline"]
        CliRunner["cli-runner.ts<br/>CLI agent execution"]
        PiRunner["pi-embedded-runner/run.ts<br/>Main agent runner"]
        SubagentRunner["subagent-registry.ts<br/>Child agent lifecycle"]
    end

    subgraph AgentRuntime["Agent Runtime"]
        SystemPrompt["system-prompt.ts<br/>- Prompt modes: full/minimal/none<br/>- Safety constraints<br/>- Skills injection"]
        ToolRegistry["pi-tools.ts<br/>Tool registration & policies"]
        ModelSelection["model-selection.ts<br/>- Provider routing<br/>- Fallback chains"]
        ContextWindow["context-window-guard.ts<br/>Token management"]
    end

    subgraph AgentCapabilities["Agent Capabilities"]
        BashTools["bash-tools.ts<br/>Shell execution"]
        FileTools["pi-tools.read.ts<br/>File operations"]
        SessionTools["sessions-spawn-tool.ts<br/>Subagent spawning"]
        MemoryTools["memory-search.ts<br/>Memory recall"]
        ChannelTools["channel-tools.ts<br/>Cross-session messaging"]
    end

    AgentScope --> PiRunner
    AgentDefaults --> PiRunner
    CliRunner --> PiRunner
    PiRunner --> SystemPrompt
    PiRunner --> ModelSelection
    SystemPrompt --> ToolRegistry
    ToolRegistry --> AgentCapabilities
    PiRunner --> ContextWindow
    SubagentRunner --> PiRunner
```

---

## 3. GATEWAY ARCHITECTURE

```mermaid
flowchart LR
    subgraph GatewayServer["Gateway Server (src/gateway/)"]
        HTTP["HTTP Layer<br/>- REST API<br/>- OpenAI-compatible<br/>- OpenResponses"]
        WS["WebSocket Layer<br/>- Real-time events<br/>- Bi-directional"]
        RPC["Internal RPC<br/>call.ts - IPC bridge"]
    end

    subgraph GatewayServices["Services"]
        Auth["auth.ts<br/>Token validation"]
        ChatRegistry["server-chat.ts<br/>Session management"]
        Hooks["hooks.ts<br/>Webhook processing"]
        Cron["server-cron.ts<br/>Scheduled tasks"]
        Nodes["Node registry<br/>Mobile/desktop nodes"]
    end

    subgraph Protocol["Protocol Layer"]
        Schema["schema.ts<br/>JSON-RPC protocol"]
        Validation["protocol/index.ts<br/>AJV validation"]
        Methods["server-methods/<br/>40+ RPC methods"]
    end

    HTTP --> Auth
    WS --> Auth
    Auth --> ChatRegistry
    ChatRegistry --> Hooks
    ChatRegistry --> Cron
    RPC --> ChatRegistry
    Schema --> Validation
    Validation --> Methods
```

---

## 4. CHANNEL PLUGIN ARCHITECTURE

```mermaid
flowchart TB
    subgraph PluginSDK["Plugin SDK (src/plugin-sdk/)"]
        CoreTypes["types.ts<br/>Channel adapters"]
        ConfigSchema["config-schema.ts"]
        Actions["message-actions.ts"]
    end

    subgraph CoreChannels["Core Channels (src/)"]
        Telegram["telegram/"]
        Signal["signal/"]
        Discord["discord/"]
        Slack["slack/"]
        IMessage["imessage/"]
        WhatsApp["web/ (WhatsApp)"]
        Line["line/"]
    end

    subgraph ExtensionChannels["Extensions (extensions/)"]
        BlueBubbles["bluebubbles/"]
        GoogleChat["googlechat/"]
        Matrix["matrix/"]
        MSTeams["msteams/"]
        Zalo["zalo/"]
        VoiceCall["voice-call/"]
    end

    subgraph ChannelAbstractions["Channel Abstractions"]
        MessagingAdapter["ChannelMessagingAdapter<br/>- send/receive messages"]
        GatewayAdapter["ChannelGatewayAdapter<br/>- Gateway integration"]
        SecurityAdapter["ChannelSecurityAdapter<br/>- Allowlists/policies"]
        SetupAdapter["ChannelSetupAdapter<br/>- Onboarding flows"]
    end

    PluginSDK --> CoreChannels
    PluginSDK --> ExtensionChannels
    CoreChannels --> ChannelAbstractions
    ExtensionChannels --> ChannelAbstractions
```

---

## 5. TOOL SYSTEM ARCHITECTURE

```mermaid
flowchart TB
    subgraph ToolFramework["Tool Framework"]
        Common["tools/common.ts<br/>Parameter parsing<br/>Result formatting"]
        Policy["tool-policy.ts<br/>Allow/deny lists"]
        Display["tool-display.ts<br/>UI formatting"]
        Schema["schema/typebox.ts<br/>TypeBox schemas"]
    end

    subgraph CoreTools["Core Tools (src/agents/tools/)"]
        Bash["bash-tools.ts<br/>exec/background/process"]
        Read["read.ts<br/>File reading"]
        Write["write.ts<br/>File operations"]
        Sessions["sessions-spawn-tool.ts<br/>Subagent spawning"]
        Status["session-status.ts<br/>Session introspection"]
    end

    subgraph OpenClawTools["OpenClaw Tools"]
        OpenClawGateway["openclaw-gateway-tool.ts<br/>Gateway integration"]
        OpenClawSession["openclaw-tools.sessions.ts<br/>Session management"]
        Camera["openclaw-tools.camera.ts<br/>Media capture"]
    end

    ToolFramework --> CoreTools
    ToolFramework --> OpenClawTools
    CoreTools --> Sandbox
    CoreTools --> SessionStore
```

---

## 6. DATA FLOW - MESSAGE PROCESSING

```mermaid
sequenceDiagram
    participant User as User
    participant Channel as Channel Adapter
    participant Gateway as Gateway Server
    participant AgentRunner as Agent Runner
    participant LLM as LLM Provider
    participant Tools as Tool System

    User->>Channel: Send message
    Channel->>Gateway: Normalize + Route
    Gateway->>AgentRunner: Trigger agent run
    AgentRunner->>AgentRunner: Build system prompt
    AgentRunner->>LLM: Send with tools
    LLM-->>AgentRunner: Tool call request
    AgentRunner->>Tools: Execute tool
    Tools->>Tools: Policy check
    Tools-->>AgentRunner: Tool result
    AgentRunner->>LLM: Continue conversation
    LLM-->>AgentRunner: Final response
    AgentRunner->>Gateway: Send reply
    Gateway->>Channel: Deliver message
    Channel->>User: Display response
```

---

## 7. SUBAGENT / MULTI-AGENT PATTERN

```mermaid
flowchart TB
    subgraph ParentAgent["Parent Agent Session"]
        MainSystemPrompt["System Prompt (full mode)"]
        MainTools["All Tools"]
        SpawnTool["sessions_spawn tool"]
    end

    subgraph SubagentRegistry["Subagent Registry"]
        RegisterRun["registerSubagentRun()"]
        TrackLifecycle["Track: pending → active → completed"]
        AnnounceFlow["subagent-announce.ts<br/>Result delivery"]
    end

    subgraph ChildAgent["Child Agent Session"]
        MinimalPrompt["System Prompt (minimal mode)"]
        IsolatedTools["Limited Tools"]
        IsolatedWorkspace["Isolated Workspace"]
    end

    ParentAgent -->|Spawn| SubagentRegistry
    SubagentRegistry -->|Create| ChildAgent
    ChildAgent -->|Complete| SubagentRegistry
    SubagentRegistry -->|Announce| ParentAgent
```

---

## 8. SECURITY & SANDBOX ARCHITECTURE

```mermaid
flowchart TB
    subgraph SecurityLayers["Security Layers"]
        ExecApproval["exec-approvals.ts<br/>User confirmation for risky ops"]
        ToolPolicy["tool-policy.ts<br/>Tool allow/deny lists"]
        ChannelSecurity["ChannelSecurityAdapter<br/>DM/Group policies"]
    end

    subgraph SandboxSystem["Sandbox System (src/agents/sandbox/)"]
        DockerSandbox["Docker Sandbox<br/>- Containerized execution<br/>- Workspace isolation"]
        BrowserSandbox["Browser Sandbox<br/>- Playwright automation<br/>- Web interactions"]
        ScopeConfig["Scope: session/agent/shared"]
    end

    subgraph AuthManagement["Authentication"]
        AuthProfiles["auth-profiles.ts<br/>Credential rotation"]
        CliCredentials["cli-credentials.ts<br/>Provider auth"]
        ModelAuth["model-auth.ts<br/>API key management"]
    end

    SecurityLayers --> SandboxSystem
    AuthManagement --> SecurityLayers
```

---

## 9. CONFIGURATION & STATE MANAGEMENT

```mermaid
flowchart LR
    subgraph ConfigSystem["Configuration"]
        ConfigLoader["config.ts<br/>YAML loading"]
        Types["types.*.ts<br/>Zod schemas"]
        RuntimeConfig["Runtime config<br/>env vars + CLI"]
    end

    subgraph StateStorage["State Storage"]
        Sessions["sessions.ts<br/>Session store"]
        SessionUtils["session-utils.ts<br/>Read/write ops"]
        StateMigrations["state-migrations.ts<br/>Version upgrades"]
    end

    subgraph PersistentData["Persistent Data"]
        Workspaces["Agent Workspaces<br/>~/openclaw/"]
        Credentials["~/.openclaw/credentials/"]
        SessionsDir["~/.openclaw/sessions/"]
    end

    ConfigSystem --> StateStorage
    StateStorage --> PersistentData
```

---

## 10. AI/LLM INTEGRATION PATTERNS

```mermaid
flowchart TB
    subgraph ModelIntegration["Model Integration"]
        ModelCatalog["model-catalog.ts<br/>Provider registry"]
        ModelSelection["model-selection.ts<br/>- Provider resolution<br/>- Model fallbacks"]
        ModelFallback["model-fallback.ts<br/>Failover handling"]
        CliBackends["cli-backends.ts<br/>External CLI support"]
    end

    subgraph ProviderAdapters["Provider Adapters"]
        Anthropic["Anthropic Claude"]
        OpenAI["OpenAI GPT"]
        Gemini["Google Gemini"]
        Bedrock["AWS Bedrock"]
        Ollama["Local/Ollama"]
        CliProvider["CLI Provider<br/>e.g. codex, aider"]
    end

    subgraph ResponseHandling["Response Processing"]
        BlockChunker["pi-embedded-block-chunker.ts<br/>Streaming"]
        Compaction["compaction.ts<br/>Context pruning"]
        ContentGuard["context-window-guard.ts"]
    end

    ModelIntegration --> ProviderAdapters
    ProviderAdapters --> ResponseHandling
```

---

## 11. EXTENSION/PLUGIN ARCHITECTURE

```mermaid
flowchart TB
    subgraph ExtensionSystem["Extension System"]
        PluginRegistry["plugins/registry.ts<br/>Plugin loading"]
        PluginRuntime["plugins/runtime/<br/>Isolation & lifecycle"]
        HttpRegistry["plugins/http-registry.ts<br/>Custom routes"]
    end

    subgraph ExtensionTypes["Extension Types"]
        ChannelExt["Channel Extensions<br/>- Matrix<br/>- Teams<br/>- Zalo"]
        AuthExt["Auth Extensions<br/>- OAuth helpers<br/>- Provider auth"]
        MemoryExt["Memory Extensions<br/>- LanceDB<br/>- Vector stores"]
        ToolExt["Tool Extensions<br/>- Custom tools"]
    end

    subgraph ExtensionPackaging["Packaging"]
        WorkspacePkg["pnpm workspace"]
        SeparateDeps["Per-extension deps<br/>--omit=dev install"]
        SdkDependency["openclaw/plugin-sdk<br/>Runtime resolution"]
    end

    ExtensionSystem --> ExtensionTypes
    ExtensionPackaging --> ExtensionTypes
```

---

## AGENT SPECIFICATIONS SUMMARY

### Agent Types

| Type | Purpose | Context | Tools |
|------|---------|---------|-------|
| **Main Agent** | User-facing primary | Full system prompt | All tools |
| **Subagent** | Background tasks | Minimal prompt | Limited set |
| **Cron Agent** | Scheduled execution | Isolated session | Configurable |
| **Hook Agent** | Webhook processing | Request context | Webhook tools |

### Key Agent Capabilities

- **Multi-model**: Supports 15+ LLM providers with fallback chains
- **Tool use**: 50+ built-in tools (bash, file, web, camera, etc.)
- **Subagents**: Parallel task execution with `sessions_spawn`
- **Memory**: Semantic search across conversation history
- **Sandboxing**: Docker/browser isolation for unsafe operations
- **Multi-channel**: Unified interface across 15+ messaging platforms

### Agent Lifecycle

1. **Initialization**: Load config → Resolve agent ID → Setup workspace
2. **Prompt Building**: Inject skills → Apply identity → Add safety rules
3. **Model Selection**: Choose provider → Apply fallbacks → Auth resolution
4. **Execution**: Stream response → Handle tool calls → Manage context window
5. **Completion**: Persist session → Cleanup → Announce (subagents)

---

## KEY ARCHITECTURAL PATTERNS

1. **Adapter Pattern**: Channel plugins implement standard adapters
2. **Registry Pattern**: Dynamic tool/subagent/skill registration
3. **Lane Pattern**: Serialized execution queues per session/global
4. **Policy Pattern**: Configurable tool/channel access controls
5. **Fallback Pattern**: Graceful degradation across models/auth profiles
6. **Event-Driven**: Agent events, diagnostic events, lifecycle hooks

---

## FILE ORGANIZATION

```
src/
├── agents/           # Agent runtime, tools, execution
├── auto-reply/       # Message handling, chunking, templating
├── channels/         # Channel abstractions + core implementations
├── cli/              # CLI commands and UI
├── commands/         # High-level command implementations
├── config/           # Configuration types and loading
├── gateway/          # Gateway server, protocol, methods
├── infra/            # Infrastructure utilities
├── media/            # Media processing pipeline
├── plugins/          # Plugin system
├── providers/        # LLM provider utilities
└── [channels]/       # Per-channel implementations
```

Extensions live in `extensions/` as separate workspace packages.
