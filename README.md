# 🛡️ SafeMCP Gateway

A zero-dependency, local-first security gateway and stdio proxy for the Model Context Protocol (MCP). It acts as an isolation barrier between AI clients (such as Claude Code, Cursor, or VS Code) and target MCP servers interacting directly with your filesystem, shell, and local network. 

By intercepting and validating JSON-RPC 2.0 frames on standard input/output streams, SafeMCP mitigates security vulnerabilities—such as path traversal, command injection, and Server-Side Request Forgery (SSRF)—before they can compromise the host machine.

---

## 🚀 Key Features

* 📁 **Path Traversal Shield:** Automatically cleans and canonicalizes file path parameters, verifying that all directory operations remain anchored within your configured workspace folders.
* ⚙️ **Subprocess Execution Guard:** Disables shell metacharacter usage and restricts binary executions to an explicit command allowlist.
* 🌐 **SSRF Network Blocker:** Prevents agents from accessing private local subnets, loopback adapters, and cloud metadata services (e.g., the AWS IMDSv2 interface at `169.254.169.254`).
* ⏳ **Token-Bucket Throttling:** Governs the execution frequency of system commands to prevent automated loops and payload floods.
* 🪵 **Forensic Audit Logs:** Generates a structured JSONL logging audit trail with anonymized parameters to ensure developer privacy and compliance.
* 📦 **Zero-Dependency Core:** Built exclusively on Node.js core modules to guarantee an absolute zero-vulnerability supply chain.

---

## 🛠️ Tech Stack

![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue?style=flat-square&logo=typescript)
![Node.js](https://img.shields.io/badge/Node.js->=18.0-green?style=flat-square&logo=node.js)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Protocol: MCP](https://img.shields.io/badge/Protocol-MCP-orange?style=flat-square)

---

## 📦 Getting Started

### Prerequisites
* **Node.js**: Version 18.0.0 or higher.
* **TypeScript**: Installed globally or as a development dependency for compilation.

### Project Structure
Ensure your local project directory matches this layout:
```text
safemcp-gateway/
├── src/
│   └── safemcp-gateway.ts    # Core proxy logic and security rules
├── dist/                     # Compiled JavaScript output (Git-ignored)
├── .gitignore                # Untracked files and build directories
├── LICENSE                   # MIT License parameters
├── package.json              # Node.js project metadata and scripts
├── tsconfig.json             # Strict TypeScript compiler configurations
└── README.md                 # Project documentation

```
### Step-by-Step Installation
 1. **Clone the repository:**
   ```bash
   git clone https://github.com/angwyn/safemcp-gateway.git
   cd safemcp-gateway
   
   ```
 2. **Install development dependencies:**
   *(SafeMCP utilizes zero production dependencies. NPM packages are strictly used for TypeScript development tooling).*
   ```bash
   npm install
   
   ```
 3. **Build the production gateway:**
   ```bash
   npm run build
   
   ```
   The compiled execution file will be output to dist/safemcp-gateway.js.
## 💡 Usage
### How SafeMCP Fits Into the Developer Workflow
```text
[ AI Client ]                   [ SafeMCP Gateway ]               [ Target MCP Server ]
  (Cursor)                        (Local Process)                   (e.g., Postgres)
     |                                   |                                   |
     |---- (1) JSON-RPC Request -------->|                                   |
     |     "tools/call: query_db"        |                                   |
     |                                   |-- (2) Run Security Checks         |
     |                                   |   - Path traversal? No.           |
     |                                   |   - Command injection? No.        |
     |                                   |   - SSRF exploit? No.             |
     |                                   |                                   |
     |                                   |==== IF VALID =====================|
     |                                   |---- (3) Forward Request --------->|
     |                                   |<--- (4) Raw Response -------------|
     |<--- (5) Unmodified Response ------|                                   |
     |                                   |===================================|
     |                                   |                                   |
     |                                   |==== IF INVALID ===================|
     |<--- (6) JSON-RPC Error -32602 ----|                                   |
     |     "Access Denied"               |                                   |

```
SafeMCP acts as a security wrapper around any executable command. The double-dash separator (--) isolates the gateway configuration parameters from the target server command line.
### Claude Desktop Integration
To wrap the official Anthropic filesystem server inside the SafeMCP security layer, update your local claude_desktop_config.json configuration file:
```json
{
  "mcpServers": {
    "secure-filesystem": {
      "command": "node",
      "args": [
        "/absolute/path/to/safemcp-gateway/dist/safemcp-gateway.js",
        "--workspace",
        "/path/to/safe/workspace",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/path/to/safe/workspace"
      ]
    }
  }
}

```
### Cursor Editor Integration
To register a secure PostgreSQL server inside your Cursor editor environment:
 1. Open **Settings** -> **Features** -> **MCP**.
 2. Click **+ Add New MCP Server**.
 3. Set the type to command.
 4. Input the execution string into the command window:
   ```bash
   node /path/to/safemcp-gateway/dist/safemcp-gateway.js --workspace /path/to/workspace -- npx -y @modelcontextprotocol/server-postgres postgresql://localhost:5432/db
   
   ```
### Usage and Testing Verification
Once active, SafeMCP runs silently in the background, only intervening when a tool parameter violates a security rule.
#### Example 1: Resolving Safe Workspace Queries (Allowed)
When the coding assistant requests a legitimate file located within the root folder, the gateway forwards the request immediately.
 * **Incoming request from client:**
   ```json
   {
     "jsonrpc": "2.0",
     "method": "tools/call",
     "params": {
       "name": "read_file",
       "arguments": { "path": "src/index.ts" }
     },
     "id": 1
   }
   
   ```
 * **SafeMCP Action:** Matches configuration standards, writes an audit log entry, and forwards the command to the target filesystem server.
#### Example 2: Blocking Directory Traversal (Prevented)
When a prompt injection payload attempts to coerce the tool into escaping its sandbox, SafeMCP detects the traversal and rejects the request.
 * **Incoming request from client:**
   ```json
   {
     "jsonrpc": "2.0",
     "method": "tools/call",
     "params": {
       "name": "read_file",
       "arguments": { "path": "../../../../../etc/passwd" }
     },
     "id": 2
   }
   
   ```
 * **SafeMCP Response:**
   ```json
   {
     "jsonrpc": "2.0",
     "id": 2,
     "error": {
       "code": -32602,
       "message": "Access Denied: Path traversal attempt detected outside authorized workspace."
     }
   }
   
   ```
## 🪵 JSONL Auditing
Every filtered request is appended to a local safemcp-audit.jsonl file. Parameter values are normalized into cryptographically anonymized signatures to ensure PII and enterprise secrets are never leaked:
```json
{"timestamp":"2026-07-01T11:20:05.123Z","status":"ALLOWED","method":"tools/call","tool":"read_file","param_hash":"a4f6e1b...92"}
{"timestamp":"2026-07-01T11:22:14.582Z","status":"BLOCKED","method":"tools/call","tool":"read_file","reason":"PATH_TRAVERSAL","attempted_payload":"../../../../../etc/passwd"}

```
## 🤝 Contributing
We welcome contributions to help improve the default security policies of SafeMCP.
 1. Fork the repository and create your feature branch: git checkout -b feature/enhanced-ssrf-signatures.
 2. Ensure any new validation code uses **only native Node.js libraries** to preserve our zero-dependency design.
 3. Verify that changes run correctly in both UNIX and Windows environments.
 4. Open a Pull Request detailing the specific vulnerability pattern your change targets.
## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
