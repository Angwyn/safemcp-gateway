import * as child_process from 'node:child_process';
import * as readline from 'node:readline';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { URL } from 'node:url';
import { createHash } from 'node:crypto'; // Added for proper SHA-256 auditing

interface GatewayConfig {
  allowedRoots: string[];
  allowedCommands: string[];
  blockPrivateIPs: boolean;
  maxPayloadBytes: number;
  auditLogPath: string;
  rateLimit: {
    maxTokens: number;
    refillRate: number; // tokens per second
  };
}

const DEFAULT_CONFIG: GatewayConfig = {
  allowedRoots: [
    process.cwd()
  ],
  allowedCommands: ['git', 'npm', 'cargo', 'pip', 'python'],
  blockPrivateIPs: true,
  maxPayloadBytes: 1048576, // 1MB payload limit
  auditLogPath: path.join(process.cwd(), 'safemcp-audit.jsonl'),
  rateLimit: {
    maxTokens: 15,
    refillRate: 0.5 // Refill 1 token every 2 seconds
  }
};

class SecurityEngine {
  private config: GatewayConfig;

  constructor(config: GatewayConfig) {
    this.config = config;
  }

  // [FIXED] Detects directory traversal sequences and forces absolute path resolution
  public validatePath(inputPath: string): boolean {
    try {
      // Clean 'file://' prefix if the AI provides a URI instead of a raw path
      const strippedPath = inputPath.replace(/^file:\/\//i, '');
      const decoded = decodeURIComponent(strippedPath);
      
      // Block null-byte injection vectors immediately
      if (decoded.includes('\x00')) {
        return false;
      }

      // We now ALWAYS resolve the path regardless of what characters are in it.
      // This patches the sandbox escape via plain filenames.
      const resolvedPath = path.resolve(decoded);
      
      const isWithinAllowedRoot = this.config.allowedRoots.some((root) => {
        const absoluteRoot = path.resolve(root);
        const relative = path.relative(absoluteRoot, resolvedPath);
        return !relative.startsWith('..') && !path.isAbsolute(relative);
      });

      return isWithinAllowedRoot;
    } catch {
      return false; // Fail securely if path parsing errors out
    }
  }

  // [FIXED] Detects shell metacharacters and command execution attempts, including newlines
  public validateCommand(command: string): boolean {
    // Added \n and \r to prevent multi-line command injection
    const metacharacters = /[|&;>$`()\n\r]/;
    if (metacharacters.test(command)) {
      return false;
    }

    const words = command.trim().split(/\s+/);
    if (words.length === 0) return false;
    
    const binary = path.basename(words[0]);
    return this.config.allowedCommands.includes(binary);
  }

  // [FIXED] Detects Server-Side Request Forgery vectors with expanded IP ranges
  public validateUrl(targetUrl: string): boolean {
    if (!targetUrl.includes('://')) {
      return true; // Parameter is not an absolute URL string
    }

    try {
      const parsed = new URL(targetUrl);
      const host = parsed.hostname.toLowerCase();

      if (this.config.blockPrivateIPs) {
        // Direct loopback and cloud metadata interface classifications
        if (host === 'localhost' || host === '::1' || host === '169.254.169.254') {
          return false;
        }

        // Catch the entire 127.x.x.x loopback block, plus standard private ranges
        if (
          host.startsWith('127.') || 
          host.startsWith('10.') ||
          host.startsWith('192.168.') ||
          /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(host)
        ) {
          return false;
        }
        
        // Note: As a synchronous parser, this cannot block DNS Rebinding attacks 
        // (e.g., evil.com resolving to 127.0.0.1). Advanced SSRF protection requires 
        // async socket interception.
      }
    } catch {
      return false; // Reject malformed URL strings
    }
    return true;
  }

  // [FIXED] Recursively inspects unknown input schemas contextually to prevent false positives
  public inspectPayload(payload: any, keyContext: string = ''): { safe: boolean; reason?: string } {
    if (!payload) return { safe: true };

    if (typeof payload === 'string') {
      const lowerKey = keyContext.toLowerCase();

      // Only check for path traversal if the parameter name implies it's a file/path,
      // or if the payload explicitly starts with a file:// protocol.
      const isPathContext = ['path', 'file', 'dir', 'folder', 'uri'].some(k => lowerKey.includes(k)) || payload.startsWith('file://');
      if (isPathContext) {
        if (!this.validatePath(payload)) {
          return { safe: false, reason: `Path traversal violation on field '${keyContext}': "${payload}"` };
        }
      }

      // Only check for command injections if the parameter implies it's a system command
      const isCommandContext = ['command', 'cmd', 'script', 'exec', 'args'].some(k => lowerKey.includes(k));
      if (isCommandContext) {
        if (!this.validateCommand(payload)) {
          return { safe: false, reason: `Command injection block on field '${keyContext}': "${payload}"` };
        }
      }

      // SSRF check applies to anything formatted as a web protocol URL
      if (/^https?:\/\//i.test(payload)) {
        if (!this.validateUrl(payload)) {
          return { safe: false, reason: `SSRF network boundary violation on field '${keyContext}': "${payload}"` };
        }
      }
    } else if (typeof payload === 'object') {
      for (const key of Object.keys(payload)) {
        // Pass the key down recursively to maintain context
        const result = this.inspectPayload(payload[key], key);
        if (!result.safe) {
          return result;
        }
      }
    }

    return { safe: true };
  }
}

// Low-overhead audit logger using structured JSONL with parameters obfuscation
class AuditLogger {
  private logPath: string;

  constructor(logPath: string) {
    this.logPath = logPath;
  }

  public log(method: string, safe: boolean, reason?: string, params?: any): void {
    const entry = {
      timestamp: new Date().toISOString(),
      method,
      verdict: safe ? 'ALLOW' : 'BLOCK',
      reason: reason || null,
      paramsSignature: params ? this.generateSignature(params) : null
    };

    try {
      fs.appendFileSync(this.logPath, JSON.stringify(entry) + '\n', 'utf8');
    } catch (err) {
      process.stderr.write(`Audit log write failure: ${String(err)}\n`);
    }
  }

  // [FIXED] Updated to use real SHA-256 via node:crypto
  private generateSignature(params: any): string {
    const serialized = JSON.stringify(params);
    return createHash('sha256').update(serialized).digest('hex').substring(0, 16);
  }
}

// Token-bucket execution governor
class RateLimiter {
  private maxTokens: number;
  private refillRate: number;
  private tokens: number;
  private lastRefill: number;

  constructor(maxTokens: number, refillRate: number) {
    this.maxTokens = maxTokens;
    this.refillRate = refillRate;
    this.tokens = maxTokens;
    this.lastRefill = Date.now();
  }

  public consume(): boolean {
    const now = Date.now();
    const elapsed = (now - this.lastRefill) / 1000;
    this.lastRefill = now;

    // Refill tokens based on elapsed duration
    this.tokens = Math.min(this.maxTokens, this.tokens + elapsed * this.refillRate);

    if (this.tokens >= 1) {
      this.tokens -= 1;
      return true;
    }
    return false;
  }
}

// Core gateway orchestration engine
class SafeMcpGateway {
  private targetProcess!: child_process.ChildProcess;
  private clientReader!: readline.Interface;
  private targetReader!: readline.Interface;
  private securityEngine: SecurityEngine;
  private auditLogger: AuditLogger;
  private rateLimiter: RateLimiter;
  private config: GatewayConfig;

  constructor(private spawnCommand: string, private spawnArgs: string[], config: GatewayConfig) {
    this.config = config;
    this.securityEngine = new SecurityEngine(config);
    this.auditLogger = new AuditLogger(config.auditLogPath);
    this.rateLimiter = new RateLimiter(config.rateLimit.maxTokens, config.rateLimit.refillRate);
  }

  public start(): void {
    this.spawnTargetServer();
    this.pipeStreams();
  }

  private spawnTargetServer(): void {
    this.targetProcess = child_process.spawn(this.spawnCommand, this.spawnArgs, {
      stdio: ['pipe', 'pipe', 'inherit'],
      shell: false,
      env: { ...process.env, PYTHONUNBUFFERED: '1' }
    });

    this.targetProcess.on('error', (err) => {
      process.stderr.write(`Target MCP server initialization failure: ${err.message}\n`);
      process.exit(1);
    });

    this.targetProcess.on('exit', (code, signal) => {
      process.stderr.write(`Target MCP server exited with code ${code} and signal ${signal}\n`);
      process.exit(code ?? 0);
    });
  }

  private pipeStreams(): void {
    this.clientReader = readline.createInterface({
      input: process.stdin,
      terminal: false
    });

    this.targetReader = readline.createInterface({
      input: this.targetProcess.stdout as NodeJS.ReadableStream,
      terminal: false
    });

    this.clientReader.on('line', (line) => this.processClientLine(line));
    this.targetReader.on('line', (line) => process.stdout.write(line + '\n'));
  }

  private processClientLine(line: string): void {
    if (line.length > this.config.maxPayloadBytes) {
      this.sendError(null, -32600, 'Payload size limit exceeded');
      return;
    }

    let request: any;
    try {
      request = JSON.parse(line);
    } catch {
      this.sendError(null, -32700, 'Parse error: invalid JSON payload');
      return;
    }

    const id = request.id !== undefined ? request.id : null;
    const method = request.method || 'unknown';

    if (request.jsonrpc !== '2.0') {
      this.sendError(id, -32600, 'Invalid Request: missing jsonrpc "2.0" version identifier');
      return;
    }

    // Evaluate execution rate throttling limits
    if (!this.rateLimiter.consume()) {
      this.auditLogger.log(method, false, 'Rate limit burst capacity exceeded', request.params);
      this.sendError(id, -32001, 'Request rejected: rate limit exceeded');
      return;
    }

    // [FIXED] Run payload inspection on ALL methods that contain parameters, preventing resources/read bypasses
    if (request.params && typeof request.params === 'object' && Object.keys(request.params).length > 0) {
      const validation = this.securityEngine.inspectPayload(request.params);

      if (!validation.safe) {
        const blockReason = validation.reason || 'Security policy block';
        this.auditLogger.log(method, false, blockReason, request.params);
        this.sendError(id, -32602, `Access Denied: ${blockReason}`);
        return;
      }
    }

    // Forward the verified request to the target server
    if (this.targetProcess.stdin && this.targetProcess.stdin.writable) {
      this.targetProcess.stdin.write(line + '\n');
    }
  }

  private sendError(id: string | number | null, code: number, message: string): void {
    const response = {
      jsonrpc: '2.0',
      id,
      error: {
        code,
        message
      }
    };
    process.stdout.write(JSON.stringify(response) + '\n');
  }
}

function main(): void {
  const args = process.argv.slice(2);
  const separatorIndex = args.indexOf('--');

  if (separatorIndex === -1 || separatorIndex === args.length - 1) {
    process.stderr.write('Usage: node safemcp-gateway.js [config-overrides] -- <target-command> [target-args...]\n');
    process.exit(1);
  }

  const targetCommand = args[separatorIndex + 1];
  const targetArgs = args.slice(separatorIndex + 2);

  const gateway = new SafeMcpGateway(targetCommand, targetArgs, DEFAULT_CONFIG);
  gateway.start();
}

main();