// Minimal Electrum JSON-RPC client over TCP
// Reference: libnunchuk src/backend/electrum/

import net from "node:net";
import tls from "node:tls";
import { sha256 } from "@noble/hashes/sha2.js";
import { Address, OutScript, NETWORK, TEST_NETWORK } from "@scure/btc-signer";
import type { ElectrumProtocol, Network } from "./config.js";

const REQUEST_TIMEOUT = 30_000;
const CONNECT_TIMEOUT = 10_000;

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (reason: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

export interface HistoryItem {
  tx_hash: string;
  height: number;
  fee?: number;
}

export interface UnspentItem {
  tx_hash: string;
  tx_pos: number;
  height: number;
  value: number;
}

export interface ScripthashBalance {
  confirmed: number;
  unconfirmed: number;
}

export class ElectrumClient {
  private socket: net.Socket | null = null;
  private nextId = 1;
  private pending = new Map<number, PendingRequest>();
  private buffer = "";

  async connect(host: string, port: number, protocol: ElectrumProtocol = "tcp"): Promise<void> {
    return new Promise((resolve, reject) => {
      let settled = false;
      const socket =
        protocol === "ssl"
          ? tls.connect({ host, port, servername: host }, () => {
              settled = true;
              resolve();
            })
          : net.createConnection({ host, port }, () => {
              settled = true;
              resolve();
            });
      const connectTimer = setTimeout(() => {
        const err = new Error(`Connection timeout: ${protocol}://${host}:${port}`);
        if (!settled) {
          settled = true;
          reject(err);
        }
        socket.destroy(err);
      }, CONNECT_TIMEOUT);

      this.socket = socket;
      socket.setEncoding("utf-8");
      socket.on("data", (chunk: string) => this.onData(chunk));
      socket.on("error", (err) => {
        clearTimeout(connectTimer);
        if (!settled) {
          settled = true;
          reject(err);
        }
        this.rejectPending(err);
      });
      socket.on("close", () => {
        clearTimeout(connectTimer);
        if (this.socket === socket) {
          this.socket = null;
        }
        const err = new Error("Connection closed");
        if (!settled) {
          settled = true;
          reject(err);
        }
        this.rejectPending(err);
      });
      socket.on("connect", () => {
        clearTimeout(connectTimer);
      });
      if (protocol === "ssl") {
        socket.on("secureConnect", () => {
          clearTimeout(connectTimer);
        });
      }
    });
  }

  close(): void {
    if (this.socket) {
      this.socket.destroy();
      this.socket = null;
    }
  }

  async serverVersion(clientName: string, protocolVersion: string): Promise<string[]> {
    return this.call("server.version", [clientName, protocolVersion]) as Promise<string[]>;
  }

  async getHistory(scripthash: string): Promise<HistoryItem[]> {
    return this.call("blockchain.scripthash.get_history", [scripthash]) as Promise<HistoryItem[]>;
  }

  async getTransaction(txHash: string): Promise<string> {
    return this.call("blockchain.transaction.get", [txHash]) as Promise<string>;
  }

  async listUnspent(scripthash: string): Promise<UnspentItem[]> {
    return this.call("blockchain.scripthash.listunspent", [scripthash]) as Promise<UnspentItem[]>;
  }

  async getBalance(scripthash: string): Promise<ScripthashBalance> {
    return this.call("blockchain.scripthash.get_balance", [
      scripthash,
    ]) as Promise<ScripthashBalance>;
  }

  async broadcast(rawTx: string): Promise<string> {
    return this.call("blockchain.transaction.broadcast", [rawTx]) as Promise<string>;
  }

  async estimateFee(blocks: number): Promise<number> {
    return this.call("blockchain.estimatefee", [blocks]) as Promise<number>;
  }

  // Returns block header as hex string (80 bytes = 160 hex chars)
  async getBlockHeader(height: number): Promise<string> {
    return this.call("blockchain.block.header", [height]) as Promise<string>;
  }

  // Subscribe to headers — returns current tip {height, hex}
  async headersSubscribe(): Promise<{ height: number; hex: string }> {
    return this.call("blockchain.headers.subscribe", []) as Promise<{
      height: number;
      hex: string;
    }>;
  }

  private call(method: string, params: unknown[]): Promise<unknown> {
    return new Promise((resolve, reject) => {
      if (!this.socket) {
        reject(new Error("Not connected"));
        return;
      }
      const id = this.nextId++;
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Request timeout: ${method}`));
      }, REQUEST_TIMEOUT);
      this.pending.set(id, { resolve, reject, timer });
      const msg = JSON.stringify({ jsonrpc: "2.0", method, params, id }) + "\n";
      this.socket.write(msg);
    });
  }

  private onData(chunk: string): void {
    this.buffer += chunk;
    const lines = this.buffer.split("\n");
    this.buffer = lines.pop()!; // keep incomplete last line in buffer
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const msg = JSON.parse(line);
        const req = this.pending.get(msg.id);
        if (!req) continue;
        this.pending.delete(msg.id);
        clearTimeout(req.timer);
        if (msg.error) {
          req.reject(new Error(msg.error.message || JSON.stringify(msg.error)));
        } else {
          req.resolve(msg.result);
        }
      } catch {
        // ignore malformed lines
      }
    }
  }

  private rejectPending(err: Error): void {
    for (const req of this.pending.values()) {
      clearTimeout(req.timer);
      req.reject(err);
    }
    this.pending.clear();
  }
}

// Parse block timestamp from 80-byte block header hex
// Block header layout: version(4) + prevHash(32) + merkle(32) + timestamp(4) + bits(4) + nonce(4)
// Timestamp is at byte offset 68 (hex offset 136), little-endian uint32
export function parseBlockTime(headerHex: string): number {
  const timestampHex = headerHex.slice(136, 144);
  // Little-endian to number
  const bytes = Buffer.from(timestampHex, "hex");
  return bytes.readUInt32LE(0);
}

// Convert Bitcoin address to Electrum scripthash
// Reference: libnunchuk src/utils/addressutils.hpp:64-72
export function addressToScripthash(address: string, network: Network): string {
  const net = network === "mainnet" ? NETWORK : TEST_NETWORK;
  const addrCodec = Address(net);
  const decoded = addrCodec.decode(address);
  const scriptPubKey = OutScript.encode(decoded);
  const hash = sha256(scriptPubKey);
  const reversed = new Uint8Array(hash).reverse();
  return Buffer.from(reversed).toString("hex");
}
