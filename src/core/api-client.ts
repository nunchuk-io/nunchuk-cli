import type { Network } from "./config.js";

const BASE_URLS: Record<Network, string> = {
  mainnet: "https://api.nunchuk.io",
  testnet: "https://api-testnet.nunchuk.io",
};

export interface ApiError {
  error: string;
  message: string;
}

export class ApiClient {
  private apiKey: string;
  private baseUrl: string;

  constructor(apiKey: string, network: Network) {
    this.apiKey = apiKey;
    this.baseUrl = BASE_URLS[network];
  }

  async get<T>(path: string): Promise<T> {
    return this.request("GET", path);
  }

  async post<T>(path: string, body?: string): Promise<T> {
    return this.request("POST", path, body);
  }

  async del<T>(path: string, body?: string): Promise<T> {
    return this.request("DELETE", path, body);
  }

  async getMe(): Promise<{ id: string; email: string; name: string }> {
    const result = await this.get<{ user: { id: string; email: string; name: string } }>(
      "/v1.1/developer/me",
    );
    return result.user;
  }

  private async request<T>(method: string, path: string, body?: string): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const headers: Record<string, string> = {
      "Api-Key": this.apiKey,
      "Content-Type": "application/json",
    };

    let response: Response;
    try {
      response = await fetch(url, {
        method,
        headers,
        body: body ?? undefined,
      });
    } catch {
      throw {
        error: "NETWORK_ERROR",
        message: `Failed to reach Nunchuk API at ${this.baseUrl}. Check network access and try again.`,
      } as ApiError;
    }

    const text = await response.text();
    let parsed = {} as {
      data?: T;
      error?: { code?: number | string; message?: string };
    };
    try {
      parsed = text ? (JSON.parse(text) as typeof parsed) : {};
    } catch {
      parsed = {};
    }

    if (parsed.error && parsed.error.code != null && Number(parsed.error.code) !== 0) {
      throw {
        error: String(parsed.error.code),
        message: parsed.error.message || text || response.statusText || "Request failed",
      } as ApiError;
    }

    if (!response.ok) {
      throw {
        error: String(response.status || "HTTP_ERROR"),
        message: text || response.statusText || "Request failed",
      } as ApiError;
    }

    return parsed.data as T;
  }
}
