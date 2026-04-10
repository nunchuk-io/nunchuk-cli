import { describe, expect, it, vi } from "vitest";
import { ELECTRUM_BATCH_LIMIT, ElectrumClient } from "../electrum.js";

interface TestRpcRequest {
  id: number;
  params: [string];
}

describe("ElectrumClient batch calls", () => {
  it("splits large batches and preserves response order", async () => {
    const client = new ElectrumClient();
    const handleMessage = (
      client as unknown as { handleMessage(msg: unknown): void }
    ).handleMessage.bind(client);
    const writes: TestRpcRequest[][] = [];
    const socket = {
      write: vi.fn((payload: string) => {
        const requests = JSON.parse(payload) as TestRpcRequest[];
        writes.push(requests);

        for (const request of [...requests].reverse()) {
          handleMessage({
            id: request.id,
            result: [{ tx_hash: request.params[0], height: request.id }],
          });
        }
        return true;
      }),
      destroy: vi.fn(),
    };
    (client as unknown as { socket: typeof socket | null }).socket = socket;

    const hashes = Array.from({ length: ELECTRUM_BATCH_LIMIT + 1 }, (_, index) => `hash-${index}`);
    const result = await client.getHistoryBatch(hashes);

    expect(socket.write).toHaveBeenCalledTimes(2);
    expect(writes[0]).toHaveLength(ELECTRUM_BATCH_LIMIT);
    expect(writes[1]).toHaveLength(1);
    expect(result.map((history) => history[0].tx_hash)).toEqual(hashes);
  });
});
