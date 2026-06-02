import { Command } from "commander";
import { afterEach, describe, expect, it, vi } from "vitest";

async function runMiniscriptCommand(args: string[]): Promise<void> {
  const { miniscriptCommand } = await import("../miniscript.js");
  const root = new Command();
  root.exitOverride();
  root.addCommand(miniscriptCommand);
  await root.parseAsync(args, { from: "user" });
}

describe("miniscript inspect", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("shows taproot key path separately from script paths", async () => {
    const output: string[] = [];
    vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
      output.push(args.join(" "));
    });

    await runMiniscriptCommand([
      "miniscript",
      "inspect",
      "--miniscript",
      "tr(A,thresh(3,pk(B),s:pk(C),s:pk(D),sln:older(1)))",
      "--address-type",
      "TAPROOT",
    ]);

    const text = output.join("\n");
    expect(text).toContain("key-path");
    expect(text).toContain("A");
    expect(text).toContain("B,C,D");
  });
});
