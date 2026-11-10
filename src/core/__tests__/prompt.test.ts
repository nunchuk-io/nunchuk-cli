import { PassThrough } from "node:stream";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  isInteractiveInput,
  isInteractiveOutput,
  NotInteractiveError,
  promptSecret,
  promptYesNo,
  readSecretFromFile,
  readStdinLines,
  resolveXprvOption,
  warnSecretsOnCommandLine,
} from "../prompt.js";

type FakeStdin = PassThrough & {
  isTTY?: boolean;
  isRaw?: boolean;
  setRawMode?: (v: boolean) => void;
};

function installFakeStdin(tty: boolean): FakeStdin {
  const fake = new PassThrough() as FakeStdin;
  fake.isTTY = tty;
  fake.isRaw = false;
  fake.setRawMode = vi.fn((v: boolean) => {
    fake.isRaw = v;
  });
  Object.defineProperty(process, "stdin", { value: fake, configurable: true });
  return fake;
}

const realStdin = process.stdin;
const realStdoutIsTTY = process.stdout.isTTY;

afterEach(() => {
  Object.defineProperty(process, "stdin", { value: realStdin, configurable: true });
  Object.defineProperty(process.stdout, "isTTY", { value: realStdoutIsTTY, configurable: true });
  vi.restoreAllMocks();
});

describe("interactivity detection", () => {
  it("reports a terminal only when isTTY is exactly true", () => {
    installFakeStdin(true);
    expect(isInteractiveInput()).toBe(true);
    installFakeStdin(false);
    expect(isInteractiveInput()).toBe(false);
    Object.defineProperty(process, "stdin", { value: new PassThrough(), configurable: true });
    expect(isInteractiveInput()).toBe(false);
  });

  it("reports an output terminal from process.stdout.isTTY", () => {
    Object.defineProperty(process.stdout, "isTTY", { value: true, configurable: true });
    expect(isInteractiveOutput()).toBe(true);
    Object.defineProperty(process.stdout, "isTTY", { value: undefined, configurable: true });
    expect(isInteractiveOutput()).toBe(false);
  });
});

describe("readStdinLines", () => {
  it("returns the requested number of trimmed lines in order", async () => {
    const stdin = installFakeStdin(false);
    const pending = readStdinLines(2);
    stdin.write("  word1 word2 word3 \n");
    stdin.write("my passphrase\nignored third line\n");
    await expect(pending).resolves.toEqual(["word1 word2 word3", "my passphrase"]);
  });

  it("resolves when the stream ends with enough lines even without a trailing newline", async () => {
    const stdin = installFakeStdin(false);
    const pending = readStdinLines(1);
    stdin.end("xprv9s21ZrQH143K");
    await expect(pending).resolves.toEqual(["xprv9s21ZrQH143K"]);
  });

  it("rejects with MISSING_PARAM when the stream ends short", async () => {
    const stdin = installFakeStdin(false);
    const pending = readStdinLines(2);
    stdin.end("only one line\n");
    await expect(pending).rejects.toEqual({
      error: "MISSING_PARAM",
      message: "Expected 2 lines on standard input, got 1",
    });
  });

  it("returns an empty array for zero lines without touching stdin", async () => {
    await expect(readStdinLines(0)).resolves.toEqual([]);
  });
});

describe("promptSecret", () => {
  it("throws NotInteractiveError when stdin is not a terminal", async () => {
    installFakeStdin(false);
    await expect(promptSecret("Enter: ")).rejects.toBeInstanceOf(NotInteractiveError);
  });

  it("collects keystrokes without echoing and resolves on Enter", async () => {
    const stdin = installFakeStdin(true);
    const writeSpy = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
    const pending = promptSecret("Enter API secret key: ");
    stdin.emit("data", "s");
    stdin.emit("data", "k");
    stdin.emit("data", "_");
    stdin.emit("data", "x");
    stdin.emit("data", "\u007F"); // backspace removes the x
    stdin.emit("data", "1");
    stdin.emit("data", "\r");
    await expect(pending).resolves.toBe("sk_1");
    const written = writeSpy.mock.calls.map((c) => String(c[0])).join("");
    expect(written).toBe("Enter API secret key: \n");
    expect(stdin.setRawMode).toHaveBeenCalledWith(true);
    expect(stdin.setRawMode).toHaveBeenLastCalledWith(false);
  });
});

describe("promptYesNo", () => {
  beforeEach(() => {
    vi.spyOn(process.stdout, "write").mockImplementation(() => true);
  });

  it("throws NotInteractiveError when stdin is not a terminal", async () => {
    installFakeStdin(false);
    await expect(promptYesNo("Proceed? ")).rejects.toBeInstanceOf(NotInteractiveError);
  });

  it.each([
    ["y\n", "yes"],
    ["YES\n", "yes"],
    ["n\n", "no"],
    ["\n", "no"],
    ["anything else\n", "no"],
  ])("maps %j to %s", async (typed, expected) => {
    const stdin = installFakeStdin(true);
    const pending = promptYesNo("Proceed? [y/N] ");
    stdin.write(typed);
    await expect(pending).resolves.toBe(expected);
  });

  it("resolves timeout when nobody answers", async () => {
    vi.useFakeTimers();
    try {
      installFakeStdin(true);
      const pending = promptYesNo("Proceed? [y/N] ", 1000);
      await vi.advanceTimersByTimeAsync(1000);
      await expect(pending).resolves.toBe("timeout");
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("readSecretFromFile", () => {
  it("returns trimmed content and leaves the file unchanged", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "nunchuk-prompt-"));
    const file = path.join(dir, "seed.txt");
    fs.writeFileSync(file, "  abandon abandon about  \n", { mode: 0o600 });
    expect(readSecretFromFile(file)).toBe("abandon abandon about");
    expect(fs.readFileSync(file, "utf-8")).toBe("  abandon abandon about  \n");
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("throws FILE_NOT_FOUND for a missing file", () => {
    expect(() => readSecretFromFile("/nonexistent/seed.txt")).toThrow();
    try {
      readSecretFromFile("/nonexistent/seed.txt");
    } catch (err) {
      expect(err).toEqual({
        error: "FILE_NOT_FOUND",
        message: "Could not read file: /nonexistent/seed.txt",
      });
    }
  });
});

describe("warnSecretsOnCommandLine", () => {
  it("prints nothing when no option is listed", () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    warnSecretsOnCommandLine([], "x");
    expect(errSpy).not.toHaveBeenCalled();
  });

  it("prints exactly one line naming every option", () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    warnSecretsOnCommandLine(["--mnemonic", "--passphrase"], "the -stdin options or the prompt");
    expect(errSpy).toHaveBeenCalledTimes(1);
    expect(errSpy).toHaveBeenCalledWith(
      "Warning: --mnemonic, --passphrase on the command line: saved in shell history and visible to other processes. Use the -stdin options or the prompt instead.",
    );
  });
});

describe("resolveXprvOption", () => {
  it("rejects --xprv together with --xprv-stdin", async () => {
    await expect(resolveXprvOption({ xprv: "xprv1", xprvStdin: true })).resolves.toEqual({
      error: "Provide --xprv or --xprv-stdin, not both",
    });
  });

  it("reads the key from standard input without warning", async () => {
    const stdin = installFakeStdin(false);
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    const pending = resolveXprvOption({ xprvStdin: true });
    stdin.end("xprv9s21ZrQH143K\n");
    await expect(pending).resolves.toEqual({ xprv: "xprv9s21ZrQH143K" });
    expect(errSpy).not.toHaveBeenCalled();
  });

  it("passes a command-line --xprv through with one warning", async () => {
    const errSpy = vi.spyOn(console, "error").mockImplementation(() => {});
    await expect(resolveXprvOption({ xprv: "xprv9s21ZrQH143K" })).resolves.toEqual({
      xprv: "xprv9s21ZrQH143K",
    });
    expect(errSpy).toHaveBeenCalledTimes(1);
    expect(String(errSpy.mock.calls[0][0])).toContain("--xprv on the command line: saved");
    expect(String(errSpy.mock.calls[0][0])).not.toContain("xprv9s21ZrQH143K");
  });

  it("returns undefined when neither option is given", async () => {
    await expect(resolveXprvOption({})).resolves.toEqual({ xprv: undefined });
  });
});
