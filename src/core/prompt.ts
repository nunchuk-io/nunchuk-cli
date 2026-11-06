// Secret input and confirmation helpers.
//
// Secrets (API keys, seed phrases, extended private keys, BIP39 passphrases)
// should not travel on the command line: arguments are visible to every process
// on the machine, saved in shell history, and recorded by agent runtimes. These
// helpers provide the alternatives: a masked prompt at an interactive terminal,
// standard input, and a file. They also detect whether a human is present so a
// prompt is only shown when it can be answered.

import * as fs from "node:fs";

/** True when standard input is a keyboard (interactive terminal), not a pipe or file. */
export function isInteractiveInput(): boolean {
  return process.stdin.isTTY === true;
}

/** True when standard output goes to a terminal screen, not a pipe or file. */
export function isInteractiveOutput(): boolean {
  return process.stdout.isTTY === true;
}

export class NotInteractiveError extends Error {
  readonly error = "NOT_INTERACTIVE";
  constructor(message = "Standard input is not an interactive terminal") {
    super(message);
    this.name = "NotInteractiveError";
  }
}

/**
 * Ask for a secret at the terminal without echoing the keystrokes.
 * Throws NotInteractiveError when standard input is not a terminal; callers
 * must check isInteractiveInput() first and offer a non-interactive channel.
 */
export async function promptSecret(prompt: string): Promise<string> {
  if (!isInteractiveInput()) {
    throw new NotInteractiveError();
  }
  process.stdout.write(prompt);
  return new Promise((resolve) => {
    const stdin = process.stdin;
    const wasRaw = stdin.isRaw;
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf-8");

    let input = "";
    const onData = (ch: string) => {
      if (ch === "\r" || ch === "\n") {
        stdin.setRawMode(wasRaw ?? false);
        stdin.pause();
        stdin.removeListener("data", onData);
        process.stdout.write("\n");
        resolve(input.trim());
      } else if (ch === "\u007F" || ch === "\b") {
        // backspace
        if (input.length > 0) {
          input = input.slice(0, -1);
        }
      } else if (ch === "\u0003") {
        // Ctrl+C
        process.exit(0);
      } else {
        input += ch;
      }
    };
    stdin.on("data", onData);
  });
}

export type YesNoAnswer = "yes" | "no" | "timeout";

/**
 * Ask a yes/no question at an interactive terminal. Anything other than
 * "y"/"yes" (case-insensitive) is "no". Resolves "timeout" when no answer
 * arrives in time, so a pseudo-terminal with nobody behind it cannot hang
 * the caller forever.
 */
export async function promptYesNo(question: string, timeoutMs = 60_000): Promise<YesNoAnswer> {
  if (!isInteractiveInput()) {
    throw new NotInteractiveError();
  }
  process.stdout.write(question);
  return new Promise((resolve) => {
    const stdin = process.stdin;
    let buffer = "";
    const finish = (answer: YesNoAnswer) => {
      clearTimeout(timer);
      stdin.removeListener("data", onData);
      stdin.pause();
      resolve(answer);
    };
    const onData = (chunk: string | Buffer) => {
      buffer += chunk.toString();
      const newline = buffer.indexOf("\n");
      if (newline === -1) return;
      const line = buffer.slice(0, newline).trim().toLowerCase();
      finish(line === "y" || line === "yes" ? "yes" : "no");
    };
    const timer = setTimeout(() => {
      process.stdout.write("\n");
      finish("timeout");
    }, timeoutMs);
    stdin.setEncoding("utf-8");
    stdin.resume();
    stdin.on("data", onData);
  });
}

/**
 * Read `count` lines from standard input, in order, each trimmed. Resolves as
 * soon as enough lines have arrived, or when the stream ends. Rejects when the
 * stream ends with fewer non-empty lines than requested.
 */
export async function readStdinLines(count: number): Promise<string[]> {
  if (count <= 0) return [];
  return new Promise((resolve, reject) => {
    const stdin = process.stdin;
    let buffer = "";
    const settle = (done: boolean) => {
      const lines = buffer
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter((l) => l.length > 0);
      if (lines.length >= count) {
        cleanup();
        resolve(lines.slice(0, count));
        return true;
      }
      if (done) {
        cleanup();
        reject({
          error: "MISSING_PARAM",
          message: `Expected ${count} line${count === 1 ? "" : "s"} on standard input, got ${lines.length}`,
        });
        return true;
      }
      return false;
    };
    const onData = (chunk: string | Buffer) => {
      buffer += chunk.toString();
      settle(false);
    };
    const onEnd = () => {
      settle(true);
    };
    const cleanup = () => {
      stdin.removeListener("data", onData);
      stdin.removeListener("end", onEnd);
      stdin.pause();
    };
    stdin.setEncoding("utf-8");
    stdin.on("data", onData);
    stdin.on("end", onEnd);
    stdin.resume();
  });
}

/** Read a secret from a file. The whole content is trimmed; the file is never modified. */
export function readSecretFromFile(filePath: string): string {
  try {
    return fs.readFileSync(filePath, "utf-8").trim();
  } catch {
    throw { error: "FILE_NOT_FOUND", message: `Could not read file: ${filePath}` };
  }
}

/**
 * One warning line, on standard error, when non-revocable secrets were passed
 * on the command line. Standard output is untouched so --json consumers are
 * unaffected. Called once per invocation with every offending option.
 */
export function warnSecretsOnCommandLine(options: string[], alternative: string): void {
  if (options.length === 0) return;
  console.error(
    `Warning: ${options.join(", ")} on the command line: saved in shell history and visible to other processes. Use ${alternative} instead.`,
  );
}

// Resolve the signing key options shared by `tx sign` and dummy-tx signing:
// `--xprv-stdin` reads the key from standard input; a plain `--xprv` still works
// but earns a warning because command-line arguments are visible and logged.
export async function resolveXprvOption(options: {
  xprv?: string;
  xprvStdin?: boolean;
}): Promise<{ xprv?: string } | { error: string }> {
  if (options.xprv && options.xprvStdin) {
    return { error: "Provide --xprv or --xprv-stdin, not both" };
  }
  if (options.xprvStdin) {
    const [xprv] = await readStdinLines(1);
    return { xprv };
  }
  if (options.xprv) {
    warnSecretsOnCommandLine(["--xprv"], "--xprv-stdin or a stored key (--fingerprint)");
  }
  return { xprv: options.xprv };
}
