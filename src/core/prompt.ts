/** Prompt the user for a secret on stdin, hiding typed characters. */
export async function promptSecret(prompt: string): Promise<string> {
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
