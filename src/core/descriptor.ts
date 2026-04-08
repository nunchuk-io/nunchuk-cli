// Bitcoin output descriptor builder and checksum
// Reference: libnunchuk src/descriptor.cpp

const INPUT_CHARSET =
  "0123456789()[],'/*abcdefgh@:$%{}" +
  "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" +
  'ijklmnopqrstuvwxyzABCDEFGH`#"\\ ';

const CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Bitcoin descriptor checksum (PolyMod-based)
// Reference: Bitcoin Core src/script/descriptor.cpp
function polyMod(c: bigint, val: number): bigint {
  const c0 = c >> 35n;
  c = ((c & 0x7ffffffffn) << 5n) ^ BigInt(val);
  if (c0 & 1n) c ^= 0xf5dee51989n;
  if (c0 & 2n) c ^= 0xa9fdca3312n;
  if (c0 & 4n) c ^= 0x1bab10e32dn;
  if (c0 & 8n) c ^= 0x3706b1677an;
  if (c0 & 16n) c ^= 0x644d626ffdn;
  return c;
}

export function descriptorChecksum(desc: string): string {
  let c = 1n;
  let cls = 0;
  let clsCount = 0;

  for (const ch of desc) {
    const pos = INPUT_CHARSET.indexOf(ch);
    if (pos === -1) throw new Error(`Invalid descriptor character: ${ch}`);
    c = polyMod(c, pos & 31);
    cls = cls * 3 + (pos >> 5);
    clsCount++;
    if (clsCount === 3) {
      c = polyMod(c, cls);
      cls = 0;
      clsCount = 0;
    }
  }

  if (clsCount > 0) c = polyMod(c, cls);
  for (let i = 0; i < 8; i++) c = polyMod(c, 0);
  c ^= 1n;

  let result = "";
  for (let i = 0; i < 8; i++) {
    result += CHECKSUM_CHARSET[Number((c >> BigInt(5 * (7 - i))) & 31n)];
  }
  return result;
}

function addChecksum(desc: string): string {
  return `${desc}#${descriptorChecksum(desc)}`;
}

// Matches libnunchuk FormalizePath: strip leading "m", replace "h" with "'", ensure leading "/"
export function formalizePath(path: string): string {
  let rs = path;
  if (rs.startsWith("m")) rs = rs.slice(1);
  rs = rs.replaceAll("h", "'");
  if (rs.length > 0 && rs[0] !== "/") rs = "/" + rs;
  return rs;
}

// Address type integer to descriptor wrapper
// Reference: GetDescriptorForSigners in src/descriptor.cpp:280-318
interface SignerDescriptor {
  masterFingerprint: string;
  derivationPath: string;
  xpub: string;
}

export function parseSignerDescriptor(desc: string): SignerDescriptor {
  // Parse "[xfp/path]xpub" format
  const match = desc.match(/^\[([0-9a-fA-F]+)(\/[^\]]*)\](.+)$/);
  if (!match) throw new Error(`Invalid signer descriptor: ${desc}`);
  return {
    masterFingerprint: match[1],
    derivationPath: match[2],
    xpub: match[3],
  };
}

function formatSignerKey(desc: string, childPath: string): string {
  const s = parseSignerDescriptor(desc);
  return `[${s.masterFingerprint}${s.derivationPath}]${s.xpub}${childPath}`;
}

// Build wallet descriptor for DescriptorPath::EXTERNAL_INTERNAL (appends /<0;1>/*)
// This is the standard format used by mobile apps (BIP-389 multipath descriptors)
// Reference: GetDescriptorForSigners in descriptor.cpp:240-328
export function buildWalletDescriptor(signers: string[], m: number, addressType: number): string {
  return addChecksum(buildDescriptorBody(signers, m, addressType, "/<0;1>/*"));
}

// Build wallet descriptor for DescriptorPath::ANY (appends /*)
// Used as PBKDF2 input for key derivation — must match SoftwareSigner behavior
// Reference: SoftwareSigner(Wallet) in softwaresigner.cpp:97-98
export function buildAnyDescriptor(signers: string[], m: number, addressType: number): string {
  return addChecksum(buildDescriptorBody(signers, m, addressType, "/*"));
}

// Build raw descriptor body for a given child path suffix
function buildDescriptorBody(
  signers: string[],
  m: number,
  addressType: number,
  childPath: string,
): string {
  const keys = signers.map((s) => formatSignerKey(s, childPath));

  if (addressType === 3) {
    return `wsh(sortedmulti(${m},${keys.join(",")}))`;
  } else if (addressType === 2) {
    return `sh(wsh(sortedmulti(${m},${keys.join(",")})))`;
  } else if (addressType === 1) {
    return `sh(sortedmulti(${m},${keys.join(",")}))`;
  } else {
    throw new Error("Taproot descriptor not yet supported");
  }
}

// Build wallet descriptor for DescriptorPath::EXTERNAL_ALL (appends /0/*)
// Reference: GetDescriptorForSigners in descriptor.cpp
export function buildExternalDescriptor(signers: string[], m: number, addressType: number): string {
  return addChecksum(buildDescriptorBody(signers, m, addressType, "/0/*"));
}

// Derive local walletId — checksum of external descriptor (raw, no checksum suffix)
// Reference: GetWalletId in descriptor.cpp:345-349
export function getWalletId(signers: string[], m: number, addressType: number): string {
  return descriptorChecksum(buildDescriptorBody(signers, m, addressType, "/0/*"));
}

// --- Descriptor parsing (reverse of building) ---
// Reference: libnunchuk ParseOutputDescriptors (descriptor.cpp:598-626),
//            ParseSignerString (descriptor.cpp:386-401)

export interface ParsedDescriptor {
  m: number;
  n: number;
  addressType: number; // 3=NATIVE_SEGWIT, 2=NESTED_SEGWIT, 1=LEGACY
  signers: string[]; // ["[xfp/path]xpub", ...] — paths use ' notation
}

// Wrapper prefixes → addressType, ordered longest-first to avoid false matches
const WRAPPER_PREFIXES: Array<{ prefix: string; suffix: string; addressType: number }> = [
  { prefix: "sh(wsh(sortedmulti(", suffix: ")))", addressType: 2 },
  { prefix: "wsh(sortedmulti(", suffix: "))", addressType: 3 },
  { prefix: "sh(sortedmulti(", suffix: "))", addressType: 1 },
];

// Regex to strip child path suffixes from xpub: /0/*, /*, /<0;1>/*
const CHILD_PATH_SUFFIX = /(?:\/\d+\/\*|\/\*|\/<[^>]+>\/\*)$/;

/**
 * Parse a descriptor string into wallet components.
 * Accepts descriptors with any child path variant (\/*, /0/*, /<0;1>/*) and strips them.
 * Normalizes derivation paths: h → ' (to match libnunchuk FormalizePath).
 */
export function parseDescriptor(descriptor: string): ParsedDescriptor {
  // 1. Validate checksum
  const hashIdx = descriptor.lastIndexOf("#");
  if (hashIdx === -1) {
    throw new Error("Could not parse descriptor: missing checksum");
  }
  const body = descriptor.slice(0, hashIdx);
  const checksum = descriptor.slice(hashIdx + 1);
  const expected = descriptorChecksum(body);
  if (checksum !== expected) {
    throw new Error("Descriptor checksum mismatch");
  }

  // 2. Detect wrapper → addressType
  let innerContent: string | null = null;
  let addressType = 0;
  for (const w of WRAPPER_PREFIXES) {
    if (body.startsWith(w.prefix) && body.endsWith(w.suffix)) {
      innerContent = body.slice(w.prefix.length, body.length - w.suffix.length);
      addressType = w.addressType;
      break;
    }
  }
  if (innerContent === null) {
    throw new Error("Could not parse descriptor: unsupported wrapper");
  }

  // 3. Split inner content: m, key1, key2, ...
  // Keys contain commas inside brackets, so we split carefully
  const parts = splitSortedMulti(innerContent);
  if (parts.length < 2) {
    throw new Error("Could not parse descriptor: invalid sortedmulti content");
  }

  const m = parseInt(parts[0], 10);
  if (isNaN(m) || m < 1) {
    throw new Error("Could not parse descriptor: invalid m value");
  }

  // 4. Parse each signer key — reuse parseSignerDescriptor, strip child path
  const signers: string[] = [];
  for (let i = 1; i < parts.length; i++) {
    const raw = parts[i].replace(CHILD_PATH_SUFFIX, "");
    const s = parseSignerDescriptor(raw);
    const xfp = s.masterFingerprint.toLowerCase();
    const path = formalizePath(s.derivationPath); // normalize h → '
    signers.push(`[${xfp}${path}]${s.xpub}`);
  }

  return { m, n: signers.length, addressType, signers };
}

/** Split sortedmulti inner content by top-level commas (not inside brackets). */
function splitSortedMulti(content: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < content.length; i++) {
    if (content[i] === "[" || content[i] === "<") depth++;
    else if (content[i] === "]" || content[i] === ">") depth--;
    else if (content[i] === "," && depth === 0) {
      parts.push(content.slice(start, i));
      start = i + 1;
    }
  }
  parts.push(content.slice(start));
  return parts;
}

/**
 * Parse a BSMS 1.0 record.
 * Validates version, path restrictions, and first address.
 * Uses dynamic import for address.ts to avoid circular dependency.
 * Reference: libnunchuk ParseBSMSRecord() in bsms.hpp:49-79
 */
export async function parseBsmsRecord(
  content: string,
  network: import("./config.js").Network,
): Promise<ParsedDescriptor> {
  const lines = content.split(/\r?\n/).filter((l) => l.length > 0);
  if (lines.length < 4) {
    throw new Error("Invalid BSMS record: expected at least 4 lines");
  }
  if (lines[0] !== "BSMS 1.0") {
    throw new Error(`Invalid BSMS record: unsupported version "${lines[0]}"`);
  }

  const parsed = parseDescriptor(lines[1]);

  if (lines[2] !== "/0/*,/1/*" && lines[2] !== "No path restrictions") {
    throw new Error(`Invalid BSMS record: invalid path restriction "${lines[2]}"`);
  }

  // Dynamic import to avoid circular dependency (address.ts imports from descriptor.ts)
  const { deriveFirstAddress } = await import("./address.js");
  const expectedAddress = deriveFirstAddress(parsed.signers, parsed.m, parsed.addressType, network);
  if (lines[3] !== expectedAddress) {
    throw new Error("Invalid BSMS record: first address does not match descriptor");
  }

  return parsed;
}
