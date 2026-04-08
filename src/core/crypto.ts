import nacl from "tweetnacl";

function encodeBase64(data: Uint8Array): string {
  return Buffer.from(data).toString("base64");
}

function decodeBase64(str: string): Uint8Array {
  return new Uint8Array(Buffer.from(str, "base64"));
}

// -- Keypair generation (Curve25519) --

export function generateKeypair(): { pub: string; priv: string } {
  const kp = nacl.box.keyPair();
  return { pub: encodeBase64(kp.publicKey), priv: encodeBase64(kp.secretKey) };
}

// -- Publicbox: asymmetric encryption (Curve25519 + XSalsa20-Poly1305) --
// Wire format: base64(senderPub) + "." + base64(nonce) + "." + base64(ciphertext)
// Matches libnunchuk's Publicbox::Box / Publicbox::Open exactly.

export function publicBox(
  plain: string,
  myPub: string,
  myPriv: string,
  receiverPub: string,
): string {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const message = new TextEncoder().encode(plain);
  const cipher = nacl.box(message, nonce, decodeBase64(receiverPub), decodeBase64(myPriv));
  if (!cipher) throw new Error("Encryption failed");
  return encodeBase64(decodeBase64(myPub)) + "." + encodeBase64(nonce) + "." + encodeBase64(cipher);
}

export function publicOpen(box: string, myPriv: string): string {
  const parts = box.split(".");
  if (parts.length !== 3) throw new Error("Invalid box format");
  const [senderPubB64, nonceB64, cipherB64] = parts;
  const plain = nacl.box.open(
    decodeBase64(cipherB64),
    decodeBase64(nonceB64),
    decodeBase64(senderPubB64),
    decodeBase64(myPriv),
  );
  if (!plain) throw new Error("Decryption failed");
  return new TextDecoder().decode(plain);
}

// -- Secretbox: symmetric encryption (XSalsa20-Poly1305) --
// Wire format: base64(nonce) + "." + base64(ciphertext)
// Used for wallet-level encryption (transactions, messages). Not needed for sandbox.

export function secretBox(plain: string, key: Uint8Array): string {
  const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
  const message = new TextEncoder().encode(plain);
  const cipher = nacl.secretbox(message, nonce, key);
  if (!cipher) throw new Error("Encryption failed");
  return encodeBase64(nonce) + "." + encodeBase64(cipher);
}

export function secretOpen(box: string, key: Uint8Array): string {
  const parts = box.split(".");
  if (parts.length !== 2) throw new Error("Invalid box format");
  const [nonceB64, cipherB64] = parts;
  const plain = nacl.secretbox.open(decodeBase64(cipherB64), decodeBase64(nonceB64), key);
  if (!plain) throw new Error("Decryption failed");
  return new TextDecoder().decode(plain);
}
