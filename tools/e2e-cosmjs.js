// End-to-end: real @cosmjs/ledger-amino LedgerSigner  ->  NNChain app on Speculos (Flex)
const net = require("net");
const { LedgerSigner } = require("@cosmjs/ledger-amino");
const { makeSignDoc, serializeSignDoc, makeCosmoshubPath } = require("@cosmjs/amino");
const { Secp256k1, Secp256k1Signature, sha256 } = require("@cosmjs/crypto");
const { fromBase64 } = require("@cosmjs/encoding");
const { TransportStatusError } = require("@ledgerhq/errors");

const API = "http://127.0.0.1:5000";

class SpeculosTransport {
  constructor(sock) {
    this.sock = sock;
    this.buf = Buffer.alloc(0);
    this.waiter = null;
    sock.on("data", (d) => {
      this.buf = Buffer.concat([this.buf, d]);
      this._try();
    });
  }
  _try() {
    if (!this.waiter || this.buf.length < 4) return;
    const len = this.buf.readUInt32BE(0);
    if (this.buf.length < 4 + len + 2) return;
    const out = this.buf.subarray(4, 4 + len + 2);
    this.buf = this.buf.subarray(4 + len + 2);
    const w = this.waiter;
    this.waiter = null;
    w(out);
  }
  exchange(apdu) {
    return new Promise((resolve) => {
      this.waiter = resolve;
      const hdr = Buffer.alloc(4);
      hdr.writeUInt32BE(apdu.length, 0);
      this.sock.write(Buffer.concat([hdr, apdu]));
      this._try();
    });
  }
  async send(cla, ins, p1, p2, data = Buffer.alloc(0), statusList = [0x9000]) {
    const apdu = Buffer.concat([Buffer.from([cla, ins, p1, p2, data.length]), Buffer.from(data)]);
    const resp = await this.exchange(apdu);
    const sw = resp.readUInt16BE(resp.length - 2);
    if (!statusList.includes(sw)) throw new TransportStatusError(sw);
    return resp;
  }
  setScrambleKey() {}
  async close() { this.sock.destroy(); }
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function post(path, body) {
  await fetch(API + path, { method: "POST", body: JSON.stringify(body) });
}
async function screen() {
  const r = await fetch(API + "/events?currentscreenonly=true");
  return (await r.json()).events || [];
}

// Taps through review pages and holds the "Hold to sign" button.
let approving = true;
async function approver() {
  let holds = 0;
  while (approving) {
    const ev = await screen();
    const texts = ev.map((e) => e.text);
    const hold = ev.find((e) => /Hold to sign/i.test(e.text));
    const confirm = ev.find((e) => /^Confirm$/.test(e.text));
    if (hold) {
      await post("/finger", { action: "press", x: hold.x + 20, y: hold.y + 10 });
      await sleep(3500);
      await post("/finger", { action: "release", x: hold.x + 20, y: hold.y + 10 });
      holds++;
      await sleep(800);
    } else if (confirm) {
      await post("/finger", { action: "press-and-release", x: confirm.x + 10, y: confirm.y + 10 });
      await sleep(800);
    } else if (texts.some((t) => /Reject/.test(t))) {
      await post("/finger", { action: "press-and-release", x: 430, y: 550 }); // next page
      await sleep(500);
    } else if (texts.some((t) => /Tap to continue|Review|Verify/i.test(t))) {
      await post("/finger", { action: "press-and-release", x: 240, y: 300 });
      await sleep(500);
    } else {
      await sleep(300);
    }
  }
}

(async () => {
  const sock = net.connect(9999, "127.0.0.1");
  await new Promise((r) => sock.once("connect", r));
  const transport = new SpeculosTransport(sock);

  const signer = new LedgerSigner(transport, {
    hdPaths: [makeCosmoshubPath(0)],
    prefix: "nnc",
    ledgerAppName: "NNChain",
    minLedgerAppVersion: "0.1.0",
  });

  const [account] = await signer.getAccounts();
  console.log("address :", account.address);
  console.log("pubkey  :", Buffer.from(account.pubkey).toString("hex"));

  const doc = makeSignDoc(
    [
      {
        type: "cosmos-sdk/MsgSend",
        value: {
          from_address: account.address,
          to_address: "nnc1qn4f9f45wf2u8gs3nzqws2d2gm8gjtgh4zqnc6",
          amount: [{ denom: "nnc", amount: "2500000" }],
        },
      },
    ],
    { amount: [{ denom: "nnc", amount: "12500" }], gas: "500000" },
    "nnchain-mainnet-1",
    "cosmjs e2e <test> & more",
    "42",
    "7",
  );

  approving = true;
  const ap = approver();
  const t0 = Date.now();
  const { signed, signature } = await signer.signAmino(account.address, doc);
  approving = false;
  await ap;
  console.log("signed in", Date.now() - t0, "ms");

  const bytes = serializeSignDoc(signed);
  const ok = await Secp256k1.verifySignature(
    Secp256k1Signature.fromFixedLength(fromBase64(signature.signature)),
    sha256(bytes),
    account.pubkey,
  );
  const sameDoc = JSON.stringify(signed) === JSON.stringify(doc);
  const s = Secp256k1Signature.fromFixedLength(fromBase64(signature.signature));
  const HALF = BigInt("0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0");
  const lowS = BigInt("0x" + Buffer.from(s.s()).toString("hex")) <= HALF;
  console.log("signature verifies against device pubkey:", ok);
  console.log("signed doc identical to requested doc  :", sameDoc);
  console.log("low-S                                   :", lowS);
  console.log("RESULT:", ok && sameDoc && lowS ? "PASS" : "FAIL");
  await transport.close();
  process.exit(ok && sameDoc && lowS ? 0 : 1);
})().catch((e) => {
  console.error("ERROR", e);
  process.exit(2);
});
