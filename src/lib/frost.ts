import { bytesToHex, numberToBytesBE } from "@noble/curves/abstract/utils";
import type { AffinePoint } from "@noble/curves/abstract/curve";
import { secp256k1 } from "@noble/curves/secp256k1";

const G = secp256k1.ProjectivePoint.BASE;

export type KeyShard = {
  secret: bigint;
  pubkey: AffinePoint<bigint>;
  pubShard: PubShard;
};

export type PubShard = {
  pubkey: AffinePoint<bigint>;
  vssCommit: AffinePoint<bigint>[];
  id: number;
};

type Polynomial = Array<bigint>;

export function trustedKeyDeal(
  secret: bigint,
  threshold: number,
  maxSigners: number,
): {
  shards: KeyShard[];
  pubkey: AffinePoint<bigint>;
  commits: AffinePoint<bigint>[];
} {
  let pubkey = G.multiplyUnsafe(secret).toAffine();
  if ((pubkey.y & 1n) === 1n) {
    secret = secp256k1.CURVE.n - secret;
    pubkey = G.multiplyUnsafe(secret).toAffine();
  }

  if (threshold > maxSigners || threshold <= 0) {
    throw new Error("invalid number of signers or threshold");
  }

  const polynomial = makePolynomial(secret, threshold);

  // evaluate the polynomial for each point x=1,...,n
  const shards: KeyShard[] = [];
  for (let i = 0; i < maxSigners; i++) {
    const id = i + 1;
    const yi = evaluatePolynomial(polynomial, BigInt(id));
    const pksh = G.multiplyUnsafe(yi).toAffine();

    shards.push({
      secret: yi,
      pubkey: pubkey,
      pubShard: {
        pubkey: pksh,
        vssCommit: [],
        id: id,
      },
    });
  }

  const commits = vssCommit(polynomial);

  return { shards, pubkey, commits };
}

function makePolynomial(secret: bigint, threshold: number): Polynomial {
  const polynomial: Polynomial = [];
  let i = 0;

  polynomial[0] = secret;
  i++;

  for (; i < threshold; i++) {
    const b = secp256k1.utils.randomPrivateKey();
    polynomial[i] = secp256k1.utils.normPrivateKeyToScalar(b);
  }

  return polynomial;
}

function vssCommit(polynomial: Polynomial): AffinePoint<bigint>[] {
  const commits: AffinePoint<bigint>[] = [];
  for (let p = 0; p < polynomial.length; p++) {
    const coeff = polynomial[p];
    const pt = G.multiplyUnsafe(coeff);
    commits.push(pt.toAffine());
  }
  return commits;
}

function evaluatePolynomial(polynomial: Polynomial, x: bigint): bigint {
  // since value is an accumulator and starts with 0, we can skip multiplying by x, and start from the end
  let value = polynomial[polynomial.length - 1];
  for (let i = polynomial.length - 2; i >= 0; i--) {
    value = (((value * x) % secp256k1.CURVE.n) + polynomial[i]) %
      secp256k1.CURVE.n;
  }
  return value;
}

export function hexShard(shard: KeyShard): string {
  return bytesToHex(encodeShard(shard));
}

function encodeShard(shard: KeyShard): Uint8Array {
  const out = new Uint8Array(
    6 + 33 + 33 * shard.pubShard.vssCommit.length + 32 + 33,
  );

  writePubShardTo(out, shard.pubShard);

  out.set(
    numberToBytesBE(shard.secret, 32),
    6 + 33 + shard.pubShard.vssCommit.length * 33,
  );
  writePointTo(
    out,
    6 + 33 + shard.pubShard.vssCommit.length * 33 + 32,
    shard.pubkey,
  );

  return out;
}

export function hexPubShard(pubShard: PubShard): string {
  return bytesToHex(encodePubShard(pubShard));
}

function encodePubShard(pubShard: PubShard): Uint8Array {
  const out = new Uint8Array(6 + 33 + 33 * pubShard.vssCommit.length);
  writePubShardTo(out, pubShard);
  return out;
}

function writePubShardTo(out: Uint8Array, pubShard: PubShard) {
  const dv = new DataView(out.buffer);

  dv.setUint16(0, pubShard.id, true);
  dv.setUint32(2, pubShard.vssCommit.length, true);

  writePointTo(out, 6, pubShard.pubkey);

  for (let i = 0; i < pubShard.vssCommit.length; i++) {
    const c = pubShard.vssCommit[i];
    writePointTo(out, 6 + 33 + i * 33, c);
  }
}

function writePointTo(
  out: Uint8Array,
  offset: number,
  pt: AffinePoint<bigint>,
) {
  if ((pt.y & 1n) === 1n) {
    // odd
    out[offset] = 3;
  } else {
    // event
    out[offset] = 2;
  }

  const xBytes = numberToBytesBE(pt.x, 32);
  out.set(xBytes, offset + 1);
}

