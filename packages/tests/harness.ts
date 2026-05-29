import {spawn, ChildProcess} from "node:child_process"
import {mkdtempSync, rmSync, existsSync} from "node:fs"
import {tmpdir} from "node:os"
import {join} from "node:path"
import {makeSecret} from "@welshman/util"
import type {ChallengePayload} from "@pomade/core"

const REPO_ROOT = new URL("../../", import.meta.url).pathname
const TS_SIGNER_BIN = join(REPO_ROOT, "packages/signer/dist/index.js")
const RUST_SIGNER_BIN = join(REPO_ROOT, "pomade-signer-rust/target/release/pomade-signer")
const GO_SIGNER_BIN = join(REPO_ROOT, "pomade-signer-go/bin/pomade-signer")

export type SignerKind = "ts" | "rust" | "go"

const SIGNER_BINS: Record<SignerKind, {path: string; build: string}> = {
  ts: {path: TS_SIGNER_BIN, build: "pnpm --filter @pomade/signer build"},
  rust: {
    path: RUST_SIGNER_BIN,
    build: "cargo build --release (in pomade-signer-rust/)",
  },
  go: {
    path: GO_SIGNER_BIN,
    build: "go build -o bin/pomade-signer . (in pomade-signer-go/)",
  },
}

export type SignerInstance = {
  url: string
  stop: () => void
}

function waitForPort(port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const deadline = setTimeout(
      () => reject(new Error(`Signer on port ${port} did not start in time`)),
      15_000,
    )

    const tryConnect = () => {
      fetch(`http://127.0.0.1:${port}/register`, {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: "{}",
      })
        .then(() => { clearTimeout(deadline); resolve() })
        .catch(() => setTimeout(tryConnect, 100))
    }

    setTimeout(tryConnect, 200)
  })
}

async function spawnSigner(
  kind: SignerKind,
  port: number,
  challengePayloads: ChallengePayload[],
): Promise<SignerInstance> {
  const secret = makeSecret()
  const url = `http://127.0.0.1:${port}`
  const dataDir = mkdtempSync(join(tmpdir(), `pomade-signer-${kind}-${port}-`))

  const parseLine = (line: string) => {
    const match = line.match(/\[challenge\]\s+otp=(\S+)\s+to=(\S+)/)
    if (match) challengePayloads.push({otp: match[1], email: match[2]})
  }

  let proc: ChildProcess
  if (kind === "ts") {
    proc = spawn("node", [TS_SIGNER_BIN], {
      env: {
        ...process.env,
        POMADE_SECRET: secret,
        POMADE_URL: url,
        POMADE_PORT: String(port),
        POMADE_DATABASE: join(dataDir, "signer.db"),
        TEST_MODE: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    })
  } else if (kind === "rust") {
    proc = spawn(RUST_SIGNER_BIN, [], {
      env: {
        ...process.env,
        POMADE_SECRET: secret,
        POMADE_URL: url,
        POMADE_PORT: String(port),
        POMADE_DATABASE: join(dataDir, "signer.sled"),
        TEST_MODE: "1",
        RUST_LOG: "pomade_signer=debug",
      },
      stdio: ["ignore", "pipe", "pipe"],
    })
  } else {
    proc = spawn(GO_SIGNER_BIN, [], {
      env: {
        ...process.env,
        POMADE_URL: url,
        POMADE_PORT: String(port),
        POMADE_DATABASE: join(dataDir, "signer.db"),
        POMADE_SECRET: secret,
        TEST_MODE: "1",
      },
      stdio: ["ignore", "pipe", "pipe"],
    })
  }

  const tag = `[${kind}:${port}]`

  proc.stdout?.on("data", (chunk: Buffer) => {
    for (const line of chunk.toString().split("\n")) {
      // if (line.trim()) process.stdout.write(`${tag} ${line}\n`)
      parseLine(line)
    }
  })
  proc.stderr?.on("data", (chunk: Buffer) => {
    for (const line of chunk.toString().split("\n")) {
      // if (line.trim()) process.stderr.write(`${tag} ${line}\n`)
      parseLine(line)
    }
  })

  await waitForPort(port)

  return {
    url,
    stop: () => {
      proc.kill("SIGTERM")
      try { rmSync(dataDir, {recursive: true, force: true}) } catch { /* ignore */ }
    },
  }
}

let nextPort = 14000

function allocatePort(): number {
  return nextPort++
}

export function assertSignersAvailable(specs: SignerKind[]): void {
  const missing = [...new Set(specs)]
    .map(kind => SIGNER_BINS[kind])
    .filter(bin => !existsSync(bin.path))

  if (missing.length > 0) {
    throw new Error(
      "Signer binaries are missing. Build them before running tests:\n" +
        missing.map(bin => `  - ${bin.path}\n    ${bin.build}`).join("\n"),
    )
  }
}

export async function spawnSigners(
  specs: SignerKind[],
  challengePayloads: ChallengePayload[],
): Promise<SignerInstance[]> {
  assertSignersAvailable(specs)

  return Promise.all(specs.map(kind => spawnSigner(kind, allocatePort(), challengePayloads)))
}
