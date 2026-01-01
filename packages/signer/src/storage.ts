import Database from "better-sqlite3"
import type {
  SignerStorage,
  SignerSession,
  SignerLogin,
  SignerRecovery,
  SignerChallenge,
} from "@pomade/core"

export type SqliteStorageOptions = {
  path: string
}

export const createSqliteStorage = (options: SqliteStorageOptions): SignerStorage => {
  const db = new Database(options.path)

  // Enable WAL mode for better concurrency
  db.pragma("journal_mode = WAL")

  // Create tables for each storage type
  db.exec(`
    CREATE TABLE IF NOT EXISTS sessions (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `)

  db.exec(`
    CREATE TABLE IF NOT EXISTS logins (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `)

  db.exec(`
    CREATE TABLE IF NOT EXISTS recoveries (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `)

  db.exec(`
    CREATE TABLE IF NOT EXISTS challenges (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `)

  // Create indexes for efficient querying
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_sessions_email
    ON sessions((json_extract(value, '$.email')))
    WHERE json_extract(value, '$.email') IS NOT NULL
  `)

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_sessions_email_hash
    ON sessions((json_extract(value, '$.email_hash')))
    WHERE json_extract(value, '$.email_hash') IS NOT NULL
  `)

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_sessions_password
    ON sessions((json_extract(value, '$.password')))
    WHERE json_extract(value, '$.password') IS NOT NULL
  `)

  // Prepared statements for sessions
  const sessionGetStmt = db.prepare(`SELECT value FROM sessions WHERE key = ?`)
  const sessionHasStmt = db.prepare(`SELECT 1 FROM sessions WHERE key = ?`)
  const sessionSetStmt = db.prepare(`INSERT OR REPLACE INTO sessions (key, value) VALUES (?, ?)`)
  const sessionDeleteStmt = db.prepare(`DELETE FROM sessions WHERE key = ?`)
  const sessionEntriesStmt = db.prepare(`SELECT key, value FROM sessions`)
  const sessionByEmailStmt = db.prepare(
    `SELECT value FROM sessions WHERE json_extract(value, '$.email') = ?`
  )
  const sessionByEmailHashStmt = db.prepare(
    `SELECT value FROM sessions WHERE json_extract(value, '$.email_hash') = ?`
  )
  const sessionByPasswordStmt = db.prepare(
    `SELECT value FROM sessions WHERE json_extract(value, '$.password') = ?`
  )

  // Prepared statements for logins
  const loginGetStmt = db.prepare(`SELECT value FROM logins WHERE key = ?`)
  const loginHasStmt = db.prepare(`SELECT 1 FROM logins WHERE key = ?`)
  const loginSetStmt = db.prepare(`INSERT OR REPLACE INTO logins (key, value) VALUES (?, ?)`)
  const loginDeleteStmt = db.prepare(`DELETE FROM logins WHERE key = ?`)
  const loginEntriesStmt = db.prepare(`SELECT key, value FROM logins`)

  // Prepared statements for recoveries
  const recoveryGetStmt = db.prepare(`SELECT value FROM recoveries WHERE key = ?`)
  const recoveryHasStmt = db.prepare(`SELECT 1 FROM recoveries WHERE key = ?`)
  const recoverySetStmt = db.prepare(`INSERT OR REPLACE INTO recoveries (key, value) VALUES (?, ?)`)
  const recoveryDeleteStmt = db.prepare(`DELETE FROM recoveries WHERE key = ?`)
  const recoveryEntriesStmt = db.prepare(`SELECT key, value FROM recoveries`)

  // Prepared statements for challenges
  const challengeGetStmt = db.prepare(`SELECT value FROM challenges WHERE key = ?`)
  const challengeHasStmt = db.prepare(`SELECT 1 FROM challenges WHERE key = ?`)
  const challengeSetStmt = db.prepare(`INSERT OR REPLACE INTO challenges (key, value) VALUES (?, ?)`)
  const challengeDeleteStmt = db.prepare(`DELETE FROM challenges WHERE key = ?`)
  const challengeEntriesStmt = db.prepare(`SELECT key, value FROM challenges`)

  // Top-level transaction management
  let lock = Promise.resolve()

  const tx = async (f: () => Promise<void>): Promise<void> => {
    const p = lock.then(async () => {
      const txn = db.transaction(f)
      return txn()
    })

    lock = p.then(() => undefined, () => undefined)

    return p
  }

  return {
    tx,
    session: {
      get: async (key: string): Promise<SignerSession | undefined> => {
        const row = sessionGetStmt.get(key) as {value: string} | undefined
        return row ? JSON.parse(row.value) : undefined
      },
      has: async (key: string): Promise<boolean> => {
        return sessionHasStmt.get(key) !== undefined
      },
      set: async (key: string, item: SignerSession): Promise<void> => {
        sessionSetStmt.run(key, JSON.stringify(item))
      },
      delete: async (key: string): Promise<void> => {
        sessionDeleteStmt.run(key)
      },
      entries: async (): Promise<Iterable<[string, SignerSession]>> => {
        const rows = sessionEntriesStmt.all() as Array<{key: string; value: string}>
        return rows.map(row => [row.key, JSON.parse(row.value)])
      },
      forEmail: async (email: string): Promise<SignerSession[]> => {
        const rows = sessionByEmailStmt.all(email) as Array<{value: string}>
        return rows.map(row => JSON.parse(row.value))
      },
      forEmailHash: async (email_hash: string): Promise<SignerSession[]> => {
        const rows = sessionByEmailHashStmt.all(email_hash) as Array<{value: string}>
        return rows.map(row => JSON.parse(row.value))
      },
      forPassword: async (password: string): Promise<SignerSession[]> => {
        const rows = sessionByPasswordStmt.all(password) as Array<{value: string}>
        return rows.map(row => JSON.parse(row.value))
      },
    },
    login: {
      get: async (key: string): Promise<SignerLogin | undefined> => {
        const row = loginGetStmt.get(key) as {value: string} | undefined
        return row ? JSON.parse(row.value) : undefined
      },
      has: async (key: string): Promise<boolean> => {
        return loginHasStmt.get(key) !== undefined
      },
      set: async (key: string, item: SignerLogin): Promise<void> => {
        loginSetStmt.run(key, JSON.stringify(item))
      },
      delete: async (key: string): Promise<void> => {
        loginDeleteStmt.run(key)
      },
      entries: async (): Promise<Iterable<[string, SignerLogin]>> => {
        const rows = loginEntriesStmt.all() as Array<{key: string; value: string}>
        return rows.map(row => [row.key, JSON.parse(row.value)])
      },
    },
    recovery: {
      get: async (key: string): Promise<SignerRecovery | undefined> => {
        const row = recoveryGetStmt.get(key) as {value: string} | undefined
        return row ? JSON.parse(row.value) : undefined
      },
      has: async (key: string): Promise<boolean> => {
        return recoveryHasStmt.get(key) !== undefined
      },
      set: async (key: string, item: SignerRecovery): Promise<void> => {
        recoverySetStmt.run(key, JSON.stringify(item))
      },
      delete: async (key: string): Promise<void> => {
        recoveryDeleteStmt.run(key)
      },
      entries: async (): Promise<Iterable<[string, SignerRecovery]>> => {
        const rows = recoveryEntriesStmt.all() as Array<{key: string; value: string}>
        return rows.map(row => [row.key, JSON.parse(row.value)])
      },
    },
    challenge: {
      get: async (key: string): Promise<SignerChallenge | undefined> => {
        const row = challengeGetStmt.get(key) as {value: string} | undefined
        return row ? JSON.parse(row.value) : undefined
      },
      has: async (key: string): Promise<boolean> => {
        return challengeHasStmt.get(key) !== undefined
      },
      set: async (key: string, item: SignerChallenge): Promise<void> => {
        challengeSetStmt.run(key, JSON.stringify(item))
      },
      delete: async (key: string): Promise<void> => {
        challengeDeleteStmt.run(key)
      },
      entries: async (): Promise<Iterable<[string, SignerChallenge]>> => {
        const rows = challengeEntriesStmt.all() as Array<{key: string; value: string}>
        return rows.map(row => [row.key, JSON.parse(row.value)])
      },
    },
  }
}
