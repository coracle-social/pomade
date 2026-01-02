import Database from "better-sqlite3"
import type {ICollection, IStorage} from "@pomade/core"

export type SqliteStorageOptions = {
  path: string
}

export const sqliteStorage = (
  options: SqliteStorageOptions,
): IStorage => {
  const db = new Database(options.path)

  db.pragma("journal_mode = WAL")

  let lock = Promise.resolve()

  return {
    tx: <R>(f: () => Promise<R>) => {
      const p = lock.then(f)

      lock = p.then(() => undefined)

      return p
    },
    collection: <T>(name: string): ICollection<T> => {
      db.exec(`
        CREATE TABLE IF NOT EXISTS ${name} (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        )
      `)

      const getStmt = db.prepare(`SELECT value FROM ${name} WHERE key = ?`)
      const setStmt = db.prepare(`INSERT OR REPLACE INTO ${name} (key, value) VALUES (?, ?)`)
      const deleteStmt = db.prepare(`DELETE FROM ${name} WHERE key = ?`)
      const entriesStmt = db.prepare(`SELECT key, value FROM ${name}`)

      return {
        get: async (key: string): Promise<T | undefined> => {
          const row = getStmt.get(key) as {value: string} | undefined

          return row ? JSON.parse(row.value) : undefined
        },
        set: async (key: string, item: T): Promise<void> => {
          setStmt.run(key, JSON.stringify(item))
        },
        delete: async (key: string): Promise<boolean> => {
          const result = deleteStmt.run(key)

          return result.changes > 0
        },
        entries: async (): Promise<Iterable<[string, T]>> => {
          const rows = entriesStmt.all() as Array<{key: string; value: string}>

          return rows.map(row => [row.key, JSON.parse(row.value)])
        },
      }
    },
  }
}
