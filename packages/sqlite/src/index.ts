import Database from "better-sqlite3"
import type {Maybe} from "@welshman/lib"
import type {IBaseStorage, IStorage, IStorageFactory} from "@pomade/core"

export type SqliteStorageFactoryOptions = {
  path: string
}

export const sqliteStorageFactory = (
  options: SqliteStorageFactoryOptions,
): IStorageFactory => {
  const db = new Database(options.path)

  // Enable WAL mode for better concurrency
  db.pragma("journal_mode = WAL")

  return <T>(name: string): IStorage<T> => {
    // Create table for this storage namespace
    db.exec(`
      CREATE TABLE IF NOT EXISTS ${name} (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
      )
    `)

    const getStmt = db.prepare(`SELECT value FROM ${name} WHERE key = ?`)
    const hasStmt = db.prepare(`SELECT 1 FROM ${name} WHERE key = ?`)
    const setStmt = db.prepare(`INSERT OR REPLACE INTO ${name} (key, value) VALUES (?, ?)`)
    const deleteStmt = db.prepare(`DELETE FROM ${name} WHERE key = ?`)
    const entriesStmt = db.prepare(`SELECT key, value FROM ${name}`)

    let lock = Promise.resolve()

    const tx = <R>(f: (s: IBaseStorage<T>) => R) => {
      const p = lock.then(() => f(storage))

      lock = p.then(() => undefined)

      return p
    }

    const storage: IBaseStorage<T> = {
      get: async (key: string): Promise<Maybe<T>> => {
        const row = getStmt.get(key) as {value: string} | undefined

        return row ? JSON.parse(row.value) : undefined
      },
      has: async (key: string): Promise<boolean> => {
        return hasStmt.get(key) !== undefined
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

    return {...storage, tx}
  }
}
