import sqlite3 from "sqlite3"
import type {ICollection, IStorage} from "@pomade/core"
import type {ISigner} from "@welshman/signer"

export type SqliteStorageOptions = {
  path: string
  signer: ISigner
}

export const sqliteStorage = (
  options: SqliteStorageOptions,
): IStorage => {
  const db = new sqlite3.Database(options.path)

  // Enable WAL mode for better concurrency
  db.run("PRAGMA journal_mode = WAL")

  const encrypt = async (data: any) => {
    return options.signer.nip44.encrypt(await options.signer.getPubkey(), JSON.stringify(data))
  }

  const decrypt = async <T>(data: string): Promise<T> => {
    return JSON.parse(await options.signer.nip44.decrypt(await options.signer.getPubkey(), data))
  }

  const dbRun = (sql: string): Promise<void> => {
    return new Promise((resolve, reject) => {
      db.run(sql, (err: Error | null) => {
        if (err) reject(err)
        else resolve()
      })
    })
  }

  // Transaction queue to prevent nested transactions
  let txQueue: Promise<void> = Promise.resolve()

  return {
    tx: async <R>(f: () => Promise<R>): Promise<R> => {
      // Queue this transaction to run after previous ones complete
      const result = txQueue.then(async () => {
        await dbRun("BEGIN")
        try {
          const result = await f()
          await dbRun("COMMIT")
          return result
        } catch (error) {
          await dbRun("ROLLBACK")
          throw error
        }
      })

      // Update queue to include this transaction (but catch errors so queue continues)
      txQueue = result.then(() => undefined, () => undefined)

      return result
    },
    collection: <T>(name: string): ICollection<T> => {
      // Create table synchronously on first access
      db.exec(`
        CREATE TABLE IF NOT EXISTS ${name} (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        )
      `)

      // Prepare statements
      const getStmt = db.prepare(`SELECT value FROM ${name} WHERE key = ?`)
      const setStmt = db.prepare(`INSERT OR REPLACE INTO ${name} (key, value) VALUES (?, ?)`)
      const deleteStmt = db.prepare(`DELETE FROM ${name} WHERE key = ?`)
      const entriesStmt = db.prepare(`SELECT key, value FROM ${name}`)

      return {
        get: async (key: string): Promise<T | undefined> => {
          return new Promise((resolve, reject) => {
            getStmt.get(key, (err: Error | null, row: {value: string} | undefined) => {
              if (err) reject(err)
              else resolve(row ? decrypt<T>(row.value) : undefined)
            })
          })
        },
        set: async (key: string, item: T): Promise<void> => {
          const data = await encrypt(item)

          return new Promise((resolve, reject) => {
            setStmt.run(key, data, (err: Error | null) => {
              if (err) reject(err)
              else resolve()
            })
          })
        },
        delete: async (key: string): Promise<boolean> => {
          return new Promise((resolve, reject) => {
            deleteStmt.run(key, function(this: sqlite3.RunResult, err: Error | null) {
              if (err) reject(err)
              else resolve(this.changes > 0)
            })
          })
        },
        entries: async (): Promise<Iterable<[string, T]>> => {
          return new Promise((resolve, reject) => {
            entriesStmt.all(async (err: Error | null, rows: Array<{key: string; value: string}>) => {
              if (err) {
                reject(err)
              } else {
                try {
                  resolve(
                    await Promise.all(
                      rows.map(async row => [row.key, await decrypt<T>(row.value)] as [string, T])
                    )
                  )
                } catch (error) {
                  reject(error)
                }
              }
            })
          })
        },
      }
    },
  }
}
