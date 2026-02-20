import type {Maybe} from "@welshman/lib"

export type ICollection<T> = {
  get(key: string): Promise<Maybe<T>>
  set(key: string, item: T): Promise<void>
  delete(key: string): Promise<boolean>
  entries(): Promise<Iterable<[string, T]>>
}

export type IStorage = {
  tx: <T>(f: () => Promise<T>) => Promise<T>
  collection: <T>(name: string) => ICollection<T>
}

let lock = Promise.resolve()

export const inMemoryStorage: IStorage = {
  tx: <R>(f: () => Promise<R>): Promise<R> => {
    const p = lock.then(f)

    lock = p.then(() => undefined) as Promise<void>

    return p
  },
  collection: <T>(name: string): ICollection<T> => {
    const data = new Map<string, T>()

    return {
      get: (key: string) => Promise.resolve(data.get(key)),
      set: (key: string, item: T) => (data.set(key, item), Promise.resolve()),
      delete: (key: string) => Promise.resolve(data.delete(key)),
      entries: () => Promise.resolve(data.entries()),
    }
  },
}
