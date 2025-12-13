import type {Maybe} from "@welshman/lib"

export type IBaseStorage<T> = {
  get(key: string): Promise<Maybe<T>>
  has(key: string): Promise<boolean>
  set(key: string, item: T): Promise<void>
  delete(key: string): Promise<boolean>
  entries(): Promise<Iterable<[string, T]>>
}

export type IStorage<T> = IBaseStorage<T> & {
  tx<R>(f: (s: IBaseStorage<T>) => R): Promise<R>
}

export type IStorageFactory = <T>(name: string) => IStorage<T>

export const defaultStorageFactory = <T>(name: string) => {
  const data = new Map<string, T>()

  let lock = Promise.resolve()

  const tx = <R>(f: (s: IBaseStorage<T>) => R) => {
    const p = lock.then(() => f(storage))

    lock = p.then(() => undefined)

    return lock
  }

  const storage: IBaseStorage<T> = {
    get: (key: string) => Promise.resolve(data.get(key)),
    has: (key: string) => Promise.resolve(data.has(key)),
    set: (key: string, item: T) => {
      data.set(key, item)

      return Promise.resolve()
    },
    delete: (key: string) => Promise.resolve(data.delete(key)),
    entries: () => Promise.resolve(data.entries()),
  }

  return {...storage, tx}
}
