import type {MaybeAsync} from "@welshman/lib"

export type IStorage<T> = {
  get(key: string): MaybeAsync<T>
  has(key: string): MaybeAsync<boolean>
  set(key: string, item: T): MaybeAsync<undefined>
  delete(key: string): MaybeAsync<undefined>
  entries(): MaybeAsync<Iterable<[string, T]>>
}

export type IStorageFactory = <T>(name: string) => IStorage<T>

export const defaultStorageFactory = <T>(name: string) => new Map<string, T>()
