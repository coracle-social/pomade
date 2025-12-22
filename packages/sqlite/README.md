# @pomade/sqlite

SQLite storage adapter for pomade.

## Installation

```bash
npm install @pomade/sqlite
```

## Usage

```typescript
import {sqliteStorageFactory} from "@pomade/sqlite"

const storageFactory = sqliteStorageFactory({
  path: "./data.db",
})

// Use with pomade signer
const storage = storageFactory("my-storage")

await storage.set("key", {some: "value"})
const value = await storage.get("key")
```

## Features

- Persistent SQLite storage
- WAL mode for better concurrency
- Transaction support via `tx()` method
- Type-safe storage with TypeScript
