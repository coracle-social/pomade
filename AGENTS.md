## Commands

For commands, refer to the justfile.

## Coding conventions

### Return values

Avoid naming return values, just return them:

BAD:

```typescript
const result = await rpc.post<RecoveryStartResult>(`${url}/recovery/start`, {auth})
return {result, url}
```

GOOD:

```typescript
return rpc.post<RecoveryStartResult>(`${url}/recovery/start`, {auth})
```

### Avoid Any

Avoid using `any` - if any is necessary, that means the upstream source of the value is not type-safe

BAD:

```typescript
// This is only necessary if results is unknown
results.every(r => (r as any)?.ok)
```

GOOD:

```typescript
// If results is defined, we know what r is
results.every(r => r?.ok)
```

### Ad-hoc types

Avoid ad-hoc types. Types should be named semantically in most cases, but especially when used in a function signature.

BAD:

```typescript
static _buildOptions<T extends {ok: boolean; items?: {client: string; idx: number; total: number; threshold: number}[]}>(
  clientSecret: string,
  messages: Maybe<{result: T; url: string}>[],
  threshold: "total" | "threshold",
): ClientOptionsResult<T> {
  // snip
}
```

GOOD:

```typescript
type WrappedMessage<T> = Maybe<{
  result: T
  url: string
}>

static _buildOptions<T extends LoginStartResult | RecoveryStartResult>(
  clientSecret: string,
  messages: WrappedMessage<T>[],
  threshold: "total" | "threshold",
): ClientOptionsResult<T> {
  // snip
}
```


### Useless comments

Avoid adding comments that are obvious if the reader understands the data model. Comments should be reserved for truly meaningful information.

BAD:

```typescript
export type ClientOptions = {
  group: GroupPackage
  secret: string
  peers: string[] // signer URLs
}
```

GOOD:

```typescript
export type ClientOptions = {
  group: GroupPackage
  secret: string
  peers: string[]
}
```

## Cryptographic conventions

### FROST session-nonce tweak is additive

The per-session nonce tweak (`tweak_seckey` / `tweak_pubkey`) is **additive**, not
multiplicative:

- `tweak_seckey(sk, t) = (sk + t) mod N`
- `tweak_pubkey(P, t) = P + t*G`

This is consistent across all three signer implementations and the reference
`@frostr/bifrost`:

- TS reference: bifrost's own `tweak_seckey` (`FD.add(sk, twk)`) — used by
  `create_sighash_share`
- Go: `frost-taproot-go/helpers/helpers.go` `TweakSeckey`/`TweakPubkey`
- Rust: `frost-taproot-rust/src/helpers.rs` `tweak_seckey`/`tweak_pubkey`

Gotcha: the transitive dependency `@cmdcode/frost` defines a *multiplicative*
`tweak_seckey` (`mod_n(sk * t)`), but bifrost does **not** use it for session-nonce
tweaking — it defines and uses its own additive version. Do not "fix" Go/Rust to be
multiplicative to match `@cmdcode/frost`; they correctly match bifrost. Both
conventions are internally self-consistent (`(sk+t)*G == sk*G + t*G`), so a mismatch
would silently produce invalid aggregate signatures rather than an obvious error.
