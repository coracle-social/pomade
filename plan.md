I am building a headless multisig hosted signer protocol for sharding secp256k1 secret keys, sharing them with signers, logging in with email/password, and recovering keys by email in a trustless way using homomorphic encryption.

- A _client_ is a end-user application that is trusted to handle, but not to store the user's private key
- A _coordinator_ is a headless application trusted to coordinate multi-party signing but not handle the user's private key
- A _signer_ is a headless application trusted to store a shard of the user's private key
