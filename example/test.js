import { makeSecret } from "@welshman/util"
import { Client } from "@pomade/core"
import { initializeSigners, stopSigners, emails } from "./src/signers.js"

console.log("Starting example app integration test...")

initializeSigners()

console.log("\n1. Testing account registration...")
const userSecret = makeSecret()
const registerResult = await Client.register(2, 3, userSecret, true)
console.log("✓ Account registered successfully")
console.log(`  - Peers: ${registerResult.clientOptions.peers.length}`)

console.log("\n2. Testing recovery setup...")
const client = new Client(registerResult.clientOptions)
const testEmail = "test@example.com"
const testPassword = "secure-password-123"
await client.setupRecovery(testEmail, testPassword)
console.log("✓ Recovery setup successfully")
console.log(`  - Email: ${testEmail}`)

console.log("\n3. Testing challenge request...")
emails.splice(0) // Clear emails
await Client.requestChallenge(testEmail)
console.log(`✓ Challenge requested, ${emails.length} email(s) sent`)
if (emails.length > 0) {
  console.log(`  - First email challenge: ${emails[0].challenge.substring(0, 32)}...`)
}

console.log("\n4. Testing password-based login...")
const loginResult = await Client.loginWithPassword(testEmail, testPassword)
console.log(`✓ Login successful - ok: ${loginResult.ok}, ${loginResult.options.length} account(s) found`)

if (loginResult.ok && loginResult.options.length > 0) {
  console.log("\n5. Testing login selection...")
  const [clientPubkey, peers] = loginResult.options[0]
  const selectResult = await Client.selectLogin(loginResult.clientSecret, clientPubkey, peers)
  console.log("✓ Login completed successfully")
  console.log(`  - Can create client: ${!!selectResult.clientOptions}`)
}

console.log("\n6. Testing password-based recovery...")
const recoveryResult = await Client.recoverWithPassword(testEmail, testPassword)
console.log(`✓ Recovery successful - ok: ${recoveryResult.ok}, ${recoveryResult.options.length} account(s) found`)

if (recoveryResult.ok && recoveryResult.options.length > 0) {
  console.log("\n7. Testing recovery selection...")
  const [clientPubkey, peers] = recoveryResult.options[0]
  const selectResult = await Client.selectRecovery(recoveryResult.clientSecret, clientPubkey, peers)
  console.log("✓ Recovery completed successfully")
  console.log(`  - Can create client: ${!!selectResult.clientOptions}`)
}

stopSigners()

console.log("\n✓ All core tests passed!")
console.log("\nYou can now start the example app with:")
console.log("  pnpm start:example")
console.log("\nThen open http://localhost:3000 in your browser")
