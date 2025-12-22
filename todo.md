- mjml
- Make docker images
- add login with other session


- reduce scope of core, put signer in its own package, remove sqlite package. core, client, signer
- add the mailer client selection/batching to client?
- rename recoveryMethodInit to recoverySetup
- Use argon2id for passwords, since password hashes are being sent to all signers
