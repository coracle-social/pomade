- mjml
- Make docker images
- add login with other session


- reduce scope of core, put signer in its own package, remove sqlite package. core, client, signer
- add the mailer client selection/batching to client?
- rename recoveryMethodInit to recoverySetup
- refactor storage to be more efficient
  - make bcrypt hashing configurable (for testing)
  - allow querying by hashed password to avoid enumerating everything
  - other enumerations
