New plan: adapt bifrost signer stuff so that it supports email recovery and login.

- Do sharing as usual
- Add an additional endpoint that authorizes a recovery email
- Implement mailer component as planned
- Add session deletion
- Add email-based recovery and login
- We can avoid copying a huge blob by always doing otp and having bunkers return a bunker url (for login) or the key (for recovery)


- When doing any otp flow, bunkers MUST validate that the same client secret is used for the entire flow.
