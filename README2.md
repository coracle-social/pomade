New plan: adapt bifrost signer stuff so that it supports email recovery and login.

- Do sharing as usual
- Add an additional endpoint that authorizes a recovery email
- Implement mailer component as planned
- Add session deletion
- Add email-based recovery and login
- We can avoid copying a huge blob by always doing otp and having bunkers return a bunker url (for login) or the key (for recovery)

- When doing any otp flow, bunkers MUST validate that the same client secret is used for the entire flow, and invalidate the challenge after a very small number of otps are attempted.

The initial email validation provides no security, because the user is the one specifying the email service. It must be done with a valid registration, where the user has already proved they have access to the key, or access to the email using a past email service. The OTP flow is still valuable to give users a familiar experience, and to ensure they don't associate the wrong email with their key.

- Run cleanup job for challenges, inactive registrations, etc that have expired
- generalize email? Login could be any string, mailer service need not use email
- update readme, include a disclaimer that it's alpha
- Remove login and always use recovery? Or add a flag that says whether to send the share?
- email has to be bound at registration, otherwise an attacker with access to any session could recover to their own email
- add last_activity timestamps and add created at from event to list endpoint
- pubkey selection isn't going to work, since it leaks info to someone with an email, and signers also don't know about all sessions. Maybe we have to restrict emails to a single pubkey? Or put pubkey selection in the email?
- Check auth created_at for replay attacks
