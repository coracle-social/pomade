New plan: adapt bifrost signer stuff so that it supports email recovery and login.

- Do sharing as usual
- Add an additional endpoint that authorizes a recovery email
- Implement mailer component as planned
- Add session deletion
- Add email-based recovery and login
- We can avoid copying a huge blob by always doing otp and having bunkers return a bunker url (for login) or the key (for recovery)

- When doing any otp flow, bunkers MUST validate that the same client secret is used for the entire flow, and invalidate the challenge after a very small number of otps are attempted.

The initial email validation provides no security, because the user is the one specifying the email service. It must be done with a valid registration, where the user has already proved they have access to the key, or access to the email using a past email service. The OTP flow is still valuable to give users a familiar experience, and to ensure they don't associate the wrong email with their key.

- update readme, include a disclaimer that it's alpha
