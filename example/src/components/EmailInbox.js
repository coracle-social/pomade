import m from "mithril"
import { emails } from "../signers.js"

export const EmailInbox = {
  view() {
    return m('.email-inbox', [
      m('h3', 'Email Inbox (Simulated)'),
      m('p', { style: 'color: #666; font-size: 0.9em; margin-bottom: 15px; border-bottom: 1px solid #e0e0e0; padding-bottom: 10px;' },
        'This simulated inbox shows recovery emails that would normally be sent to your email address. In a real deployment, these would be actual emails.'
      ),
      emails.length === 0
        ? m('p', { style: 'color: #999; text-align: center;' }, 'No emails yet')
        : emails.slice().reverse().map(email =>
            m('.email', { key: email.id }, [
              m('.email-header', [
                m('.email-from', email.from),
                m('.email-date', email.date.toLocaleString())
              ]),
              m('.email-subject', email.subject),
              m('.email-body', [
                email.body.split('\n').map(line =>
                  line.includes(email.challenge)
                    ? m('.challenge-code', email.challenge)
                    : m('div', line)
                )
              ])
            ])
          )
    ])
  }
}
