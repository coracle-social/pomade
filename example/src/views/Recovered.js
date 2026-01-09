import m from "mithril"
import { getPubkey } from "@welshman/util"
import { state } from "../state.js"
import { StatusMessage } from "../components/StatusMessage.js"

export const Recovered = {
  view() {
    if (!state.recoveredSecret) {
      return m('.main-content', [
        m('.view-header', [
          m('button.back-button', {
            onclick: () => state.reset()
          }, '← Back'),
          m('h2', 'Recovered Secret')
        ]),
        m('p', 'No recovered secret available.')
      ])
    }

    return m('.main-content', [
      m('.view-header', [
        m('button.back-button', {
          onclick: () => state.reset()
        }, '← Back'),
        m('h2', 'Account Recovered')
      ]),

      state.statusMessage && m(StatusMessage, state.statusMessage),

      m('p', { style: 'color: #666; margin-bottom: 20px;' },
        'Your account has been successfully recovered. Save your private key securely!'
      ),

      m('.form-group', [
        m('label', 'Public Key (npub)'),
        m('input[type=text][readonly]', {
          value: getPubkey(state.recoveredSecret),
          style: 'font-family: monospace; background: #f0f0f0;',
          onclick: e => e.target.select()
        })
      ]),

      m('.form-group', [
        m('label', 'Private Key (nsec)'),
        m('input[type=text][readonly]', {
          value: state.recoveredSecret,
          style: 'font-family: monospace; background: #f0f0f0;',
          onclick: e => e.target.select()
        })
      ]),

      m('button', {
        onclick: () => {
          navigator.clipboard.writeText(state.recoveredSecret)
          state.setStatus('Private key copied to clipboard!', 'success')
        }
      }, 'Copy Private Key to Clipboard')
    ])
  }
}
