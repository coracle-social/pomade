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

      m('div', { style: 'background: #d1ecf1; border: 2px solid #17a2b8; border-radius: 8px; padding: 15px; margin-bottom: 20px;' }, [
        m('p', { style: 'margin: 0 0 10px 0; font-weight: 600; color: #0c5460;' }, 'Recovery Successful!'),
        m('p', { style: 'margin: 0 0 8px 0; color: #0c5460; font-size: 0.95em;' },
          'Your private key (nsec) has been successfully reconstructed using the challenge codes.'
        ),
      ]),

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
    ])
  }
}
