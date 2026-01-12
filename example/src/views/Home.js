import m from "mithril"
import { state } from "../state.js"

export const Home = {
  view() {
    return m('.main-content', [
      m('h2', 'Welcome to Pomade'),

      m('p', { style: 'color: #666; margin-bottom: 20px;' },
        'A multisig recovery protocol for Nostr accounts. Choose an action to get started.'
      ),

      m('div', { style: 'background: #fff3cd; border: 2px solid #ffc107; border-radius: 8px; padding: 15px; margin-bottom: 30px;' }, [
        m('p', { style: 'margin: 0 0 8px 0; color: #856404; font-size: 0.95em;' },
          'This is a fully self-contained demo running entirely in your browser. No data is sent to external servers.'
        ),
        m('p', { style: 'margin: 0; color: #856404; font-size: 0.95em;' },
          'All accounts, sessions, and data will be lost when you refresh the page or close this tab.'
        )
      ]),

      m('div', { style: 'display: flex; flex-direction: column; gap: 15px; max-width: 400px; margin: 0 auto;' }, [
        m('div', [
          m('button', {
            onclick: () => state.setView('register'),
            style: 'padding: 20px; font-size: 1.1em; width: 100%;'
          }, 'Sign Up'),
          m('p', { style: 'color: #999; font-size: 0.85em; margin-top: 5px;' },
            'Create a new multisig account with email and password recovery'
          )
        ]),

        m('div', [
          m('button', {
            onclick: () => state.setView('login'),
            style: 'padding: 20px; font-size: 1.1em; width: 100%;'
          }, 'Log In'),
          m('p', { style: 'color: #999; font-size: 0.85em; margin-top: 5px;' },
            'Access an existing account using email and password'
          )
        ]),

        m('div', [
          m('button', {
            onclick: () => state.setView('recovery'),
            style: 'padding: 20px; font-size: 1.1em; width: 100%;'
          }, 'Recover Account'),
          m('p', { style: 'color: #999; font-size: 0.85em; margin-top: 5px;' },
            'Retrieve your private key using email and password'
          )
        ])
      ])
    ])
  }
}
