import m from "mithril"
import { state } from "../state.js"

export const Home = {
  view() {
    return m('.main-content', [
      m('h2', 'Welcome to Pomade'),

      m('p', { style: 'color: #666; margin-bottom: 40px;' },
        'A multisig recovery protocol for Nostr accounts. Choose an action to get started.'
      ),

      m('div', { style: 'display: flex; flex-direction: column; gap: 15px; max-width: 400px; margin: 0 auto;' }, [
        m('button', {
          onclick: () => state.setView('register'),
          style: 'padding: 20px; font-size: 1.1em;'
        }, 'Sign Up'),

        m('button', {
          onclick: () => state.setView('login'),
          style: 'padding: 20px; font-size: 1.1em;'
        }, 'Log In'),

        m('button', {
          onclick: () => state.setView('recovery'),
          style: 'padding: 20px; font-size: 1.1em;'
        }, 'Recover Account')
      ])
    ])
  }
}
