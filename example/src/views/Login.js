import m from "mithril"
import { Client } from "@pomade/core"
import { state } from "../state.js"
import { StatusMessage } from "../components/StatusMessage.js"

export const Login = {
  async login() {
    if (!state.email || !state.password) {
      state.setStatus('Please enter email and password', 'error')
      return
    }

    try {
      state.setLoading(true)
      state.clearStatus()

      const result = await Client.loginWithPassword(state.email, state.password)

      if (!result.ok || result.options.length === 0) {
        state.setStatus('No accounts found with these credentials', 'error')
        state.setLoading(false)
        return
      }

      const [clientPubkey, peers] = result.options[0]
      const loginResult = await Client.selectLogin(result.clientSecret, clientPubkey, peers)

      state.clientOptions = loginResult.clientOptions
      state.client = new Client(loginResult.clientOptions)

      state.setView('dashboard')
    } catch (error) {
      state.setStatus(`Login failed: ${error.message}`, 'error')
      state.setLoading(false)
    }
  },

  view() {
    return m('.main-content', [
      m('.view-header', [
        m('button.back-button', {
          onclick: () => state.reset()
        }, '← Back'),
        m('h2', 'Log In')
      ]),

      state.statusMessage && m(StatusMessage, state.statusMessage),

      m('p', { style: 'color: #666; margin-bottom: 20px;' },
        'Log in to your existing account with email and password.'
      ),

      m('.form-group', [
        m('label', 'Email'),
        m('input[type=email]', {
          value: state.email,
          placeholder: 'you@example.com',
          oninput: e => state.email = e.target.value,
          disabled: state.loading
        })
      ]),

      m('.form-group', [
        m('label', 'Password'),
        m('input[type=password]', {
          value: state.password,
          placeholder: 'Your password',
          oninput: e => state.password = e.target.value,
          disabled: state.loading,
          autocomplete: 'off'
        })
      ]),

      m('button', {
        onclick: () => this.login(),
        disabled: state.loading
      }, state.loading ? 'Logging in...' : 'Log In')
    ])
  }
}
