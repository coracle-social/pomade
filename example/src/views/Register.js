import m from "mithril"
import { makeSecret } from "@welshman/util"
import { Client } from "@pomade/core"
import { state } from "../state.js"
import { StatusMessage } from "../components/StatusMessage.js"

export const Register = {
  async register() {
    if (!state.email || !state.password) {
      state.setStatus('Please enter email and password', 'error')
      return
    }

    try {
      state.setLoading(true)
      state.clearStatus()

      const userSecret = makeSecret()
      const result = await Client.register(2, 3, userSecret, true)

      state.clientOptions = result.clientOptions
      state.client = new Client(result.clientOptions)

      await state.client.setupRecovery(state.email, state.password)

      state.setView('dashboard')
    } catch (error) {
      state.setStatus(`Registration failed: ${error.message}`, 'error')
      state.setLoading(false)
    }
  },

  view() {
    return m('.main-content', [
      m('.view-header', [
        m('button.back-button', {
          onclick: () => state.reset()
        }, '← Back'),
        m('h2', 'Sign Up')
      ]),

      state.statusMessage && m(StatusMessage, state.statusMessage),

      m('p', { style: 'color: #666; margin-bottom: 20px;' },
        'Create a new account with email and password for recovery.'
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
          placeholder: 'Enter a strong password',
          oninput: e => state.password = e.target.value,
          disabled: state.loading,
          autocomplete: 'off'
        })
      ]),

      m('button', {
        onclick: () => this.register(),
        disabled: state.loading
      }, state.loading ? 'Creating Account...' : 'Sign Up')
    ])
  }
}
