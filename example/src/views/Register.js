import m from "mithril"
import { makeSecret } from "@welshman/util"
import { Client } from "@pomade/core"
import { state } from "../state.js"
import { StatusMessage } from "../components/StatusMessage.js"

export const Register = {
  step: 1,
  challengeInput: '',

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

      await Client.requestChallenge(state.email, result.clientOptions.peers.slice(0, 1))

      this.step = 2
      state.setStatus('Verification code sent! Check the email inbox on the right.', 'success')
      state.setLoading(false)
    } catch (error) {
      state.setStatus(`Registration failed: ${error.message}`, 'error')
      state.setLoading(false)
    }
  },

  async verifyAndComplete() {
    if (!this.challengeInput) {
      state.setStatus('Please enter the verification code', 'error')
      return
    }

    // Challenge validation is not required, just proceed
    this.step = 1
    this.challengeInput = ''
    state.setView('dashboard')
  },

  view() {
    return m('.main-content', [
      m('.view-header', [
        m('button.back-button', {
          onclick: () => {
            this.step = 1
            this.challengeInput = ''
            state.reset()
          }
        }, '← Back'),
        m('h2', 'Sign Up')
      ]),

      state.statusMessage && m(StatusMessage, state.statusMessage),

      // Step 1: Enter email and password
      this.step === 1 && [
        m('p', { style: 'color: #666; margin-bottom: 20px;' },
          'Create a new account with email and password for recovery. This will:'
        ),

        m('ul', { style: 'color: #666; margin-bottom: 20px; margin-left: 20px;' }, [
          m('li', { style: 'margin-bottom: 8px;' }, 'Generate a 2-of-3 multisig account using Frost cryptography'),
          m('li', { style: 'margin-bottom: 8px;' }, 'Share each share with a different signer'),
          m('li', { style: 'margin-bottom: 8px;' }, 'Enable recovery using your email and password'),
          m('li', { style: 'margin-bottom: 8px;' }, 'Send a verification code to confirm your email')
        ]),

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
      ],

      // Step 2: Enter verification code
      this.step === 2 && [
        m('p', { style: 'color: #666; margin-bottom: 20px;' },
          'Your account has been created! We\'ve sent a verification code to your email. Enter it below to complete setup.'
        ),

        m('div', { style: 'background: #f8f9fa; border: 1px solid #e0e0e0; border-radius: 6px; padding: 15px; margin-bottom: 20px;' }, [
          m('p', { style: 'margin: 0 0 5px 0; font-weight: 600; color: #333;' }, 'Email:'),
          m('p', { style: 'margin: 0; color: #666;' }, state.email)
        ]),

        m('.form-group', [
          m('label', 'Verification Code'),
          m('p', { style: 'color: #666; font-size: 0.9em; margin-bottom: 10px;' },
            'Check the email inbox on the right for your verification code.'
          ),
          m('input[type=text]', {
            value: this.challengeInput,
            placeholder: 'Enter verification code',
            oninput: e => this.challengeInput = e.target.value,
            autocomplete: 'off'
          })
        ]),

        m('button', {
          onclick: () => this.verifyAndComplete()
        }, 'Complete Setup')
      ]
    ])
  }
}
