import m from "mithril"
import { Client } from "@pomade/core"
import { state } from "../state.js"
import { StatusMessage } from "../components/StatusMessage.js"
import { emails } from "../signers.js"

export const Recovery = {
  challenge1: '',
  challenge2: '',
  challenge3: '',

  async requestChallenge() {
    if (!state.email) {
      state.setStatus('Please enter your email', 'error')
      return
    }

    try {
      state.setLoading(true)
      state.clearStatus()

      await Client.requestChallenge(state.email)
      state.setStatus('Challenge codes sent! Check the email inbox on the right.', 'success')
      state.setLoading(false)
    } catch (error) {
      state.setStatus(`Failed to request challenge: ${error.message}`, 'error')
      state.setLoading(false)
    }
  },

  async recover() {
    if (!state.email) {
      state.setStatus('Please enter your email', 'error')
      return
    }

    if (!this.challenge1 || !this.challenge2 || !this.challenge3) {
      state.setStatus('Please enter all three challenge codes from your emails', 'error')
      return
    }

    try {
      state.setLoading(true)
      state.clearStatus()

      const challenges = [this.challenge1.trim(), this.challenge2.trim(), this.challenge3.trim()]
      const result = await Client.recoverWithChallenge(state.email, challenges)

      if (!result.ok || result.options.length === 0) {
        state.setStatus('No accounts found or invalid challenge codes', 'error')
        state.setLoading(false)
        return
      }

      const [clientPubkey, peers] = result.options[0]
      const recoveryResult = await Client.selectRecovery(result.clientSecret, clientPubkey, peers)

      if (!recoveryResult.ok || !recoveryResult.userSecret) {
        state.setStatus('Failed to recover user secret', 'error')
        state.setLoading(false)
        return
      }

      state.recoveredSecret = recoveryResult.userSecret
      state.setView('recovered')
      state.setLoading(false)
    } catch (error) {
      state.setStatus(`Recovery failed: ${error.message}`, 'error')
      state.setLoading(false)
    }
  },

  view() {
    return m('.main-content', [
      m('.view-header', [
        m('button.back-button', {
          onclick: () => state.reset()
        }, '← Back'),
        m('h2', 'Recover Account')
      ]),

      state.statusMessage && m(StatusMessage, state.statusMessage),

      m('p', { style: 'color: #666; margin-bottom: 10px;' },
        'Recover your private key using your email and challenge codes. The recovery process:'
      ),

      m('ul', { style: 'color: #666; margin-bottom: 20px; margin-left: 20px;' }, [
        m('li', { style: 'margin-bottom: 8px;' }, 'Request OTP challenges from the signers'),
        m('li', { style: 'margin-bottom: 8px;' }, 'Each signer sends a unique challenge code (visible in the email inbox to the right)'),
        m('li', { style: 'margin-bottom: 8px;' }, 'Enter the challenges to prove to each signer you have access to your email'),
        m('li', { style: 'margin-bottom: 8px;' }, 'The signers will return your key shares and the client will reconstruct your key')
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

      m('button', {
        onclick: () => this.requestChallenge(),
        disabled: state.loading
      }, state.loading ? 'Sending...' : 'Request Challenge Codes'),

      emails.length > 0 && m('div', { style: 'margin-top: 20px;' }, [
        m('label', 'Challenge Codes'),
        m('p', { style: 'color: #666; font-size: 0.9em; margin-bottom: 15px;' },
          'Enter the three challenge codes from the emails on the right:'
        ),
        m('.form-group', [
          m('label', 'Challenge Code 1'),
          m('input[type=text]', {
            value: this.challenge1,
            placeholder: 'Enter first code',
            oninput: e => this.challenge1 = e.target.value,
            disabled: state.loading
          })
        ]),
        m('.form-group', [
          m('label', 'Challenge Code 2'),
          m('input[type=text]', {
            value: this.challenge2,
            placeholder: 'Enter second code',
            oninput: e => this.challenge2 = e.target.value,
            disabled: state.loading
          })
        ]),
        m('.form-group', [
          m('label', 'Challenge Code 3'),
          m('input[type=text]', {
            value: this.challenge3,
            placeholder: 'Enter third code',
            oninput: e => this.challenge3 = e.target.value,
            disabled: state.loading
          })
        ])
      ]),

      (this.challenge1 || this.challenge2 || this.challenge3) && m('button', {
        onclick: () => this.recover(),
        disabled: state.loading,
        style: 'margin-top: 10px;'
      }, state.loading ? 'Recovering...' : 'Recover Account')
    ])
  }
}
