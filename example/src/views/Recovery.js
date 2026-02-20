import m from "mithril"
import { Client } from "@pomade/core"
import { state } from "../state.js"
import { StatusMessage } from "../components/StatusMessage.js"
import { emails } from "../signers.js"

export const Recovery = {
  peersByPrefix: null,
  otpInputs: [],

  async requestChallenge() {
    if (!state.email) {
      state.setStatus('Please enter your email', 'error')
      return
    }

    try {
      state.setLoading(true)
      state.clearStatus()

      const result = await Client.requestChallenge(state.email)
      this.peersByPrefix = result.peersByPrefix
      this.otpInputs = Array.from(result.peersByPrefix.keys()).map(() => '')
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

    const otps = this.otpInputs.map(s => s.trim()).filter(Boolean)

    if (otps.length === 0) {
      state.setStatus('Please enter at least one challenge code', 'error')
      return
    }

    try {
      state.setLoading(true)
      state.clearStatus()

      const result = await Client.recoverWithChallenge(state.email, this.peersByPrefix, otps)

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
          onclick: () => {
            this.peersByPrefix = null
            this.otpInputs = []
            state.reset()
          }
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

      this.peersByPrefix && emails.length > 0 && m('div', { style: 'margin-top: 20px;' }, [
        m('label', 'Challenge Codes'),
        m('p', { style: 'color: #666; font-size: 0.9em; margin-bottom: 15px;' },
          'Enter the challenge codes from the emails on the right:'
        ),
        this.otpInputs.map((value, i) =>
          m('.form-group', { key: i }, [
            m('label', `Challenge Code ${i + 1}`),
            m('input[type=text]', {
              value,
              placeholder: 'Enter code',
              oninput: e => { this.otpInputs[i] = e.target.value },
              disabled: state.loading
            })
          ])
        ),
        m('button', {
          onclick: () => this.recover(),
          disabled: state.loading,
          style: 'margin-top: 10px;'
        }, state.loading ? 'Recovering...' : 'Recover Account')
      ])
    ])
  }
}
