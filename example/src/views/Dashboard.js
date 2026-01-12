import m from "mithril"
import { state } from "../state.js"
import { StatusMessage } from "../components/StatusMessage.js"

export const Dashboard = {
  async oninit() {
    await this.loadSessions()
  },

  async loadSessions() {
    if (!state.client) return

    try {
      state.setLoading(true)
      const result = await state.client.listSessions()

      const allSessions = result.messages.flatMap(m =>
        m?.payload.items?.map(item => ({
          client: item.client,
          peer: m.event.pubkey,
          created_at: item.created_at,
          recovery: item.recovery
        })) || []
      )

      const sessionsByClient = {}
      allSessions.forEach(session => {
        if (!sessionsByClient[session.client]) {
          sessionsByClient[session.client] = {
            client: session.client,
            peers: [],
            created_at: session.created_at,
            recovery: session.recovery
          }
        }
        sessionsByClient[session.client].peers.push(session.peer)
      })

      state.sessions = Object.values(sessionsByClient)
    } catch (error) {
      state.setStatus(`Failed to load sessions: ${error.message}`, 'error')
    } finally {
      state.setLoading(false)
    }
  },

  async deleteSession(clientPubkey, peers) {
    try {
      state.setLoading(true)
      await state.client.deleteSession(clientPubkey, peers)
      await this.loadSessions()
    } catch (error) {
      state.setStatus(`Failed to delete session: ${error.message}`, 'error')
      state.setLoading(false)
    }
  },

  view() {
    if (!state.client) {
      return m('.main-content', [
        m('h2', 'Dashboard'),
        m('p', 'You are not logged in.'),
        m('button', { onclick: () => state.setView('home') }, 'Go to Home')
      ])
    }

    return m('.main-content', [
      m('.view-header', [
        m('button.back-button', {
          onclick: () => state.reset()
        }, '← Back'),
        m('h2', 'Dashboard')
      ]),

      state.statusMessage && m(StatusMessage, state.statusMessage),

      m('p', { style: 'color: #666; margin-bottom: 20px;' },
        'You are now logged in, and able to sign events. This dashboard shows your account details and active sessions.'
      ),

      m('div', { style: 'margin-bottom: 30px;' }, [
        m('h3', 'Account Information'),
        m('div', { style: 'background: #f8f9fa; padding: 15px; border-radius: 6px;' }, [
          m('p', [
            m('strong', 'User Public Key: '),
            m('code', { style: 'word-break: break-all;' }, state.client.userPubkey)
          ]),
          m('p', { style: 'margin-top: 10px;' }, [
            m('strong', 'Configuration: '),
            `${state.client.group.threshold}-of-${state.client.peers.length} multisig`
          ]),
          m('p', { style: 'margin-top: 10px;' }, [
            m('strong', 'Signers: '),
            `${state.client.peers.length} peers`
          ])
        ])
      ]),

      m('.session-list', [
        m('div', { style: 'margin-bottom: 15px;' }, [
          m('h3', 'Active Sessions'),
          m('p', { style: 'color: #666; font-size: 0.9em; margin-top: 5px;' },
            'Sessions represent devices or applications that can access your account. You can delete any session to revoke its access.'
          )
        ]),
        state.loading && m('.loading', 'Loading sessions'),
        !state.loading && state.sessions.length === 0 && m('p', { style: 'color: #999;' }, 'No active sessions'),
        !state.loading && state.sessions.length > 0 && state.sessions.map((session, idx) =>
          m('.session-item', { key: session.client }, [
            m('.session-info', [
              m('.session-id', session.client === state.client.pubkey ? 'Current Session' : 'Session ' + (idx + 1)),
              m('.session-date', [
                m('div', 'Client: ' + session.client.substring(0, 16) + '...'),
                m('div', 'Peers: ' + session.peers.length + ' signer(s)'),
                m('div', 'Created: ' + new Date(session.created_at * 1000).toLocaleString()),
                session.recovery && m('div', { style: 'color: #28a745; margin-top: 4px;' }, 'Recovery enabled')
              ])
            ]),
            m('button.danger', {
              onclick: () => this.deleteSession(session.client, session.peers),
              disabled: state.loading
            }, state.loading ? 'Deleting...' : 'Delete')
          ])
        )
      ])
    ])
  }
}
