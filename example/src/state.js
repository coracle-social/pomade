import m from "mithril"

export const state = {
  currentView: 'home',
  client: null,
  clientOptions: null,
  statusMessage: null,

  email: '',
  password: '',

  userSecret: null,
  recoveredSecret: null,
  sessions: [],

  loading: false,

  setView(view) {
    this.currentView = view
    this.statusMessage = null
    m.redraw()
  },

  setStatus(message, type = 'info') {
    this.statusMessage = { message, type }
    m.redraw()
  },

  clearStatus() {
    this.statusMessage = null
    m.redraw()
  },

  setLoading(loading) {
    this.loading = loading
    m.redraw()
  },

  reset() {
    this.currentView = 'home'
    this.client = null
    this.clientOptions = null
    this.statusMessage = null
    this.email = ''
    this.password = ''
    this.userSecret = null
    this.recoveredSecret = null
    this.sessions = []
    this.loading = false
    m.redraw()
  }
}
