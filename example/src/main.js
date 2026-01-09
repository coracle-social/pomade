import m from "mithril"
import { initializeSigners } from "./signers.js"
import { state } from "./state.js"
import { Home } from "./views/Home.js"
import { Register } from "./views/Register.js"
import { Login } from "./views/Login.js"
import { Recovery } from "./views/Recovery.js"
import { Recovered } from "./views/Recovered.js"
import { Dashboard } from "./views/Dashboard.js"
import { EmailInbox } from "./components/EmailInbox.js"

initializeSigners()

const App = {
  view() {
    return m('.container', [
      m('.header', [
        m('h1', 'Pomade Example Client'),
        m('p', 'Multisig Account Management with Recovery')
      ]),

      m('.two-column', [
        m('div', [
          state.currentView === 'home' && m(Home),
          state.currentView === 'register' && m(Register),
          state.currentView === 'login' && m(Login),
          state.currentView === 'recovery' && m(Recovery),
          state.currentView === 'recovered' && m(Recovered),
          state.currentView === 'dashboard' && m(Dashboard)
        ]),

        m(EmailInbox)
      ])
    ])
  }
}

m.mount(document.getElementById('app'), App)
