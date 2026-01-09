import m from "mithril"

export const StatusMessage = {
  view(vnode) {
    const { message, type } = vnode.attrs
    if (!message) return null

    return m(`.status-message.${type}`, message)
  }
}
