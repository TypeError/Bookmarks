package burp

import java.awt.Toolkit
import java.awt.datatransfer.Clipboard
import java.awt.datatransfer.StringSelection
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
import javax.swing.JMenu
import javax.swing.JMenuItem
import javax.swing.JOptionPane
import javax.swing.JPopupMenu
import javax.swing.event.MenuEvent
import javax.swing.event.MenuListener

class BookmarkActions(
    private val panel: BookmarksPanel,
    private val bookmarks: MutableList<Bookmark>,
    private val callbacks: IBurpExtenderCallbacks
) : ActionListener {
    private val table = panel.table
    private val actionsMenu = JPopupMenu()
    private val sendToRepeater = JMenuItem("Send request(s) to Repeater")
    private val sendToIntruder = JMenuItem("Send request(s) to Intruder")
    private val copyURLs = JMenuItem("Copy URL(s)")
    private val deleteMenu = JMenuItem("Delete Bookmark(s)")
    private val clearMenu = JMenuItem("Clear Bookmarks")
    private val addTag = JMenu("Add Tag")
    private val existingTagsMenu = JMenu("Existing Tags")
    private val newTag = JMenuItem("New Tag")
    private val comments = JMenuItem("Add comment")

    init {
        sendToRepeater.addActionListener(this)
        sendToIntruder.addActionListener(this)
        copyURLs.addActionListener(this)
        deleteMenu.addActionListener(this)
        clearMenu.addActionListener(this)
        actionsMenu.add(sendToRepeater)
        actionsMenu.add(sendToIntruder)
        actionsMenu.add(copyURLs)
        actionsMenu.addSeparator()
        actionsMenu.add(deleteMenu)
        actionsMenu.add(clearMenu)
        actionsMenu.addSeparator()
        newTag.addActionListener(this)
        comments.addActionListener(this)
        addTag.add(newTag)
        existingTagsMenu.addMenuListener(UpdateTagMenu(this))
        addTag.add(existingTagsMenu)
        actionsMenu.add(addTag)
        actionsMenu.addSeparator()
        actionsMenu.add(comments)
        panel.table.componentPopupMenu = actionsMenu

    }


    override fun actionPerformed(e: ActionEvent?) {
        if (table.selectedRow == -1) return
        val selectedBookmarks = getSelectedBookmarks()
        when (val source = e?.source) {
            deleteMenu -> {
                panel.model.removeBookmarks(selectedBookmarks)
            }
            clearMenu -> {
                panel.model.clearBookmarks()
                panel.requestViewer?.setMessage(ByteArray(0), true)
                panel.responseViewer?.setMessage(ByteArray(0), false)
            }
            copyURLs -> {
                val urls = selectedBookmarks.map { it.url }.joinToString()
                val clipboard: Clipboard = Toolkit.getDefaultToolkit().systemClipboard
                clipboard.setContents(StringSelection(urls), null)
            }
            newTag -> {
                val tagToAdd = JOptionPane.showInputDialog("Tag:")
                selectedBookmarks.forEach { it.tags.add(tagToAdd) }
                panel.model.updateTags()
                panel.bookmarkOptions.updateTags()
            }
            else -> {
                for (selectedBookmark in selectedBookmarks) {
                    val https = useHTTPs(selectedBookmark)
                    val url = selectedBookmark.url
                    when (source) {
                        sendToRepeater -> {
                            var title = selectedBookmark.title
                            if (title.length > 10) {
                                title = title.substring(0, 9) + "+"
                            } else if (title.isBlank()) {
                                title = "[^](${bookmarks.indexOf(selectedBookmark)}"
                            }
                            callbacks.sendToRepeater(
                                url.host,
                                url.port,
                                https,
                                selectedBookmark.requestResponse.request,
                                title
                            )
                        }
                        sendToIntruder -> {
                            callbacks.sendToIntruder(
                                url.host, url.port, https,
                                selectedBookmark.requestResponse.request, null
                            )
                        }
                        comments -> {
                            val newComments = JOptionPane.showInputDialog("Comments:", selectedBookmark.comments)
                            selectedBookmark.comments = newComments
                            panel.model.refreshBookmarks()
                        }
                    }
                }
            }
        }
    }

    class UpdateTagMenu(private val bookmarkActions: BookmarkActions) : MenuListener {
        private val existingTagsMenu = bookmarkActions.existingTagsMenu
        private val panel = bookmarkActions.panel

        override fun menuSelected(me: MenuEvent) {
            existingTagsMenu.removeAll()
            val tags = panel.model.tags.sorted()
            tags.forEach {
                val menuItem = JMenuItem(it)
                menuItem.addActionListener(TagsActionListener(bookmarkActions))
                existingTagsMenu.add(menuItem)
            }
            existingTagsMenu.revalidate()
            existingTagsMenu.repaint()
            existingTagsMenu.doClick()
        }

        override fun menuCanceled(p0: MenuEvent?) {}

        override fun menuDeselected(p0: MenuEvent?) {}
    }

    class TagsActionListener(bookmarkActions: BookmarkActions) : ActionListener {
        private val selectedBookmarks = bookmarkActions.getSelectedBookmarks()
        private val panel = bookmarkActions.panel
        override fun actionPerformed(e: ActionEvent) {
            val menuItem = e.source as JMenuItem
            selectedBookmarks.forEach { it.tags.add(menuItem.text) }
            panel.model.updateTags()
            panel.bookmarkOptions.updateTags()
        }

    }

    fun getSelectedBookmarks(): MutableList<Bookmark> {
        val selectedBookmarks: MutableList<Bookmark> = ArrayList()
        for (index in table.selectedRows) {
            selectedBookmarks.add(bookmarks[index])
        }
        return selectedBookmarks
    }

    private fun useHTTPs(bookmark: Bookmark): Boolean {
        return (bookmark.url.protocol.toLowerCase() == "https")

    }
}
