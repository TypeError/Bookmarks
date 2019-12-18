package burp

import javax.swing.JMenuItem

class BookmarkMenu(private val table: BookmarksPanel) : IContextMenuFactory {
    override fun createMenuItems(invocation: IContextMenuInvocation?): MutableList<JMenuItem> {
        val menuItems: MutableList<JMenuItem> = arrayListOf()
        val requests = invocation?.selectedMessages
        val bookmarkButton = JMenuItem("Add bookmark(s) [^]")
        bookmarkButton.addActionListener {
            if (requests != null) {
                table.model.refreshBookmarks()
                table.addBookmark(requests)
            }
        }

        menuItems.add(bookmarkButton)
        return menuItems
    }

}