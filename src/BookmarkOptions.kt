package burp

import javax.swing.JButton
import javax.swing.JPanel
import kotlin.concurrent.thread

class BookmarkOptions(
    private val bookmarksPanel: BookmarksPanel,
    private val callbacks: IBurpExtenderCallbacks
) {
    val panel = JPanel()

    init {
        val loadButton = JButton("Load Highlighted Proxy History")
        loadButton.addActionListener {
            thread {
                val bookmarks = bookmarksPanel.bookmarks
                val proxyHistory = callbacks.proxyHistory.filter { it.highlight != null }
                val bookmarkRequests = bookmarks.map { callbacks.helpers.bytesToString(it.requestResponse.request) }
                val bookmarksToAdd = proxyHistory
                    .filter { !bookmarkRequests.contains(callbacks.helpers.bytesToString(it.request)) }.toTypedArray()
                bookmarksPanel.addBookmark(bookmarksToAdd)
            }
            loadButton.isFocusPainted = false
        }
        panel.add(loadButton)
    }


}