package burp

import java.awt.FlowLayout
import javax.swing.*
import kotlin.concurrent.thread

class BookmarkOptions(
    private val bookmarksPanel: BookmarksPanel,
    private val callbacks: IBurpExtenderCallbacks
) {
    val panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
    private val loadButton = JButton("Load Highlighted Proxy History")
    private val loadPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
    private val searchBar = JTextField("", 20)
    private val searchPanel = JPanel(FlowLayout(FlowLayout.LEFT))


    init {
        val searchLabel = JLabel("Search Bookmarks:")
        val resetButton = JButton("Reset")
        loadButton.addActionListener { loadHighlightedRequests() }
        searchBar.addActionListener { searchBookmarks() }
        resetButton.addActionListener { resetSearch() }
        searchPanel.add(searchLabel)
        searchPanel.add(searchBar)
        searchPanel.add(resetButton)
        loadPanel.add(loadButton)
        panel.leftComponent = searchPanel
        panel.rightComponent = loadPanel
        panel.dividerSize = 0
    }

    private fun loadHighlightedRequests() {
        thread {
            val bookmarks = bookmarksPanel.bookmarks
            val highlightedProxyHistory = callbacks.proxyHistory.filter { it.highlight != null }
            val bookmarkRequests = bookmarks.map { callbacks.helpers.bytesToString(it.requestResponse.request) }
            val bookmarksToAdd = highlightedProxyHistory
                .filter { !bookmarkRequests.contains(callbacks.helpers.bytesToString(it.request)) }.toTypedArray()
            bookmarksPanel.addBookmark(bookmarksToAdd)
        }
        this.loadButton.isFocusPainted = false
    }

    private fun searchBookmarks() {
        val searchText = searchBar.text
        if (searchText.isNotEmpty()) {
            Thread {
                val bookmarks = this.bookmarksPanel.bookmarks
                val filteredBookmarks = bookmarks
                    .filter {
                        callbacks.helpers.bytesToString(it.requestResponse.request).contains(searchText) ||
                                callbacks.helpers.bytesToString(it.requestResponse.response).contains(searchText)
                    }.toMutableList()
                bookmarksPanel.model.filteredBookmarks(filteredBookmarks)
            }.start()
            bookmarksPanel.model.fireTableDataChanged()
        } else {
            bookmarksPanel.model.filteredBookmarks()
            bookmarksPanel.model.fireTableDataChanged()
        }
    }

    private fun resetSearch() {
        bookmarksPanel.model.filteredBookmarks()
        bookmarksPanel.model.fireTableDataChanged()
    }
}