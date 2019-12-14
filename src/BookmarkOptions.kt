package burp

import java.awt.FlowLayout
import javax.swing.*

class BookmarkOptions(
    private val bookmarksPanel: BookmarksPanel,
    private val callbacks: IBurpExtenderCallbacks
) {
    val panel = JSplitPane(JSplitPane.HORIZONTAL_SPLIT)
    private val loadPanel = JPanel(FlowLayout(FlowLayout.RIGHT))
    private val searchBar = JTextField("", 20)
    private val searchPanel = JPanel(FlowLayout(FlowLayout.LEFT))


    init {
        val loadButton = JButton("Load Highlighted Proxy History")
        val clearButton = JButton("Clear Bookmarks")
        val searchLabel = JLabel("Search Bookmarks:")
        val searchButton = JButton("Search")
        val resetButton = JButton("Reset")
        loadButton.addActionListener { loadHighlightedRequests() }
        clearButton.addActionListener { clearBookmarks() }
        searchBar.addActionListener { searchBookmarks() }
        searchButton.addActionListener { searchBookmarks() }
        resetButton.addActionListener { resetSearch() }
        searchPanel.add(searchLabel)
        searchPanel.add(searchBar)
        searchPanel.add(searchButton)
        searchPanel.add(resetButton)
        loadPanel.add(clearButton)
        loadPanel.add(loadButton)
        panel.leftComponent = searchPanel
        panel.rightComponent = loadPanel
        panel.dividerSize = 0
    }

    private fun loadHighlightedRequests() {
        val bookmarks = bookmarksPanel.bookmarks
        val highlightedProxyHistory = callbacks.proxyHistory.filter { it.highlight != null }
        val bookmarkRequests = bookmarks.map { callbacks.helpers.bytesToString(it.requestResponse.request) }
        val bookmarksToAdd = highlightedProxyHistory
            .filter { !bookmarkRequests.contains(callbacks.helpers.bytesToString(it.request)) }.toTypedArray()
        bookmarksPanel.addBookmark(bookmarksToAdd)
    }

    private fun searchBookmarks() {
        val searchText = searchBar.text
        val bookmarks = this.bookmarksPanel.bookmarks
        if (searchText.isNotEmpty()) {
            val filteredBookmarks = bookmarks
                .filter {
                    callbacks.helpers.bytesToString(it.requestResponse.request).contains(searchText) ||
                            callbacks.helpers.bytesToString(it.requestResponse.response).contains(searchText)
                }.toMutableList()
            bookmarksPanel.model.refreshBookmarks(filteredBookmarks)
        }
    }

    private fun resetSearch() {
        searchBar.text = ""
        bookmarksPanel.model.refreshBookmarks()
    }

    private fun clearBookmarks() {
        bookmarksPanel.model.bookmarks.clear()
        bookmarksPanel.model.refreshBookmarks()
    }
}