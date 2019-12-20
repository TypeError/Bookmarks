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
        bookmarksPanel.model.refreshBookmarks()
        SwingUtilities.invokeLater {
            val bookmarks = bookmarksPanel.bookmarks
            val bookmarkRequestResponse = bookmarks.map {
                Pair(
                    callbacks.helpers.bytesToString(it.requestResponse.request),
                    callbacks.helpers.bytesToString(it.requestResponse.response ?: ByteArray(0))
                )
            }
            val proxyHistory = callbacks.proxyHistory.asSequence()
            val bookmarksToAdd = proxyHistory
                .filter { it.highlight != null }
                .filterNot {
                    bookmarkRequestResponse.contains(
                        Pair(
                            callbacks.helpers.bytesToString(it.request),
                            callbacks.helpers.bytesToString(it.response ?: ByteArray(0))
                        )
                    )
                }
                .distinct()
                .toList()
                .toTypedArray()
            bookmarksPanel.addBookmark(bookmarksToAdd)
        }
    }

    private fun searchBookmarks() {
        SwingUtilities.invokeLater {
            val searchText = searchBar.text.toLowerCase()
            val bookmarks = this.bookmarksPanel.bookmarks
            if (searchText.isNotEmpty()) {
                val filteredBookmarks = bookmarks
                    .filter {
                        it.url.toString().toLowerCase().contains(searchText) ||
                                callbacks.helpers.bytesToString(it.requestResponse.request).toLowerCase().contains(
                                    searchText
                                ) ||
                                callbacks.helpers.bytesToString(
                                    it.requestResponse.response ?: ByteArray(0)
                                ).toLowerCase().contains(
                                    searchText
                                )
                    }.toMutableList()
                bookmarksPanel.model.refreshBookmarks(filteredBookmarks)
                rowSelection()
            }
        }
    }

    private fun resetSearch() {
        searchBar.text = ""
        bookmarksPanel.model.refreshBookmarks()
        rowSelection()
    }

    private fun clearBookmarks() {
        bookmarksPanel.model.clearBookmarks()
        bookmarksPanel.requestViewer?.setMessage(ByteArray(0), true)
        bookmarksPanel.responseViewer?.setMessage(ByteArray(0), false)
    }

    private fun rowSelection() {
        val rowCount = bookmarksPanel.table.rowCount
        if (rowCount != -1) {
            bookmarksPanel.table.setRowSelectionInterval(rowCount - 1, rowCount - 1)
        } else {
            bookmarksPanel.requestViewer?.setMessage(ByteArray(0), true)
            bookmarksPanel.responseViewer?.setMessage(ByteArray(0), false)
        }
    }
}