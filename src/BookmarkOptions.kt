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
    private val tagComboBox = JComboBox(arrayOf<String>())

    init {
        val loadButton = JButton("Load Highlighted Proxy History")
        val clearButton = JButton("Clear Bookmarks")
        val searchLabel = JLabel("Search Bookmarks:")
        val searchButton = JButton("Search")
        val resetButton = JButton("Reset")
        tagComboBox.selectedIndex = -1
        tagComboBox.prototypeDisplayValue = "railroad"
        tagComboBox.addItem("Tags")
        loadButton.addActionListener { loadHighlightedRequests() }
        clearButton.addActionListener { clearBookmarks() }
        searchBar.addActionListener { searchBookmarks() }
        searchButton.addActionListener { searchBookmarks() }
        resetButton.addActionListener { resetSearch() }
        searchPanel.add(searchLabel)
        searchPanel.add(searchBar)
        searchPanel.add(tagComboBox)
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

    fun searchBookmarks() {
        val selectedTag = tagComboBox.selectedItem
        SwingUtilities.invokeLater {
            val searchText = searchBar.text.toLowerCase()
            var filteredBookmarks = this.bookmarksPanel.bookmarks
            filteredBookmarks = filterTags(filteredBookmarks)
            if (searchText.isNotEmpty()) {
                filteredBookmarks = filteredBookmarks
                    .filter {
                        it.comments.toLowerCase().contains(searchText) ||
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
            }
            bookmarksPanel.model.refreshBookmarks(filteredBookmarks)
            if (selectedTag != "Tags") {
                tagComboBox.selectedItem = selectedTag
            }
            rowSelection()
        }
    }

    private fun filterTags(bookmarks: MutableList<Bookmark>): MutableList<Bookmark> {
        return if (tagComboBox.selectedItem != "Tags" || tagComboBox.selectedItem == null) {
            val tag = tagComboBox.selectedItem
            bookmarks
                .filter {
                    it.tags.contains(tag)
                }.toMutableList()
        } else {
            bookmarks
        }
    }

    private fun resetSearch() {
        searchBar.text = ""
        bookmarksPanel.model.refreshBookmarks()
        rowSelection()
        updateTags()
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

    fun updateTags() {
        tagComboBox.removeAllItems()
        tagComboBox.addItem("Tags")
        for (tag in bookmarksPanel.model.tags.sorted()) {
            tagComboBox.addItem(tag)
        }
    }
}