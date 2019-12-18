package burp

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.swing.Swing
import kotlinx.coroutines.withContext
import java.awt.FlowLayout
import java.net.URL
import java.time.LocalDateTime
import java.time.format.DateTimeFormatter
import javax.swing.*
import javax.swing.table.AbstractTableModel

class BookmarkTab(callbacks: IBurpExtenderCallbacks) : ITab {
    val bookmarkTable = BookmarksPanel(callbacks)

    override fun getTabCaption() = "[^]"

    override fun getUiComponent() = bookmarkTable.panel
}

data class Bookmark(
    val requestResponse: IHttpRequestResponse,
    val dateTime: String,
    val host: String,
    val url: URL,
    val method: String,
    val statusCode: String,
    val title: String,
    val length: String,
    val mimeType: String,
    val protocol: String,
    val file: String,
    val parameters: Boolean,
    val repeated: Boolean,
    val comments: String
)

class BookmarksPanel(private val callbacks: IBurpExtenderCallbacks) {
    val model = BookmarksModel()
    val table = JTable(model)

    private val messageEditor = MessageEditor(callbacks)
    val requestViewer: IMessageEditor? = messageEditor.requestViewer
    val responseViewer: IMessageEditor? = messageEditor.responseViewer

    val panel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
    val bookmarks = model.bookmarks

    private val repeatInTable = JCheckBox("Add repeated request to table")

    init {
        BookmarkActions(this, bookmarks, callbacks)
        val bookmarkOptions = BookmarkOptions(this, callbacks)
        table.autoResizeMode = JTable.AUTO_RESIZE_OFF
        table.columnModel.getColumn(0).preferredWidth = 30 // ID
        table.columnModel.getColumn(1).preferredWidth = 145 // date
        table.columnModel.getColumn(2).preferredWidth = 125 // host
        table.columnModel.getColumn(3).preferredWidth = 380 // url
        table.columnModel.getColumn(4).preferredWidth = 130 // title
        table.columnModel.getColumn(5).preferredWidth = 60 // repeated
        table.columnModel.getColumn(6).preferredWidth = 55 // params
        table.columnModel.getColumn(7).preferredWidth = 50 // method
        table.columnModel.getColumn(8).preferredWidth = 50 // status
        table.columnModel.getColumn(9).preferredWidth = 50 // length
        table.columnModel.getColumn(10).preferredWidth = 50 // mime
        table.columnModel.getColumn(11).preferredWidth = 50 // protocol
        table.columnModel.getColumn(12).preferredWidth = 80 // file
        table.columnModel.getColumn(13).preferredWidth = 120 // comments
        table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION)

        table.selectionModel.addListSelectionListener {
            if (table.selectedRow != -1) {
                val requestResponse = bookmarks[table.selectedRow].requestResponse
                messageEditor.requestResponse = requestResponse
                requestViewer?.setMessage(requestResponse.request, true)
                responseViewer?.setMessage(requestResponse.response ?: ByteArray(0), false)
            }
        }

        val repeatPanel = JPanel(FlowLayout(FlowLayout.LEFT))

        val repeatButton = JButton("Repeat Request")
        repeatButton.addActionListener { repeatRequest() }
        repeatInTable.isSelected = true

        repeatPanel.add(repeatButton)
        repeatPanel.add(repeatInTable)

        val bookmarksTable = JScrollPane(table)
        val reqResSplit =
            JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer?.component, responseViewer?.component)
        reqResSplit.resizeWeight = 0.5

        val repeatReqSplit =
            JSplitPane(JSplitPane.VERTICAL_SPLIT, repeatPanel, reqResSplit)

        val bookmarksOptSplit =
            JSplitPane(JSplitPane.VERTICAL_SPLIT, bookmarkOptions.panel, bookmarksTable)

        panel.topComponent = bookmarksOptSplit
        panel.bottomComponent = repeatReqSplit
        callbacks.customizeUiComponent(panel)
    }

    fun addBookmark(requestsResponses: Array<IHttpRequestResponse>) {
        for (requestResponse in requestsResponses) {
            createBookmark(requestResponse)
        }
    }

    private fun createBookmark(
        requestResponse: IHttpRequestResponse,
        repeated: Boolean = false,
        proxyHistory: Boolean = true
    ) {
        val savedRequestResponse = callbacks.saveBuffersToTempFiles(requestResponse)
        val now = LocalDateTime.now()
        val dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
        val dateTime = now.format(dateFormatter) ?: ""
        val requestInfo = callbacks.helpers.analyzeRequest(requestResponse)
        val response = if (requestResponse.response != null) {
            callbacks.helpers.analyzeResponse(requestResponse.response)
        } else {
            null
        }
        val host = requestInfo.url.host
        val url = requestInfo.url
        val method = requestInfo?.method ?: ""
        val statusCode = response?.statusCode?.toString() ?: ""
        val title = getTitle(requestResponse.response)
        val mimeType = response?.inferredMimeType ?: ""
        val length = requestResponse.response?.size?.toString() ?: ""
        val protocol = requestInfo?.url?.protocol ?: ""
        val file = requestInfo?.url?.file ?: ""
        val parameters =
            !requestInfo.parameters.filter { it.type != IParameter.PARAM_COOKIE }.isNullOrEmpty() || !requestInfo.url.query.isNullOrEmpty()
        val comments = requestResponse.comment ?: ""
        val bookmark = Bookmark(
            savedRequestResponse,
            dateTime,
            host,
            url,
            method,
            statusCode,
            title,
            length,
            mimeType,
            protocol,
            file,
            parameters,
            repeated,
            comments
        )

        model.addBookmark(bookmark)
        if (proxyHistory) {
            requestResponse.highlight = "magenta"
        }

        SwingUtilities.invokeLater {
            table.scrollRectToVisible(table.getCellRect(table.rowCount - 1, 0, true))
        }
    }

    private fun getTitle(response: ByteArray?): String {
        if (response == null) return ""
        val html = callbacks.helpers.bytesToString(response)
        val titleRegex = "<title>(.*?)</title>".toRegex()
        val title = titleRegex.find(html)?.value ?: ""
        return title.removePrefix("<title>").removeSuffix("</title>")
    }


    private fun repeatRequest() {
        GlobalScope.launch(Dispatchers.IO) {
            val requestResponse = callbacks.makeHttpRequest(messageEditor.httpService, requestViewer?.message)
            withContext(Dispatchers.Swing) {
                SwingUtilities.invokeLater {
                    responseViewer?.setMessage(requestResponse.response, false)
                    if (repeatInTable.isSelected) {
                        createBookmark(requestResponse, repeated = true, proxyHistory = false)
                    }
                }
            }
        }
    }
}

class MessageEditor(callbacks: IBurpExtenderCallbacks) : IMessageEditorController {
    var requestResponse: IHttpRequestResponse? = null

    val requestViewer: IMessageEditor? = callbacks.createMessageEditor(this, true)
    val responseViewer: IMessageEditor? = callbacks.createMessageEditor(this, false)

    override fun getResponse(): ByteArray? = requestResponse?.response ?: ByteArray(0)

    override fun getRequest(): ByteArray? = requestResponse?.request

    override fun getHttpService(): IHttpService? = requestResponse?.httpService
}

class BookmarksModel : AbstractTableModel() {
    private val columns =
        listOf(
            "ID",
            "Added",
            "Host",
            "URL",
            "Title",
            "Repeated",
            "Params",
            "Method",
            "Status",
            "Length",
            "MIME",
            "Protocol",
            "File",
            "Comments"
        )
    var bookmarks: MutableList<Bookmark> = ArrayList()
    private var displayedBookmarks: MutableList<Bookmark> = ArrayList()

    override fun getRowCount(): Int = displayedBookmarks.size

    override fun getColumnCount(): Int = columns.size

    override fun getColumnName(column: Int): String {
        return columns[column]
    }

    override fun getColumnClass(columnIndex: Int): Class<*> {
        return when (columnIndex) {
            0 -> java.lang.Integer::class.java
            1 -> String::class.java
            2 -> String::class.java
            3 -> String::class.java
            4 -> String::class.java
            5 -> java.lang.Boolean::class.java
            6 -> java.lang.Boolean::class.java
            7 -> String::class.java
            8 -> String::class.java
            9 -> String::class.java
            10 -> String::class.java
            11 -> String::class.java
            12 -> String::class.java
            13 -> String::class.java
            else -> throw RuntimeException()
        }
    }

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val bookmark = displayedBookmarks[rowIndex]

        return when (columnIndex) {
            0 -> rowIndex
            1 -> bookmark.dateTime
            2 -> bookmark.host
            3 -> bookmark.url.toString()
            4 -> bookmark.title
            5 -> bookmark.repeated
            6 -> bookmark.parameters
            7 -> bookmark.method
            8 -> bookmark.statusCode
            9 -> bookmark.length
            10 -> bookmark.mimeType
            11 -> bookmark.protocol
            12 -> bookmark.file
            13 -> bookmark.comments
            else -> ""
        }
    }

    fun addBookmark(bookmark: Bookmark) {
        bookmarks.add(bookmark)
        displayedBookmarks = bookmarks
        fireTableRowsInserted(displayedBookmarks.lastIndex, displayedBookmarks.lastIndex)
    }

    fun removeBookmarks(selectedBookmarks: MutableList<Bookmark>) {
        bookmarks.removeAll(selectedBookmarks)
        refreshBookmarks()
    }

    fun clearBookmarks() {
        bookmarks.clear()
        refreshBookmarks()
    }

    fun refreshBookmarks(updatedBookmarks: MutableList<Bookmark> = bookmarks) {
        displayedBookmarks = updatedBookmarks
        fireTableDataChanged()
    }
}


