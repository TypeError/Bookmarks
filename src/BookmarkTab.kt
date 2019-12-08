package burp

import java.awt.FlowLayout
import java.awt.event.ActionEvent
import java.awt.event.ActionListener
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
    val statusCode: Int,
    val title: String,
    val mimeType: String,
    val protocol: String,
    val file: String
)

class BookmarksPanel(private val callbacks: IBurpExtenderCallbacks) {
    val model = BookmarksModel()
    val table = JTable(model)

    private val messageEditor = MessageEditor(callbacks)
    private val requestViewer: IMessageEditor? = messageEditor.requestViewer
    private val responseViewer: IMessageEditor? = messageEditor.responseViewer

    val panel = JSplitPane(JSplitPane.VERTICAL_SPLIT)
    private val bookmarks = model.bookmarks

    private val repeatInTable = JCheckBox("Add repeated request to table")

    init {
        BookmarkActions(this, bookmarks, callbacks)
        table.autoResizeMode = JTable.AUTO_RESIZE_OFF
        table.columnModel.getColumn(0).preferredWidth = 30 // ID
        table.columnModel.getColumn(1).preferredWidth = 150 // date
        table.columnModel.getColumn(2).preferredWidth = 150 // host
        table.columnModel.getColumn(3).preferredWidth = 500 // url
        table.columnModel.getColumn(4).preferredWidth = 80 // method
        table.columnModel.getColumn(5).preferredWidth = 60 // status
        table.columnModel.getColumn(6).preferredWidth = 120 // title
        table.columnModel.getColumn(7).preferredWidth = 70 // mime
        table.columnModel.getColumn(8).preferredWidth = 70 // protocol
        table.columnModel.getColumn(9).preferredWidth = 100 // file

        table.selectionModel.addListSelectionListener {
            val requestResponse = bookmarks[table.selectedRow].requestResponse
            messageEditor.requestResponse = requestResponse
            requestViewer?.setMessage(requestResponse.request, true)
            responseViewer?.setMessage(requestResponse.response, false)
        }

        val repeatPanel = JPanel(FlowLayout(FlowLayout.LEFT))

        val repeatButton = JButton("Repeat Request")
        repeatButton.addActionListener {
            repeatRequest()
            repeatButton.isFocusPainted = false
        }

        repeatInTable.isSelected = true

        repeatPanel.add(repeatButton)
        repeatPanel.add(repeatInTable)

        val bookmarksTable = JScrollPane(table)
        val reqResSplit =
            JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer?.component, responseViewer?.component)
        reqResSplit.resizeWeight = 0.5

        val repeatReqSplit =
            JSplitPane(JSplitPane.VERTICAL_SPLIT, repeatPanel, reqResSplit)

        panel.topComponent = bookmarksTable
        panel.bottomComponent = repeatReqSplit
        callbacks.customizeUiComponent(panel)
    }

    fun addBookmark(requestsResponses: Array<IHttpRequestResponse>) {
        for (requestResponse in requestsResponses) {
            createBookmark(requestResponse)
        }
    }

    private fun createBookmark(requestResponse: IHttpRequestResponse) {
        val now = LocalDateTime.now()
        val dateFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
        val dateTime = now.format(dateFormatter) ?: ""
        val requestInfo = callbacks.helpers.analyzeRequest(requestResponse)
        val responseInfo = callbacks.helpers.analyzeResponse(requestResponse.response)
        val host = requestInfo.url.host ?: ""
        val url = requestInfo.url
        val method = requestInfo.method ?: ""
        val statusCode = responseInfo.statusCode.toInt()
        val title = getTitle(requestResponse.response)
        val mimeType = responseInfo.inferredMimeType ?: ""
        val protocol = requestInfo.url.protocol
        val file = requestInfo.url.file
        val bookmark = Bookmark(
            requestResponse,
            dateTime,
            host,
            url,
            method,
            statusCode,
            title,
            mimeType,
            protocol,
            file
        )
        model.addBookmark(bookmark)
        requestResponse.highlight = "magenta"
        requestResponse.comment = "[^]"
    }

    private fun getTitle(response: ByteArray): String {
        val html = callbacks.helpers.bytesToString(response)
        val titleRegex = "<title>(.*?)</title>".toRegex()
        val title = titleRegex.find(html)?.value ?: ""
        val parsedTitle = title.removePrefix("<title>").removeSuffix("</title>")
        if (parsedTitle.length > 15) {
            return parsedTitle.substring(0, 14) + "+"
        }
        return parsedTitle
    }


    private fun repeatRequest() {
        Thread {
            callbacks.stdout.write("pushed".toByteArray())
            val requestResponse = callbacks.makeHttpRequest(messageEditor.httpService, requestViewer?.message)
            responseViewer?.setMessage(requestResponse.response, false)
            if (repeatInTable.isSelected) {
                createBookmark(requestResponse)
            }
        }.start()
    }
}

class MessageEditor(callbacks: IBurpExtenderCallbacks) : IMessageEditorController {
    var requestResponse: IHttpRequestResponse? = null

    val requestViewer: IMessageEditor? = callbacks.createMessageEditor(this, true)
    val responseViewer: IMessageEditor? = callbacks.createMessageEditor(this, false)

    override fun getResponse(): ByteArray? = requestResponse?.response

    override fun getRequest(): ByteArray? = requestResponse?.request

    override fun getHttpService(): IHttpService? = requestResponse?.httpService
}

class BookmarksModel : AbstractTableModel() {
    private val columns =
        listOf("ID", "Datetime", "Host", "URL", "Method", "Status", "Title", "MIME", "Protocol", "File")
    var bookmarks: MutableList<Bookmark> = ArrayList()

    override fun getRowCount(): Int = bookmarks.size

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
            5 -> java.lang.Integer::class.java
            6 -> String::class.java
            7 -> String::class.java
            8 -> String::class.java
            9 -> String::class.java
            else -> throw RuntimeException()
        }
    }

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val bookmark = bookmarks[rowIndex]

        return when (columnIndex) {
            0 -> rowIndex
            1 -> bookmark.dateTime
            2 -> bookmark.host
            3 -> bookmark.url.toString()
            4 -> bookmark.method
            5 -> bookmark.statusCode
            6 -> bookmark.title
            7 -> bookmark.mimeType
            8 -> bookmark.protocol
            9 -> bookmark.file
            else -> ""
        }
    }

    fun addBookmark(bookmark: Bookmark) {
        bookmarks.add(bookmark)
        fireTableRowsInserted(bookmarks.lastIndex, bookmarks.lastIndex)
    }

    fun removeBookmarks(selectedBookmarks: MutableList<Bookmark>) {
        bookmarks.removeAll(selectedBookmarks)
        fireTableDataChanged()
    }

    fun clearBookmarks() {
        bookmarks.clear()
        fireTableDataChanged()

    }
}

class BookmarkActions(
    private val panel: BookmarksPanel,
    private val bookmarks: MutableList<Bookmark>,
    private val callbacks: IBurpExtenderCallbacks
) : ActionListener {
    private val table = panel.table
    private val bookmarksActions = JPopupMenu()
    private val sendToRepeater = JMenuItem("Send request(s) to Repeater")
    private val sendToIntruder = JMenuItem("Send request(s) to Intruder")
    private val deleteBookmarks = JMenuItem("Delete bookmark(s)")
    private val clearBookmarks = JMenuItem("Clear bookmarks")


    init {
        sendToRepeater.addActionListener(this)
        sendToIntruder.addActionListener(this)
        deleteBookmarks.addActionListener(this)
        clearBookmarks.addActionListener(this)
        bookmarksActions.add(sendToRepeater)
        bookmarksActions.add(sendToIntruder)
        bookmarksActions.add(deleteBookmarks)
        bookmarksActions.add(clearBookmarks)
        panel.table.componentPopupMenu = bookmarksActions
    }


    override fun actionPerformed(e: ActionEvent?) {
        if (table.selectedRow == -1) return
        val selectedBookmarks = getSelectedBookmarks()
        when (val source = e?.source) {
            deleteBookmarks -> {
                panel.model.removeBookmarks(selectedBookmarks)
            }
            clearBookmarks -> {
                panel.model.clearBookmarks()
            }
            else -> {
                for (selectedBookmark in selectedBookmarks) {
                    val https = useHTTPs(selectedBookmark)
                    val url = selectedBookmark.url
                    when (source) {
                        sendToRepeater -> {
                            callbacks.sendToRepeater(
                                url.host,
                                url.port,
                                https,
                                selectedBookmark.requestResponse.request,
                                "${selectedBookmark.title}[^](${bookmarks.indexOf(selectedBookmark)})"
                            )
                        }
                        sendToIntruder -> {
                            callbacks.sendToIntruder(
                                url.host, url.port, https,
                                selectedBookmark.requestResponse.request, null
                            )
                        }
                    }

                }
            }
        }
    }

    private fun getSelectedBookmarks(): MutableList<Bookmark> {
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
