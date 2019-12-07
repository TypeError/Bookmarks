package burp

class BurpExtender : IBurpExtender {
    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        val tab = BookmarkTab(callbacks)
        val table = tab.bookmarkTable
        val menuItem = BookmarkMenu(table)
        callbacks.stdout.write("Bookmarks [^] v0.1".toByteArray())
        callbacks.stdout.write("\nAuthor: Caleb Kinney".toByteArray());
        callbacks.stdout.write("\nGitHub: github.com/cak".toByteArray());
        callbacks.setExtensionName("Bookmarks [^]")
        callbacks.addSuiteTab(tab)
        callbacks.registerContextMenuFactory(menuItem)
    }
}