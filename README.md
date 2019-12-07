# Bookmarks [^]

A simple Burp Suite extension to *bookmark* requests for later, instead of those 100 unnamed repeater tabs you've got open. 

#### Features:
* Save requests to table
* Highlight bookmarked requests in Proxy History
* Send to Repeater with tabs labeled with response titles

## Install the Bookmarks Burp Suite Plugin
### Build the extension

```sh
./gradlew fatJar
```

Extension JAR will be located at: `build/libs/bookmarks.jar`

#### Load the extension
1. Open Burp Suite
2. Go to Extender tab
3. Burp Extensions -> Add
4. Load bookmarks.jar


### Usage
1. Select and right click on request(s)
2. Select `add bookmark(s) [^]`
3. Requests will be added to the `[^]` tab.