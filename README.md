# Bookmarks [^]

A [Burp Suite](https://portswigger.net/burp) extension to *bookmark* requests for later, instead of those 100 unnamed repeater tabs you've got open. 

Bookmarks works in both the Community (Free) and Professional versions. 

You can find [Bookmarks](https://portswigger.net/bappstore/ef6d970f0d11452ea024691dffb4b39c) on the [BApp Store](https://portswigger.net/bappstore). 

#### Features:
* Save requests to table
* Repeat requests directly from the `[^]` tab (and save to table)
* Highlight bookmarked requests in Proxy History
* Send to Repeater with tabs labeled with response titles
* Load highlighted requests from existing Proxy History
* Search bookmarks
* Tags
* Comments

![Bookmarks](/images/bookmarks.png)

## Install the Bookmarks Burp Suite Extension

### BApp Store
Install [Bookmarks](https://portswigger.net/bappstore/ef6d970f0d11452ea024691dffb4b39c) from the [BApp Store](https://portswigger.net/bappstore) inside Burp Suite. 

### Download or build the extension
#### Option 1: Download release
You can find the latest release (JAR file) [here](https://github.com/TypeError/Bookmarks/releases). 

#### Option 2: Build the extension

```sh
gradle build fatJar
```

Extension JAR will be located at: `build/libs/bookmarks.jar`

### Load the extension
1. Open Burp Suite
2. Go to Extender tab
3. Burp Extensions -> Add
4. Load bookmarks.jar


### Usage
#### Add bookmark
1. Select and right click on request(s)
2. Select `add bookmark(s) [^]`
3. Requests will be added to the `[^]` tab.

#### Repeat requests
1. Edit request (left)
2. Click the `Repeat Request` button
3. Response (right) will be updated

*If the `Add repeated request to table` checkbox is checked, requests will be added to the table*

 
