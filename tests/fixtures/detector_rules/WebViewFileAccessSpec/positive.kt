package fixture

import android.content.Context
import android.webkit.WebView

fun searchView(context: Context): WebView {
    return WebView(context).apply {
        settings.apply {
            javaScriptEnabled = true
            allowFileAccessFromFileURLs = true
            allowUniversalAccessFromFileURLs = true
        }
    }
}
