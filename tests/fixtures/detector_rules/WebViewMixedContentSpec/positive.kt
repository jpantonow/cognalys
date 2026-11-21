package fixture

import android.content.Context
import android.webkit.WebSettings
import android.webkit.WebView

fun createWebView(context: Context): WebView {
    return WebView(context).apply {
        settings.javaScriptEnabled = true
        settings.mixedContentMode = WebSettings.MIXED_CONTENT_ALWAYS_ALLOW
    }
}
