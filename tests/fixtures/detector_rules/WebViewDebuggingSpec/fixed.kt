package fixture

import android.webkit.WebView

class Screen(private val webView: WebView) {
    fun setupWebView() {
        if (BuildConfig.DEBUG) {
            WebView.setWebContentsDebuggingEnabled(true)
        }
        webView.settings.javaScriptEnabled = true
    }
}
