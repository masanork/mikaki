package app.mikaki.app_session

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Bitmap
import android.net.Uri
import android.net.http.SslError
import android.view.View
import android.view.ViewGroup
import android.webkit.*
import android.widget.FrameLayout
import androidx.appcompat.app.AppCompatActivity
import androidx.activity.OnBackPressedCallback
import androidx.webkit.WebSettingsCompat
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import app.tauri.annotation.Command
import app.tauri.annotation.InvokeArg
import app.tauri.annotation.TauriPlugin
import app.tauri.plugin.Invoke
import app.tauri.plugin.JSObject
import app.tauri.plugin.Plugin

@InvokeArg
class WorkspaceArgs {
    var visible: Boolean = false
    var page: String = "chat"
    var top: Double = 0.0
    var bottom: Double = 0.0
    var viewportWidth: Double = 0.0
}

/** A plain WebView, without Tauri IPC, signer methods, or JS cookie access. */
@TauriPlugin
class AppSessionPlugin(private val activity: Activity): Plugin(activity) {
    private lateinit var shell: WebView
    private var workspace: WebView? = null
    private var ready = false
    private var failure: String? = null
    private var shown = false
    private var draft = false
    private var page = "chat"
    private var back: OnBackPressedCallback? = null

    override fun load(webView: WebView) {
        shell = webView
        val owner = activity as AppCompatActivity
        back = object: OnBackPressedCallback(false) {
            override fun handleOnBackPressed() {
                // Let the local shell request the normal hide/discard path.
                if (shell.url?.startsWith("http://tauri.localhost/") == true || shell.url?.startsWith("https://tauri.localhost/") == true)
                    shell.evaluateJavascript("if(!document.getElementById('wallet-login-cancel').hidden)document.getElementById('wallet-login-cancel').click();location.hash='wallet'", null)
            }
        }.also { owner.onBackPressedDispatcher.addCallback(owner, it) }
    }

    private fun trusted(uri: Uri): Boolean =
        uri.scheme == "https" && uri.host == "auth.mikaki.org" &&
        uri.port == -1 && uri.userInfo == null

    private fun visibility(visible: Boolean) {
        val changed = shown != visible
        shown = visible
        back?.isEnabled = visible
        workspace?.let {
            // Fixed lifecycle signal only. No keys, account IDs, or cookie values.
            if (changed) it.evaluateJavascript("window.__MIKAKI_WORKSPACE_VISIBLE__=$visible;window.dispatchEvent(new Event('mikaki-workspace-visibility'))", null)
            it.visibility = if (visible) View.VISIBLE else View.INVISIBLE
        }
    }

    @Suppress("SetJavaScriptEnabled")
    private fun create(): WebView {
        check(WebViewFeature.isFeatureSupported(WebViewFeature.WEB_AUTHENTICATION))
        check(WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_LISTENER))
        check(WebViewFeature.isFeatureSupported(WebViewFeature.DOCUMENT_START_SCRIPT))
        val parent = shell.parent as FrameLayout
        val view = WebView(activity)
        view.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            allowFileAccess = false
            allowContentAccess = false
            mixedContentMode = WebSettings.MIXED_CONTENT_NEVER_ALLOW
            setSupportMultipleWindows(false)
            javaScriptCanOpenWindowsAutomatically = false
        }
        CookieManager.getInstance().setAcceptThirdPartyCookies(view, false)
        WebSettingsCompat.setWebAuthenticationSupport(view.settings, WebSettingsCompat.WEB_AUTHENTICATION_SUPPORT_FOR_APP)
        WebViewCompat.addDocumentStartJavaScript(view,
            "Object.defineProperty(window,'__MIKAKI_NATIVE__',{value:true});Object.defineProperty(window,'__MIKAKI_NATIVE_SHELL__',{value:true});window.__MIKAKI_NATIVE_PAGE__='$page';window.__MIKAKI_WORKSPACE_VISIBLE__=true;",
            setOf("https://auth.mikaki.org"))
        WebViewCompat.addWebMessageListener(view, "MikakiWorkspace", setOf("https://auth.mikaki.org")) { _, message, origin, mainFrame, _ ->
            if (mainFrame && trusted(origin)) when (message.data) {
                "ready" -> { ready = true; failure = null }
                "locked" -> { ready = false }
                "draft" -> { draft = true }
                "clean" -> { draft = false }
                "wallet" -> {
                    visibility(false)
                    // The shell itself must still be a bundled document.
                    if (shell.url?.startsWith("http://tauri.localhost/") == true || shell.url?.startsWith("https://tauri.localhost/") == true)
                        shell.evaluateJavascript("location.hash='wallet'", null)
                }
            }
        }
        view.webViewClient = object: WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                if (!request.isForMainFrame) return !trusted(request.url)
                if (trusted(request.url) && request.url.path == "/native/wallet" && request.url.query == null && request.url.fragment == null) {
                    visibility(false)
                    shell.evaluateJavascript("location.hash='wallet'", null)
                    return true
                }
                return !trusted(request.url)
            }
            override fun onPageStarted(view: WebView, url: String, favicon: Bitmap?) {
                ready = false
                failure = null
            }
            override fun onReceivedSslError(view: WebView, handler: SslErrorHandler, error: SslError) {
                handler.cancel()
                ready = false
                failure = "secure_connection_failed"
                visibility(false)
            }
            override fun onReceivedError(view: WebView, request: WebResourceRequest, error: WebResourceError) {
                if (request.isForMainFrame) {
                    ready = false
                    failure = "connection_failed"
                    visibility(false)
                }
            }
            override fun onReceivedHttpError(view: WebView, request: WebResourceRequest, response: WebResourceResponse) {
                if (request.isForMainFrame && response.statusCode >= 400) {
                    ready = false
                    failure = "service_unavailable"
                    visibility(false)
                }
            }
        }
        view.webChromeClient = object: WebChromeClient() {
            override fun onJsConfirm(view: WebView, url: String, message: String, result: JsResult): Boolean {
                if (!trusted(Uri.parse(url))) { result.cancel(); return true }
                AlertDialog.Builder(activity).setMessage(message)
                    .setPositiveButton("続ける") { _, _ -> result.confirm() }
                    .setNegativeButton("戻る") { _, _ -> result.cancel() }
                    .setOnCancelListener { result.cancel() }.show()
                return true
            }
        }
        parent.addView(view, FrameLayout.LayoutParams(1, 1))
        workspace = view
        view.loadUrl("https://auth.mikaki.org/vault")
        return view
    }

    @Command
    fun workspace(invoke: Invoke) = activity.runOnUiThread {
        try {
            val args = invoke.parseArgs(WorkspaceArgs::class.java)
            require(args.page in setOf("chat", "account"))
            require(args.top.isFinite() && args.bottom.isFinite() && args.viewportWidth.isFinite())
            require(args.top in 0.0..250.0 && args.bottom in 48.0..300.0 && args.viewportWidth in 280.0..3000.0)
            if (!args.visible) {
                if (shown && draft) {
                    AlertDialog.Builder(activity)
                        .setMessage("入力中の内容を破棄して移動しますか？")
                        .setPositiveButton("破棄して移動") { _, _ -> draft = false; visibility(false); invoke.resolve() }
                        .setNegativeButton("Chatに戻る") { _, _ -> invoke.reject("draft_kept") }
                        .setOnCancelListener { invoke.reject("draft_kept") }.show()
                } else { visibility(false); invoke.resolve() }
                return@runOnUiThread
            }
            if (failure != null) resetView()
            val pageChanged = page != args.page
            page = args.page
            val view = workspace ?: create()
            val scale = shell.width / args.viewportWidth
            val top = (args.top * scale).toInt()
            val bottom = (args.bottom * scale).toInt()
            view.layoutParams = FrameLayout.LayoutParams(shell.width, (shell.height - top - bottom).coerceAtLeast(1)).apply {
                topMargin = shell.top + top
                leftMargin = shell.left
            }
            visibility(true)
            if (pageChanged) view.evaluateJavascript("window.__MIKAKI_NATIVE_PAGE__='$page';window.dispatchEvent(new Event('mikaki-workspace-page'))", null)
            invoke.resolve()
        } catch (_: Exception) { failure = "workspace_unavailable"; invoke.reject("workspace_unavailable") }
    }

    @Command
    fun status(invoke: Invoke) = activity.runOnUiThread {
        // HttpOnly cookie is returned ONLY to the Rust plugin handle. The plugin
        // has no JavaScript command registration or capability.
        val cookie = CookieManager.getInstance().getCookie("https://auth.mikaki.org/")
            ?.split(';')?.map { it.trim() }?.filter { it.startsWith("__Host-op-sso=") }
            ?.singleOrNull()?.substringAfter('=')?.takeIf { it.matches(Regex("[A-Za-z0-9_-]{43}")) }
        invoke.resolve(JSObject().apply {
            put("ready", ready)
            put("error", failure)
            if (ready && cookie != null) put("cookie", cookie)
        })
    }

    @Command
    fun reset(invoke: Invoke) = activity.runOnUiThread { resetView(); invoke.resolve() }

    private fun resetView() {
        workspace?.let { view ->
            (view.parent as? ViewGroup)?.removeView(view)
            view.stopLoading()
            view.destroy()
        }
        workspace = null
        ready = false
        shown = false
        back?.isEnabled = false
        failure = null
        draft = false
    }

    @Command
    fun clear(invoke: Invoke) = activity.runOnUiThread {
        resetView()
        // Sign out this app, without deleting unrelated site/app cookies.
        CookieManager.getInstance().setCookie("https://auth.mikaki.org/", "__Host-op-sso=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Lax") {
            CookieManager.getInstance().flush()
            invoke.resolve()
        }
    }

    override fun onPause(activity: AppCompatActivity) {
        workspace?.evaluateJavascript("window.__MIKAKI_WORKSPACE_VISIBLE__=false;window.dispatchEvent(new Event('mikaki-workspace-visibility'))", null)
    }
    override fun onResume(activity: AppCompatActivity) {
        if (shown) workspace?.evaluateJavascript("window.__MIKAKI_WORKSPACE_VISIBLE__=true;window.dispatchEvent(new Event('mikaki-workspace-visibility'))", null)
    }
    override fun onDestroy(activity: AppCompatActivity) {
        workspace?.destroy()
        workspace = null
    }
}
