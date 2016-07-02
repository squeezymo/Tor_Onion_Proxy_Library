package com.msopentech.thali.android.toronionproxy;

import com.msopentech.thali.toronionproxy.OnionProxyManagerEventHandler;

public class AndroidOnionProxyManagerEventHandler extends OnionProxyManagerEventHandler {

    private final AndroidOnionProxyManager.LogManager logManager;

    public AndroidOnionProxyManagerEventHandler(AndroidOnionProxyManager.LogManager logManager) {
        this.logManager = logManager;
    }

    @Override
    public void message(String severity, String msg) {
        super.message(severity, msg);
        logManager.handleLogMessage(msg);
    }

}
