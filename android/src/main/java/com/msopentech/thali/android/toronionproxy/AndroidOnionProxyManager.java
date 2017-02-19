/*
Copyright (C) 2011-2014 Sublime Software Ltd

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
 */

/*
Copyright (c) Microsoft Open Technologies, Inc.
All Rights Reserved
Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED,
INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
MERCHANTABLITY OR NON-INFRINGEMENT.

See the Apache 2 License for the specific language governing permissions and limitations under the License.
*/

package com.msopentech.thali.android.toronionproxy;

import android.annotation.SuppressLint;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.os.Build;
import android.os.Handler;
import android.os.HandlerThread;
import android.os.Message;

import com.msopentech.thali.toronionproxy.OnionProxyManager;
import com.msopentech.thali.toronionproxy.OnionProxyManagerEventHandler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.lang.ref.WeakReference;
import java.util.logging.LogManager;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static android.content.Context.CONNECTIVITY_SERVICE;
import static android.net.ConnectivityManager.CONNECTIVITY_ACTION;
import static android.net.ConnectivityManager.EXTRA_NO_CONNECTIVITY;

public class AndroidOnionProxyManager extends OnionProxyManager {
    public static final String EXTRA_MESSAGE_TYPE = "MessageType";
    public static final String EXTRA_BOOTSTRAP_PROGRESS = "BootstrapProgress";
    public static final String EXTRA_BOOTSTRAP_INFO = "BootstrapInfo";

    public static final int MESSAGE_TYPE_BOOTSTRAP = 1;

    private static final int INNER_MESSAGE_NETWORK_STATE = 1;

    private static final Logger LOG = LoggerFactory.getLogger(AndroidOnionProxyManager.class);

    private volatile BroadcastReceiver networkStateReceiver;

    private final Context context;
    private final LogManager logManager;
    private final HandlerThread backgroundThread;
    private final Handler backgroundHandler;

    public AndroidOnionProxyManager(final Context context, final String workingSubDirectoryName) {
        super(new AndroidOnionProxyContext(context, workingSubDirectoryName));

        this.context = context;
        this.logManager = new LogManager(context);
        this.backgroundThread = new HandlerThread(
                AndroidOnionProxyManager.class.getCanonicalName(),
                android.os.Process.THREAD_PRIORITY_BACKGROUND
        );

        this.backgroundThread.start();
        this.backgroundHandler = new Handler(backgroundThread.getLooper(), new Handler.Callback() {
            @Override
            public boolean handleMessage(Message msg) {
                if (msg.what == INNER_MESSAGE_NETWORK_STATE) {
                    final Intent intent = msg.getData().getParcelable("intent");

                    try {
                        if(intent == null || !isRunning()) {
                            return true;
                        }
                    }
                    catch (IOException e) {
                        LOG.info("Did someone call before Tor was ready?", e);
                        return true;
                    }

                    boolean online = !intent.getBooleanExtra(EXTRA_NO_CONNECTIVITY, false);

                    if (online) {
                        // Some devices fail to set EXTRA_NO_CONNECTIVITY, double check
                        final Object o = context.getSystemService(CONNECTIVITY_SERVICE);
                        final ConnectivityManager cm = (ConnectivityManager) o;
                        final NetworkInfo net = cm.getActiveNetworkInfo();

                        if (net == null || !net.isConnected()) {
                            online = false;
                        }
                    }

                    LOG.info("Online: " + online);

                    try {
                        enableNetwork(online);
                    }
                    catch(IOException e) {
                        LOG.warn(e.toString(), e);
                    }

                    return true;
                }

                return false;
            }
        });

    }

    @Override
    public boolean installAndStartTorOp() throws IOException, InterruptedException {
        if (super.installAndStartTorOp()) {
            // Register to receive network status events
            networkStateReceiver = new NetworkStateReceiver();
            IntentFilter filter = new IntentFilter(CONNECTIVITY_ACTION);
            context.registerReceiver(networkStateReceiver, filter);
            return true;
        }
        return false;
    }

    @Override
    public void stop() throws IOException {
        try {
            super.stop();
        } finally {
            if (networkStateReceiver != null) {
                try {
                    context.unregisterReceiver(networkStateReceiver);
                } catch(IllegalArgumentException e) {
                    // There is a race condition where if someone calls stop before installAndStartTorOp is done
                    // then we could get an exception because the network state receiver might not be properly
                    // registered.
                    LOG.info("Someone tried to call stop before we had finished registering the receiver", e);
                }
            }
        }
    }

    @SuppressLint("NewApi")
    protected boolean setExecutable(File f) {
        if(Build.VERSION.SDK_INT >= 9) {
            return f.setExecutable(true, true);
        } else {
            String[] command = { "chmod", "700", f.getAbsolutePath() };
            try {
                return Runtime.getRuntime().exec(command).waitFor() == 0;
            } catch(IOException e) {
                LOG.warn(e.toString(), e);
            } catch(InterruptedException e) {
                LOG.warn("Interrupted while executing chmod");
                Thread.currentThread().interrupt();
            } catch(SecurityException e) {
                LOG.warn(e.toString(), e);
            }
            return false;
        }
    }

    @Override
    protected void handleLogMessage(final String logMessage) {
        logManager.handleLogMessage(logMessage);
    }

    @Override
    protected OnionProxyManagerEventHandler getEventHandler() {
        if (onionProxyManagerEventHandler == null) {
            onionProxyManagerEventHandler = new AndroidOnionProxyManagerEventHandler(logManager);
        }

        return onionProxyManagerEventHandler;
    }

    public static class LogManager {
        private final static Pattern bootstrapProgressPattern = Pattern.compile("Bootstrapped (\\d+)%: (.*)");
        private final WeakReference<Context> context;

        public LogManager(Context context) {
            this.context = new WeakReference<>(context);
        }

        public void handleLogMessage(final String logMessage) {
            final Matcher bootstrapMatcher = bootstrapProgressPattern.matcher(logMessage);

            if (bootstrapMatcher.matches()) {
                final int progressPercent = Integer.valueOf(bootstrapMatcher.group(1));
                final String progressInfo = bootstrapMatcher.group(2);

                broadcastBootstrapProgress(progressPercent, progressInfo);
            }
        }

        private void broadcastBootstrapProgress(final int progressPercent, final String progressInfo) {
            final Context context = this.context.get();

            if (context != null) {
                final Intent intent = new Intent();

                intent.setAction(AndroidOnionProxyManager.class.getCanonicalName());
                intent.setPackage(context.getPackageName());

                intent.putExtra(EXTRA_MESSAGE_TYPE, MESSAGE_TYPE_BOOTSTRAP);
                intent.putExtra(EXTRA_BOOTSTRAP_PROGRESS, progressPercent);
                intent.putExtra(EXTRA_BOOTSTRAP_INFO, progressInfo);

                context.sendBroadcast(intent);
            }
        }
    }

    private class NetworkStateReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context ctx, Intent i) {
            final Message message = Message.obtain();

            message.what = INNER_MESSAGE_NETWORK_STATE;
            message.getData().putParcelable("intent", i);

            backgroundHandler.sendMessage(message);
        }
    }
}
