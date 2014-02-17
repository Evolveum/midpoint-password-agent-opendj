/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright © 2011-2012 ForgeRock AS. All rights reserved.
 *
 * The contents of this file are subject to the terms
 * of the Common Development and Distribution License
 * (the License). You may not use this file except in
 * compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://forgerock.org/license/CDDLv1.0.html
 * See the License for the specific language governing
 * permission and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL
 * Header Notice in each file and include the License file
 * at http://forgerock.org/license/CDDLv1.0.html
 * If applicable, add the following below the CDDL Header,
 * with the fields enclosed by brackets [] replaced by
 * your own identifying information:
 * "Portions Copyrighted [year] [name of copyright owner]"
 * 
 * Portions Copyrighted 2013 Salford Software td
 */
package com.evolveum.midpoint.pwdfilter.opendj;

import static com.evolveum.midpoint.pwdfilter.opendj.messages.MidpointAccountStatusNotificationHandlerMessages.ERR_MIDPOINT_PWDSYNC_CACHE_DIR_IS_NOT_DIR;
import static com.evolveum.midpoint.pwdfilter.opendj.messages.MidpointAccountStatusNotificationHandlerMessages.ERR_MIDPOINT_PWDSYNC_CACHE_DIR_IS_NOT_WRITABLE;
import static com.evolveum.midpoint.pwdfilter.opendj.messages.MidpointAccountStatusNotificationHandlerMessages.ERR_MIDPOINT_PWDSYNC_INVALID_CHACHE_DIR;
import static com.evolveum.midpoint.pwdfilter.opendj.messages.MidpointAccountStatusNotificationHandlerMessages.ERR_OPENIDM_PWSYNC_CREATE_LOGFILE;
import static com.evolveum.midpoint.pwdfilter.opendj.messages.MidpointAccountStatusNotificationHandlerMessages.ERR_MIDPOINT_PWSYNC_MISSING_CLIENTKEYALIAS;
import static com.evolveum.midpoint.pwdfilter.opendj.messages.MidpointAccountStatusNotificationHandlerMessages.INFO_OPENIDM_PWSYNC_LOGFILE_CHANGE_REQUIRES_RESTART;
import static com.evolveum.midpoint.pwdfilter.opendj.messages.MidpointAccountStatusNotificationHandlerMessages.INFO_OPENIDM_PWSYNC_UPDATE_INTERVAL_CHANGE_REQUIRES_RESTART;
import static org.opends.server.loggers.debug.DebugLogger.debugEnabled;
import static org.opends.server.loggers.debug.DebugLogger.getTracer;
import static org.opends.server.types.AccountStatusNotificationProperty.NEW_PASSWORD;
import static org.opends.server.util.StaticUtils.getFileForPath;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.opends.messages.Message;
import org.opends.server.admin.server.ConfigurationChangeListener;
import org.opends.server.admin.std.server.AccountStatusNotificationHandlerCfg;
import org.opends.server.api.AccountStatusNotificationHandler;
import org.opends.server.api.DirectoryThread;
import org.opends.server.api.ServerShutdownListener;
import org.opends.server.config.ConfigException;
import org.opends.server.core.DirectoryServer;
import org.opends.server.loggers.LogLevel;
import org.opends.server.loggers.debug.DebugTracer;
import org.opends.server.types.AccountStatusNotification;
import org.opends.server.types.Attribute;
import org.opends.server.types.AttributeType;
import org.opends.server.types.AttributeValue;
import org.opends.server.types.ConfigChangeResult;
import org.opends.server.types.DebugLogLevel;
import org.opends.server.types.Entry;
import org.opends.server.types.InitializationException;
import org.opends.server.types.ResultCode;

import com.evolveum.midpoint.pwdfilter.opendj.utils.CipherUtils;
import com.evolveum.midpoint.pwdfilter.opendj.utils.PasswordChange;
import com.evolveum.midpoint.xml.ns._public.model.model_1_wsdl.ModelPortType;
import com.evolveum.midpoint.pwdfilter.opendj.server.MidpointAccountStatusNotificationHandlerCfg;

/**
 * This class defines an account status notification handler that captures
 * information about account status notifications and forward them
 * to OpenIDM. The 2 events of interest are password reset and password
 * change, which will convey the new clear-text password.
 * 
 * @author Paul Heaney
 */
public class MidpointAccountStatusNotificationHandler
        extends AccountStatusNotificationHandler<MidpointAccountStatusNotificationHandlerCfg>
        implements
        ConfigurationChangeListener<MidpointAccountStatusNotificationHandlerCfg>,
        ServerShutdownListener {

    // The thread name.
    private static final String name = "MidPoint AccountStatus Notification Handler Thread";
    private MidpointAccountStatusNotificationHandlerCfg currentConfig;
    /**
     * The tracer object for the debug logger.
     */
    private static final DebugTracer TRACER = getTracer();
    private static final byte PWD_CHANGED = 1;
    private static final byte PWD_RESET = 2;
    //The name of the logfile that the update thread uses to process change
    //records. Defaults to "logs/pwsync", but can be changed in the
    //configuration.
    private String logFileName = null;
    //The hostname of the server
    private String hostname;
    //The File class that logfile corresponds to.
    private File logFile;
    //The update interval the background thread uses. If it is 0, then
    //the changes are processed in foreground.
    private long interval;
    //The flag used by the background thread to check if it should exit.
    private boolean stopRequested = false;
    //The Thread class that the background thread corresponds to.
    private Thread backGroundThread = null;
    //Request Queue
    private PersistedQueue queue = null;
    
    private ModelPortType midPointModelPort = null;
    
    private CipherUtils crypto;
    
    /**
     * {@inheritDoc}
     */
    public void initializeStatusNotificationHandler(
            MidpointAccountStatusNotificationHandlerCfg configuration)
            throws ConfigException, InitializationException {
        System.out.println("Starting to Initilise Midpoint notification handler");
        currentConfig = configuration;
        currentConfig.addMidpointChangeListener(this);

        // Fetch the local host name for the client host identification.
        try {
            hostname = java.net.InetAddress.getLocalHost().getCanonicalHostName();
        } catch (UnknownHostException ex) {
            hostname = "UnknownHost";
        }

        crypto = new CipherUtils();
        crypto.setEncryptionKeyAlias(currentConfig.getEncryptionKeyAlias());

        // Read configuration, check and initialize things here.
        logFileName = configuration.getLogFile();
        setUpLogFile(logFileName);

        /*
        midPointModelPort = setupMidPointConnection();
        // Update interval is applied only when server is restarted.
        interval = configuration.getUpdateInterval();
        //Set up background processing if interval > 0.
        if (interval > 0) {
            queue = new PersistedQueue(getFileForPath("pwsyncDb"), "OpenIDMSyncQueue", 10);
            setUpBackGroundProcessing();
        }
        */
        System.out.println("Finished initilising Midpoint notification handler");
    }

    /**
     * {@inheritDoc}
     */
    @Override()
    public boolean isConfigurationAcceptable(
            AccountStatusNotificationHandlerCfg configuration,
            List<Message> unacceptableReasons) {
        MidpointAccountStatusNotificationHandlerCfg config =
                (MidpointAccountStatusNotificationHandlerCfg) configuration;
        return isConfigurationChangeAcceptable(config, unacceptableReasons);
    }

    /**
     * {@inheritDoc}
     */
    public boolean isConfigurationChangeAcceptable(
            MidpointAccountStatusNotificationHandlerCfg configuration,
            List<Message> unacceptableReasons) {
        boolean isAcceptable = true;

        if (configuration.getEncryptionKeyAlias() == null) {
            isAcceptable = false;
            unacceptableReasons.add(ERR_MIDPOINT_PWSYNC_MISSING_CLIENTKEYALIAS.get());
        }
        
        // TODO check we have valid alias
        if (configuration.getPasswordCacheDir() == null) {
            isAcceptable = false;
            unacceptableReasons.add(ERR_MIDPOINT_PWDSYNC_INVALID_CHACHE_DIR.get());
        } else {
            File dir = new File(configuration.getPasswordCacheDir());
            if (!dir.isDirectory()) {
                isAcceptable = false;
                unacceptableReasons.add(ERR_MIDPOINT_PWDSYNC_CACHE_DIR_IS_NOT_DIR.get());
            } else {
                if (!dir.canWrite()) {
                    isAcceptable = false;
                    unacceptableReasons.add(ERR_MIDPOINT_PWDSYNC_CACHE_DIR_IS_NOT_WRITABLE.get());
                }
            }
        }

        System.out.println("isConfigAcceptable end");
        return isAcceptable;
    }

    /**
     * Makes a best-effort attempt to apply the configuration contained in the
     * provided entry.  Information about the result of this processing should be
     * added to the provided message list.  Information should always be added to
     * this list if a configuration change could not be applied.  If detailed
     * results are requested, then information about the changes applied
     * successfully (and optionally about parameters that were not changed) should
     * also be included.
     *
     * @param configuration   The entry containing the new configuration to
     *                        apply for this component.
     * @param detailedResults Indicates whether detailed information about the
     *                        processing should be added to the list.
     * @return Information about the result of the configuration update.
     */
    public ConfigChangeResult applyConfigurationChange(
            MidpointAccountStatusNotificationHandlerCfg configuration,
            boolean detailedResults) {
        ConfigChangeResult changeResult = applyConfigurationChange(configuration);
        return changeResult;
    }

    /**
     * {@inheritDoc}
     */
    public ConfigChangeResult applyConfigurationChange(
            MidpointAccountStatusNotificationHandlerCfg configuration) {
        ArrayList<Message> messages = new ArrayList<Message>();
        Boolean adminActionRequired = false;
        //User is not allowed to change the logfile name, append a message that the
        //server needs restarting for change to take effect.
        String newLogFileName = configuration.getLogFile();
        if (!logFileName.equals(newLogFileName)) {
            adminActionRequired = true;
            messages.add(INFO_OPENIDM_PWSYNC_LOGFILE_CHANGE_REQUIRES_RESTART.get(logFileName,
                    newLogFileName));
        }


        if ((currentConfig.getUpdateInterval() == 0) != (configuration.getUpdateInterval() == 0)) {
            adminActionRequired = true;
            messages.add(INFO_OPENIDM_PWSYNC_UPDATE_INTERVAL_CHANGE_REQUIRES_RESTART.get(
                    Long.toString(currentConfig.getUpdateInterval()),
                    Long.toString(configuration.getUpdateInterval())));
        } else {
            interval = configuration.getUpdateInterval();
        }
        currentConfig = configuration;

        return new ConfigChangeResult(ResultCode.SUCCESS, adminActionRequired,
                messages);
    }

    /**
     * Sets up the log file that the plugin can write update records to and
     * the background thread can use to read update records from. The specifed
     * log file name is the name to use for the file. If the file exists from
     * a previous run, use it.
     *
     * @param logFileName The name of the file to use, may be absolute.
     * @throws ConfigException If a new file cannot be created if needed.
     */
    private void setUpLogFile(String logFileName)
            throws ConfigException {
        this.logFileName = logFileName;
        logFile = getFileForPath(logFileName);

        try {
            if (!logFile.exists()) {
                logFile.createNewFile();
            }
        } catch (IOException io) {
            throw new ConfigException(ERR_OPENIDM_PWSYNC_CREATE_LOGFILE.get(
                    io.getMessage()), io);
        }
    }


    /**
     * {@inheritDoc}
     */
    public void handleStatusNotification(AccountStatusNotification notification) {
        MidpointAccountStatusNotificationHandlerCfg config = currentConfig;
        List<String> newPasswords = null;

        HashMap<String, List<String>> returnedData = new HashMap<String, List<String>>();
        Byte passwordEvent = 0;

        String userDN = String.valueOf(notification.getUserDN());
        Entry userEntry = notification.getUserEntry();

        Set<AttributeType> notificationAttrs = config.getAttributeType();
        for (AttributeType t : notificationAttrs) {
            List<Attribute> attrList = userEntry.getAttribute(t);
            if (attrList != null) {
                for (Attribute a : attrList) {
                    ArrayList<String> attrVals = new ArrayList<String>();
                    for (AttributeValue v : a) {
                        if (debugEnabled()) {
                            TRACER.debugInfo("Adding end user attribute value "
                                    + v.getValue().toString() + " from attr "
                                    + a.getNameWithOptions() + "to notification");
                        }
                        // Add the value of this attribute to the Notif message
                        attrVals.add(v.getValue().toString());
                    }
                    returnedData.put(a.getName().toString(), attrVals);
                }
            }
        }

        switch (notification.getNotificationType()) {
            case PASSWORD_CHANGED:
                // Build the password changed message
                newPasswords =
                        notification.getNotificationProperties().get(NEW_PASSWORD);
                passwordEvent = PWD_CHANGED;

                break;
            case PASSWORD_RESET:
                // Build the password reset message
                newPasswords =
                        notification.getNotificationProperties().get(NEW_PASSWORD);
                passwordEvent = PWD_RESET;
                break;
            default:
                // We are not interest by other events, just return
                return;
        }

        // Process the notification
        processMidPointNotification(passwordEvent, userDN, newPasswords, returnedData);
    }

    /**
     * Process a password change notification and sends it to OpenIDM.
     *
     * @param passwordEvent A byte indicating if it's a change or reset.
     * @param userDN        The user distinguished name as a string.
     * @param newPasswords  the list of new passwords (there may be more than 1).
     * @param returnedData  the additional attributes and values of the user
     *                      entry.
     */
    private void processMidPointNotification(byte passwordEvent,
                                            String userDN,
                                            List<String> newPasswords,
                                            Map<String, List<String>> returnedData) {
        if (debugEnabled()) {
            System.out.println("User " + userDN + " 's password "
                    + (passwordEvent == PWD_CHANGED ? "changed" : "reset")
                    + " to : " + newPasswords.toString() + " Additional data: "
                    + returnedData.toString());

        }

        PasswordChange pwdChange = new PasswordChange(userDN, returnedData.get("entryUUID").get(0), newPasswords.toString(), passwordEvent, hostname);
        pwdChange.addAdditionalData(returnedData);

        try {
            String filename = this.crypto.getEncryptionKeyAlias()+"_"+System.currentTimeMillis();
            String path = currentConfig.getPasswordCacheDir()+"/"+filename;
            if (debugEnabled()) {
                System.out.println("Writing pwd to "+path);
            }
            // PrintWriter pw = new PrintWriter(path);
            FileWriter fw = new FileWriter(new File(path));
            fw.write(crypto.encrypt(pwdChange.toXML()));
            // pw.println(crypto.encrypt(pwdChange.toXML()));
            // pw.println(pwdChange.toXML());
            // pw.close();
            fw.close();
        }catch (IOException ioe) {
            TRACER.debugCaught(LogLevel.ALL, ioe);
            System.out.println("Error writing to log file "+ioe.getMessage());
        }
    }

    /**
     * Return the listener name.
     *
     * @return The name of the listener.
     */
    public String getShutdownListenerName() {
        return name;
    }

    /**
     * @return the current configuration of the plugin
     */
    public MidpointAccountStatusNotificationHandlerCfg getCurrentConfiguration() {
        return currentConfig;
    }

    /**
     * Process a server shutdown. If the background thread is running it needs
     * to be interrupted so it can read the stop request variable and exit.
     *
     * @param reason The reason message for the shutdown.
     */
    public void processServerShutdown(Message reason) {
        stopRequested = true;

        // Wait for back ground thread to terminate
        while (backGroundThread != null && backGroundThread.isAlive()) {
            try {
                // Interrupt if its sleeping
                backGroundThread.interrupt();
                backGroundThread.join();
            } catch (InterruptedException ex) {
                //Expected.
            }
        }
        DirectoryServer.deregisterShutdownListener(this);
        queue.close();
        backGroundThread = null;
    }

    /**
     * Returns the interval time converted to milliseconds.
     *
     * @return The interval time for the background thread.
     */
    private long getInterval() {
        return interval * 1000;
    }

    /**
     * Sets up background processing of referential integrity by creating a
     * new background thread to process updates.
     */
    /* TODO look to get this working with midPoint - current runs into a clash of XML libraries
    private void setUpBackGroundProcessing() {
        if (backGroundThread == null) {
            DirectoryServer.registerShutdownListener(this);
            stopRequested = false;
            backGroundThread = new BackGroundThread();
            backGroundThread.start();
        }
    }
    */

    /**
     * Used by the background thread to determine if it should exit.
     *
     * @return Returns <code>true</code> if the background thread should exit.
     */
    private boolean isShuttingDown() {
        return stopRequested;
    }

    /**
     * The background referential integrity processing thread. Wakes up after
     * sleeping for a configurable interval and checks the log file for update
     * records.
     */
    private class BackGroundThread extends DirectoryThread {

        /**
         * Constructor for the background thread.
         */
        public BackGroundThread() {
            super(name);
        }

        /**
         * Run method for the background thread.
         */
        @Override
        public void run() {
            System.out.println("backgroundtread.run");
            while (!isShuttingDown()) {
                try {
                    sleep(getInterval());
                } catch (InterruptedException e) {
                    continue;
                } catch (Exception e) {
                    if (debugEnabled()) {
                        TRACER.debugCaught(DebugLogLevel.ERROR, e);
                    }
                }
                if (queue.size() > 0) {
                    String[] request = null;
                    try {
                        boolean success = true;
                        while (success && ((request = queue.poll()) != null)) {
                            /* TODO implement
                            Map item = mapper.readValue(request[1], Map.class);
                            List patch = (List) item.get("patch");
                            Map queryParameter = (Map) item.get(
                                    "queryParameter");
                            // success = postREST(queryParameter, patch);
                            System.out.println("Doing stuff to "+queryParameter+" with "+patch);
                            if (success) {
                                request = null;
                            }
                            */
                        }
                    } catch (Exception t) {
                        TRACER.debugCaught(DebugLogLevel.ERROR, t);
                    } finally {
                        if (null != request) {
                            try {
                                queue.push(request[0], request[1]);
                            } catch (IOException ex) {
                                //TODO: Do something here
                            }
                        }
                    }

                }
            }
        }
    }
}
