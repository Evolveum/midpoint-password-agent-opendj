/*
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 *
 * Copyright © 2013 Salford Software Ltd. All rights reserved.
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
 */
package com.evolveum.midpoint.pwdfilter.opendj;

import static com.evolveum.midpoint.pwdfilter.opendj.messages.MidpointAccountStatusNotificationHandlerMessages.ERR_MIDPOINT_PWDSYNC_CREATE_BLANK_DOCUMENT_ERROR;
import static com.evolveum.midpoint.pwdfilter.opendj.messages.MidpointAccountStatusNotificationHandlerMessages.ERR_MIDPOINT_PWDSYNC_PARSING_XML_CONFIG;
import static com.evolveum.midpoint.pwdfilter.opendj.messages.MidpointAccountStatusNotificationHandlerMessages.ERR_MIDPOINT_PWDSYNC_READING_CONFIG_FROM_LDAP;
import static com.evolveum.midpoint.pwdfilter.opendj.messages.MidpointAccountStatusNotificationHandlerMessages.ERR_MIDPOINT_PWDSYNC_PARSING_XML_PWD_FILE;
import static com.evolveum.midpoint.pwdfilter.opendj.messages.MidpointAccountStatusNotificationHandlerMessages.ERR_MIDPOINT_PWDSYNC_PROBLEM_UPDATING_PWD;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.Holder;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.XMLConfiguration;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.comparator.LastModifiedFileComparator;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.opends.server.types.InitializationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import com.evolveum.midpoint.model.client.ModelClientUtil;
import com.evolveum.midpoint.pwdfilter.opendj.utils.CipherUtils;
import com.evolveum.midpoint.xml.ns._public.common.api_types_2.ObjectListType;
import com.evolveum.midpoint.xml.ns._public.common.api_types_2.OperationOptionsType;
import com.evolveum.midpoint.xml.ns._public.common.common_2a.ObjectType;
import com.evolveum.midpoint.xml.ns._public.common.common_2a.OperationResultType;
import com.evolveum.midpoint.xml.ns._public.common.common_2a.ProtectedStringType;
import com.evolveum.midpoint.xml.ns._public.common.common_2a.ResourceObjectShadowChangeDescriptionType;
import com.evolveum.midpoint.xml.ns._public.common.common_2a.ShadowType;
import com.evolveum.midpoint.xml.ns._public.common.fault_1_wsdl.FaultMessage;
import com.evolveum.midpoint.xml.ns._public.model.model_1_wsdl.ModelPortType;
import com.evolveum.midpoint.xml.ns._public.model.model_1_wsdl.ModelService;
import com.evolveum.prism.xml.ns._public.query_2.QueryType;
import com.evolveum.prism.xml.ns._public.types_2.ChangeTypeType;
import com.evolveum.prism.xml.ns._public.types_2.ItemDeltaType;
import com.evolveum.prism.xml.ns._public.types_2.ModificationTypeType;
import com.evolveum.prism.xml.ns._public.types_2.ObjectDeltaType;

/**
 * 
 * @author Paul Heaney
 *
 */
public class PasswordPusher {

    private String endPoint = null;
    private String username = null;
    private String password = null;

    private DocumentBuilderFactory docBuilderFactor = DocumentBuilderFactory.newInstance();
    private DocumentBuilder docBuilder = null;

    private ModelPortType midPointModelPort = null;

    boolean shuttingDown = false;

    private String pwdChangeDirectory = null;

    // XML constants
    public static final String NS_COMMON = "http://midpoint.evolveum.com/xml/ns/public/common/common-2a";
    private static final QName COMMON_PATH = new QName(NS_COMMON, "path");
    private static final QName COMMON_VALUE = new QName(NS_COMMON, "value");
    private static final QName COMMON_ASSIGNMENT = new QName(NS_COMMON, "assignment");
    
    private CipherUtils cipherUtils;
    
    public PasswordPusher() throws InitializationException {
        this.readConfig();
        midPointModelPort = setupMidPointConnection();
        docBuilderFactor.setNamespaceAware(true);

        try {
            this.docBuilder = docBuilderFactor.newDocumentBuilder();
        } catch (ParserConfigurationException pce) {
            throw new InitializationException(ERR_MIDPOINT_PWDSYNC_CREATE_BLANK_DOCUMENT_ERROR.get(), pce.getCause());
        }

        cipherUtils = new CipherUtils();
    }
    
    public void startBackgroundThread() {
        (new BackgroundThread()).start();
    }
    
    private boolean isShuttingDown() {
        return shuttingDown;
    }
    
    private void readConfig() throws InitializationException {

        String configFile = "/opt/midpoint/opendj-pwdpusher.xml";
        if (System.getProperty("config") != null) {
            configFile = System.getProperty("config");
        }

        File f = new File(configFile);
        if (!f.exists() || !f.canRead()) {
            throw new IllegalArgumentException("Config file "+configFile+" does not exist or is not readable");
        }

        try {
            XMLConfiguration config = new XMLConfiguration(f);

            String notifierDN = "cn="+config.getString("passwordpusher.statusNotifierName") + ",cn=Account Status Notification Handlers";
            String ldapURL = config.getString("passwordpusher.ldapServerURL");
            boolean ldapSSL = config.getBoolean("passwordpusher.ldapServerSSL");
            String ldapUsername = config.getString("passwordpusher.ldapServerUsername");
            String ldapPassword = config.getString("passwordpusher.ldapServerPassword");

            Hashtable<Object, Object> env = new Hashtable<Object, Object>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, ldapURL+"/cn=config");
            env.put(Context.SECURITY_AUTHENTICATION, "simple");
            env.put(Context.SECURITY_PRINCIPAL, ldapUsername);
            env.put(Context.SECURITY_CREDENTIALS, ldapPassword);

            if (ldapSSL) {
                env.put(Context.SECURITY_PROTOCOL, "ssl");
            }

            try {
                DirContext context = new InitialDirContext(env);
                Attributes attr = context.getAttributes(notifierDN);

                this.endPoint = attr.get("ds-cfg-referrals-url").get(0).toString();
                this.username = attr.get("ds-cfg-midpoint-username").get(0).toString();
                this.password = attr.get("ds-cfg-midpoint-password").get(0).toString();
                this.pwdChangeDirectory = attr.get("ds-cfg-midpoint-passwordcachedir").get(0).toString();
            } catch (NamingException ne) {
                throw new InitializationException(ERR_MIDPOINT_PWDSYNC_READING_CONFIG_FROM_LDAP.get(ne.getMessage()), ne);
            }
        } catch (ConfigurationException ce) {
            throw new InitializationException(ERR_MIDPOINT_PWDSYNC_PARSING_XML_CONFIG.get(ce.getMessage()), ce);
        }
    }

    ModelPortType setupMidPointConnection() {

        System.out.println("Pwd Sync Endpoint is "+endPoint);

        ModelService modelService = new ModelService();
        ModelPortType modelPort = modelService.getModelPort();
        BindingProvider bp = (BindingProvider)modelPort;
        Map<String, Object> requestContext = bp.getRequestContext();
        requestContext.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, endPoint);

        org.apache.cxf.endpoint.Client client = ClientProxy.getClient(modelPort);
        org.apache.cxf.endpoint.Endpoint cxfEndpoint = client.getEndpoint();

        Map<String,Object> outProps = new HashMap<String,Object>();

        outProps.put(WSHandlerConstants.ACTION, WSHandlerConstants.USERNAME_TOKEN);

        outProps.put(WSHandlerConstants.USER, username);
        outProps.put(WSHandlerConstants.PASSWORD_TYPE, WSConstants.PW_DIGEST);
        outProps.put(WSHandlerConstants.PW_CALLBACK_REF, new MidPointPasswordCallback(password));
        System.out.println("After pwd");
        WSS4JOutInterceptor wssOut = new WSS4JOutInterceptor(outProps);
        cxfEndpoint.getOutInterceptors().add(wssOut);

        return modelPort;
    }

    /**
     * Copied from model-client-sample from Evolveum
     * @author semancik
     * @param type
     * @return
     */
    private String getTypeUri(Class<? extends ObjectType> type) {
        String typeUri = NS_COMMON + "#" + type.getSimpleName();
        return typeUri;
    }
    
    /**
     * Copied from model-client-sample from Evolveum
     * @author  
     * @param stringXml
     * @return
     * @throws SAXException
     * @throws IOException
     */
    private Element parseElement(String stringXml) throws SAXException, IOException {
        Document document = this.docBuilder.parse(IOUtils.toInputStream(stringXml, "utf-8"));
        return getFirstChildElement(document);
    }
    
    /**
     * Copied from model-client-sample from Evolveum
     * @author semancik
     * @param parent
     * @return
     */
    private Element getFirstChildElement(Node parent) {
        if (parent == null || parent.getChildNodes() == null) {
            return null;
        }

        NodeList nodes = parent.getChildNodes();
        for (int i = 0; i < nodes.getLength(); i++) {
            Node child = nodes.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                return (Element) child;
            }
        }

        return null;
    }


    boolean updatePassword(String dn, String password) {
        try {
            String oid = getOID(dn);

            return sendPassword(oid, password);
        }catch (Exception e){
            e.printStackTrace();// FIXME TODO improve
        }
        return false;
    }


    String getOID(String dn) throws IOException, JAXBException, SAXException, IllegalStateException, FaultMessage {

        /*Element filter = parseElement("<equal xmlns='http://prism.evolveum.com/xml/ns/public/query-2' xmlns:c='http://midpoint.evolveum.com/xml/ns/public/common/common-2a' >" +
                "<path>c:name</path>" +
                "<value>" + dn + "</value>" +
                "<recourceRed oid='229bc496-05bb-c47b-4998-66040aabb438'</resourceOid>" +
              "</equal>");*/


        QueryType query = unmarshallResouce("shadow.xml");
        OperationOptionsType options = new OperationOptionsType();
        Holder<ObjectListType> objectListHolder = new Holder<ObjectListType>();
        Holder<OperationResultType> resultHolder = new Holder<OperationResultType>();

        midPointModelPort.searchObjects(getTypeUri(ShadowType.class), query, options, objectListHolder, resultHolder);

        ObjectListType objectList = objectListHolder.value;
        List<ObjectType> objects = objectList.getObject();
        if (objects.isEmpty()) {
            return null;
        }
        if (objects.size() == 1) {
            ShadowType st = (ShadowType) objects.get(0);
            return st.getOid();
        }
        throw new IllegalStateException("Expected to find a single user with username '"+dn+"' but found "+objects.size()+" users instead");
    }


    boolean sendPassword(String oid, String password) {
        ResourceObjectShadowChangeDescriptionType change = new ResourceObjectShadowChangeDescriptionType();
        change.setOldShadowOid(oid);

        Document doc = docBuilder.newDocument();
        ItemDeltaType passwordDelta = new ItemDeltaType();
        passwordDelta.setModificationType(ModificationTypeType.REPLACE);
        passwordDelta.setPath(createPathElement("credentials/password", doc));
        ItemDeltaType.Value passwordValue = new ItemDeltaType.Value();
        passwordValue.getAny().add(toJaxbElement(COMMON_VALUE, createProtectedString(password)));
        passwordDelta.setValue(passwordValue);

        ObjectDeltaType delta = new ObjectDeltaType();
        delta.setOid(oid);
        delta.setChangeType(ChangeTypeType.MODIFY);
        delta.getModification().add(passwordDelta);

        change.setObjectDelta(delta);

        try {
            this.midPointModelPort.notifyChange(change);
        } catch (FaultMessage fe) {
            System.err.println("Fault: "+fe.getLocalizedMessage());
            fe.printStackTrace();
            return false;
        }

        return true;
    }

    /*
     * From model client RADO
     */
    private static Element createPathElement(String stringPath, Document doc) {
        String pathDeclaration = "declare default namespace '" + NS_COMMON + "'; " + stringPath;
        return createTextElement(COMMON_PATH, pathDeclaration, doc);
    }

    private static Element createTextElement(QName qname, String value, Document doc) {
        Element element = doc.createElementNS(qname.getNamespaceURI(), qname.getLocalPart());
        element.setTextContent(value);
        return element;
    }

    private static ProtectedStringType createProtectedString(String clearValue) {
        ProtectedStringType protectedString = new ProtectedStringType();
        protectedString.setClearValue(clearValue);
        return protectedString;
    }
    
    private static <T> JAXBElement<T> toJaxbElement(QName name, T value) {
        return new JAXBElement<T>(name, (Class<T>) value.getClass(), value);
    }
    /*
     * END
     */

    @SuppressWarnings("unchecked")
    private static <T> T unmarshallResouce(String path) throws JAXBException, FileNotFoundException {
        JAXBContext jc = ModelClientUtil.instantiateJaxbContext();
        Unmarshaller unmarshaller = jc.createUnmarshaller(); 

        InputStream is = null;
        JAXBElement<T> element = null;
        try {
            is = PasswordPusher.class.getClassLoader().getResourceAsStream(path);
            if (is == null) {
                throw new FileNotFoundException("System resource "+path+" was not found");
            }
            element = (JAXBElement<T>) unmarshaller.unmarshal(is);
        } finally {
            if (is != null) {
                IOUtils.closeQuietly(is);
            }
        }
        if (element == null) {
            return null;
        }
        return element.getValue();
    }


    private void processFile(File file) {

        try {
            FileInputStream fis = new FileInputStream(file);

            String s = IOUtils.toString(fis, "UTF-8").trim();
            System.out.println(s);

            String[] a = file.getName().split("_");
            cipherUtils.setEncryptionKeyAlias(a[0]);
            
            String xml = cipherUtils.decrypt(s);

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            DocumentBuilder db = dbf.newDocumentBuilder();

            Document doc = db.parse(new InputSource(new StringReader(xml)));

            String dn = doc.getElementsByTagName("userDN").item(0).getTextContent();
            String password = doc.getElementsByTagName("newPassword").item(0).getTextContent();

            fis.close();

            if (updatePassword(dn, password)) {
                file.delete();
            } else {
                // Record error
                System.out.println("Error updating password for "+dn); // TODO handle better
            }
        } catch (IOException ioe) {
            System.out.println("Error reading encrypted password change back from "+file.getName()+", "+ioe.getMessage()); // TODO handle better
        } catch (ParserConfigurationException pce) {
            System.out.println("Error parsing XML document of password change back from "+file.getName()+", "+pce.getMessage()); // TODO handle better
        } catch (SAXException se) {
            System.out.println("Error parsing XML document of password change back from "+file.getName()+", "+se.getMessage()); // TODO handle better
        }
    }

    public static void main(String[] args) throws InitializationException {
        PasswordPusher pp = new PasswordPusher();
        pp.startBackgroundThread();
    }

    public class BackgroundThread extends Thread {
        
        private int pollInterval = 1;
        
        public BackgroundThread() {
            super("BackgroundPasswordPusher");
        }
        
        @Override
        public void run() {
            File pwdChangeDir = new File(pwdChangeDirectory);

            while (!isShuttingDown()) {
                try {
                    sleep(getInterval());
                } catch (InterruptedException ie) {
                    continue;
                }

                // Scan directory and push
                File[] files = pwdChangeDir.listFiles();
                Arrays.sort(files, LastModifiedFileComparator.LASTMODIFIED_COMPARATOR);
                
                for (File f : files) {
                    processFile(f);
                }
            }
        }
        
        private int getInterval() {
            return pollInterval * 1000;
        }

    }
}
