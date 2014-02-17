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
package com.evolveum.midpoint.pwdfilter.opendj.utils;

import java.io.Serializable;
import java.io.StringWriter;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author Paul Heaney
 *
 */
public class PasswordChange implements Serializable {

    /**
     * 
     */
    private static final long serialVersionUID = 266092412620767878L;

    private String password;
    private String uuid;
    private String userDN;
    private byte type;
    private Map<String, List<String>> additionalData;
    private String hostname;
    
    public PasswordChange(String userDN, String uuid, String password, byte type, String hostname) {
        this.userDN = userDN;
        this.uuid = uuid;
        this.password = password;
        this.type = type;
        this.hostname = hostname;
    }
    
    public void addAdditionalData(Map<String, List<String>> additionalData) {
        this.additionalData = additionalData; 
    }

    public String getPassword() {
        return password;
    }

    public String getUuid() {
        return uuid;
    }

    public String getUserDN() {
        return userDN;
    }

    public byte getType() {
        return type;
    }

    public String getHostName() {
        return hostname;
    };
    
    public String toXML() {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        try {
            DocumentBuilder db = dbf.newDocumentBuilder();
            
            Document doc = db.newDocument();
            
            Element root = doc.createElement("pwdChange");
            Element dn = doc.createElement("userDN");
            dn.setTextContent(this.userDN);
            root.appendChild(dn);
            
            Element pwd = doc.createElement("newPassword");
            pwd.setTextContent(password.substring(1, password.length()-1));
            root.appendChild(pwd);
            
            Element t = doc.createElement("type");
            t.setTextContent(Byte.toString(type));
            root.appendChild(t);
            
            Element host = doc.createElement("hostname");
            host.setTextContent(hostname);
            root.appendChild(host);
            
            Element other = doc.createElement("additionalData");
            Set<String> keys = additionalData.keySet();
            for (String key : keys) {
                Element a = doc.createElement(key);
                if (additionalData.get(key).size() > 1) {
                    List<String> l = additionalData.get(key);
                    for (String v : l) {
                        Element value = doc.createElement("value");
                        value.setTextContent(v);
                        a.appendChild(value);
                    }
                } else {
                    a.setTextContent(additionalData.get(key).get(0));
                }
                
                other.appendChild(a);
            }
            
            root.appendChild(other);
            
            
            doc.appendChild(root);
            
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            StringWriter sw = new StringWriter();
            transformer.transform(new DOMSource(doc), new StreamResult(sw));
            return sw.getBuffer().toString();
        } catch (ParserConfigurationException pce) {
            System.out.println("Failed to create XML document for password change "+pce.getMessage());
        } catch (TransformerConfigurationException tce) {
            System.out.println("Failed to transform XML document to string "+tce.getMessage());
        } catch (TransformerException te) {
            System.out.println("Failed to transform XML document to string "+te.getMessage());
        }
        
        return null;
        
        
    }
}
