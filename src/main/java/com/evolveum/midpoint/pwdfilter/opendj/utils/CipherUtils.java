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

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.opends.server.util.Base64;

/**
 * @author Paul Heaney
 * Inspired by AESProtector for midPoint
 */
public class CipherUtils {

    private static final String CIPHER = "AES/ECB/PKCS5Padding";
    
    private String keyStorePath = "/usr/local/opendj/config/password.jceks"; // TODO we should store this in a file referenced from DS config
    private String keyStorePassword = "changeit"; // TODO we should store this in a file referenced from DS config
    private char[] password = keyStorePassword.toCharArray();
    private String encryptionKeyAlias = "strong";
    
    private KeyStore keyStore;

    public void setEncryptionKeyAlias(String key) {
        this.encryptionKeyAlias = key;
    }
    
    public String encrypt(String rawText) {
        
        try {
            init();

            SecretKey key = getSecretKeyByAlias(encryptionKeyAlias);
    
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            
            final String encryptedString = Base64.encode(cipher.doFinal(rawText.getBytes()));
            
            return encryptedString;
        } catch (Exception e) {
            e.printStackTrace(); // TODO handle better
        }
        
        return null;
    }
    
    public String decrypt(String encryptedText) {
        try {
            init();
            
            SecretKey key = getSecretKeyByAlias(encryptionKeyAlias);
    
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, key);
            
            final String decryptedString = new String (cipher.doFinal(Base64.decode(encryptedText)));
            
            return decryptedString;
        } catch (Exception e) {
            e.printStackTrace(); // TODO handle better
        }
        
        return null;
    }
    
    private SecretKey getSecretKeyByAlias(String alias) throws EncryptionException {
        Key key = null;
        
        try {
            key = keyStore.getKey(alias, password);
        } catch (Exception e) {
            throw new EncryptionException("Could not obtain key with alias "+alias+" fom keystore, reason: "+e.getMessage(), e);
        }
        
        if (key == null || !(key instanceof SecretKey)) {
            throw new EncryptionException("Key with alias "+alias+" is not instance of secret key, it is "+key);
        }
        
        return (SecretKey) key;
    }
    
    public String getEncryptionKeyAlias() {
        return this.encryptionKeyAlias;
    }
    
    private void init() throws Exception {
        this.keyStore = KeyStore.getInstance("jceks");
        FileInputStream inStream = new FileInputStream(keyStorePath);
        keyStore.load(inStream, password);
        inStream.close();
    }
}
