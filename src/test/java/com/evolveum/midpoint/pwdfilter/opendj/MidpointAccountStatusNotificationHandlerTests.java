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

import org.opends.server.types.InitializationException;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.evolveum.midpoint.pwdfilter.opendj.utils.CipherUtils;

/**
 * 
 * @author Paul Heaney
 *
 */
public class MidpointAccountStatusNotificationHandlerTests {

    PasswordPusher pp; 
   
    @BeforeClass
    public void oneTimeSetUp() {
          try {
              pp = new PasswordPusher();
          } catch (InitializationException ie) {
              System.err.println("Error unable to setup Password Pusher");
          }
    }
    
    @Test (enabled = false)
    public void createModelPort() throws Exception {
        String oid = pp.getOID("cn=topsecret1,justIDMTenancyName=default,ou=tenancies,ou=cloud,o=local");

        Assert.assertNotNull(oid);
        Assert.assertTrue(oid.length() > 0);
    }
    
    @Test
    public void testCrypto() {
        CipherUtils cu = new CipherUtils();
        
        String base = "bob";
        
        String enc = cu.encrypt(base);
        String dec = cu.decrypt(enc);
        
        Assert.assertEquals(base, dec);
    }
    
    @Test(enabled=false)
    public void testShadowChange() {
        pp.sendPassword("8b6700d4-43fc-43fd-bf3b-49eef12ff2af", "Fred123!");
    }
    
    public static void main(String[] args) throws Exception {
        /*
        PasswordPusher pp1 = new PasswordPusher();
        String oid = pp1.getOID("topsecret1", "dafault");
        Assert.assertNotNull(oid);
        Assert.assertTrue(oid.length() > 0);
        
        */
        CipherUtils cu = new CipherUtils();
        String base = "bob";
        
        String enc = cu.encrypt(base);
        String dec = cu.decrypt(enc);
        
        System.out.println("Bas: "+base);
        System.out.println("Enc: "+enc);
        System.out.println("Dec: "+dec);
        
        String s = "vSY2YEa8O2SENq2RWAniRLlCk4GPIc7yqDFOYamKQ2isrRimLYGvUv5EHzFQJYKIhjUhSSQyMgCPZC6DTU+v5F1SUsiodEdeVpxSEv3qA4zKyJqBpF+H49aOnxvjtAlaPs86lomhigarnCn55yq3Ijs1/1yDdxFwWtgu8eGOUGu6iTzYaAOmryT7FQiG4XBXgiqJmvs5DKT5Sih278fSKD85al1KRcYz8ZHj4aGoqbLZEEs8KQQGXieum3McFlvIL9pcW2q69MbhbCBobAZ1ZPbvn5yqqbebzkbWIsocYpT68VMhEl+VjSLnkRXuvjfEdRbIwTEmKeSQWn7MB6e/3BM5PK10BFitlUSIYgixTyF+1ZF+dbrw85xEXkqJCmp+kjoN4WkY1kaYtc18vmGnYLOuhylN8iP4k+6Nfm0F78ujhoxHSt1N6dmNhBghVjhgKSNPW1GiOiI/7N4d/Rfb6A==";
        System.out.println("Dec: "+cu.decrypt(s));
    }

}
