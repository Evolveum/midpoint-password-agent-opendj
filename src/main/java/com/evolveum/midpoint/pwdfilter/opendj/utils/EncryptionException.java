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

/**
 * @author Paul Heaney
 *
 */
public class EncryptionException extends Exception {
    
    /**
     * 
     */
    private static final long serialVersionUID = 6069664101866873310L;

    public EncryptionException(String message) {
        super(message);
    }
    
    public EncryptionException(String message, Throwable throwable) {
            super(message, throwable);
    }
    
    public EncryptionException(Throwable throwable) {
            super(throwable);
    }
}
