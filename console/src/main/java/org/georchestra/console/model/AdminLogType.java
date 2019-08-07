/*
 * Copyright (C) 2009-2018 by the geOrchestra PSC
 *
 * This file is part of geOrchestra.
 *
 * geOrchestra is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option)
 * any later version.
 *
 * geOrchestra is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * geOrchestra.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.georchestra.console.model;

public enum AdminLogType {

    ACCOUNT_MODERATION("Account moderation"),
    ACCOUNT_MODERATION_ADD ("Account moderation add"),
    ACCOUNT_MODERATION_DEL ("Account moderation deleted"),
    ACCOUNT_MODERATION_CHANGE ("Account moderation changed"),
    SYSTEM_ROLE_ADD("Sytem role added"),
    SYSTEM_ROLE_DEL("Sytem role deleted"),
    SYSTEM_ROLE_CHANGE("System role"),
    OTHER_ROLE_ADD("Sytem role added"),
    OTHER_ROLE_DEL("Sytem role deleted"),
    OTHER_ROLE_CHANGE("Other role"),
    LDAP_ATTRIBUTE_CHANGE("User attributes"),
    EMAIL_SENT("Email sent"),
    ROLE_CREATE("Role added"),
    ROLE_DELETE("Role removed");


    private String name;

    private AdminLogType(String name){
        this.name = name;
    }

    public String toString(){ return name; }
}


