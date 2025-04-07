/*
 * (C) Copyright 2015 Nuxeo SA (http://nuxeo.com/) and others.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Contributors:
 *     François Maturel
 */

package org.nuxeo.ecm.platform.ui.web.keycloak;

import java.io.Serializable;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.nuxeo.ecm.core.api.DocumentModel;
import org.nuxeo.ecm.core.api.DocumentModelList;
import org.nuxeo.ecm.core.api.NuxeoException;
import org.nuxeo.ecm.core.api.NuxeoPrincipal;
import org.nuxeo.ecm.core.cache.Cache;
import org.nuxeo.ecm.core.cache.CacheService;
import org.nuxeo.ecm.platform.api.login.UserIdentificationInfo;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.runtime.api.Framework;
import org.nuxeo.usermapper.extension.UserMapper;

/**
 * Plugin for the UserMapper to manage mapping between Ketcloack user and Nuxeo counterpart
 *
 * @since 7.4
 */
public class KeycloakUserMapper implements UserMapper {

    private static final Logger log = LogManager.getLogger(KeycloakUserMapper.class);

    protected static String userSchemaName = "user";

    protected static String groupSchemaName = "group";

    protected UserManager userManager;
    
    private Cache keycloakCache;

    @Override
    public NuxeoPrincipal getOrCreateAndUpdateNuxeoPrincipal(Object userObject) {
        return getOrCreateAndUpdateNuxeoPrincipal(userObject, true, true, null);
    }

    private boolean cleanUserRoles(String userId, List<String> userGroups, Set<String> keycloakRoles) {
        log.error("clean user roles for: " + userId);
        log.error("  user groups = " + userGroups);
        log.error("  keycloak roles = " + keycloakRoles);
        if (!Framework.isBooleanPropertyTrue("org.nuxeo.keycloak.roles.override")) {
            log.error("cleaning roles is disabled");
            return false;
        } else {
            boolean invalidatePrincipal = false;

            for (String userGroup : userGroups) {
                if (!keycloakRoles.contains(userGroup)) {
                    DocumentModel groupDoc = findGroup(userGroup);
//                    List<String> users = userManager.getUsersInGroupAndSubGroups(userGroup);
                    List<String> users = userManager.getUsersInGroup(userGroup);
                    users.remove(userId);
                    groupDoc.setProperty(groupSchemaName, userManager.getGroupMembersField(), users);
                    userManager.updateGroup(groupDoc);
                    log.error("  => remove user from group: " + userGroup);
                    invalidatePrincipal = true;
                }
            }

            if (invalidatePrincipal) {
                userManager.notifyUserChanged(userId, null);
                return true;
            } else {
                return false;
            }
        }
    }
    
    private boolean hasEntryInKeycloakCache(String userId) {
        if (keycloakCache != null) {
            return keycloakCache.hasEntry(userId);
        }
        return false;
    }
    
    private NuxeoPrincipal getEntryFromKeycloakCache(String userId) {
        if (keycloakCache != null) {
            return (NuxeoPrincipal) keycloakCache.get(userId);
        }
        return null;
    }
    
    private void putEntryInKeycloakCache(String userId) {
        if (keycloakCache != null) {
            keycloakCache.put(userId, userManager.getPrincipal(userId, true));
        }
    }
    
     @Override
     public NuxeoPrincipal getOrCreateAndUpdateNuxeoPrincipal(Object userObject, boolean createIfNeeded, boolean update,
             Map<String, Serializable> params) {
         return Framework.doPrivileged(() -> {
             KeycloakUserInfo userInfo = (KeycloakUserInfo) userObject;
             String userId = userInfo.getUserName();
             if (userId != null && hasEntryInKeycloakCache(userId)) {
                 log.info(String.format("%s found in Keycloak cache", userId));
                 if (cleanUserRoles(userId, getEntryFromKeycloakCache(userId).getGroups(),
                         userInfo.getRoles())) {
                     putEntryInKeycloakCache(userId);
                 }
                 return getEntryFromKeycloakCache(userId);
             } else {
                 // Remember that username is preferred_name by default
                 DocumentModel userDoc = findUser(userInfo);
                 if (userDoc == null) {
                     userDoc = createUser(userInfo);
                 }
                 updateUser(userDoc, userInfo);

                 for (String role : userInfo.getRoles()) {
                     log.error("Check role: " + role);
                     findOrCreateGroup(role, userInfo.getUserName());
                 }


                 cleanUserRoles(userId, userManager.getPrincipal(userId, true).getGroups(),
                         userInfo.getRoles());
                 NuxeoPrincipal principal = userManager.getPrincipal(userId, true);
                 putEntryInKeycloakCache(userId);
                 return principal;
             }
         });
     }

    @Override
    public void init(Map<String, String> params) throws Exception {
        userManager = Framework.getService(UserManager.class);
        userSchemaName = userManager.getUserSchemaName();
        groupSchemaName = userManager.getGroupSchemaName();
        CacheService cacheService = Framework.getService(CacheService.class);
        keycloakCache = cacheService.getCache("keycloak");
    }

    private DocumentModel findOrCreateGroup(String role, String userName) {
        DocumentModel groupDoc = findGroup(role);
        boolean invalidatePrincipal = false;
        if (groupDoc == null) {
            log.error("Group does not exist => create it : " + role);
            groupDoc = userManager.getBareGroupModel();
            groupDoc.setPropertyValue(userManager.getGroupIdField(), role);
            groupDoc.setProperty(groupSchemaName, "groupname", role);
            groupDoc.setProperty(groupSchemaName, "grouplabel", role + " group");
            groupDoc.setProperty(groupSchemaName, "description",
                    "Group automatically created by Keycloak based on user role [" + role + "]");
            groupDoc = userManager.createGroup(groupDoc);
        }
//        List<String> users = userManager.getUsersInGroupAndSubGroups(role);
        List<String> users = userManager.getUsersInGroup(role);
        log.error("Users in group = " + users);
        if (!users.contains(userName)) {
            users.add(userName);
            log.error("  adding '" + userName + "' to " + role);
            groupDoc.setProperty(groupSchemaName, userManager.getGroupMembersField(), users);
            log.error("users before update = " + groupDoc.getPropertyValue(groupSchemaName + ":" + userManager.getGroupMembersField()));
            userManager.updateGroup(groupDoc);
            log.error("users after update = " + userManager.getGroup(role).getMemberUsers());
            invalidatePrincipal = true;
        }

        if (invalidatePrincipal) {
            userManager.notifyUserChanged(userName, null);
        }
        return groupDoc;
    }

    private DocumentModel findGroup(String role) {
        Map<String, Serializable> query = new HashMap<>();
        query.put(userManager.getGroupIdField(), role);
        DocumentModelList groups = userManager.searchGroups(query, null);

        if (groups.isEmpty()) {
            return null;
        }
        return groups.get(0);
    }

    private DocumentModel findUser(UserIdentificationInfo userInfo) {
        Map<String, Serializable> query = new HashMap<>();
        log.error("Trying to find user: " + userManager.getUserIdField() + "=" + userInfo.getUserName());
        query.put(userManager.getUserIdField(), userInfo.getUserName());
        DocumentModelList users = userManager.searchUsers(query, null);

        if (users.isEmpty()) {
            return null;
        }
        return users.get(0);
    }

    private DocumentModel createUser(KeycloakUserInfo userInfo) {
        try {
            log.error("create user = " + userInfo.getUserName());
            DocumentModel userDoc = userManager.getBareUserModel();
            userDoc.setPropertyValue(userManager.getUserIdField(), userInfo.getUserName());
            userDoc.setPropertyValue(userManager.getUserEmailField(), userInfo.getEmail());
            return userManager.createUser(userDoc);
        } catch (NuxeoException e) {
            String message = "Error while creating user [" + userInfo.getUserName() + "] in UserManager";
            log.error(message, e);
            throw new RuntimeException(message);
        }
    }

    private void updateUser(DocumentModel userDoc, KeycloakUserInfo userInfo) {
        userDoc.setPropertyValue(userManager.getUserIdField(), userInfo.getUserName());
        userDoc.setPropertyValue(userManager.getUserEmailField(), userInfo.getEmail());
        userDoc.setProperty(userSchemaName, "firstName", userInfo.getFirstName());
        userDoc.setProperty(userSchemaName, "lastName", userInfo.getLastName());
        userDoc.setProperty(userSchemaName, "password", userInfo.getPassword());
        userDoc.setProperty(userSchemaName, "company", userInfo.getCompany());
        userManager.updateUser(userDoc);
    }

    @Override
    public Object wrapNuxeoPrincipal(NuxeoPrincipal principal, Object nativePrincipal,
            Map<String, Serializable> params) {
        throw new UnsupportedOperationException();
    }

    @Override
    public void release() {
    }

}
