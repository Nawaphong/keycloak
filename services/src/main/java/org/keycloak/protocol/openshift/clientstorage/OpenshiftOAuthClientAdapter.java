/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.keycloak.protocol.openshift.clientstorage;

import org.keycloak.models.ClientTemplateModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ProtocolMapperModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory;
import org.keycloak.protocol.openshift.connections.rest.apis.oauth.OAuthClients;
import org.keycloak.storage.client.AbstractReadOnlyClientStorageAdapter;
import org.keycloak.storage.client.ClientStorageProviderModel;

import java.util.Collections;
import java.util.Map;
import java.util.Set;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class OpenshiftOAuthClientAdapter extends AbstractReadOnlyClientStorageAdapter {
    protected OAuthClients.OAuthClientRepresentation client;

    public OpenshiftOAuthClientAdapter(KeycloakSession session, RealmModel realm, ClientStorageProviderModel component, OAuthClients.OAuthClientRepresentation client) {
        super(session, realm, component);
        this.client = client;
    }

    @Override
    public String getClientId() {
        return client.getName();
    }

    @Override
    public String getName() {
        return client.getName();
    }

    @Override
    public String getDescription() {
        return "";
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Set<String> getWebOrigins() {
        return Collections.EMPTY_SET;
    }

    @Override
    public Set<String> getRedirectUris() {
        return client.getRedirectURIs();
    }

    @Override
    public String getManagementUrl() {
        return null;
    }

    @Override
    public String getRootUrl() {
        return null;
    }

    @Override
    public String getBaseUrl() {
        return null;
    }

    @Override
    public boolean isBearerOnly() {
        return false;
    }

    @Override
    public int getNodeReRegistrationTimeout() {
        return 0;
    }

    @Override
    public String getClientAuthenticatorType() {
        return null;
    }

    @Override
    public boolean validateSecret(String secret) {
        return client.getSecret().equals(secret);
    }

    @Override
    public String getSecret() {
        return client.getSecret();
    }

    @Override
    public String getRegistrationToken() {
        return null;
    }

    @Override
    public String getProtocol() {
        return OIDCLoginProtocol.LOGIN_PROTOCOL;
    }

    @Override
    public String getAttribute(String name) {
        return null;
    }

    @Override
    public Map<String, String> getAttributes() {
        return Collections.EMPTY_MAP;
    }

    @Override
    public String getAuthenticationFlowBindingOverride(String binding) {
        return null;
    }

    @Override
    public Map<String, String> getAuthenticationFlowBindingOverrides() {
        return Collections.EMPTY_MAP;
    }

    @Override
    public boolean isFrontchannelLogout() {
        return false;
    }

    @Override
    public boolean isPublicClient() {
        return false;
    }

    @Override
    public boolean isConsentRequired() {
        return client.getGrantMethod() == null ? false : client.getGrantMethod().equalsIgnoreCase("prompt");
    }

    @Override
    public boolean isStandardFlowEnabled() {
        return true;
    }

    @Override
    public boolean isImplicitFlowEnabled() {
        return true;
    }

    @Override
    public boolean isDirectAccessGrantsEnabled() {
        return true;
    }

    @Override
    public boolean isServiceAccountsEnabled() {
        return false;
    }

    @Override
    public ClientTemplateModel getClientTemplate() {
        return null;
    }

    @Override
    public boolean useTemplateScope() {
        return false;
    }

    @Override
    public boolean useTemplateMappers() {
        return false;
    }

    @Override
    public boolean useTemplateConfig() {
        return false;
    }

    @Override
    public int getNotBefore() {
        return 0;
    }

    @Override
    public Set<ProtocolMapperModel> getProtocolMappers() {
        return Collections.EMPTY_SET;
    }

    @Override
    public ProtocolMapperModel getProtocolMapperById(String id) {
        return null;
    }

    @Override
    public ProtocolMapperModel getProtocolMapperByName(String protocol, String name) {
        return null;
    }

    @Override
    public boolean isFullScopeAllowed() {
        return false;
    }

    @Override
    public Set<RoleModel> getScopeMappings() {
        return Collections.EMPTY_SET;
    }

    @Override
    public Set<RoleModel> getRealmScopeMappings() {
        return Collections.EMPTY_SET;
    }

    @Override
    public boolean hasScope(RoleModel role) {
        return false;
    }
}
