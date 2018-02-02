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
package org.keycloak.testsuite.osin;

import org.jboss.arquillian.container.test.api.Deployment;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.openshift.OpenshiftProtocolEndpoint;
import org.keycloak.protocol.openshift.TokenReviewRequestRepresentation;
import org.keycloak.protocol.openshift.TokenReviewResponseRepresentation;
import org.keycloak.protocol.openshift.clientstorage.OpenshiftOAuthClientStorageProviderFactory;
import org.keycloak.protocol.openshift.connections.rest.OpenshiftClient;
import org.keycloak.protocol.openshift.connections.rest.apis.oauth.OAuthClients;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.storage.client.ClientStorageProvider;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.admin.ApiUtil;
import org.keycloak.testsuite.federation.HardcodedClientStorageProviderFactory;
import org.keycloak.testsuite.runonserver.RunOnServerDeployment;
import org.keycloak.testsuite.util.OAuthClient;
import org.keycloak.util.BasicAuthHelper;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Ignore
public class OpenshiftOAuthClientStorageTest extends AbstractTestRealmKeycloakTest {

    @Rule
    public AssertEvents events = new AssertEvents(this);


    @Override
    public void configureTestRealm(RealmRepresentation testRealm) {
    }

    @Deployment
    public static WebArchive deploy() {
        return RunOnServerDeployment.create(UserResource.class)
                .addPackages(true, "org.keycloak.testsuite");
    }

    protected String addComponent(ComponentRepresentation component) {
        Response resp = adminClient.realm("test").components().add(component);
        resp.close();
        String id = ApiUtil.getCreatedId(resp);
        getCleanup().addComponentId(id);
        return id;
    }

    @Before
    public void addProvidersBeforeTest() throws URISyntaxException, IOException {
        List<ComponentRepresentation> reps = adminClient.realm("test").components().query(null, ClientStorageProvider.class.getName());
        if (reps.size() > 0) return;
        ComponentRepresentation provider = new ComponentRepresentation();
        provider.setName("openshift oauth client provider");
        provider.setProviderId(OpenshiftOAuthClientStorageProviderFactory.PROVIDER_ID);
        provider.setProviderType(ClientStorageProvider.class.getName());
        provider.setConfig(new MultivaluedHashMap<>());
        provider.getConfig().putSingle(OpenshiftOAuthClientStorageProviderFactory.ACCESS_TOKEN, OpenshiftClientTest.MASTER_TOKEN);
        provider.getConfig().putSingle(OpenshiftOAuthClientStorageProviderFactory.OPENSHIFT_URI, OpenshiftClientTest.BASE_URL);

        addComponent(provider);
    }

    @Before
    public void createClients() {
        OpenshiftClient client = OpenshiftClient.instance(OpenshiftClientTest.BASE_URL, OpenshiftClientTest.MASTER_TOKEN);

        OAuthClients.OAuthClientRepresentation rep = OAuthClients.OAuthClientRepresentation.create();
        // with literal scope restriction
        client.apis().oauth().clients().delete("literal-oauth-client").close();
        rep.setName("literal-oauth-client");
        rep.setGrantMethod("auto");
        rep.setSecret("geheim");
        rep.setRespondWithChallenges(false);
        rep.addRedirectURI("http://host1");
        rep.addRedirectURI("http://host2");
        rep.addLiteralScopeRestriction("foo");
        rep.addLiteralScopeRestriction("foo:bar");
        client.apis().oauth().clients().create(rep).close();
        client.close();

    }

    @Test
    public void testGrant() throws Exception {
        Client httpClient = javax.ws.rs.client.ClientBuilder.newClient();
        String grantUri = getResourceOwnerPasswordCredentialGrantUrl();
        WebTarget grantTarget = httpClient.target(grantUri);

        String accessToken = null;
        {   // test valid password
            String header = BasicAuthHelper.createHeader("literal-oauth-client", "geheim");
            Form form = new Form();
            form.param(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD);
            form.param("username", "test-user@localhost");
            form.param("password", "password");
            form.param("scope", "oauth openid");
            Response response = grantTarget.request()
                    .header(HttpHeaders.AUTHORIZATION, header)
                    .post(Entity.form(form));
            assertEquals(200, response.getStatus());
            AccessTokenResponse tokenResponse = response.readEntity(AccessTokenResponse.class);
            accessToken = tokenResponse.getToken();
            response.close();
        }
        httpClient.close();
        events.clear();
    }

    public String getResourceOwnerPasswordCredentialGrantUrl() {
        UriBuilder b = OpenshiftProtocolEndpoint.tokenUrl(UriBuilder.fromUri(OAuthClient.AUTH_SERVER_ROOT));
        return b.build("test").toString();
    }

    public String getTokenReviewUrl() {
        UriBuilder b = OpenshiftProtocolEndpoint.tokenReviewnUrl(UriBuilder.fromUri(OAuthClient.AUTH_SERVER_ROOT));
        return b.build("test").toString();
    }


}
