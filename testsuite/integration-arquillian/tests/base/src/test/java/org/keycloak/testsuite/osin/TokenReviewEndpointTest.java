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
import org.jboss.arquillian.graphene.page.Page;
import org.jboss.shrinkwrap.api.spec.WebArchive;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.resource.ClientsResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordFormFactory;
import org.keycloak.events.Details;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.AuthenticationFlowModel;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.oidc.OIDCLoginProtocolService;
import org.keycloak.protocol.openshift.OpenshiftProtocolEndpoint;
import org.keycloak.protocol.openshift.TokenReviewRequestRepresentation;
import org.keycloak.protocol.openshift.TokenReviewResponseRepresentation;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.RealmRepresentation;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.AssertEvents;
import org.keycloak.testsuite.authentication.PushButtonAuthenticatorFactory;
import org.keycloak.testsuite.pages.AppPage;
import org.keycloak.testsuite.pages.ErrorPage;
import org.keycloak.testsuite.pages.LoginPage;
import org.keycloak.testsuite.runonserver.RunOnServerDeployment;
import org.keycloak.testsuite.util.OAuthClient;
import org.keycloak.util.BasicAuthHelper;
import org.keycloak.util.JsonSerialization;
import org.openqa.selenium.By;

import javax.ws.rs.client.Client;
import javax.ws.rs.client.Entity;
import javax.ws.rs.client.WebTarget;
import javax.ws.rs.core.Form;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class TokenReviewEndpointTest extends AbstractTestRealmKeycloakTest {

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


    @Before
    public void setupFlows() {
        testingClient.server().run(session -> {
            RealmModel realm = session.realms().getRealmByName("test");

            ClientModel client = session.realms().getClientByClientId("test-app", realm);
            client.setDirectAccessGrantsEnabled(true);

            GroupModel group = realm.createGroup("openshift");
            GroupModel child = realm.createGroup("child");
            realm.moveGroup(child, group);

            UserModel user = session.users().addUser(realm, "reviewer");
            user.setEnabled(true);
            session.userCredentialManager().updateCredential(realm, user, UserCredentialModel.password("password"));
            user.joinGroup(child);
        });
    }




    @Test
    public void testTokenReview() throws Exception {
        Client httpClient = javax.ws.rs.client.ClientBuilder.newClient();
        String grantUri = getResourceOwnerPasswordCredentialGrantUrl();
        WebTarget grantTarget = httpClient.target(grantUri);

        String accessToken = null;
        {   // test valid password
            String header = BasicAuthHelper.createHeader("test-app", "password");
            Form form = new Form();
            form.param(OAuth2Constants.GRANT_TYPE, OAuth2Constants.PASSWORD);
            form.param("username", "reviewer");
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

        String tokenReviewUrl = getTokenReviewUrl();
        WebTarget tokenReviewTarget =  httpClient.target(tokenReviewUrl);

        {
            Response response = tokenReviewTarget.request()
                    .post(Entity.json(TokenReviewRequestRepresentation.build(accessToken)));
            assertEquals(200, response.getStatus());
            String reviewString = response.readEntity(String.class);
            System.out.println(reviewString);
            TokenReviewResponseRepresentation review = JsonSerialization.readValue(reviewString, TokenReviewResponseRepresentation.class);
            Assert.assertTrue(review.getStatus().isAuthenticated());
            TokenReviewResponseRepresentation.Status.User user = review.getStatus().getUser();
            Assert.assertEquals("reviewer", user.getUsername());
            Assert.assertTrue(user.getGroups().contains("openshift"));
            Assert.assertTrue(user.getGroups().contains("openshift:child"));
            List<String> scopes = (List<String>)user.getExtra().getData().get("scopes.authorization.openshift.io");
            Assert.assertTrue(scopes.contains("oauth"));
            Assert.assertTrue(scopes.contains("openid"));

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
