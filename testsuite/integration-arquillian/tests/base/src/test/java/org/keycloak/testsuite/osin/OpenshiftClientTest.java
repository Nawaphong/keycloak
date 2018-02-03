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

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;
import org.keycloak.protocol.openshift.TokenReviewRequestRepresentation;
import org.keycloak.protocol.openshift.TokenReviewResponseRepresentation;
import org.keycloak.protocol.openshift.connections.rest.OpenshiftClient;
import org.keycloak.protocol.openshift.connections.rest.api.v1.Namespace;
import org.keycloak.protocol.openshift.connections.rest.api.v1.Secrets;
import org.keycloak.protocol.openshift.connections.rest.api.v1.ServiceAccounts;
import org.keycloak.protocol.openshift.connections.rest.apis.oauth.OAuthClients;

import javax.ws.rs.NotFoundException;
import javax.ws.rs.core.Response;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
@Ignore
public class OpenshiftClientTest {

    public static final String BASE_URL = "https://192.168.64.2:8443";
    public static final String MASTER_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJteXByb2plY3QiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoia2V5Y2xvYWstdG9rZW4tbjc3MjkiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoia2V5Y2xvYWsiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIxODI5YjcxNi0wNzY5LTExZTgtOTI0NS01ZWQ0ODZlZDdkYzEiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6bXlwcm9qZWN0OmtleWNsb2FrIn0.gGDHWIob4HNEbj57s_4Lm_2XCMp5DRSvUEafqfzohrcXLfoN-XMACkuwebn6EghfTB_9ITrkzhJSd3T0BbKO7l0dYchW4dRIMtz5SZs7y097Bxcl9bkPQG3wC-TkcqWgCV9PdE-dzdm8qb5c1lHd1QFBkCnX0slZ1kQd0tUIvoAf7if47YCgzvmMfsAXr88fzEZ_eMjimgTvzyudPvfsNnfQ_-0mr_dQMfVJXpFDrMSL2Fec8fxhktKgCGLdOX5d_2sqEfy1G_vAwnA2NV6CcLFailoTLoQztyvZDpsuLkMo6b3UV1sqFGwCUXkzGFnzr5yV27q4-zC-vsalSQmYPA";

    @Test
    public void testServiceAccount() throws Exception {

        OpenshiftClient client = OpenshiftClient.instance(BASE_URL, MASTER_TOKEN);
        Namespace myproject = client.api().namespace("myproject");

        // test not found
        try {
            myproject.serviceAccounts().get("notfound");
            Assert.fail();
        } catch (NotFoundException e) {
           if (e.getResponse() != null) e.getResponse().close();
        }

        Response response = myproject.serviceAccounts().delete("sa-oauth");
        response.close();
        ServiceAccounts.ServiceAccountRepresentation rep = new ServiceAccounts.ServiceAccountRepresentation();
        rep.setName("sa-oauth");
        rep.setNamespace("myproject");
        rep.setOauthWantChallenges(true);
        rep.addRedirectUri("http:/host1");
        rep.addRedirectUri("http:/host2");
        rep = myproject.serviceAccounts().create(rep);

        for (int i = 0; i < 5; i++) {
            // sleep as generating secrets takes awhile.
            Thread.sleep(1000);
            rep = myproject.serviceAccounts().get("sa-oauth");
            if (rep.getSecrets().isEmpty()) continue;
            break;
        }
        Assert.assertEquals("sa-oauth", rep.getName());
        Assert.assertEquals("myproject", rep.getNamespace());
        Assert.assertTrue(rep.getOauthRedirectUris().contains("http:/host1"));
        Assert.assertTrue(rep.getOauthRedirectUris().contains("http:/host2"));
        Assert.assertTrue(rep.oauthWantChallenges());

        String token = null;
        for (String secret : rep.getSecrets()) {
            Secrets.SecretRepresentation secretRep = myproject.secrets().get(secret);
            if (secretRep.isServiceAccountToken()) {
                token = secretRep.getToken();
            }
        }
        Assert.assertNotNull(token);


        response = myproject.serviceAccounts().delete("sa-oauth");
        Assert.assertEquals(200, response.getStatus());
        response.close();
        try {
            rep = myproject.serviceAccounts().get("sa-oauth");
            Assert.fail("should be deleted already");
        } catch (NotFoundException e) {
        }
    }

    @Test
    public void testTokenReview() throws Exception {
        OpenshiftClient client = OpenshiftClient.instance(BASE_URL, MASTER_TOKEN);
        TokenReviewRequestRepresentation request = TokenReviewRequestRepresentation.create(MASTER_TOKEN);

        //TokenReviewResponseRepresentation review = client.apis().kubernetesAuthentication("v1beta1").tokenReview().review(request);
        Response response = client.apis().kubernetesAuthentication().tokenReview().review(request);
        String data = response.readEntity(String.class);
        System.out.println(data);


    }
    @Test
    public void testOAuthClients() throws Exception {
        OpenshiftClient client = OpenshiftClient.instance(BASE_URL, MASTER_TOKEN);

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
        rep = client.apis().oauth().clients().get("literal-oauth-client");

        Assert.assertEquals("literal-oauth-client", rep.getName());
        Assert.assertEquals("auto", rep.getGrantMethod());
        Assert.assertEquals("geheim", rep.getSecret());
        Assert.assertFalse(rep.isRespondWithChallenges());
        Assert.assertTrue(rep.getRedirectURIs().contains("http://host1"));
        Assert.assertTrue(rep.getRedirectURIs().contains("http://host2"));
        Assert.assertTrue(rep.getLiteralScopeRestrictions().contains("foo"));
        Assert.assertTrue(rep.getLiteralScopeRestrictions().contains("foo:bar"));

        client.apis().oauth().clients().delete("literal-oauth-client").close();

        // with cluster role scope restriction

        client.apis().oauth().clients().delete("role-oauth-client").close();

        rep = OAuthClients.OAuthClientRepresentation.create();
        rep.setName("role-oauth-client");
        rep.setGrantMethod("prompt");
        rep.setSecret("geheim");
        rep.setRespondWithChallenges(true);
        rep.addRedirectURI("http://host1");
        OAuthClients.OAuthClientRepresentation.ClusterRoleRestriction restriction = new OAuthClients.OAuthClientRepresentation.ClusterRoleRestriction();
        restriction.setAllowEscalation(true);
        restriction.getNamespaces().add("foo");
        restriction.getRoleNames().add("bar");
        rep.addClusterRoleScopeRestriction(restriction);
        client.apis().oauth().clients().create(rep).close();
        rep = client.apis().oauth().clients().get("role-oauth-client");

        Assert.assertEquals("role-oauth-client", rep.getName());
        Assert.assertEquals("prompt", rep.getGrantMethod());
        Assert.assertEquals("geheim", rep.getSecret());
        Assert.assertTrue(rep.isRespondWithChallenges());
        Assert.assertTrue(rep.getRedirectURIs().contains("http://host1"));
        Assert.assertEquals(1, rep.getClusterRoleRestrictions().size());
        OAuthClients.OAuthClientRepresentation.ClusterRoleRestriction testRestriction = rep.getClusterRoleRestrictions().get(0);
        Assert.assertTrue(testRestriction.isAllowEscalation());
        Assert.assertTrue(testRestriction.getNamespaces().contains("foo"));
        Assert.assertTrue(testRestriction.getRoleNames().contains("bar"));

        client.apis().oauth().clients().delete("role-oauth-client").close();


        // with both literal and cluster role scope restriction

        client.apis().oauth().clients().delete("both-oauth-client").close();

        rep = OAuthClients.OAuthClientRepresentation.create();
        rep.setName("both-oauth-client");
        rep.setGrantMethod("prompt");
        rep.setSecret("geheim");
        rep.setRespondWithChallenges(true);
        rep.addRedirectURI("http://host1");
        rep.addClusterRoleScopeRestriction(restriction);
        rep.addLiteralScopeRestriction("foo");
        rep.addLiteralScopeRestriction("foo:bar");
        client.apis().oauth().clients().create(rep).close();
        rep = client.apis().oauth().clients().get("both-oauth-client");

        Assert.assertEquals("both-oauth-client", rep.getName());
        Assert.assertEquals("prompt", rep.getGrantMethod());
        Assert.assertEquals("geheim", rep.getSecret());
        Assert.assertTrue(rep.isRespondWithChallenges());
        Assert.assertTrue(rep.getRedirectURIs().contains("http://host1"));
        Assert.assertEquals(1, rep.getClusterRoleRestrictions().size());
        testRestriction = rep.getClusterRoleRestrictions().get(0);
        Assert.assertTrue(testRestriction.isAllowEscalation());
        Assert.assertTrue(testRestriction.getNamespaces().contains("foo"));
        Assert.assertTrue(testRestriction.getRoleNames().contains("bar"));
        Assert.assertTrue(rep.getLiteralScopeRestrictions().contains("foo"));
        Assert.assertTrue(rep.getLiteralScopeRestrictions().contains("foo:bar"));

        client.apis().oauth().clients().delete("both-oauth-client").close();




    }
}
