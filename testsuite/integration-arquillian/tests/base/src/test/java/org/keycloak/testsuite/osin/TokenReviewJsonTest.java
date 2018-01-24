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

import org.junit.Test;
import org.keycloak.protocol.openshift.TokenReviewRequestRepresentation;
import org.keycloak.protocol.openshift.TokenReviewResponseRepresentation;
import org.keycloak.util.JsonSerialization;

import java.util.HashSet;
import java.util.Set;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public class TokenReviewJsonTest {
    @Test
    public void testJson() throws Exception {
        String request = "{\n" +
                "  \"apiVersion\": \"authentication.k8s.io/v1beta1\",\n" +
                "  \"kind\": \"TokenReview\",\n" +
                "  \"junk\": \"junk\",\n" +
                "  \"spec\": {\n" +
                "    \"token\": \"(BEARERTOKEN)\",\n" +
                "    \"junk\": \"junk\"\n" +
                "  }\n" +
                "}";
        TokenReviewRequestRepresentation rep = JsonSerialization.readValue(request, TokenReviewRequestRepresentation.class);

        TokenReviewResponseRepresentation success = TokenReviewResponseRepresentation.success();
        TokenReviewResponseRepresentation.Status.User user = success.getStatus().getUser();
        user.setUsername("bburke");
        user.setUid("234234");
        Set<String> scopes = new HashSet<>();
        scopes.add("oauth");
        scopes.add("oidc");
        user.putExtra( "scopes.authorization.openshift.io", scopes);

        String output = JsonSerialization.writeValueAsPrettyString(success);
        System.out.println("------ success message ------");
        System.out.println(output);
        System.out.println("------ error message ------");
        System.out.println(JsonSerialization.writeValueAsPrettyString(TokenReviewResponseRepresentation.error()));

    }
}
