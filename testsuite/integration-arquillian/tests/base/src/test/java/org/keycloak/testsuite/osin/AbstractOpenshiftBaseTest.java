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

import org.junit.Before;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.protocol.openshift.clientstorage.OpenshiftClientStorageProviderFactory;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.storage.client.ClientStorageProvider;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.admin.ApiUtil;

import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public abstract class AbstractOpenshiftBaseTest extends AbstractTestRealmKeycloakTest {
    public static final String BASE_URL = "https://192.168.238.132:8443";
    public static final String MASTER_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJteXByb2plY3QiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoia2V5Y2xvYWstdG9rZW4tY2o0bjIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoia2V5Y2xvYWsiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIxYjg5YjQ3Ny0yZDNkLTExZTgtOWQ5MC0wMDBjMjk4MmM5YjgiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6bXlwcm9qZWN0OmtleWNsb2FrIn0.kIyxRgaNz853n5CpriLG8ywSLTnq5UaKwgBXUtKCObGw5zn8Ae5Rg9VUJ_yYHHtGGjK-KVbwLs9hKYsF76P5H9QnhtYdEIgFhnrJ5VVnN4_Lhot4XIeq5BUn_p_VKf76-UTGXGlMMtDo4cf4iYw7ptI1h3iaD2W8f4zZ49esj1Z4ApLMSqHXE6iVLBTJaCwt_Mw02lNm9yk79XrujvuDGCV_fdDCLk08fedhbc_OYN-if3c8KjxP7cklrlW-itM6N6G7rjAoHuUY3OR-GF7KLdVibIdRvXtFNgqP7zp_kWKXxax8zQSDXkMzmFPGjvkAIUn7swIvLwjgb-5XDBySbw";

    /*
    $ oc create sa keycloak
    $ oc adm policy add-cluster-role-to-user system:auth-delegator -z keycloak
    $ oc adm policy add-cluster-role-to-user system:master -z keycloak
    $ oc describe sa keycloak
    # look for token and describe it
    $ oc describe secret xxxxx-xxx
    # copy token to MASTER_TOKEN constant above
     */
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
        provider.setProviderId(OpenshiftClientStorageProviderFactory.PROVIDER_ID);
        provider.setProviderType(ClientStorageProvider.class.getName());
        provider.setConfig(new MultivaluedHashMap<>());
        provider.getConfig().putSingle(OpenshiftClientStorageProviderFactory.ACCESS_TOKEN, MASTER_TOKEN);
        provider.getConfig().putSingle(OpenshiftClientStorageProviderFactory.OPENSHIFT_URI, BASE_URL);

        addComponent(provider);
    }
}
