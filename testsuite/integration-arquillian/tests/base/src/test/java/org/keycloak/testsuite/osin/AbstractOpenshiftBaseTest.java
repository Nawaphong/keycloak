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
    public static final String BASE_URL = "https://192.168.64.2:8443";
    public static final String MASTER_TOKEN = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJteXByb2plY3QiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlY3JldC5uYW1lIjoia2V5Y2xvYWstdG9rZW4tbjc3MjkiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC5uYW1lIjoia2V5Y2xvYWsiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiIxODI5YjcxNi0wNzY5LTExZTgtOTI0NS01ZWQ0ODZlZDdkYzEiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6bXlwcm9qZWN0OmtleWNsb2FrIn0.gGDHWIob4HNEbj57s_4Lm_2XCMp5DRSvUEafqfzohrcXLfoN-XMACkuwebn6EghfTB_9ITrkzhJSd3T0BbKO7l0dYchW4dRIMtz5SZs7y097Bxcl9bkPQG3wC-TkcqWgCV9PdE-dzdm8qb5c1lHd1QFBkCnX0slZ1kQd0tUIvoAf7if47YCgzvmMfsAXr88fzEZ_eMjimgTvzyudPvfsNnfQ_-0mr_dQMfVJXpFDrMSL2Fec8fxhktKgCGLdOX5d_2sqEfy1G_vAwnA2NV6CcLFailoTLoQztyvZDpsuLkMo6b3UV1sqFGwCUXkzGFnzr5yV27q4-zC-vsalSQmYPA";

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
