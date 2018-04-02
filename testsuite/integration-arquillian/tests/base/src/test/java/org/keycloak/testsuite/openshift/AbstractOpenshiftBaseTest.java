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
package org.keycloak.testsuite.openshift;

import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.protocol.openshift.clientstorage.OpenshiftClientStorageProviderFactory;
import org.keycloak.protocol.openshift.connections.rest.OpenshiftClient;
import org.keycloak.representations.idm.ComponentRepresentation;
import org.keycloak.storage.client.ClientStorageProvider;
import org.keycloak.testsuite.AbstractTestRealmKeycloakTest;
import org.keycloak.testsuite.admin.ApiUtil;

import javax.ws.rs.core.Response;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Properties;

/**
 * @author <a href="mailto:bill@burkecentral.com">Bill Burke</a>
 * @version $Revision: 1 $
 */
public abstract class AbstractOpenshiftBaseTest extends AbstractTestRealmKeycloakTest {
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
        provider.getConfig().putSingle(OpenshiftClientStorageProviderFactory.ACCESS_TOKEN, getMasterToken());
        provider.getConfig().putSingle(OpenshiftClientStorageProviderFactory.OPENSHIFT_URI, getOpenshiftUrl());

        addComponent(provider);
    }

    public static Properties config = new Properties();

    public static final String OPENSHIFT_CONFIG = "openshift.config";

    @BeforeClass
    public static void loadConfig() throws Exception {
        Assume.assumeTrue(System.getProperties().containsKey(OPENSHIFT_CONFIG));
        config.load(new FileInputStream(System.getProperty(OPENSHIFT_CONFIG)));
    }

    public static String getMasterToken() {
        return config.getProperty("master_token");
    }

    public static String getOpenshiftUrl() {
        return config.getProperty("openshift_url");
    }

    public static OpenshiftClient createOpenshiftClient() {
        return OpenshiftClient.instance(AbstractOpenshiftBaseTest.getOpenshiftUrl(), AbstractOpenshiftBaseTest.getMasterToken());
    }


}
