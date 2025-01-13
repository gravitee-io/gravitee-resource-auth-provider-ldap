/*
 * Copyright © 2015 The Gravitee team (http://gravitee.io)
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
 */
package io.gravitee.resource.authprovider.ldap;

import io.gravitee.el.TemplateEngine;
import io.gravitee.resource.api.AbstractConfigurableResource;
import io.gravitee.resource.authprovider.ldap.configuration.LdapAuthenticationProviderResourceConfiguration;
import java.lang.reflect.Field;

/**
 * @author Benoit BORDIGONI (benoit.bordigoni at graviteesource.com)
 * @author GraviteeSource Team
 */
public class Helper {

    public static LdapAuthenticationProviderResource newLdapResource(
        LdapAuthenticationProviderResourceConfiguration config,
        TemplateEngine templateEngine
    ) throws IllegalAccessException, NoSuchFieldException {
        LdapAuthenticationProviderResource redisCacheResource = new LdapAuthenticationProviderResource();
        Field configurationField = AbstractConfigurableResource.class.getDeclaredField("configuration");
        configurationField.setAccessible(true);
        configurationField.set(redisCacheResource, config);
        redisCacheResource.setDeploymentContext(new TestDeploymentContext(templateEngine));
        return redisCacheResource;
    }
}
