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
package io.gravitee.resource.authprovider.ldap.configuration;

import static io.gravitee.resource.authprovider.ldap.Helper.newLdapResource;
import static org.assertj.core.api.Assertions.assertThat;

import io.gravitee.el.TemplateEngine;
import io.gravitee.el.spel.context.SecuredResolver;
import io.gravitee.resource.authprovider.ldap.LdapAuthenticationProviderResource;
import io.gravitee.secrets.api.el.DelegatingEvaluatedSecretsMethods;
import io.gravitee.secrets.api.el.EvaluatedSecretsMethods;
import io.gravitee.secrets.api.el.FieldKind;
import io.gravitee.secrets.api.el.SecretFieldAccessControl;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.*;

/**
 * @author Benoit BORDIGONI (benoit.bordigoni at graviteesource.com)
 * @author GraviteeSource Team
 */
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class LdapAuthenticationProviderResourceConfigurationTest {

    private static TemplateEngine templateEngine;
    private final List<SecretFieldAccessControl> recordedSecretFieldAccessControls = new ArrayList<>();

    @BeforeAll
    static void init() {
        SecuredResolver.initialize(null);
        templateEngine = TemplateEngine.templateEngine();
    }

    @BeforeEach
    void before() {
        EvaluatedSecretsMethods delegate = new EvaluatedSecretsMethods() {
            @Override
            public String fromGrant(String secretValue, SecretFieldAccessControl secretFieldAccessControl) {
                recordedSecretFieldAccessControls.add(secretFieldAccessControl);
                return secretValue;
            }

            @Override
            public String fromGrant(String contextId, String secretKey, SecretFieldAccessControl secretFieldAccessControl) {
                return fromGrant(contextId, secretFieldAccessControl);
            }

            @Override
            public String fromEL(String contextId, String uriOrName, SecretFieldAccessControl secretFieldAccessControl) {
                return fromGrant(contextId, secretFieldAccessControl);
            }
        };
        templateEngine.getTemplateContext().setVariable("secrets", new DelegatingEvaluatedSecretsMethods(delegate));
        templateEngine.getTemplateContext().setVariable("userSearchFilter", "uid={0}");
        templateEngine.getTemplateContext().setVariable("userSearchBase", "ou=users");
    }

    @Test
    void should_have_defaults() {
        LdapAuthenticationProviderResourceConfiguration configuration = new LdapAuthenticationProviderResourceConfiguration();
        assertThat(configuration.getCacheMaxElements()).isEqualTo(100);
        assertThat(configuration.getCacheTimeToLive()).isEqualTo(60000);
        assertThat(configuration.getConnectTimeout()).isEqualTo(5000L);
        assertThat(configuration.getResponseTimeout()).isEqualTo(5000L);
        assertThat(configuration.getMinPoolSize()).isEqualTo(5);
        assertThat(configuration.getMaxPoolSize()).isEqualTo(15);
    }

    @Test
    void should_process_config_withoutEL() throws NoSuchFieldException, IllegalAccessException {
        LdapAuthenticationProviderResourceConfiguration configuration = new LdapAuthenticationProviderResourceConfiguration();
        configuration.setContextSourceUrl("ldap://localhost:10389");
        configuration.setContextSourceBase("ou=people,dc=planetexpress,dc=com");
        configuration.setContextSourceUsername("cn=admin,dc=planetexpress,dc=com");
        configuration.setContextSourcePassword("GoodNewsEveryone");
        configuration.setUserSearchFilter("uid={0}");
        configuration.setUserSearchBase("ou=users");

        LdapAuthenticationProviderResource resource = newLdapResource(configuration, templateEngine);
        LdapAuthenticationProviderResourceConfiguration evaluatedConfiguration = resource.configuration();

        assertThat(evaluatedConfiguration).usingRecursiveComparison().isEqualTo(configuration);
    }

    @Test
    void should_process_config_withEL_and_secret() throws Exception {
        LdapAuthenticationProviderResourceConfiguration configuration = new LdapAuthenticationProviderResourceConfiguration();
        configuration.setContextSourceUrl(asSecretEL("ldap://localhost:10389"));
        configuration.setContextSourceBase(asSecretEL("ou=people,dc=planetexpress,dc=com"));
        configuration.setContextSourceUsername(asSecretEL("cn=admin,dc=planetexpress,dc=com"));
        configuration.setContextSourcePassword(asSecretEL("GoodNewsEveryone"));
        configuration.setUserSearchFilter("{#userSearchFilter}");
        configuration.setUserSearchBase("{#userSearchBase}");

        LdapAuthenticationProviderResource resource = newLdapResource(configuration, templateEngine);
        LdapAuthenticationProviderResourceConfiguration evaluatedConfiguration = resource.configuration();

        assertThat(evaluatedConfiguration.getContextSourceUrl()).isEqualTo("ldap://localhost:10389");
        assertThat(evaluatedConfiguration.getContextSourceBase()).isEqualTo("ou=people,dc=planetexpress,dc=com");
        assertThat(evaluatedConfiguration.getContextSourceUsername()).isEqualTo("cn=admin,dc=planetexpress,dc=com");
        assertThat(evaluatedConfiguration.getContextSourcePassword()).isEqualTo("GoodNewsEveryone");
        assertThat(evaluatedConfiguration.getUserSearchFilter()).isEqualTo("uid={0}");
        assertThat(evaluatedConfiguration.getUserSearchBase()).isEqualTo("ou=users");

        assertThat(recordedSecretFieldAccessControls)
            .containsExactlyInAnyOrder(
                new SecretFieldAccessControl(true, FieldKind.GENERIC, "contextSourceUrl"),
                new SecretFieldAccessControl(true, FieldKind.GENERIC, "contextSourceBase"),
                new SecretFieldAccessControl(true, FieldKind.GENERIC, "contextSourceUsername"),
                new SecretFieldAccessControl(true, FieldKind.PASSWORD, "contextSourcePassword")
            );
    }

    @Test
    void should_not_be_able_to_resolve_secret_on_non_sensitive_field() throws Exception {
        LdapAuthenticationProviderResourceConfiguration configuration = new LdapAuthenticationProviderResourceConfiguration();
        configuration.setUserSearchFilter(asSecretEL("foo"));

        LdapAuthenticationProviderResource resource = newLdapResource(configuration, templateEngine);
        resource.configuration();

        assertThat(recordedSecretFieldAccessControls).containsExactlyInAnyOrder(new SecretFieldAccessControl(false, null, null));
    }

    static String asSecretEL(String password) {
        return "{#secrets.fromGrant('%s', #%s)}".formatted(password, SecretFieldAccessControl.EL_VARIABLE);
    }
}
