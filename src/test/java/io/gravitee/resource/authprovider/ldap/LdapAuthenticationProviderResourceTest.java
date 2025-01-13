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

import static io.gravitee.resource.authprovider.ldap.Helper.newLdapResource;
import static io.gravitee.resource.authprovider.ldap.LdapAuthenticationProviderResource.LDAP_URL_ATTRIBUTE;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.awaitility.Awaitility.await;

import io.gravitee.el.TemplateEngine;
import io.gravitee.el.spel.context.SecuredResolver;
import io.gravitee.resource.authprovider.api.Authentication;
import io.gravitee.resource.authprovider.ldap.configuration.LdapAuthenticationProviderResourceConfiguration;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import javax.annotation.Nonnull;
import org.junit.jupiter.api.*;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.LogMessageWaitStrategy;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * @author Benoit BORDIGONI (benoit.bordigoni at graviteesource.com)
 * @author GraviteeSource Team
 */
@Testcontainers
@DisplayNameGeneration(DisplayNameGenerator.ReplaceUnderscores.class)
class LdapAuthenticationProviderResourceTest {

    static TemplateEngine templateEngine;

    static final int LDAP_PORT = 10389;

    @Container
    static GenericContainer<?> ldapServer = new GenericContainer<>("ghcr.io/rroemhild/docker-test-openldap:master")
        .withExposedPorts(LDAP_PORT)
        .waitingFor(new LogMessageWaitStrategy().withRegEx(".*slapd starting.*"));

    @Container
    static GenericContainer<?> extraLdapServer = new GenericContainer<>("ghcr.io/rroemhild/docker-test-openldap:master")
        .withExposedPorts(LDAP_PORT)
        .waitingFor(new LogMessageWaitStrategy().withRegEx(".*slapd starting.*"));

    private LdapAuthenticationProviderResource underTest;

    @BeforeAll
    static void init() {
        SecuredResolver.initialize(null);
        templateEngine = TemplateEngine.templateEngine();
    }

    @BeforeEach
    void create() throws NoSuchFieldException, IllegalAccessException {
        underTest = newLdapResource(newConfiguration(), templateEngine);
    }

    @AfterEach
    void stop() throws Exception {
        underTest.stop();
    }

    @Test
    void should_authenticate_user() {
        assertThatCode(underTest::start).doesNotThrowAnyException();

        AtomicReference<Authentication> authentication = new AtomicReference<>();
        underTest.authenticate("professor", "professor", authentication::set);

        assertThat(authentication.get()).isNotNull();
        assertThat(authentication.get().getUsername()).isEqualTo("cn=Hubert J. Farnsworth,ou=people,dc=planetexpress,dc=com");
        assertThat(authentication.get().getAttributes()).hasSize(13);

        assertThat(underTest.getCachedAuthentication("professor", "professor")).isSameAs(authentication.get());
    }

    @Test
    void should_authenticate_user_no_cache() {
        underTest.configuration().setCacheMaxElements(0);
        assertThatCode(underTest::start).doesNotThrowAnyException();

        AtomicReference<Authentication> authentication = new AtomicReference<>();
        underTest.authenticate("professor", "professor", authentication::set);
        assertThat(authentication.get()).isNotNull();
        assertThat(authentication.get().getUsername()).isEqualTo("cn=Hubert J. Farnsworth,ou=people,dc=planetexpress,dc=com");

        assertThat(underTest.getCachedAuthentication("professor", "professor")).isNull();
    }

    @Test
    void should_authenticate_user_and_retrieve_only_some_attributes() {
        underTest.configuration().setAttributes(List.of("mail", "displayName", "ou"));

        assertThatCode(underTest::start).doesNotThrowAnyException();

        AtomicReference<Authentication> authentication = new AtomicReference<>();
        underTest.authenticate("professor", "professor", authentication::set);

        assertThat(authentication.get()).isNotNull();
        assertThat(authentication.get().getUsername()).isEqualTo("cn=Hubert J. Farnsworth,ou=people,dc=planetexpress,dc=com");
        assertThat(authentication.get().getAttributes())
            .containsAllEntriesOf(
                Map.of("mail", "professor@planetexpress.com", "displayName", "Professor Farnsworth", "ou", "Office Management")
            );
    }

    @Test
    void should_authenticate_user_evicted() {
        underTest.configuration().setCacheTimeToLive(500);
        underTest.configuration().setCacheChecksMs(250);

        assertThatCode(underTest::start).doesNotThrowAnyException();

        AtomicReference<Authentication> authentication = new AtomicReference<>();
        underTest.authenticate("professor", "professor", authentication::set);

        await()
            .atMost(1, TimeUnit.SECONDS)
            .untilAsserted(() -> {
                // it should no longer not be in the cache after 500ms, hence fail and thus return null
                underTest.authenticate("professor", "foobar", authentication::set);
                assertThat(authentication.get()).isNull();
            });
    }

    @Test
    void should_authenticate_user_despite_non_working_url() {
        String firstServer = "ldap://localhost:" + extraLdapServer.getMappedPort(LDAP_PORT);
        String secondServer = underTest.configuration().getContextSourceUrl();
        underTest
            .configuration()
            .setContextSourceUrl(
                firstServer
                    .concat(" , ") // testing having spaces and comma work
                    .concat(secondServer)
            );
        underTest.configuration().setConnectTimeout(500L);
        underTest.configuration().setResponseTimeout(500L);
        underTest.configuration().setAttributes(List.of(LDAP_URL_ATTRIBUTE));

        assertThatCode(underTest::start).doesNotThrowAnyException();

        AtomicReference<Authentication> authentication = new AtomicReference<>();
        underTest.authenticate("professor", "professor", authentication::set);
        assertThat(authentication.get()).isNotNull();
        assertThat(authentication.get().getUsername()).isEqualTo("cn=Hubert J. Farnsworth,ou=people,dc=planetexpress,dc=com");
        assertThat(authentication.get().getAttributes()).containsAllEntriesOf(Map.of(LDAP_URL_ATTRIBUTE, firstServer));

        underTest.authenticate("fry", "fry", authentication::set);
        assertThat(authentication.get()).isNotNull();
        assertThat(authentication.get().getUsername()).isEqualTo("cn=Philip J. Fry,ou=people,dc=planetexpress,dc=com");
        assertThat(authentication.get().getAttributes()).containsAllEntriesOf(Map.of(LDAP_URL_ATTRIBUTE, firstServer));

        extraLdapServer.stop();

        underTest.authenticate("zoidberg", "zoidberg", authentication::set);
        assertThat(authentication.get()).isNotNull();
        assertThat(authentication.get().getUsername()).isEqualTo("cn=John A. Zoidberg,ou=people,dc=planetexpress,dc=com");
        assertThat(authentication.get().getAttributes()).containsAllEntriesOf(Map.of(LDAP_URL_ATTRIBUTE, secondServer));
    }

    @Test
    void should_not_authenticate_user_wrong_password() throws Exception {
        underTest.start();

        AtomicReference<Authentication> authentication = new AtomicReference<>();
        underTest.authenticate("professor", "ba bee doo sha bada", authentication::set);
        assertThat(authentication.get()).isNull();
    }

    @Test
    void should_not_authenticate_user_wrong_admin_password() throws Exception {
        underTest.configuration().setContextSourcePassword("ba bee doo sha bada");
        underTest.start();

        AtomicReference<Authentication> authentication = new AtomicReference<>();
        underTest.authenticate("professor", "professor", authentication::set);
        assertThat(authentication.get()).isNull();
    }

    @Nonnull
    private LdapAuthenticationProviderResourceConfiguration newConfiguration() {
        LdapAuthenticationProviderResourceConfiguration configuration = new LdapAuthenticationProviderResourceConfiguration();
        configuration.setContextSourceUrl("ldap://localhost:" + ldapServer.getMappedPort(LDAP_PORT));
        configuration.setContextSourceBase("dc=planetexpress,dc=com");
        configuration.setContextSourceUsername("cn=admin,dc=planetexpress,dc=com");
        configuration.setContextSourcePassword("GoodNewsEveryone");
        configuration.setUserSearchFilter("uid={0}");
        // this is part of the default users that come with the docker image
        configuration.setUserSearchBase("ou=people");
        return configuration;
    }
}
