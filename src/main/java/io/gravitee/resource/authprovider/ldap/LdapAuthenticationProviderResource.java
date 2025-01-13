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

import io.gravitee.gateway.api.ExecutionContext;
import io.gravitee.gateway.api.handler.Handler;
import io.gravitee.gateway.reactive.api.context.DeploymentContext;
import io.gravitee.resource.authprovider.api.Authentication;
import io.gravitee.resource.authprovider.api.AuthenticationProviderResource;
import io.gravitee.resource.authprovider.ldap.cache.LRUCache;
import io.gravitee.resource.authprovider.ldap.configuration.LdapAuthenticationProviderResourceConfiguration;
import io.gravitee.resource.authprovider.ldap.configuration.LdapAuthenticationProviderResourceConfigurationEvaluator;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.inject.Inject;
import lombok.Setter;
import org.ldaptive.*;
import org.ldaptive.auth.*;
import org.ldaptive.url.Url;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
public class LdapAuthenticationProviderResource extends AuthenticationProviderResource<LdapAuthenticationProviderResourceConfiguration> {

    public static final String LDAP_URL_ATTRIBUTE = "ldapURL";
    private final Logger logger = LoggerFactory.getLogger(LdapAuthenticationProviderResource.class);

    private static final String LDAP_SEPARATOR = ",";

    private PooledConnectionFactory connectionFactory;

    private Authenticator authenticator;

    private LRUCache cache;

    @Inject
    @Setter
    private DeploymentContext deploymentContext;

    LdapAuthenticationProviderResourceConfiguration configuration;

    @Override
    public LdapAuthenticationProviderResourceConfiguration configuration() {
        if (this.configuration == null) {
            this.configuration =
                new LdapAuthenticationProviderResourceConfigurationEvaluator(super.configuration()).evalNow(deploymentContext);
        }
        return this.configuration;
    }

    @Override
    public void authenticate(String username, String password, ExecutionContext context, Handler<Authentication> handler) {
        Authentication authentication = cache.get(new LRUCache.Key(username, password));
        if (authentication == null) {
            try {
                AuthenticationResponse response = authenticator.authenticate(new AuthenticationRequest(username, new Credential(password)));

                if (response.isSuccess()) {
                    LdapEntry userEntry = response.getLdapEntry();

                    authentication = new Authentication(userEntry.getDn());

                    List<LdapAttribute> attributes = new ArrayList<>(userEntry.getAttributes());
                    addLdapUrlAttribute(attributes, response);
                    authentication.setAttributes(
                        attributes.stream().collect(Collectors.toMap(LdapAttribute::getName, LdapAttribute::getStringValue))
                    );
                    cache.put(new LRUCache.Key(username, password), authentication);
                } else {
                    logger.debug(
                        "Failed to authenticate user[{}] message[{}]",
                        username,
                        response.getAuthenticationHandlerResponse().getDiagnosticMessage()
                    );
                }
            } catch (LdapException ldapEx) {
                logger.error("An error occurs while trying to authenticate a user from LDAP [{}]", name(), ldapEx);
            }
        }
        handler.handle(authentication);
    }

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        logger.info("Init LDAP connection to source[{}]", configuration().getContextSourceUrl());
        connectionFactory = pooledConnectionFactory();
        connectionFactory.initialize();

        String[] userAttributes = getUserAttributes();

        authenticator =
            Authenticator
                .builder()
                .dnResolver(
                    SearchDnResolver
                        .builder()
                        .factory(connectionFactory)
                        .dn(
                            Optional
                                .ofNullable(configuration().getUserSearchBase())
                                .map(dn -> {
                                    if (!dn.isEmpty()) {
                                        return dn.concat(LDAP_SEPARATOR);
                                    }
                                    return dn;
                                })
                                .orElse("")
                                .concat(configuration().getContextSourceBase())
                        )
                        // replace *={0} authentication filter (ldaptive use *={user})
                        .filter(configuration().getUserSearchFilter().replace("{0}", "{user}"))
                        .subtreeSearch(true)
                        .allowMultipleDns(false)
                        .build()
                )
                .returnAttributes(userAttributes)
                .authenticationHandler(new SimpleBindAuthenticationHandler(connectionFactory))
                .entryResolver(new SearchEntryResolver())
                .build();

        cache =
            new LRUCache(
                configuration().getCacheMaxElements(),
                Duration.ofMillis(configuration().getCacheTimeToLive()),
                Duration.ofMillis(configuration.getCacheChecksMs())
            );
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();

        if (connectionFactory != null) {
            logger.info("Closing LDAP connections to source[{}]", configuration().getContextSourceUrl());
            connectionFactory.close();
        }

        if (cache != null) {
            cache.clear();
            cache.close();
            cache = null;
        }
    }

    private PooledConnectionFactory pooledConnectionFactory() {
        @SuppressWarnings("java:S5852")
        String contextSourceUrl = configuration().getContextSourceUrl().trim().replaceAll("\\s*,\\s*", " ");
        return PooledConnectionFactory
            .builder()
            .config(
                ConnectionConfig
                    .builder()
                    .url(contextSourceUrl)
                    .useStartTLS(configuration().isUseStartTLS())
                    .connectTimeout(Duration.ofMillis(configuration().getConnectTimeout()))
                    .responseTimeout(Duration.ofMillis(configuration().getResponseTimeout()))
                    .connectionInitializers(
                        BindConnectionInitializer
                            .builder()
                            .dn(configuration().getContextSourceUsername())
                            .credential(configuration().getContextSourcePassword())
                            .build()
                    )
                    .build()
            )
            .failFastInitialize(false)
            .min(configuration().getMinPoolSize())
            .max(configuration().getMaxPoolSize())
            .validatePeriodically(true)
            .validator(new SearchConnectionValidator())
            .build();
    }

    private String[] getUserAttributes() {
        String[] userAttributes = ReturnAttributes.ALL_USER.value();
        if (configuration().getAttributes() != null && !configuration().getAttributes().isEmpty()) {
            userAttributes = configuration().getAttributes().toArray(new String[0]);
        }
        return userAttributes;
    }

    private void addLdapUrlAttribute(List<LdapAttribute> attributes, AuthenticationResponse response) {
        if (Arrays.asList(getUserAttributes()).contains(LDAP_URL_ATTRIBUTE)) {
            Url url = response.getAuthenticationHandlerResponse().getConnection().getLdapURL().getUrl();
            attributes.add(
                new LdapAttribute(LDAP_URL_ATTRIBUTE, "%s://%s:%d".formatted(url.getScheme(), url.getHostname(), url.getPort()))
            );
        }
    }

    // Visible for tests
    Authentication getCachedAuthentication(String username, String password) {
        return cache.get(new LRUCache.Key(username, password));
    }
}
