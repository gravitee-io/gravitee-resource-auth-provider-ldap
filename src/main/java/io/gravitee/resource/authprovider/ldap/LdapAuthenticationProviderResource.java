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
import io.gravitee.resource.authprovider.api.Authentication;
import io.gravitee.resource.authprovider.api.AuthenticationProviderResource;
import io.gravitee.resource.authprovider.ldap.cache.LRUCache;
import io.gravitee.resource.authprovider.ldap.configuration.LdapAuthenticationProviderResourceConfiguration;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.extern.slf4j.Slf4j;
import org.ldaptive.BindConnectionInitializer;
import org.ldaptive.ConnectionConfig;
import org.ldaptive.Credential;
import org.ldaptive.LdapAttribute;
import org.ldaptive.LdapEntry;
import org.ldaptive.LdapException;
import org.ldaptive.PooledConnectionFactory;
import org.ldaptive.ReturnAttributes;
import org.ldaptive.SearchConnectionValidator;
import org.ldaptive.auth.AbstractAuthenticationHandler;
import org.ldaptive.auth.AccountState;
import org.ldaptive.auth.AuthenticationRequest;
import org.ldaptive.auth.AuthenticationResponse;
import org.ldaptive.auth.Authenticator;
import org.ldaptive.auth.EntryResolver;
import org.ldaptive.auth.SearchDnResolver;
import org.ldaptive.auth.SearchEntryResolver;
import org.ldaptive.auth.SimpleBindAuthenticationHandler;

/**
 * @author David BRASSELY (david.brassely at graviteesource.com)
 * @author GraviteeSource Team
 */
@Slf4j
public class LdapAuthenticationProviderResource extends AuthenticationProviderResource<LdapAuthenticationProviderResourceConfiguration> {

    private static final String LDAP_SEPARATOR = ",";

    private String[] userAttributes = ReturnAttributes.ALL_USER.value();

    private PooledConnectionFactory pooledConnectionFactory;
    private PooledConnectionFactory searchPooledConnectionFactory;
    private Authenticator authenticator;
    private LRUCache cache;

    @Override
    public void authenticate(String username, String password, ExecutionContext context, Handler<Authentication> handler) {
        Authentication authentication = cache.get(username);
        if (authentication == null) {
            try {
                AuthenticationResponse response = authenticator.authenticate(
                    new AuthenticationRequest(username, new Credential(password), userAttributes)
                );
                if (response.isSuccess()) {
                    LdapEntry userEntry = response.getLdapEntry();
                    authentication = new Authentication(userEntry.getDn());
                    Map<String, Object> attributes = userEntry
                        .getAttributes()
                        .stream()
                        .collect(Collectors.toMap(LdapAttribute::getName, LdapAttribute::getStringValue));
                    authentication.setAttributes(attributes);
                    cache.put(username, authentication);
                    handler.handle(authentication);
                } else {
                    AccountState.Error error = Optional.ofNullable(response.getAccountState()).map(AccountState::getError).orElse(null);
                    log.debug("Failed to authenticate user[{}] message[{}]", username, error);
                    handler.handle(null);
                }
            } catch (LdapException ldapEx) {
                log.error("An error occurs while trying to authenticate a user from LDAP [{}]", name(), ldapEx);
                handler.handle(null);
            }
        } else {
            handler.handle(authentication);
        }
    }

    @Override
    protected void doStart() throws Exception {
        super.doStart();

        pooledConnectionFactory = getPooledFactory();
        searchPooledConnectionFactory = getPooledFactory();

        log.info("Init LDAP connection to source[{}]", configuration().getContextSourceUrl());
        if (!pooledConnectionFactory.isInitialized()) {
            pooledConnectionFactory.initialize();
        }

        if (!searchPooledConnectionFactory.isInitialized()) {
            searchPooledConnectionFactory.initialize();
        }

        var dnResolver = new SearchDnResolver();
        //searchPooledConnectionFactory
        String userSearchBase = configuration().getUserSearchBase();
        dnResolver.setBaseDn(configuration().getContextSourceBase());
        if (userSearchBase != null && !userSearchBase.isEmpty()) {
            dnResolver.setBaseDn(userSearchBase + LDAP_SEPARATOR + dnResolver.getBaseDn());
        }
        // unable *={0} authentication filter (ldaptive use *={user})
        dnResolver.setUserFilter(configuration().getUserSearchFilter().replace("\\{0\\}", "{user}"));
        dnResolver.setSubtreeSearch(true);
        dnResolver.setAllowMultipleDns(false);

        AbstractAuthenticationHandler authHandler = new SimpleBindAuthenticationHandler(pooledConnectionFactory);
        EntryResolver pooledSearchEntryResolver = new SearchEntryResolver(pooledConnectionFactory);

        authenticator = new Authenticator(dnResolver, authHandler);
        authenticator.setEntryResolver(pooledSearchEntryResolver);

        cache =
            new LRUCache(
                configuration().getCacheMaxElements(),
                Duration.ofMillis(configuration().getCacheTimeToLive()),
                Duration.ofMinutes(1)
            );

        if (configuration().getAttributes() != null && !configuration().getAttributes().isEmpty()) {
            userAttributes = new String[configuration().getAttributes().size()];
            userAttributes = configuration().getAttributes().toArray(userAttributes);
        }
    }

    @Override
    protected void doStop() throws Exception {
        super.doStop();

        if (pooledConnectionFactory.isInitialized()) {
            log.info("Closing LDAP connections to source[{}]", configuration().getContextSourceUrl());
            pooledConnectionFactory.close();
        }

        if (searchPooledConnectionFactory.isInitialized()) {
            log.info("Closing LDAP search connections to source[{}]", configuration().getContextSourceUrl());
            searchPooledConnectionFactory.close();
        }

        if (cache != null) {
            cache.clear();
            cache.close();
        }
    }

    private ConnectionConfig connectionConfig() {
        ConnectionConfig connectionConfig = new ConnectionConfig();
        connectionConfig.setConnectTimeout(Duration.ofMillis(configuration().getConnectTimeout()));
        connectionConfig.setResponseTimeout(Duration.ofMillis(configuration().getResponseTimeout()));
        connectionConfig.setLdapUrl(configuration().getContextSourceUrl());
        connectionConfig.setUseStartTLS(configuration().isUseStartTLS());
        BindConnectionInitializer connectionInitializer = new BindConnectionInitializer(
            configuration().getContextSourceUsername(),
            new Credential(configuration().getContextSourcePassword())
        );
        connectionConfig.setConnectionInitializers(connectionInitializer);
        return connectionConfig;
    }

    private PooledConnectionFactory getPooledFactory() {
        var poolConfig = new PooledConnectionFactory();
        poolConfig.setConnectionConfig(connectionConfig());
        poolConfig.setMinPoolSize(configuration().getMinPoolSize());
        poolConfig.setMaxPoolSize(configuration().getMaxPoolSize());
        poolConfig.setValidator(new SearchConnectionValidator());
        poolConfig.setValidatePeriodically(true);
        return poolConfig;
    }
}
