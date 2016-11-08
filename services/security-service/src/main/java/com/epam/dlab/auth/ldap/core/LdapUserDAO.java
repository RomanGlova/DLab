/******************************************************************************************************

 Copyright (c) 2016 EPAM Systems Inc.

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 *****************************************************************************************************/
package com.epam.dlab.auth.ldap.core;

import com.epam.dlab.auth.UserInfo;
import com.epam.dlab.auth.ldap.SecurityServiceConfiguration;
import com.epam.dlab.auth.ldap.core.filter.SearchResultProcessor;
import com.epam.dlab.auth.rest.ExpirableContainer;
import com.epam.dlab.auth.script.ScriptHolder;
import com.epam.dlab.auth.script.SearchResultToDictionaryMapper;
import org.apache.commons.pool.PoolableObjectFactory;
import org.apache.directory.api.ldap.model.cursor.SearchCursor;
import org.apache.directory.api.ldap.model.message.SearchRequest;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapConnectionPool;
import org.apache.directory.ldap.client.api.ValidatingPoolableLdapConnectionFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;


public class LdapUserDAO {

    private final LdapConnectionConfig connConfig;
    private final List<Request> requests;
    private final String bindTemplate;
    private final LdapConnectionPool usersPool;
    private final LdapConnectionPool searchPool;
    private final ExpirableContainer<Map<String, Object>> filteredDictionaries = new ExpirableContainer<>();
    private final ScriptHolder script = new ScriptHolder();
    protected final static Logger LOG = LoggerFactory.getLogger(LdapUserDAO.class);

    public LdapUserDAO(	SecurityServiceConfiguration config ) {
        this.connConfig = config.getLdapConnectionConfig();
        this.requests = config.getLdapSearch();
        this.bindTemplate = config.getLdapBindTemplate();
        PoolableObjectFactory<LdapConnection> userPoolFactory = new ValidatingPoolableLdapConnectionFactory(connConfig);
        this.usersPool = new LdapConnectionPool(userPoolFactory);
        PoolableObjectFactory<LdapConnection> searchPoolFactory = new ValidatingPoolableLdapConnectionFactory(connConfig);
        this.searchPool = new LdapConnectionPool(searchPoolFactory);
    }

    public UserInfo getUserInfo(String username, String password) throws Exception {
        try (ReturnableConnection userRCon = new ReturnableConnection(usersPool)) {
            LdapConnection userCon = userRCon.getConnection();
            // just confirm user exists
            String bind = String.format(bindTemplate, username);
            userCon.bind(bind, password);
            userCon.unBind();
            LOG.debug("User '{}' identified.", username);
            return new UserInfo(username, "******");
        } catch(Exception e){
            LOG.error("LDAP getUserInfo authentication error for username '{}': {}",username ,e.getMessage());
            throw e;
        }
    }

    public UserInfo enrichUserInfo(final UserInfo userInfo) throws Exception {
        String username = userInfo.getName();
        UserInfo ui = userInfo.withToken("******");
        try (ReturnableConnection searchRCon = new ReturnableConnection(searchPool)) {
            LdapConnection searchCon = searchRCon.getConnection();
            Map<String, Object> conextTree = new HashMap<>();
            for (Request req : requests) {
                if (req == null) {
                    continue;
                }
                SearchResultProcessor proc = req.getSearchResultProcessor();
                SearchRequest sr = req.buildSearchRequest(new HashMap<String, Object>() {
                    private static final long serialVersionUID = 1L;
                    {
                        put(Pattern.quote("${username}"), username);
                    }
                });
                String filter = sr.getFilter().toString();
                Map<String, Object> contextMap = filteredDictionaries.get(filter);
                SearchResultToDictionaryMapper mapper = new SearchResultToDictionaryMapper(req.getName(),
                        conextTree);
                if (contextMap == null) {
                    LOG.debug("Retrieving new branch {} for {}", req.getName(), filter);
                    try (SearchCursor cursor = searchCon.search(sr)) {
                        contextMap = mapper.transformSearchResult(cursor);
                    }
                    if (req.isCache()) {
                        filteredDictionaries.put(filter, contextMap, req.getExpirationTimeMsec());
                    }
                } else {
                    LOG.debug("Restoring old branch {} for {}: {}", req.getName(), filter, contextMap);
                    mapper.getBranch().putAll(contextMap);
                }
                if (proc != null) {
                    LOG.debug("Executing: {}", proc.getLanguage());
                    ui = script.evalOnce(req.getName(), proc.getLanguage(), proc.getCode()).apply(ui, conextTree);
                }
            }
        } catch (Exception e) {
            LOG.error("LDAP enrichUserInfo authentication error for username '{}': {}",username ,e.getMessage());
            throw e;
        }
        return ui;
    }

}
