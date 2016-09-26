/*
Copyright 2016 EPAM Systems, Inc.
 
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
 
    http://www.apache.org/licenses/LICENSE-2.0
 
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package com.epam.datalab.auth.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.dropwizard.views.View;

public class LoginView extends View {
	
	private final static Logger LOG = LoggerFactory.getLogger(LoginView.class);
	
	private final String nextPage;
	
	public LoginView(String referrer) {
		super("login.mustache");
		this.nextPage = referrer;
	}

	public String getNextPage() {
		return nextPage;
	}
	
}