/***************************************************************************

Copyright (c) 2016, EPAM SYSTEMS INC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

****************************************************************************/

package com.epam.dlab.configuration;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.fail;

import javax.validation.constraints.NotNull;

import org.junit.Test;

import com.epam.dlab.exception.InitializationException;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ConfigurationValidatorTest {
	
	class TestProperty {
		
		@JsonProperty
		@NotNull
		String property;
	}
	
	@Test
	public void validate() throws InitializationException {
		ConfigurationValidator<TestProperty> v = new ConfigurationValidator<>();
		TestProperty o = new TestProperty();
		try {
			v.validate(o);
			fail("Property is null but validate is passed");
		} catch (InitializationException e) {
			// OK
		}
		o.property = "value";
		v.validate(o);
		assertEquals("value", o.property);
	}
}
