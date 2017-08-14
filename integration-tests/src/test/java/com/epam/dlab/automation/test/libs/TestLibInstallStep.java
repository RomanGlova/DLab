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

package com.epam.dlab.automation.test.libs;

import com.epam.dlab.automation.helper.ConfigPropertyValue;
import com.epam.dlab.automation.helper.NamingHelper;
import com.epam.dlab.automation.http.ContentType;
import com.epam.dlab.automation.http.HttpRequest;
import com.epam.dlab.automation.http.HttpStatusCode;
import com.epam.dlab.automation.test.libs.models.Lib;
import com.epam.dlab.automation.test.libs.models.LibInstallRequest;
import com.epam.dlab.automation.test.libs.models.LibStatusResponse;
import com.jayway.restassured.response.Response;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.testng.Assert;

import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

@TestDescription("Test \"Install libraries\" ")
public class TestLibInstallStep extends TestLibStep {
    private final static String REALLY_FAILED_ERROR = " [Error]:Failed to install additional libraries.";
    private final static Logger LOGGER = LogManager.getLogger(TestLibInstallStep.class);
    private String statusUrl;
    private Lib libToInstall;

    public TestLibInstallStep(String requestUrl, String statusUrl, String token, String notebookName, long initTimeoutSec,
                              Lib libToInstall) {

        super(NamingHelper.getSelfServiceURL(requestUrl), token, notebookName, initTimeoutSec);
        this.statusUrl = NamingHelper.getSelfServiceURL(statusUrl);
        this.libToInstall = libToInstall;
    }

    @Override
    public void init() throws InterruptedException {
        LibInstallRequest request = new LibInstallRequest(Arrays.asList(libToInstall), notebookName);

        LOGGER.info("Install lib {}", request);

        long currentTime = System.currentTimeMillis() / 1000L;
        long expiredTime = currentTime + initTimeoutSec;

        Response response = new HttpRequest().webApiPost(url, ContentType.JSON, request, token);
        if (response.getStatusCode() != HttpStatusCode.OK) {
            LOGGER.error("Response status {}, body {}", response.getStatusCode(), response.getBody().print());
            Assert.fail("Cannot install libs for " + request);
        }

        while (expiredTime > currentTime) {

            response = new HttpRequest().webApiPost(statusUrl, ContentType.JSON, notebookName, token);
            if (response.getStatusCode() == HttpStatusCode.OK) {

                List<LibStatusResponse> actualStatuses = Arrays.asList(response.getBody().as(LibStatusResponse[].class));

                LOGGER.info("Actual statuses {}", actualStatuses);

                LibStatusResponse s = actualStatuses.stream()
                        .filter(e -> e.getGroup().equals(libToInstall.getGroup())
                                && e.getName().equals(libToInstall.getName())
                                && (e.getVersion().equals(libToInstall.getVersion()) || "N/A".equals(libToInstall.getVersion())))
                        .findFirst().get();

                LOGGER.info("Lib status is {}", s);
                if (s.getStatus().equals("installing")) {
                    LOGGER.info("Wait {} sec left for installation libs {}", expiredTime - currentTime, request);
                    TimeUnit.SECONDS.sleep(ConfigPropertyValue.isRunModeLocal() ? 3L : 20L);
                } else {
                    return;
                }
            } else {
                LOGGER.error("Response status{}, body {}", response.getStatusCode(), response.getBody().print());
                Assert.fail("Install libs failed for " + notebookName);
            }

            currentTime = System.currentTimeMillis() / 1000L;
        }

        Assert.fail("Timeout Cannot install libs on " + notebookName + " " + request);
    }

    @Override
    public void verify() {
        Response response = new HttpRequest().webApiPost(statusUrl, ContentType.JSON, notebookName, token);

        if (response.getStatusCode() == HttpStatusCode.OK) {

            List<LibStatusResponse> actualStatuses = Arrays.asList(response.getBody().as(LibStatusResponse[].class));
            LOGGER.error("Actual statuses {}", actualStatuses);

            LibStatusResponse libStatusResponse = actualStatuses.stream()
                    .filter(e -> e.getGroup().equals(libToInstall.getGroup())
                            && e.getName().equals(libToInstall.getName())
                            && (e.getVersion().equals(libToInstall.getVersion()) || "N/A".equals(libToInstall.getVersion())))
                    .findFirst().get();

            if ("installed".equals(libStatusResponse.getStatus())) {
                LOGGER.info("Library status of {} is {}", libToInstall, libStatusResponse);
            } else if ("failed".equals(libStatusResponse.getStatus())) {

                if (REALLY_FAILED_ERROR.equals(libStatusResponse.getErrorMessage())
                        || libStatusResponse.getErrorMessage() == null
                        || libStatusResponse.getErrorMessage().isEmpty()) {

                    Assert.fail(String.format("Installing library failed %s", libStatusResponse));
                }

                LOGGER.warn("Failed status with proper error message happend for {}", libStatusResponse);
            } else {
                Assert.assertTrue(libStatusResponse.getStatus().equals("installed"),
                        "Lib " + libToInstall + " is not installed. Status " + libStatusResponse);
            }
        } else {
            LOGGER.error("Response status{}, body {}", response.getStatusCode(), response.getBody().print());
            Assert.fail("Install libs failed for " + notebookName);
        }
        LOGGER.info(getDescription() + "passed");
    }
}
