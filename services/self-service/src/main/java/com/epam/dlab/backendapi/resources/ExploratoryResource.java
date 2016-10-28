/******************************************************************************************************

 Copyright (c) 2016 EPAM Systems Inc.

 Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

 *****************************************************************************************************/

package com.epam.dlab.backendapi.resources;

import com.epam.dlab.auth.UserInfo;
import com.epam.dlab.backendapi.api.form.ExploratoryActionFormDTO;
import com.epam.dlab.backendapi.api.form.ExploratoryCreateFormDTO;
import com.epam.dlab.backendapi.api.instance.UserInstanceDTO;
import com.epam.dlab.backendapi.api.instance.UserInstanceStatus;
import com.epam.dlab.backendapi.client.rest.ExploratoryAPI;
import com.epam.dlab.backendapi.dao.KeyDAO;
import com.epam.dlab.backendapi.dao.SettingsDAO;
import com.epam.dlab.backendapi.dao.UserListDAO;
import com.epam.dlab.client.restclient.RESTService;
import com.epam.dlab.dto.StatusBaseDTO;
import com.epam.dlab.dto.exploratory.ExploratoryActionDTO;
import com.epam.dlab.dto.exploratory.ExploratoryCreateDTO;
import com.google.inject.Inject;
import com.google.inject.name.Named;
import io.dropwizard.auth.Auth;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

import static com.epam.dlab.backendapi.SelfServiceApplicationConfiguration.PROVISIONING_SERVICE;

@Path("infrastructure_provision/exploratory_environment")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public class ExploratoryResource implements ExploratoryAPI {
    private static final Logger LOGGER = LoggerFactory.getLogger(ExploratoryResource.class);

    @Inject
    private SettingsDAO settingsDAO;
    @Inject
    private UserListDAO userListDAO;
    @Inject
    @Named(PROVISIONING_SERVICE)
    private RESTService provisioningService;

    @PUT
    public Response create(@Auth UserInfo userInfo, ExploratoryCreateFormDTO formDTO) {
        LOGGER.debug("creating exploratory environment {} for user {}", formDTO.getName(), userInfo.getName());
        boolean isAdded = userListDAO.insertExploratory(new UserInstanceDTO()
                .withUser(userInfo.getName())
                .withEnvironmentName(formDTO.getName())
                .withStatus(UserInstanceStatus.CREATING.getStatus())
                .withShape(formDTO.getShape()));
        if (isAdded) {
            ExploratoryCreateDTO dto = new ExploratoryCreateDTO()
                    .withServiceBaseName(settingsDAO.getServiceBaseName())
                    .withNotebookUserName(userInfo.getName())
                    .withNotebookInstanceType(formDTO.getShape())
                    .withRegion(settingsDAO.getAwsRegion())
                    .withSecurityGroupIds(settingsDAO.getSecurityGroup());
            LOGGER.debug("created exploratory environment {} for user {}", formDTO.getName(), userInfo.getName());
            return Response
                    .ok(provisioningService.post(EXPLORATORY_CREATE, dto, String.class))
                    .build();
        } else {
            LOGGER.debug("used existing exploratory environment {} for user {}", formDTO.getName(), userInfo.getName());
            return Response.status(Response.Status.FOUND).build();
        }
    }

    @POST
    @Path("/status")
    public Response create(StatusBaseDTO dto) {
        LOGGER.debug("update status for exploratory environment {} for user {}", dto.getName(), dto.getUser());
        userListDAO.updateExploratoryStatus(dto);
        return Response.ok().build();
    }

    @POST
    public String start(@Auth UserInfo userInfo, ExploratoryActionFormDTO formDTO) {
        LOGGER.debug("starting exploratory environment {} for user {}", formDTO.getNotebookInstanceName(), userInfo.getName());
        return action(userInfo, formDTO, EXPLORATORY_START, UserInstanceStatus.RUNNING);
    }

    @DELETE
    public String terminate(@Auth UserInfo userInfo, ExploratoryActionFormDTO formDTO) {
        if(formDTO.getNotebookAction() == "terminate")
        {
            LOGGER.debug("terminating exploratory environment {} for user {}", formDTO.getNotebookInstanceName(), userInfo.getName());
            UserInstanceStatus status = UserInstanceStatus.TERMINATING;
            userListDAO.updateComputationalStatusesForExploratory(createStatusDTO(userInfo, formDTO, status));
            return action(userInfo, formDTO, EXPLORATORY_TERMINATE, status);
        }
        else
        {
            LOGGER.debug("stopping exploratory environment {} for user {}", formDTO.getNotebookInstanceName(), userInfo.getName());
            return action(userInfo, formDTO, EXPLORATORY_STOP, UserInstanceStatus.STOPPING);
        }
    }

    private String action(UserInfo userInfo, ExploratoryActionFormDTO formDTO, String action, UserInstanceStatus status) {
        userListDAO.updateExploratoryStatus(createStatusDTO(userInfo, formDTO, status));
        ExploratoryActionDTO dto = new ExploratoryActionDTO()
                .withServiceBaseName(settingsDAO.getServiceBaseName())
                .withNotebookUserName(userInfo.getName())
                .withNotebookInstanceName(formDTO.getNotebookInstanceName())
                .withRegion(settingsDAO.getAwsRegion());
        return provisioningService.post(action, dto, String.class);
    }

    private StatusBaseDTO createStatusDTO(UserInfo userInfo, ExploratoryActionFormDTO formDTO, UserInstanceStatus status) {
        return new StatusBaseDTO()
                .withUser(userInfo.getName())
                .withName(formDTO.getNotebookInstanceName())
                .withStatus(status.getStatus());
    }
}