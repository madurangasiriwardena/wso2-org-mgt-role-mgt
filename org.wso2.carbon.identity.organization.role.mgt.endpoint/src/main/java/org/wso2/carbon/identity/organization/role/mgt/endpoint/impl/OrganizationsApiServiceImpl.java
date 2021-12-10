/*
 * Copyright (c) 2021, WSO2 Inc. (http://www.wso2.com).
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.organization.role.mgt.endpoint.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.organization.role.mgt.core.exception.OrganizationUserRoleMgtClientException;
import org.wso2.carbon.identity.organization.role.mgt.core.models.UserRoleMapping;
import org.wso2.carbon.identity.organization.role.mgt.core.models.UserRoleMappingUser;
import org.wso2.carbon.identity.organization.role.mgt.endpoint.*;
import org.wso2.carbon.identity.organization.role.mgt.endpoint.dto.*;
import org.wso2.carbon.identity.organization.role.mgt.endpoint.utils.RoleMgtEndpointUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.stream.Collectors;
import javax.ws.rs.core.Response;

import static org.wso2.carbon.identity.organization.role.mgt.endpoint.constant.RoleMgtEndPointConstants.ORGANIZATION_ROLES_PATH;
import static org.wso2.carbon.identity.organization.role.mgt.endpoint.utils.RoleMgtEndpointUtils.getOrganizationUserRoleManager;

public class OrganizationsApiServiceImpl implements OrganizationsApiService {

    private static final Log log = LogFactory.getLog(OrganizationsApiServiceImpl.class);

    @Override
    public Response organizationsOrganizationIdRolesPost(String organizationId, UserRoleMappingDTO userRoleMappingDTO) {
        try {
            UserRoleMapping newUserRoleMappings = new UserRoleMapping(organizationId, userRoleMappingDTO.getUsers().stream()
                    .map(mapping -> new UserRoleMappingUser(mapping.getUserId(), mapping.getMandatory(), mapping.getIncludeSubOrgs())).collect(Collectors.toList()));
            getOrganizationUserRoleManager().addOrganizationUserRoleMappings(organizationId, newUserRoleMappings);
            return Response.created(getOrganizationRoleResourceURI(organizationId)).build();
        } catch (OrganizationUserRoleMgtClientException e) {
            return RoleMgtEndpointUtils.handleBadRequestResponse(e, log);
        } catch (Throwable throwable) {
            return RoleMgtEndpointUtils.handleUnexpectedServerError(throwable, log);
        }
    }

    @Override
    public Response organizationsOrganizationIdRolesRoleIdUsersGet(String organizationId, String roleId, Integer offset, Integer limit, String attributes, String filter) {

        // do some magic!
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response organizationsOrganizationIdRolesRoleIdUsersUserIdDelete(String organizationId, String roleId, String userId, Boolean mandatory, Boolean includeSubOrgs, String assignedAt) {

        // do some magic!
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response organizationsOrganizationIdRolesRoleIdUsersUserIdPatch(String organizationId, String roleId, String userId, List<UserRoleOperationDTO> userRoleOperationDTO) {

        // do some magic!
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response organizationsOrganizationIdUsersUserIdRolesGet(String organizationId, String userId) {

        // do some magic!
        return Response.ok().entity("magic!").build();
    }


    private URI getOrganizationRoleResourceURI(String organizationId) throws URISyntaxException {

        return new URI(String.format(ORGANIZATION_ROLES_PATH, organizationId));
    }
}
