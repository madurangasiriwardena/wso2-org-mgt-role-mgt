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

package org.wso2.carbon.identity.organization.role.mgt.endpoint;

import org.wso2.carbon.identity.organization.role.mgt.endpoint.*;
import org.wso2.carbon.identity.organization.role.mgt.endpoint.dto.*;
import org.apache.cxf.jaxrs.ext.multipart.Attachment;
import org.apache.cxf.jaxrs.ext.multipart.Multipart;
import java.io.InputStream;
import java.util.List;
import org.wso2.carbon.identity.organization.role.mgt.endpoint.dto.ErrorDTO;
import java.util.List;
import org.wso2.carbon.identity.organization.role.mgt.endpoint.dto.RoleDTO;
import org.wso2.carbon.identity.organization.role.mgt.endpoint.dto.UserDTO;
import org.wso2.carbon.identity.organization.role.mgt.endpoint.dto.UserRoleMappingDTO;
import org.wso2.carbon.identity.organization.role.mgt.endpoint.dto.UserRoleOperationDTO;
import javax.ws.rs.core.Response;


public interface OrganizationsApiService {

      public Response organizationsOrganizationIdRolesPost(String organizationId, UserRoleMappingDTO userRoleMappingDTO);

      public Response organizationsOrganizationIdRolesRoleIdUsersGet(String organizationId, String roleId, Integer offset, Integer limit, String attributes, String filter);

      public Response organizationsOrganizationIdRolesRoleIdUsersUserIdDelete(String organizationId, String roleId, String userId, Boolean includeSubOrgs);

      public Response organizationsOrganizationIdRolesRoleIdUsersUserIdPatch(String organizationId, String roleId, String userId, List<UserRoleOperationDTO> userRoleOperationDTO);

      public Response organizationsOrganizationIdUsersUserIdRolesGet(String organizationId, String userId);
}
