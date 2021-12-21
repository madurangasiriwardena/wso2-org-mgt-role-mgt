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

package org.wso2.carbon.identity.organization.role.mgt.core;

import org.wso2.carbon.identity.organization.role.mgt.core.models.Role;
import org.wso2.carbon.identity.organization.role.mgt.core.models.UserRoleOperation;
import org.wso2.carbon.identity.organization.role.mgt.core.exception.OrganizationUserRoleMgtException;
import org.wso2.carbon.identity.organization.role.mgt.core.models.RoleMember;
import org.wso2.carbon.identity.organization.role.mgt.core.models.UserRoleMapping;

import java.util.List;

public interface OrganizationUserRoleManager {
    void addOrganizationUserRoleMappings(String organizationId, UserRoleMapping userRoleMappings)
            throws OrganizationUserRoleMgtException;
    List<RoleMember> getUsersByOrganizationAndRole(String organizationID, String roleId, int offset, int limit,
                                                   List<String> requestedAttributes, String filter)
            throws OrganizationUserRoleMgtException;

    void patchOrganizationsUserRoleMapping(String organizationId, String roleId,
                                           String userId, List<UserRoleOperation> userRoleOperations)
            throws OrganizationUserRoleMgtException;

    void deleteOrganizationsUserRoleMapping(String organizationId, String userId, String roleId, String assignedLevel, boolean mandatory, boolean includeSubOrgs)
            throws OrganizationUserRoleMgtException;

    void deleteOrganizationsUserRoleMappings(String userId) throws OrganizationUserRoleMgtException;

    List<Role> getRolesByOrganizationAndUser(String organizationId, String userId)
            throws OrganizationUserRoleMgtException;

    boolean isOrganizationUserRoleMappingExists(String organizationId, String userId, String roleId,
                                                String assignedLevel, boolean mandatory)
            throws OrganizationUserRoleMgtException;
}
