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

import org.wso2.carbon.identity.organization.role.mgt.core.exception.OrganizationUserRoleMgtException;
import org.wso2.carbon.identity.organization.role.mgt.core.models.OrganizationUserRoleMapping;
import org.wso2.carbon.identity.organization.role.mgt.core.models.Role;
import org.wso2.carbon.identity.organization.role.mgt.core.models.RoleMember;
import org.wso2.carbon.identity.organization.role.mgt.core.models.UserRoleMapping;
import org.wso2.carbon.identity.organization.role.mgt.core.models.UserRoleOperation;

import java.util.List;

/**
 * Interface for Organization-User-Role Management.
 */
public interface OrganizationUserRoleManager {
    /**
     * Create new {@link OrganizationUserRoleMapping}s in the database.
     * @param organizationId ID of the organization
     * @param userRoleMappings User-Role Mapping
     * @throws OrganizationUserRoleMgtException Organization-User-Role Management exception.
     */
    void addOrganizationUserRoleMappings(String organizationId, UserRoleMapping userRoleMappings)
            throws OrganizationUserRoleMgtException;

    /**
     * Get users by organization and role
     * @param organizationId ID of the organization.
     * @param roleId ID of the role.
     * @param offset Offset.
     * @param limit Limit.
     * @param requestedAttributes The list of requested attributes.
     * @param filter Filter.
     * @return A list of Role Members.
     * @throws OrganizationUserRoleMgtException Organization-User-Role management exception.
     */
    List<RoleMember> getUsersByOrganizationAndRole(String organizationId, String roleId, int offset, int limit,
                                                   List<String> requestedAttributes, String filter)
            throws OrganizationUserRoleMgtException;

    /**
     * Patch organization-user-role mappings
     * @param organizationId ID of the organization.
     * @param roleId ID of the role.
     * @param userId ID of the user.
     * @param userRoleOperations List of user role operations.
     * @throws OrganizationUserRoleMgtException Organization-User-Role management exception.
     */
    void patchOrganizationsUserRoleMapping(String organizationId, String roleId,
                                           String userId, List<UserRoleOperation> userRoleOperations)
            throws OrganizationUserRoleMgtException;

    /**
     * Delete organization-user-role mappings.
     * @param organizationId
     * @param userId
     * @param roleId
     * @param includeSubOrgs
     * @throws OrganizationUserRoleMgtException
     */
    void deleteOrganizationsUserRoleMapping(String organizationId, String userId, String roleId,
                                            boolean includeSubOrgs) throws OrganizationUserRoleMgtException;

    /**
     * Delete all organization-user-role mappings of a user.
     * @param userId
     * @throws OrganizationUserRoleMgtException
     */
    void deleteOrganizationsUserRoleMappings(String userId) throws OrganizationUserRoleMgtException;

    /**
     * Get roles by organization and user.
     * @param organizationId
     * @param userId
     * @return The list of Roles.
     * @throws OrganizationUserRoleMgtException
     */
    List<Role> getRolesByOrganizationAndUser(String organizationId, String userId)
            throws OrganizationUserRoleMgtException;

    /**
     * Fina whether there is a organization-user-role mapping or not
     * @param organizationId
     * @param userId
     * @param roleId
     * @param assignedLevel
     * @param mandatory
     * @return Boolean value of whether an organization-user-role mapping exists.
     * @throws OrganizationUserRoleMgtException
     */
    boolean isOrganizationUserRoleMappingExists(String organizationId, String userId, String roleId,
                                                String assignedLevel, boolean mandatory)
            throws OrganizationUserRoleMgtException;
}
