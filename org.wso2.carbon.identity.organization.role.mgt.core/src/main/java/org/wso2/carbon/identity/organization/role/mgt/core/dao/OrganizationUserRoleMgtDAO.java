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

package org.wso2.carbon.identity.organization.role.mgt.core.dao;

import org.wso2.carbon.identity.organization.role.mgt.core.exception.OrganizationUserRoleMgtException;
import org.wso2.carbon.identity.organization.role.mgt.core.exception.OrganizationUserRoleMgtServerException;
import org.wso2.carbon.identity.organization.role.mgt.core.models.*;

import java.util.List;
import java.util.Map;

public interface OrganizationUserRoleMgtDAO {
    /**
     * Add organization-user-role mappings.
     * @param organizationUserRoleMappings
     * @param tenantID
     * @throws OrganizationUserRoleMgtException
     */
    void addOrganizationUserRoleMappings(List<OrganizationUserRoleMapping> organizationUserRoleMappings, int tenantID)
            throws OrganizationUserRoleMgtException;

    /**
     * Add organization-user-role mappings with stored procedures.
     * @param userList
     * @param roleId
     * @param hybridRoleId
     * @param tenantID
     * @param assignedAt
     * @throws OrganizationUserRoleMgtException
     */
    /*
    void addOrganizationUserRoleMappingsWithSp(List<UserRoleMappingUser> userList, String roleId,
                                               int hybridRoleId, int tenantID, String assignedAt)
            throws OrganizationUserRoleMgtException;*/

    /**
     * Get user-ids by organization and role.
     * @param organizationId
     * @param roleId
     * @param offset
     * @param limit
     * @param requestedAttributes
     * @param tenantID
     * @param filter
     * @return
     * @throws OrganizationUserRoleMgtServerException
     */
    List<RoleMember> getUserIdsByOrganizationAndRole(String organizationId, String roleId, int offset, int limit,
                                                     List<String> requestedAttributes, int tenantID, String filter)
            throws OrganizationUserRoleMgtServerException;

    /**
     * Delete organization-user-role mappings.
     * @param deletionList
     * @param userId
     * @param roleId
     * @param tenantId
     * @throws OrganizationUserRoleMgtException
     */
    void deleteOrganizationsUserRoleMapping(Map<String,String> deletionList, String userId,
                                            String roleId, int tenantId)
            throws OrganizationUserRoleMgtException;

    /**
     * Delete all organization-user-role mappings of a user.
     * @param userId
     * @param tenantId
     * @throws OrganizationUserRoleMgtException
     */
    void deleteOrganizationsUserRoleMappings(String userId, int tenantId) throws OrganizationUserRoleMgtException;

    /**
     * Get roleids by organization and user ids.
     * @param organizationId
     * @param userId
     * @param tenantId
     * @return
     * @throws OrganizationUserRoleMgtServerException
     */
    List<Role> getRolesByOrganizationAndUser(String organizationId, String userId, int tenantId)
            throws OrganizationUserRoleMgtServerException;

    /**
     * Updating the organization-user-role mappings on mandatory property.
     * @param organizationId
     * @param userId
     * @param roleId
     * @param organizationUserRoleMappingsToAdd
     * @param organizationUserRoleMappingsToUpdate
     * @param childOrganizationIdsToDeleteRecords
     * @param tenantId
     * @throws OrganizationUserRoleMgtServerException
     */
    void updateMandatoryProperty(String organizationId, String userId, String roleId,
                                 List<OrganizationUserRoleMapping> organizationUserRoleMappingsToAdd,
                                 List<OrganizationUserRoleMapping> organizationUserRoleMappingsToUpdate,
                                 Map<String, String> childOrganizationIdsToDeleteRecords, int tenantId)
            throws OrganizationUserRoleMgtServerException;

    /**
     * Check whether there is an organization-user-role mapping.
     * @param organizationId
     * @param userId
     * @param roleId
     * @param assignedLevel
     * @param mandatory
     * @param tenantId
     * @return The boolean value of whether the user exists or not.
     * @throws OrganizationUserRoleMgtException
     */
    boolean isOrganizationUserRoleMappingExists(String organizationId, String userId, String roleId,
                                                String assignedLevel, boolean mandatory,
                                                int tenantId)
            throws OrganizationUserRoleMgtException;

    /**
     * Get the mandatory value of a directly assigned organization-user-role mapping.
     * @param organizationId
     * @param userId
     * @param roleId
     * @param tenantId
     * @return The mandatory value of the organization-user-role mapping.
     * @throws OrganizationUserRoleMgtException
     */
    int getDirectlyAssignedOrganizationUserRoleMappingInheritance(String organizationId, String userId, String roleId,
                                                                  int tenantId)
            throws OrganizationUserRoleMgtException;

    /**
     * Get role id by SCIM group name.
     * @param roleName
     * @param tenantId
     * @return The roleId
     * @throws OrganizationUserRoleMgtServerException
     */
    Integer getRoleIdBySCIMGroupName(String roleName, int tenantId) throws OrganizationUserRoleMgtServerException;

    /**
     * Get all the sub organizations and their immediate parents.
     * @param organizationId
     * @return The child-parent association of all the sub-organizations.
     * @throws OrganizationUserRoleMgtException
     */
    List<ChildParentAssociation> getAllSubOrganizations(String organizationId) throws OrganizationUserRoleMgtException;

    /**
     * Get mandatory value of any organization-user-role mapping.
     * @param organizationId
     * @param userId
     * @param roleId
     * @param tenantId
     * @return The mandatory value of an organization-user-role-mapping.
     * @throws OrganizationUserRoleMgtException
     */
    int getMandatoryOfAnyOrganizationUserRoleMapping(String organizationId, String userId, String roleId, int tenantId) throws OrganizationUserRoleMgtException;

    /**
     * Get assignedAt value of any organization-user-role mapping.
     * @param organizationId
     * @param userId
     * @param roleId
     * @param tenantId
     * @return The assignedAt value of an organization-user-role mapping.
     * @throws OrganizationUserRoleMgtException
     */
    String getAssignedAtOfAnyOrganizationUserRoleMapping(String organizationId, String userId, String roleId, int tenantId) throws OrganizationUserRoleMgtException;
}
