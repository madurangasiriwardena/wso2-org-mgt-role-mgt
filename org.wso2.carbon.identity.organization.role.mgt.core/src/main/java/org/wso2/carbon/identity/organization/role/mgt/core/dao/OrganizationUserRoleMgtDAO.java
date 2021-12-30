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

public interface OrganizationUserRoleMgtDAO {
    void addOrganizationUserRoleMappings(List<OrganizationUserRoleMapping> organizationUserRoleMappings, int tenantID)
            throws OrganizationUserRoleMgtException;

    void addOrganizationUserRoleMappingsWithSp(List<UserRoleMappingUser> userList, String roleId,
                                               int hybridRoleId, int tenantID, String assignedAt)
            throws OrganizationUserRoleMgtException;

    List<RoleMember> getUserIdsByOrganizationAndRole(String organizationId, String roleId, int offset, int limit,
                                                     List<String> requestedAttributes, int tenantID, String filter)
            throws OrganizationUserRoleMgtServerException;

    void deleteOrganizationsUserRoleMapping(String deleteInvokedOrgId, List<ChildParentAssociation> childParentAssociations, String userId,
                                            String roleId, int tenantId, boolean isMandatory)
            throws OrganizationUserRoleMgtException;

    void deleteOrganizationsUserRoleMappings(String userId, int tenantId) throws OrganizationUserRoleMgtException;

    List<Role> getRolesByOrganizationAndUser(String organizationId, String userId, int tenantId)
            throws OrganizationUserRoleMgtServerException;

    void updateMandatoryProperty(String organizationId, String userId, String roleId,
                                 List<OrganizationUserRoleMapping> organizationUserRoleMappingsToAdd,
                                 List<OrganizationUserRoleMapping> organizationUserRoleMappiingsToUpdate,
                                 List<String> childOrganizationIdsToDeleteRecords, int tenantId)
            throws OrganizationUserRoleMgtServerException;

    boolean isOrganizationUserRoleMappingExists(String organizationId, String userId, String roleId,
                                                String assignedLevel, boolean mandatory,
                                                int tenantId)
            throws OrganizationUserRoleMgtException;

    int getDirectlyAssignedOrganizationUserRoleMappingInheritance(String organizationId, String userId, String roleId,
                                                                  int tenantId)
            throws OrganizationUserRoleMgtException;

    Integer getRoleIdBySCIMGroupName(String roleName, int tenantId) throws OrganizationUserRoleMgtServerException;

    List<ChildParentAssociation> getAllSubOrganizations(String organizationId) throws OrganizationUserRoleMgtException;

    int getMandatoryOfAnyOrganizationUserRoleMapping(String organizationId, String userId, String roleId, int tenantId) throws OrganizationUserRoleMgtException;

    String getAssignedAtOfAnyOrganizationUserRoleMapping(String organizationId, String userId, String roleId, int tenantId) throws OrganizationUserRoleMgtException;
}
