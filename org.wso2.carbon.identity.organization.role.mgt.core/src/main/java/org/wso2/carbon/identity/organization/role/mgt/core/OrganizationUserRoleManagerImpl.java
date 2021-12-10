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

import org.apache.commons.collections.CollectionUtils;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.event.IdentityEventException;
import org.wso2.carbon.identity.event.event.Event;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.organization.role.mgt.core.constants.OrganizationUserRoleEventConstants;
import org.wso2.carbon.identity.organization.role.mgt.core.constants.OrganizationUserRoleMgtConstants;
import org.wso2.carbon.identity.organization.role.mgt.core.dao.OrganizationUserRoleMgtDAO;
import org.wso2.carbon.identity.organization.role.mgt.core.dao.OrganizationUserRoleMgtDAOImpl;
import org.wso2.carbon.identity.organization.role.mgt.core.exception.OrganizationUserRoleMgtServerException;
import org.wso2.carbon.identity.organization.role.mgt.core.internal.OrganizationUserRoleMgtDataHolder;
import org.wso2.carbon.identity.organization.role.mgt.core.models.*;
import org.wso2.carbon.identity.organization.role.mgt.core.exception.OrganizationUserRoleMgtException;
import org.wso2.carbon.identity.organization.role.mgt.core.util.Utils;
import org.wso2.carbon.identity.scim2.common.DAO.GroupDAO;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.wso2.carbon.identity.organization.role.mgt.core.constants.OrganizationUserRoleEventConstants.*;
import static org.wso2.carbon.identity.organization.role.mgt.core.constants.OrganizationUserRoleMgtConstants.CASCADE_INSERT_USER_ORG_ROLES;
import static org.wso2.carbon.identity.organization.role.mgt.core.constants.OrganizationUserRoleMgtConstants.ErrorMessages.*;
import static org.wso2.carbon.identity.organization.role.mgt.core.util.Utils.*;
import static org.wso2.carbon.registry.core.session.CurrentSession.getTenantId;

public class OrganizationUserRoleManagerImpl implements OrganizationUserRoleManager {
    @Override
    public void addOrganizationUserRoleMappings(String organizationId, UserRoleMapping userRoleMapping) throws OrganizationUserRoleMgtException {
        //Fire pre-event
        fireEvent(PRE_ASSIGN_ORGANIZATION_USER_ROLE, organizationId, null,
                OrganizationUserRoleEventConstants.Status.FAILURE);
        OrganizationUserRoleMgtDAO organizationUserRoleMgtDAO = new OrganizationUserRoleMgtDAOImpl();
        String roleId = userRoleMapping.getRoleId();
        int hybridRoleId = getHybridRoleIdFromSCIMGroupId(roleId);
        userRoleMapping.setHybridRoleId(hybridRoleId);
        validateAddRoleMappingRequest(organizationId, userRoleMapping);
        List<UserRoleMappingUser> usersGetPermissionsForSubOrgsNonMandatory = new ArrayList<>();
        List<UserRoleMappingUser> usersGetPermissionOnlyToOneOrgNonMandatory = new ArrayList<>();
        List<UserRoleMappingUser> usersGetPermissionForSubOrgsMandatory = new ArrayList<>();
        AbstractUserStoreManager userStoreManager;
        try {
            userStoreManager = (AbstractUserStoreManager) getUserStoreManager(getTenantId());
            if (userStoreManager == null) {
                throw handleServerException(ERROR_CODE_USER_STORE_OPERATIONS_ERROR, " for tenant Id: " + getTenantId());
            } else {
                for (UserRoleMappingUser user :
                        userRoleMapping.getUsers()) {
                    boolean userExists = userStoreManager.isExistingUser(user.getUserId());
                    if (!userExists) {
                        throw handleServerException(ADD_ORG_ROLE_USER_REQUEST_INVALID_USER,
                                "No user exists with user ID: " + user.getUserId());
                    }
                    if (user.isMandatoryRole()) {
                        usersGetPermissionForSubOrgsMandatory.add(user);
                    } else if (user.isCascadedRole()) {
                        usersGetPermissionsForSubOrgsNonMandatory.add(user);
                    } else {
                        usersGetPermissionOnlyToOneOrgNonMandatory.add(user);
                    }
                }
            }
        } catch (UserStoreException e) {
            throw handleServerException(ERROR_CODE_USER_STORE_OPERATIONS_ERROR, " for tenant id: " + getTenantId());
        }

        String isCascadeInsert = System.getProperty(CASCADE_INSERT_USER_ORG_ROLES);
        // Defaults to SP when property is not available
        if (isCascadeInsert == null || Boolean.parseBoolean(isCascadeInsert)) {
            organizationUserRoleMgtDAO.addOrganizationUserRoleMappingsWithSp(usersGetPermissionsForSubOrgsNonMandatory, roleId,
                    hybridRoleId, getTenantId(), organizationId);
        } else {
            List<OrganizationUserRoleMapping> organizationUserRoleMappings = new ArrayList<>();
            if (CollectionUtils.isNotEmpty(usersGetPermissionsForSubOrgsNonMandatory)) {
                List<String> childOrganizationIds = organizationUserRoleMgtDAO.getAllSubOrganizations(organizationId);
                // add starting organization populate role mapping
                organizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(organizationId, roleId, hybridRoleId, organizationId,
                        usersGetPermissionsForSubOrgsNonMandatory));
                /* TODO:
                 Assume we have organizations A,B,C,D and A is the immediate parent of B and B is the immediate parent of C and so on.
                 If we assign a non-mandatory role and if it is assigned at A saying include it to the sub organizations.
                 Then we have to copy that role for all the sub organizations and they only get that from their immediate parent.
                 Say we are assigning A a role R1 to propagate then it will go to B and B's assigned level id will be id of A. But when it propagates
                 to C the parent id of it will be the id of B.
                 */
                int n = childOrganizationIds.size();
                for(int i=0;i<n;i++){
                    organizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(childOrganizationIds.get(i), roleId, hybridRoleId,
                            i==0 ? organizationId: childOrganizationIds.get(i-1), usersGetPermissionsForSubOrgsNonMandatory));
                }
            }
            if(CollectionUtils.isNotEmpty(usersGetPermissionForSubOrgsMandatory)){
                List<String> childOrganizationIds = organizationUserRoleMgtDAO.getAllSubOrganizations(organizationId);
                // Add starting organization to populate role mapping
                organizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(organizationId, roleId, hybridRoleId, organizationId,
                        usersGetPermissionForSubOrgsMandatory));
                /* TODO:
                Assume we have organizations A,B,C,D and A is the immediate parent of B and B is the immediate parent of C and so on.
                It we assign a mandatory role and if it is assigned at A saying include it to the sub organizations.
                Then we have to copy that role for all athe sub organizations and they only get that from the assignedLevel.
                Say we are assigning A a role R1 as mandatory role it will be assigned to B and B's assigned level id will be the id of A. And
                the assigned level id of C will be the id of A.*/
                for(String childOrgId: childOrganizationIds){
                    organizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(childOrgId, roleId, hybridRoleId, organizationId,
                            usersGetPermissionForSubOrgsMandatory));
                }
            }

            if(CollectionUtils.isNotEmpty(usersGetPermissionOnlyToOneOrgNonMandatory)){
                /* TODO:
                Assume we have organizations A,B,C,D and A is the immediate parent of B and B is the immediate parent of C and so on.
                If we assign a non mandatory role that we do not need to propagate to the child organizations, the assigned level id will
                be the same as the organization id and it will stop at that level without further propagating.
                */
                organizationUserRoleMappings
                        .addAll(populateOrganizationUserRoleMappings(organizationId, roleId, hybridRoleId, organizationId,
                                usersGetPermissionOnlyToOneOrgNonMandatory));
            }
            organizationUserRoleMgtDAO
                    .addOrganizationUserRoleMappings(organizationUserRoleMappings, getTenantId());

        }
    }

    @Override
    public List<RoleMember> getUsersByOrganizationAndRole(String organizationID, String roleId, int offset, int limit, List<String> requestedAttributes, String filter) throws OrganizationUserRoleMgtException {
        return null;
    }

    @Override
    public void patchOrganizationsUserRoleMapping(String organizationId, String roleId, String userId, List<UserRoleOperation> userRoleOperation) throws OrganizationUserRoleMgtException {

    }

    @Override
    public void deleteOrganizationsUserRoleMapping(String organizationId, String userId, String roleId, String assignedLevel, boolean includeSubOrg, boolean checkInheritance) throws OrganizationUserRoleMgtException {

    }

    @Override
    public void deleteOrganizationsUserRoleMappings(String userId) throws OrganizationUserRoleMgtException {

    }

    @Override
    public List<Role> getRolesByOrganizationAndUser(String organizationId, String userId) throws OrganizationUserRoleMgtException {
        return null;
    }

    @Override
    public boolean isOrganizationUserRoleMappingExists(String organizationId, String userId, String roleId, String assignedLevel, boolean mandatory) throws OrganizationUserRoleMgtException {
        return false;
    }

    private void fireEvent(String eventName, String organizationId, Object data, OrganizationUserRoleEventConstants.Status status) throws OrganizationUserRoleMgtServerException {
        IdentityEventService eventService = OrganizationUserRoleMgtDataHolder.getInstance().getIdentityEventService();
        Map<String, Object> eventProperties = new HashMap<>();
        eventProperties.put(USER_NAME, getAuthenticatedUsername());
        eventProperties.put(USER_ID, getAuthenticatedUserId());
        eventProperties.put(TENANT_DOMAIN, getTenantDomain());
        eventProperties.put(STATUS, status);
        if (data != null) {
            eventProperties.put(DATA, data);
        }
        if (organizationId != null) {
            eventProperties.put(ORGANIZATION_ID, organizationId);
        }
        Event event = new Event(eventName, eventProperties);
        try {
            eventService.handleEvent(event);
        } catch (IdentityEventException e) {
            throw handleServerException(OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_EVENTING_ERROR,
                    eventName, e);
        }
    }

    private String getTenantDomain() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
    }

    private String getAuthenticatedUserId() throws OrganizationUserRoleMgtServerException {

        return Utils.getUserIdFromUserName(getAuthenticatedUsername(), getTenantId());
    }

    private String getAuthenticatedUsername() {

        return PrivilegedCarbonContext.getThreadLocalCarbonContext().getUsername();
    }

    private int getHybridRoleIdFromSCIMGroupId(String roleId) throws OrganizationUserRoleMgtException {
        GroupDAO groupDAO = new GroupDAO();
        OrganizationUserRoleMgtDAO organizationUserRoleMgtDAO = new OrganizationUserRoleMgtDAOImpl();
        try {
            String groupName = groupDAO.getGroupNameById(getTenantId(), roleId);
            if (groupName == null) {
                throw handleClientException(INVALID_ROLE_ID, "Invalid role ID : " + roleId);
            }
            String[] groupNameParts = groupName.split("/");
            if (groupNameParts.length != 2) {
                throw handleServerException(INVALID_ROLE_ID, "Invalid role ID. Group name : " + groupName);
            }
            String domain = groupNameParts[0];
            if (!"INTERNAL".equalsIgnoreCase(domain)) {
                throw handleClientException(INVALID_ROLE_NON_INTERNAL_ROLE,
                        "Provided role : " + groupName + ", is not an INTERNAL role");
            }
            String roleName = groupNameParts[1];
            return organizationUserRoleMgtDAO.getRoleIdBySCIMGroupName(roleName, getTenantId());
        } catch (IdentitySCIMException e) {
            throw new OrganizationUserRoleMgtServerException(e);
        }
    }

    private void validateAddRoleMappingRequest(String organizationId, UserRoleMapping userRoleMapping) throws OrganizationUserRoleMgtException {
        for (UserRoleMappingUser user : userRoleMapping.getUsers()) {
            boolean isRoleMappingExists = isOrganizationUserRoleMappingExists(organizationId, user.getUserId(), userRoleMapping.getRoleId(),
                    organizationId, user.isMandatoryRole());
            if (isRoleMappingExists) {
                throw handleClientException(ADD_ORG_ROLE_USER_REQUEST_MAPPING_EXISTS, String.format(
                        "Directly assigned role %s to user: %s over the organization: %s is already exists",
                        userRoleMapping.getRoleId(), user.getUserId(), organizationId));
            }
        }
    }

    private List<OrganizationUserRoleMapping> populateOrganizationUserRoleMappings(String organizationId, String roleId, int hybridRoleId,
                                                                                   String assignedAt, List<UserRoleMappingUser> usersList){
        List<OrganizationUserRoleMapping> organizationUserRoleMappings = new ArrayList<>();
        for (UserRoleMappingUser user : usersList) {
            OrganizationUserRoleMapping organizationUserRoleMapping = new OrganizationUserRoleMapping();
            organizationUserRoleMapping.setOrganizationId(organizationId);
            organizationUserRoleMapping.setRoleId(roleId);
            organizationUserRoleMapping.setHybridRoleId(hybridRoleId);
            organizationUserRoleMapping.setUserId(user.getUserId());
            organizationUserRoleMapping.setAssignedLevelOrganizationId(assignedAt);
            organizationUserRoleMapping.setMandatory(user.isMandatoryRole());
            organizationUserRoleMappings.add(organizationUserRoleMapping);
        }
        return organizationUserRoleMappings;
    }
}
