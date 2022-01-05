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
import org.apache.commons.lang.StringUtils;
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
import org.wso2.carbon.identity.scim2.common.DAO.GroupDAO;
import org.wso2.carbon.identity.scim2.common.exceptions.IdentitySCIMException;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.common.AbstractUserStoreManager;

import java.util.Arrays;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.organization.role.mgt.core.constants.OrganizationUserRoleEventConstants.*;
import static org.wso2.carbon.identity.organization.role.mgt.core.constants.OrganizationUserRoleMgtConstants.CASCADE_INSERT_USER_ORG_ROLES;
import static org.wso2.carbon.identity.organization.role.mgt.core.constants.OrganizationUserRoleMgtConstants.ErrorMessages.*;
import static org.wso2.carbon.identity.organization.role.mgt.core.constants.OrganizationUserRoleMgtConstants.PATCH_OP_REPLACE;
import static org.wso2.carbon.identity.organization.role.mgt.core.util.Utils.getUserStoreManager;
import static org.wso2.carbon.identity.organization.role.mgt.core.util.Utils.handleServerException;
import static org.wso2.carbon.identity.organization.role.mgt.core.util.Utils.handleClientException;
import static org.wso2.carbon.identity.organization.role.mgt.core.util.Utils.getUserIdFromUserName;
import static org.wso2.carbon.identity.organization.role.mgt.core.util.Utils.getTenantDomain;
import static org.wso2.carbon.identity.organization.role.mgt.core.util.Utils.getTenantId;

public class OrganizationUserRoleManagerImpl implements OrganizationUserRoleManager {
    @Override
    public void addOrganizationUserRoleMappings(String organizationId, UserRoleMapping userRoleMapping) throws OrganizationUserRoleMgtException {
        //Fire pre-event
        fireEvent(PRE_ASSIGN_ORGANIZATION_USER_ROLE, organizationId, null,
                OrganizationUserRoleEventConstants.Status.FAILURE);

        //DAO Object
        OrganizationUserRoleMgtDAO organizationUserRoleMgtDAO = new OrganizationUserRoleMgtDAOImpl();

        //Get and set roleId and hybridRoleId
        String roleId = userRoleMapping.getRoleId();
        int hybridRoleId = getHybridRoleIdFromSCIMGroupId(roleId);
        userRoleMapping.setHybridRoleId(hybridRoleId);

        //Validation of adding role mappings
        validateAddRoleMappingRequest(organizationId, userRoleMapping);

        //Create lists for mandatory and non-mandatory user role mappings considering their propagations.
        List<UserRoleMappingUser> usersGetPermissionsForSubOrgsNonMandatory = new ArrayList<>();
        List<UserRoleMappingUser> usersGetPermissionOnlyToOneOrgNonMandatory = new ArrayList<>();
        List<UserRoleMappingUser> usersGetPermissionForSubOrgsMandatory = new ArrayList<>();

        //Getting the user store manager
        AbstractUserStoreManager userStoreManager;
        try {
            userStoreManager = (AbstractUserStoreManager) getUserStoreManager(getTenantId());
            if (userStoreManager == null) {
                throw handleServerException(ERROR_CODE_USER_STORE_OPERATIONS_ERROR, " for tenant Id: " + getTenantId());
            } else {
                for (UserRoleMappingUser user : userRoleMapping.getUsers()) {
                    boolean userExists = userStoreManager.isExistingUserWithID(user.getUserId());
                    if (!userExists) {
                        throw handleServerException(ADD_ORG_ROLE_USER_REQUEST_INVALID_USER,
                                "No user exists with user Id: " + user.getUserId());
                    }
                    if (user.isMandatoryRole()) {
                        //if it is mandatory then the cascaded property is implied.
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
            organizationUserRoleMgtDAO.addOrganizationUserRoleMappingsWithSp(usersGetPermissionForSubOrgsMandatory, roleId,
                    hybridRoleId, getTenantId(), organizationId);
            organizationUserRoleMgtDAO.addOrganizationUserRoleMappingsWithSp(usersGetPermissionsForSubOrgsNonMandatory, roleId,
                    hybridRoleId, getTenantId(), organizationId);
        } else {
            List<OrganizationUserRoleMapping> organizationUserRoleMappings = new ArrayList<>();
            if (CollectionUtils.isNotEmpty(usersGetPermissionsForSubOrgsNonMandatory)) {
                List<ChildParentAssociation> childParentAssociations = organizationUserRoleMgtDAO.getAllSubOrganizations(organizationId);
                // add starting organization populate role mapping
                organizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(organizationId, roleId, hybridRoleId, organizationId,
                        usersGetPermissionsForSubOrgsNonMandatory));
                /*
                 Assume we have organizations A,B,C,D and A is the immediate parent of B and B is the immediate parent of C and so on.
                 If we assign a non-mandatory role and if it is assigned at A saying include it to the sub organizations.
                 Then we have to copy that role for all the sub organizations and the assigned level is A.
                 Say we are assigning A, a role R1 to propagate then it will go to B and B's assigned level id will be id of A. And when it propagates
                 to C the assigned level id of it will be the id of A.
                 A -> roleId - R1, assignedLevelId - id(A), orgId - id(A), Mandatory - 0
                  \
                   B -> roleId - R1, assignedLevelId - id(A), orgId - id(B), Mandatory - 0
                    \
                     C -> roleId - R1, assignedLevelId - id(A), orgId - id(C), Mandatory - 0
                      \
                       D -> roleId - R1, assignedLevelId - id(A), orgId - id(D), Mandatory - 0
                 */

                for (ChildParentAssociation childParentAssociation : childParentAssociations) {
                    organizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(childParentAssociation.getOrganizationId(), roleId, hybridRoleId,
                            organizationId, usersGetPermissionsForSubOrgsNonMandatory));
                }
            }
            if (CollectionUtils.isNotEmpty(usersGetPermissionForSubOrgsMandatory)) {
                List<ChildParentAssociation> childParentAssociations = organizationUserRoleMgtDAO.getAllSubOrganizations(organizationId);
                // Add starting organization to populate role mapping
                organizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(organizationId, roleId, hybridRoleId, organizationId,
                        usersGetPermissionForSubOrgsMandatory));
                /*
                Assume we have organizations A,B,C,D and A is the immediate parent of B and B is the immediate parent of C and so on.
                If we assign a mandatory role and if it is assigned at A saying include it to the sub organizations.
                Then we have to copy that role for all athe sub organizations, and they only get that from the assignedLevel.
                Say we are assigning A, a role R1 as mandatory role it will be assigned to B and B's assigned level id will be the id of A. And
                the assigned level id of C will be the id of A.
                A -> roleId - R1, assignedLevelId - id(A), orgId - id(A), Mandatory - 1
                 \
                  B -> roleId - R1, assignedLevelId - id(A), orgId - id(B), Mandatory - 1
                   \
                    C -> roleId - R1, assignedLevelId - id(A), orgId - id(C), Mandatory - 1
                     \
                      D -> roleId - R1, assignedLevelId - id(A), orgId - id(D), Mandatory - 1
                */
                for (ChildParentAssociation childParentAssociation : childParentAssociations) {
                    organizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(childParentAssociation.getOrganizationId(), roleId, hybridRoleId,
                            organizationId, usersGetPermissionForSubOrgsMandatory));
                }
            }
            if (CollectionUtils.isNotEmpty(usersGetPermissionOnlyToOneOrgNonMandatory)) {
                /*
                Assume we have organizations A,B,C,D and A is the immediate parent of B and B is the immediate parent of C and so on.
                If we assign a non-mandatory role that we do not need to propagate to the child organizations, the assigned level id will
                be the same as the organization id, and it will stop at that level without further propagating.
                */
                organizationUserRoleMappings
                        .addAll(populateOrganizationUserRoleMappings(organizationId, roleId, hybridRoleId, organizationId,
                                usersGetPermissionOnlyToOneOrgNonMandatory));
            }
            organizationUserRoleMgtDAO
                    .addOrganizationUserRoleMappings(organizationUserRoleMappings, getTenantId());
        }
        // Fire post-event
        OrganizationUserRoleMappingForEvent organizationUserRoleMappingForEvent =
                new OrganizationUserRoleMappingForEvent(organizationId, roleId, userRoleMapping.getUsers().stream()
                        .map(m -> new UserRoleMappingUser(m.getUserId(), m.isMandatoryRole(), m.isCascadedRole()))
                        .collect(Collectors.toList()));
        fireEvent(POST_ASSIGN_ORGANIZATION_USER_ROLE, organizationId, organizationUserRoleMappingForEvent,
                OrganizationUserRoleEventConstants.Status.SUCCESS);
    }

    @Override
    public List<RoleMember> getUsersByOrganizationAndRole(String organizationId, String roleId, int offset, int limit, List<String> requestedAttributes, String filter) throws OrganizationUserRoleMgtException {
        OrganizationUserRoleMgtDAO organizationUserRoleMgtDAO = new OrganizationUserRoleMgtDAOImpl();
        return organizationUserRoleMgtDAO
                .getUserIdsByOrganizationAndRole(organizationId, roleId, offset, limit, requestedAttributes,
                        getTenantId(), filter);
    }

    @Override
    public void patchOrganizationsUserRoleMapping(String organizationId, String roleId, String userId, List<UserRoleOperation> userRoleOperations) throws OrganizationUserRoleMgtException {
        /*
        The patchOrganizationUserRoleMapping can have two userRoleOperations.
        1. mandatory operation
        2. include sub organizations role operation
        For mandatory role operation, if the operation is mandatory, then includeSubOrganizations is implied. If the mandatory is
        given then we have to check the equality of the organizationId and the organization id of the assignedLevel.
        But if only the includeSubOrganization operation is given then, we have to check for non-mandatory organization-user-role
        mapping for sub organizations too.
        */
        if (userRoleOperations.size() > 2) {
            throw handleClientException(PATCH_ORG_ROLE_USER_REQUEST_TOO_MANY_OPERATIONS, null);
        }
        UserRoleOperation[] userRoleOperationsArr = {userRoleOperations.get(0), userRoleOperations.get(1)};
        validatePatchOperation(userRoleOperations);
        OrganizationUserRoleMgtDAO organizationUserRoleMgtDAO = new OrganizationUserRoleMgtDAOImpl();
        int directlyAssignedRoleMappingsInheritance = organizationUserRoleMgtDAO
                .getDirectlyAssignedOrganizationUserRoleMappingInheritance(organizationId, userId, roleId,
                        getTenantId());
        int mandatoryOfAnyOrganizationUserRoleMapping = organizationUserRoleMgtDAO.getMandatoryOfAnyOrganizationUserRoleMapping(organizationId, userId,
                roleId, getTenantId());
        /* Check whether directly assigned role mapping exists and the mandatory value of the role mapping
         if directly assigned role mapping value is -1 and the inheritanceOfAnyOrganizationUserRoleMapping = 1 it means that
         we are going to change a mandatory role, and it is not allowed.
        */
        // If role assigned level == organization id
        if (directlyAssignedRoleMappingsInheritance == -1 && mandatoryOfAnyOrganizationUserRoleMapping == 1) {
            throw handleClientException(PATCH_ORG_ROLE_USER_REQUEST_INVALID_MAPPING, null);
        }
        /*
        Check whether directly assigned role mapping exists. If the organization-user-role operation is
        mandatory, the validity of the patch operation only includes to that.
        directlyAssignedRoleMappingsInheritance should be 1(mandatory = true) or 0(mandatory = false) or
        -1 ( zero directly assigned role mapping).
        If it is 1 then, the patch operation need to check the equality of organizationId and the assignedLevel,
        and it should be mapped to the every user mappings deriving to the sub-organizations.
        If it is 0 then, the patch operation doesn't need to be checked the organizationId equals to  the assignedLevel,
        but if the includeSubOrgs = true we need to check whether there were previous organization-user-role mappings
        and if so we need to update them. But if there weren't any organization-user-role mappings for the sub organizations
        we need to add them.
        */

        /*
        If the directlyAssignedRoleMapping value is equal to the op value of 1 then no change is required.
        If the directlyAssignedRoleMapping value is 1 then includeSubOrganizations condition is automatically fulfilled.
        But if the directlyAssignedRoleMapping value is 0 and there is a need for the inclusion of sub organizations, we will
        do it.
        */

        UserRoleOperation isMandatoryOp = StringUtils.equals("/isMandatory", userRoleOperationsArr[0].getPath()) ? userRoleOperationsArr[0] : userRoleOperationsArr[1];
        UserRoleOperation includeSubOrgsOp = StringUtils.equals("/includeSubOrgs", userRoleOperationsArr[0].getPath()) ? userRoleOperationsArr[0] : userRoleOperationsArr[1];
        /*
        1. Current -> Mandatory & Propagating , Change -> Mandatory & Propagating (No-Change)
        2. Current -> Mandatory & Propagating, Change -> Mandatory & Non-Propagating (Invalid)
        3. Current -> Mandatory & Propagating, Change -> Non-Mandatory & Propagating
        4. Current -> Mandatory & Propagating, Change -> Non-Mandatory & Non-Propagating
        5. Current -> Non-Mandatory & Non-Propagating , Change -> Mandatory & Propagating (Implied)
        6. Current -> Non-Mandatory & Non-Propagating, Change -> Non-Mandatory & Propagating
        7. Current -> Non-Mandatory & Propagating, Change -> Mandatory & Propagating (Implied)
        8. Current -> Non-Mandatory & Propagating, Change -> Mandatory & Non-Propagating (Invalid)
        9. Current -> Non-Mandatory & Non-Propagating, Change -> Non-Mandatory & Non-Propagating (No-Change)
        10. Current -> Non-Mandatory & Propagating, Change -> Non-Mandatory & Propagating (No-Change)
        11. Current -> Non-Mandatory & Propagating, Change -> Non-Mandatory, Non-Propagating
        12. Current -> Non-Mandatory & Non-Propagating, Change -> Mandatory & Non-Propagating (Invalid)
        */
        List<OrganizationUserRoleMapping> addOrganizationUserRoleMappings = new ArrayList<>();
        List<OrganizationUserRoleMapping> updateOrganizationUserRoleMappings = new ArrayList<>();
        List<ChildParentAssociation> childParentAssociations = organizationUserRoleMgtDAO.getAllSubOrganizations(organizationId);
        Map<String, String> organizationListToBeDeleted = new HashMap<>(); //organizationId and assignedAt
        int hybridRoleId = getHybridRoleIdFromSCIMGroupId(roleId);
        /*
        Case 1: Current -> Mandatory & Propagating, Change -> Mandatory & Propagating
        Case 2: Current -> Mandatory & Propagating, Change -> Mandatory & Non-Propagating (invalid case)
        Case 2 is an invalid case and, it has been handled.
        */
        if (directlyAssignedRoleMappingsInheritance == 1 && isMandatoryOp.getValue()) {
            if (includeSubOrgsOp.getValue()) {
                return;
            } else {
                throw handleClientException(PATCH_ORG_ROLE_USER_REQUEST_INVALID_BOOLEAN_VALUE, null);
            }

        /*
        Case 3: Current -> Mandatory & Propagating, Change -> Non-Mandatory & Propagating
        Here, since it was a mandatory role it was already propagating. Here, if we want to just make the role non-mandatory
        we can just change the mandatory property in the user-role mappings after taking the sub-organizations.

        Case 4: Current -> Mandatory & Propagating, Change -> Non-Mandatory & Non-Propagating
        Here, we have to remove the mandatory property from the parent user-role mapping and remove all the user-role mappings in
        the sub organizations.
        */
        } else if (directlyAssignedRoleMappingsInheritance == 1 && !isMandatoryOp.getValue()) {
            if (includeSubOrgsOp.getValue()) { //if includeSubOrgs is true -> Propagating
                //we need to update the parent organization
                updateOrganizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(organizationId, roleId,
                        hybridRoleId, organizationId, Arrays.asList(new UserRoleMappingUser[]{new UserRoleMappingUser(userId, false, true)})));
                for (ChildParentAssociation childParentAssociation : childParentAssociations) {
                    List<UserRoleMappingUser> userRoleMappingUsersList = new ArrayList<>();
                    userRoleMappingUsersList.add(new UserRoleMappingUser(userId, false, true));
                    // we already have organization-user-role mappings, so we need to update them.
                    updateOrganizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(childParentAssociation.getOrganizationId(), roleId,
                            hybridRoleId, organizationId, userRoleMappingUsersList));
                }
            } else {
                for (ChildParentAssociation childParentAssociation : childParentAssociations) {
                    organizationListToBeDeleted.put(childParentAssociation.getOrganizationId(), organizationId);
                }
            }
        /*
        Case 5: Current -> Non-Mandatory & Non-Propagating, Change -> Mandatory & Propagating
        Case 6: Current -> Non-Mandatory & Non-Propagating, Change -> Mandatory & Non-Propagating (invalid case)
        Case 6 is an invalid case, and it has been handled.
        7. Current -> Non-Mandatory & Propagating, Change -> Mandatory & Propagating (implied)
        (Assume we have organizations A,B,C and D. A is the immediate parent of the organization A, B is the immediate parent of
        the organization C and so on. We assign a non-mandatory role for A saying it to propagate. Then A,B,C,D all of them
        will have that role. But after the propagation we delete that non-mandatory role only from B. Then A,C,D will have that role.
        Then we do this operation at A, a new record will be added to B and C,D records will be updated.)
        8. Current -> Non-Mandatory & Propagating, Change -> Mandatory & Non-Propagating (invalid case)
        Case 8 is an invalid case, and it has been handled.
        12. Current -> Non-Mandatory & Non-Propagating, Change -> Mandatory & Non-Propagating (Invalid)
        Case 12 is an invalid case, and it has been handled.
        */
        } else if (directlyAssignedRoleMappingsInheritance == 0 && isMandatoryOp.getValue()) {
            if (!includeSubOrgsOp.getValue()) {
                throw handleClientException(PATCH_ORG_ROLE_USER_REQUEST_INVALID_BOOLEAN_VALUE, null);
            } else {
                // update the parent organization first.
                updateOrganizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(organizationId, roleId,
                        hybridRoleId, organizationId, Arrays.asList(new UserRoleMappingUser[]{new UserRoleMappingUser(userId, true, true)})));
                int n = childParentAssociations.size();
                for (ChildParentAssociation childParentAssociation : childParentAssociations) {
                    List<UserRoleMappingUser> userRoleMappingUsersList = new ArrayList<>();
                    boolean mappingExists = organizationUserRoleMgtDAO.isOrganizationUserRoleMappingExists(childParentAssociation.getOrganizationId(), userId,
                            roleId, organizationId, false, getTenantId());
                    userRoleMappingUsersList.add(new UserRoleMappingUser(userId, true, true));
                    if (mappingExists) {
                        // We have organization-user-role mappings, so we need to update them.
                        updateOrganizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(childParentAssociation.getOrganizationId(), roleId,
                                hybridRoleId, organizationId, userRoleMappingUsersList));
                    } else {
                        // We don't have organization-user-role mappings, so we need to add them.
                        addOrganizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(childParentAssociation.getOrganizationId(), roleId,
                                hybridRoleId, organizationId, userRoleMappingUsersList));
                    }
                }
            }
        /*
        9. Current -> Non-Mandatory & Non-Propagating, Change -> Non-Mandatory & Non-Propagating (No-Change)
        10. Current -> Non-Mandatory & Propagating, Change -> Non-Mandatory & Propagating (No-Change)
        11. Current -> Non-Mandatory & Propagating, Change -> Non-Mandatory, Non-Propagating
        */
        } else if (directlyAssignedRoleMappingsInheritance == 0 && !isMandatoryOp.getValue()) {
            if (!includeSubOrgsOp.getValue()) {
                // update the parent organization first
                updateOrganizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(organizationId, roleId,
                        hybridRoleId, organizationId, Arrays.asList(new UserRoleMappingUser[]{new UserRoleMappingUser(userId, false, true)})));
                for (ChildParentAssociation childParentAssociation : childParentAssociations) {
                    boolean mappingExists = organizationUserRoleMgtDAO.isOrganizationUserRoleMappingExists(childParentAssociation.getOrganizationId(), userId,
                            roleId, organizationId, false, getTenantId());
                    if (mappingExists) {
                        organizationListToBeDeleted.put(childParentAssociation.getOrganizationId(), organizationId);
                    }
                    //else we don't have to do anything.
                }
            } else {
                return;
            }
            //Non Mandatory, Non Propagating -> Non Mandatory, Propagating
            //Non Mandatory, Propagating -> Non Mandatory, Non Propagating
        } else if (directlyAssignedRoleMappingsInheritance == -1 && mandatoryOfAnyOrganizationUserRoleMapping == 0) {
            if (isMandatoryOp.getValue()) {
                //can't patch op a mandatory role at sub-levels.
                throw handleClientException(PATCH_ORG_ROLE_USER_REQUEST_INVALID_BOOLEAN_VALUE, null);
            } else {
                String assignedAt = organizationUserRoleMgtDAO.getAssignedAtOfAnyOrganizationUserRoleMapping(organizationId, userId, roleId, getTenantId());
                if (StringUtils.equals(assignedAt, null)) {
                    throw handleClientException(PATCH_ORG_ROLE_USER_REQUEST_INVALID_MAPPING, null);
                }
                //update the parent organization first
                updateOrganizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(organizationId, roleId,
                        hybridRoleId, assignedAt, Arrays.asList(new UserRoleMappingUser[]{new UserRoleMappingUser(userId, false, true)})));
                if (!includeSubOrgsOp.getValue()) {
                    for (ChildParentAssociation childParentAssociation : childParentAssociations) {
                        boolean mappingExists = organizationUserRoleMgtDAO.isOrganizationUserRoleMappingExists(childParentAssociation.getOrganizationId(), userId,
                                roleId, organizationId, false, getTenantId());
                        if (mappingExists) {
                            organizationListToBeDeleted.put(childParentAssociation.getOrganizationId(),assignedAt);
                        }
                        //else we don't have to do anything
                    }
                } else {
                    for (ChildParentAssociation childParentAssociation : childParentAssociations) {
                        List<UserRoleMappingUser> userRoleMappingUsersList = new ArrayList<>();
                        boolean mappingExists = organizationUserRoleMgtDAO.isOrganizationUserRoleMappingExists(childParentAssociation.getOrganizationId(), userId,
                                roleId, organizationId, false, getTenantId());
                        if (mappingExists) {
                            updateOrganizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(childParentAssociation.getOrganizationId(), roleId,
                                    hybridRoleId, assignedAt, Arrays.asList(new UserRoleMappingUser[]{new UserRoleMappingUser(userId, false, true)})));
                        } else {
                            addOrganizationUserRoleMappings.addAll(populateOrganizationUserRoleMappings(childParentAssociation.getOrganizationId(), roleId,
                                    hybridRoleId, assignedAt, Arrays.asList(new UserRoleMappingUser[]{new UserRoleMappingUser(userId, false, true)})));
                        }
                    }
                }
            }
        }

        organizationUserRoleMgtDAO
                .updateMandatoryProperty(organizationId, userId, roleId, addOrganizationUserRoleMappings,
                        updateOrganizationUserRoleMappings, organizationListToBeDeleted, getTenantId());

    }

    @Override
    public void deleteOrganizationsUserRoleMapping(String organizationId, String userId, String roleId, String assignedLevel,
                                                   boolean mandatory, boolean includeSubOrgs) throws OrganizationUserRoleMgtException {
        //Fire Pre-Event
        fireEvent(PRE_REVOKE_ORGANIZATION_USER_ROLE, organizationId, null, Status.FAILURE);

        //DAO Object
        OrganizationUserRoleMgtDAO organizationUserRoleMgtDAO = new OrganizationUserRoleMgtDAOImpl();
        boolean roleMappingExists = organizationUserRoleMgtDAO.isOrganizationUserRoleMappingExists(organizationId, userId,
                roleId, assignedLevel, mandatory, getTenantId());
        if (!roleMappingExists) {
            throw handleClientException(DELETE_ORG_ROLE_USER_REQUEST_INVALID_MAPPING,
                    String.format("No organization user role mapping found for organization: %s, user: %s, role: %s",
                            organizationId, roleId, userId));
        }
        /*
         Check whether the role mapping is directly assigned to the particular organization or inherited from the
         parent level.
         */
        int directlyAssignedRoleMappingsInheritance = organizationUserRoleMgtDAO
                .getDirectlyAssignedOrganizationUserRoleMappingInheritance(organizationId, userId, roleId,
                        getTenantId());
        int mandatoryOfAnyOrganizationUserRoleMapping = organizationUserRoleMgtDAO.getMandatoryOfAnyOrganizationUserRoleMapping(organizationId, userId,
                roleId, getTenantId());

        if (directlyAssignedRoleMappingsInheritance == -1 && mandatoryOfAnyOrganizationUserRoleMapping==1) {
            throw handleClientException(DELETE_ORG_ROLE_USER_REQUEST_INVALID_DIRECT_MAPPING,
                    String.format("No directly assigned organization user role mapping found for organization: %s, " +
                                    "user: %s, role: %s, directly assigned at organization: %s",
                            organizationId, userId, roleId, organizationId));
        }
        /*
        directlyAssignedRoleMappingsInheritance should be 1(mandatory = true) or 0(mandatory = false) or
        -1 ( zero directly assigned role mapping).
        If returns 0, we need to check whether that should be removed from the sub organizations or not.
        When we are removing that user role mapping from sub organizations, we should check whether the sub organizations
        have their own user mappings with the same roleId. If they exist we should remove them too.
        For example: There are organizations A,B,C,D. A is the immediate parent of organization B, C is the immediate parent of
        the organization C and so on.
        1. Assume we have a non-mandatory role assigned at B including the sub organizations C and D by user U1.
        2. And the same role is again there at B with not including the organizations C and D by user U1.
        3. And the same role is again there at B with including the sub organizations C and D by user U1.
        4. And that same role again at C assigned by user U1.
        Now if we are removing the role from B saying we don't need to include the sub organizations then,
        two user role mappings will be removed (from B). And the user role mappings for C and D sub-organizations will not be
        removed.
        If we are removing a user role mapping saying we need to remove the user role mappings from sub organizations too, then,
        the role mappings at points 1,2,3,4 all will be removed.
        If the user of those points are not the same user, they will not be removed on above-mentioned notes.
        Therefore, to remove user-role-organization mappings we need to confirm the validity of userId, roleId, and organizationIds.
         */
        Map<String, String> organizationListToBeDeleted = new HashMap<>();
        if (directlyAssignedRoleMappingsInheritance == 1) {
            // Mandatory roles can only be removed from their assigned levels. And since directlyAssignedRoleMappingsInheritance checks
            // with the assignedLevel (an org. id) = organizationId, we are simply removing a mandatory role from the organization hierarchy.
            // Then all the organization-user-role mappings of that mandatory role should be removed.

            // All ids of the sub organizations and the assigned level are added to the organizationListToBeDeleted
            List<ChildParentAssociation> subOrganizations = organizationUserRoleMgtDAO.getAllSubOrganizations(organizationId);
            for (ChildParentAssociation subOrganization:subOrganizations) {
                organizationListToBeDeleted.put(subOrganization.getOrganizationId(), assignedLevel);
            }
            // Add the organization to be deleted
            organizationListToBeDeleted.put(organizationId, assignedLevel);
            organizationUserRoleMgtDAO.deleteOrganizationsUserRoleMapping(organizationListToBeDeleted,
                    userId, roleId, getTenantId());
        } else if(directlyAssignedRoleMappingsInheritance == 0) {
            if (includeSubOrgs) {
                List<ChildParentAssociation> subOrganizations = organizationUserRoleMgtDAO.getAllSubOrganizations(organizationId);
                for (ChildParentAssociation subOrganization:subOrganizations) {
                    organizationListToBeDeleted.put(subOrganization.getOrganizationId(), assignedLevel);
                }
            }
            organizationListToBeDeleted.put(organizationId,assignedLevel);
            organizationUserRoleMgtDAO.deleteOrganizationsUserRoleMapping( organizationListToBeDeleted,
                    userId, roleId, getTenantId());
        } else if(directlyAssignedRoleMappingsInheritance==-1 && mandatoryOfAnyOrganizationUserRoleMapping==0){
            if(includeSubOrgs){
                List<ChildParentAssociation> subOrganizations = organizationUserRoleMgtDAO.getAllSubOrganizations(organizationId);
                for (ChildParentAssociation subOrganization:
                     subOrganizations) {
                    String assignedAt = organizationUserRoleMgtDAO.getAssignedAtOfAnyOrganizationUserRoleMapping(subOrganization.getOrganizationId(),
                            userId, roleId, getTenantId());
                    if(StringUtils.equals(assignedAt, null)){
                        throw handleClientException(DELETE_ORG_ROLE_USER_REQUEST_INVALID_MAPPING, null);
                    }
                    organizationListToBeDeleted.put(subOrganization.getOrganizationId(), assignedAt);
                }
            }
            String assignedAt = organizationUserRoleMgtDAO.getAssignedAtOfAnyOrganizationUserRoleMapping(organizationId, userId, roleId, getTenantId());
            if(StringUtils.equals(assignedAt, null)){
                throw handleClientException(DELETE_ORG_ROLE_USER_REQUEST_INVALID_DIRECT_MAPPING, null);
            }
            organizationListToBeDeleted.put(organizationId, assignedAt);
            organizationUserRoleMgtDAO.deleteOrganizationsUserRoleMapping(organizationListToBeDeleted,
                    userId, roleId, getTenantId());
        }
        // Fire post-event.
        OrganizationUserRoleMappingForEvent organizationUserRoleMappingForEvent =
                new OrganizationUserRoleMappingForEvent(organizationId, roleId, userId);
        fireEvent(POST_REVOKE_ORGANIZATION_USER_ROLE, organizationId, organizationUserRoleMappingForEvent,
                OrganizationUserRoleEventConstants.Status.SUCCESS);

    }

    @Override
    public void deleteOrganizationsUserRoleMappings(String userId) throws OrganizationUserRoleMgtException {
        OrganizationUserRoleMgtDAO organizationUserRoleMgtDAO = new OrganizationUserRoleMgtDAOImpl();
        organizationUserRoleMgtDAO.deleteOrganizationsUserRoleMappings(userId, getTenantId());
    }

    @Override
    public List<Role> getRolesByOrganizationAndUser(String organizationId, String userId) throws OrganizationUserRoleMgtException {
        OrganizationUserRoleMgtDAO organizationUserRoleMgtDAO = new OrganizationUserRoleMgtDAOImpl();
        return organizationUserRoleMgtDAO.getRolesByOrganizationAndUser(organizationId, userId, getTenantId());
    }

    @Override
    public boolean isOrganizationUserRoleMappingExists(String organizationId, String userId, String roleId, String assignedLevel, boolean mandatory) throws OrganizationUserRoleMgtException {
        OrganizationUserRoleMgtDAO organizationUserRoleMgtDAO = new OrganizationUserRoleMgtDAOImpl();
        return organizationUserRoleMgtDAO
                .isOrganizationUserRoleMappingExists(organizationId, userId, roleId, assignedLevel, mandatory, getTenantId());
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



    private String getAuthenticatedUserId() throws OrganizationUserRoleMgtServerException {
        return getUserIdFromUserName(getAuthenticatedUsername(), getTenantId());
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
                                                                                   String assignedAt, List<UserRoleMappingUser> usersList) {
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

    private void validatePatchOperation(List<UserRoleOperation> userRoleOperations) throws OrganizationUserRoleMgtException {
        // Validate op.
        for (UserRoleOperation userRoleOperation :
                userRoleOperations) {
            if (StringUtils.isBlank(userRoleOperation.getOp())) {
                throw handleClientException(PATCH_ORG_ROLE_USER_REQUEST_OPERATION_UNDEFINED, null);
            }
            String op = userRoleOperation.getOp().trim().toLowerCase(Locale.ENGLISH);
            if (!PATCH_OP_REPLACE.equals(op)) {
                throw handleClientException(PATCH_ORG_ROLE_USER_REQUEST_INVALID_OPERATION, null);
            }

            // Validate path.
            if (StringUtils.isBlank(userRoleOperation.getPath())) {
                throw handleClientException(PATCH_ORG_ROLE_USER_REQUEST_PATH_UNDEFINED, null);
            }
            //In the path, if there is not includeSubOrgs or isMandatory property throw an error
            if (!(StringUtils.equals("/includeSubOrgs", userRoleOperation.getPath()) || StringUtils.equals("/isMandatory", userRoleOperation.getPath()))
            ) {
                throw handleClientException(PATCH_ORG_ROLE_USER_REQUEST_INVALID_PATH, null);
            }

            // Validate value.
            if (!userRoleOperation.getValue() || userRoleOperation.getValue()) {
                return;
            }
        }

        throw handleClientException(PATCH_ORG_ROLE_USER_REQUEST_INVALID_VALUE, null);
    }
}
