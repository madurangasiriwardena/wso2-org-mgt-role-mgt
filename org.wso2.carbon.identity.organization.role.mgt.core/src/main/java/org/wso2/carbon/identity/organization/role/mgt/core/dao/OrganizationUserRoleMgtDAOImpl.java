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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.poi.poifs.property.Child;
import org.wso2.carbon.identity.organization.role.mgt.core.constants.DatabaseConstants;
import org.wso2.carbon.identity.organization.role.mgt.core.constants.OrganizationUserRoleMgtConstants;
import org.wso2.carbon.identity.organization.role.mgt.core.exception.OrganizationUserRoleMgtException;
import org.wso2.carbon.identity.organization.role.mgt.core.exception.OrganizationUserRoleMgtServerException;
import org.wso2.carbon.identity.organization.role.mgt.core.models.*;
import org.wso2.carbon.identity.organization.role.mgt.core.util.Utils;
import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.database.utils.jdbc.JdbcTemplate;

import org.wso2.carbon.database.utils.jdbc.exceptions.DataAccessException;
import org.wso2.carbon.database.utils.jdbc.exceptions.TransactionException;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.scim2.common.impl.IdentitySCIMManager;
import org.wso2.charon3.core.exceptions.CharonException;
import org.wso2.charon3.core.extensions.UserManager;
import org.wso2.charon3.core.protocol.SCIMResponse;
import org.wso2.charon3.core.protocol.endpoints.UserResourceManager;

import java.io.IOException;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.*;
import java.util.stream.Collectors;

import static org.wso2.carbon.identity.organization.role.mgt.core.constants.OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_GET_CHILDREN_ERROR;
import static org.wso2.carbon.identity.organization.role.mgt.core.util.Utils.handleServerException;

public class OrganizationUserRoleMgtDAOImpl implements OrganizationUserRoleMgtDAO {
    private static final Log LOG = LogFactory.getLog(OrganizationUserRoleMgtDAOImpl.class);

    //TODO: ADD NamedJdbcTemplate and NamedPreparedStatement? = Use it
    //TODO : https://medium.com/@jayanga/named-prepared-statements-in-c5-user-core-ac91c5828d37

    @Override
    public void addOrganizationUserRoleMappings(List<OrganizationUserRoleMapping> organizationUserRoleMappings,
                                                int tenantID)
            throws OrganizationUserRoleMgtException {
        JdbcTemplate jdbcTemplate = Utils.getNewJdbcTemplate();
        try {
            jdbcTemplate.withTransaction(template -> {
                template.executeBatchInsert(queryForMultipleInserts(organizationUserRoleMappings.size()), preparedStatement -> {
                    int parameterIndex = 0;
                    for (OrganizationUserRoleMapping organizationUserRoleMapping : organizationUserRoleMappings) {
                        preparedStatement.setString(++parameterIndex, Utils.generateUniqueID()); //Unique ID // 1
                        preparedStatement.setString(++parameterIndex, organizationUserRoleMapping.getUserId()); // 2
                        preparedStatement.setString(++parameterIndex, organizationUserRoleMapping.getRoleId()); // 3
                        preparedStatement.setInt(++parameterIndex, organizationUserRoleMapping.getHybridRoleId()); // 4
                        preparedStatement.setInt(++parameterIndex, tenantID); // 5
                        preparedStatement.setString(++parameterIndex, organizationUserRoleMapping.getOrganizationId()); // 6
                        preparedStatement.setString(++parameterIndex, organizationUserRoleMapping.getAssignedLevelOrganizationId()); // 7
                        preparedStatement.setInt(++parameterIndex, organizationUserRoleMapping.isMandatory() ? 1 : 0); // 8
                    }
                }, organizationUserRoleMappings);
                return null;
            });
        } catch (TransactionException e) {
            throw handleServerException(OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_ADD_ERROR, "", e);
        }
    }

    //TODO: Better check this with OrganiztionUserRoleManagerImpl addOrganizationUserRoleMapping()
    @Override
    public void addOrganizationUserRoleMappingsWithSp(List<UserRoleMappingUser> userList, String roleId,
                                                      int hybridRoleId, int tenantID, String assignedAt)
            throws OrganizationUserRoleMgtException {
        try (Connection connection = IdentityDatabaseUtil.getUserDBConnection()) {
            connection.setAutoCommit(false);
            try (CallableStatement callableStatement = connection.prepareCall(
                    DatabaseConstants.H2Constants.INSERT_INTO_ORGANIZATION_USER_ROLE_MAPPING_USING_SP)) {
                for (UserRoleMappingUser user : userList) {
                    callableStatement.setString(1, user.getUserId());
                    callableStatement.setString(2, roleId);
                    callableStatement.setInt(3, hybridRoleId);
                    callableStatement.setInt(4, tenantID);
                    callableStatement.setString(5, assignedAt);
                    callableStatement.setInt(6, user.isMandatoryRole() ? 1 : 0);

                    callableStatement.addBatch();
                }
                //execute batch
                callableStatement.executeBatch();
                connection.commit();
            } catch (SQLException e) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Error occurred while executing the batch insert: ", e);
                }
                connection.rollback();
                throw handleServerException(OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_ADD_ERROR, "", e);
            }
        } catch (Exception e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Error occurred while executing the batch insert: ", e);
            }
            throw handleServerException(OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_ADD_ERROR, "", e);
        }

    }

    @Override
    public List<RoleMember> getUserIdsByOrganizationAndRole(String organizationId, String roleId, int offset, int limit,
                                                            List<String> requestedAttributes, int tenantID, String filter)
            throws OrganizationUserRoleMgtServerException {
        boolean paginationReq = offset > -1 || limit > 0;
        JdbcTemplate jdbcTemplate = Utils.getNewJdbcTemplate();
        List<OrganizationUserRoleMapping> organizationUserRoleMappings;
        Map<String, List<RoleAssignment>> userRoleAssignments = new HashMap<>();
        List<RoleMember> roleMembers = new ArrayList<>();

        try {
            organizationUserRoleMappings = jdbcTemplate.executeQuery(DatabaseConstants.H2Constants.GET_USERS_BY_ORG_AND_ROLE,
                    (resultSet, rowNumber) ->
                            new OrganizationUserRoleMapping(organizationId,
                                    resultSet.getString(DatabaseConstants.H2Constants.VIEW_USER_ID_COLUMN), roleId,
                                    resultSet.getString(DatabaseConstants.H2Constants.VIEW_ASSIGNED_AT_COLUMN),
                                    resultSet.getString(DatabaseConstants.H2Constants.VIEW_ASSIGNED_AT_NAME_COLUMN),
                                    resultSet.getInt(DatabaseConstants.H2Constants.VIEW_MANDATORY_COLUMN) == 1),
                    preparedStatement -> {
                        int parameterIndex = 0;
                        preparedStatement.setString(++parameterIndex, organizationId);
                        preparedStatement.setString(++parameterIndex, roleId);
                        preparedStatement.setInt(++parameterIndex, tenantID);
                    });

            organizationUserRoleMappings.stream().map(organizationUserRoleMapping -> userRoleAssignments
                            .computeIfAbsent(organizationUserRoleMapping.getUserId(), k -> new ArrayList<>())
                            .add(new RoleAssignment(organizationUserRoleMapping.isMandatory(),
                                    new RoleAssignedLevel(organizationUserRoleMapping.getAssignedLevelOrganizationId(),
                                            organizationUserRoleMapping.getAssignedLevelOrganizationName()))))
                    .collect(Collectors.toList());

            for (Map.Entry<String, List<RoleAssignment>> entry : userRoleAssignments.entrySet()) {

                String userId = entry.getKey();
                // Obtain the user store manager.
                UserManager userManager = IdentitySCIMManager.getInstance().getUserManager();
                // Create an endpoint and hand-over the request.
                UserResourceManager userResourceManager = new UserResourceManager();
                // Modify the given filter by adding the user ID.
                String modifiedFilter;
                if (StringUtils.isNotEmpty(filter)) {
                    modifiedFilter = filter + " and id eq " + userId;
                } else {
                    modifiedFilter = "id eq " + userId;
                }

                SCIMResponse scimResponse = userResourceManager.listWithGET(userManager, modifiedFilter,
                        1, 1, null, null, null,
                        requestedAttributes.stream().collect(Collectors.joining(",")), null);

                // Decode the received response.
                Map<String, Object> attributes;
                ObjectMapper mapper = new ObjectMapper();
                attributes =
                        mapper.readValue(scimResponse.getResponseMessage(), new TypeReference<Map<String, Object>>() {
                        });
                if (attributes.containsKey("totalResults") && ((Integer) attributes.get("totalResults")) > 0 &&
                        attributes.containsKey("Resources") && ((ArrayList) attributes.get("Resources")).size() > 0) {
                    Map<String, Object> userAttributes =
                            (Map<String, Object>) ((ArrayList) attributes.get("Resources")).get(0);
                    userAttributes.put("assignedMeta", entry.getValue());
                    RoleMember roleMember = new RoleMember(userAttributes);
                    roleMembers.add(roleMember);
                }
            }
            // Sort role member list.
            Collections.sort(roleMembers, (m1, m2) -> ((String) m1.getUserAttributes().get("userName")).compareTo(
                    String.valueOf(m2.getUserAttributes().get("userName"))));

            if (paginationReq && CollectionUtils.isNotEmpty(roleMembers)) {
                return roleMembers.subList(offset < 0 ? 0 : offset, Math.min(offset + limit, roleMembers.size()));
            }
        } catch (CharonException | IOException | DataAccessException e) {
            String message = String.format(String.valueOf(OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_USERS_PER_ORG_ROLE_RETRIEVING_ERROR), roleId,
                    organizationId);
            throw new OrganizationUserRoleMgtServerException(message,
                    OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_USERS_PER_ORG_ROLE_RETRIEVING_ERROR.getCode(), e);
            //TODO: Changing exception pipeline to trace errors one by one.
        }
        return roleMembers;
    }


    // TODO: Recursive?
    @Override
    public void deleteOrganizationsUserRoleMapping(String deleteInvokedOrgId, List<ChildParentAssociation> childParentAssociations,
                                                   String userId, String roleId, int tenantId, boolean isMandatory)
            throws OrganizationUserRoleMgtException {
        JdbcTemplate jdbcTemplate = Utils.getNewJdbcTemplate();
        try {
            jdbcTemplate.withTransaction(template -> {
                if (isMandatory) {
                    template.executeUpdate(queryForMultipleRoleMappingDeletion(childParentAssociations.size()),
                            preparedStatement -> {
                                int parameterIndex = 0;
                                preparedStatement.setString(++parameterIndex, userId);
                                preparedStatement.setString(++parameterIndex, roleId);
                                preparedStatement.setInt(++parameterIndex, tenantId);
                                preparedStatement.setString(++parameterIndex, deleteInvokedOrgId);
                                for (ChildParentAssociation childParentAssociation : childParentAssociations) {
                                    preparedStatement.setString(++parameterIndex, childParentAssociation.getOrganizationId());
                                }
                            });
                } else {
                    for (ChildParentAssociation childParentAssociation : childParentAssociations) {
                        template.executeUpdate(DatabaseConstants.H2Constants.DELETE_ORGANIZATION_USER_ROLE_MAPPINGS_ASSIGNED_AT_ORG_LEVEL_NON_MANDATORY,
                                preparedStatement -> {
                                    int parameterIndex = 0;
                                    preparedStatement.setString(++parameterIndex, userId);
                                    preparedStatement.setString(++parameterIndex, roleId);
                                    preparedStatement.setInt(++parameterIndex, tenantId);
                                    preparedStatement.setString(++parameterIndex, childParentAssociation.getParentOrgId());
                                    preparedStatement.setString(++parameterIndex, childParentAssociation.getOrganizationId());
                                }
                        );
                    }
                }
                return null;
            });
        } catch (TransactionException e) {
            throw new OrganizationUserRoleMgtServerException(String.format(
                    OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_DELETE_ERROR.getMessage(), roleId, userId),
                    OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_DELETE_ERROR.getCode(), e);
        }
    }

    @Override
    public void deleteOrganizationsUserRoleMappings(String userId, int tenantId) throws OrganizationUserRoleMgtException {
        JdbcTemplate jdbcTemplate = Utils.getNewJdbcTemplate();
        try {
            jdbcTemplate.withTransaction(template -> {
                template.executeUpdate(DatabaseConstants.H2Constants.DELETE_ALL_ORGANIZATION_USER_ROLE_MAPPINGS_BY_USERID,
                        preparedStatement -> {
                            int parameterIndex = 0;
                            preparedStatement.setString(++parameterIndex, userId);
                            preparedStatement.setInt(++parameterIndex, tenantId);
                        });
                return null;
            });
        } catch (TransactionException e) {
            throw new OrganizationUserRoleMgtServerException(
                    String.format(OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_DELETE_PER_USER_ERROR.getMessage(), userId),
                    OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_DELETE_PER_USER_ERROR.getCode(), e);
        }
    }

    @Override
    public List<Role> getRolesByOrganizationAndUser(String organizationId, String userId, int tenantID)
            throws OrganizationUserRoleMgtServerException {
        JdbcTemplate jdbcTemplate = Utils.getNewJdbcTemplate();
        List<Role> roles;
        try {
            roles = jdbcTemplate.executeQuery(DatabaseConstants.H2Constants.GET_ROLES_BY_ORG_AND_USER,
                    (resultSet, rowNumber) -> new Role(resultSet.getString(DatabaseConstants.H2Constants.VIEW_ROLE_ID_COLUMN),
                            "Internal/" + resultSet.getString(DatabaseConstants.H2Constants.VIEW_ROLE_NAME_COLUMN)),
                    preparedStatement -> {
                        int parameterIndex = 0;
                        preparedStatement.setString(++parameterIndex, organizationId);
                        preparedStatement.setString(++parameterIndex, userId);
                        preparedStatement.setInt(++parameterIndex, tenantID);
                    });
        } catch (DataAccessException e) {
            String message =
                    String.format(String.valueOf(OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_ROLES_PER_ORG_USER_RETRIEVING_ERROR.getMessage()), userId,
                            organizationId);
            throw new OrganizationUserRoleMgtServerException(message,
                    OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_ROLES_PER_ORG_USER_RETRIEVING_ERROR.getCode(), e);
        }
        return roles;
    }

    @Override
    //TODO: Need to change accrodingly
    public void updateMandatoryProperty(String organizationId, String userId, String roleId, List<OrganizationUserRoleMapping> organizationUserRoleMappingsToAdd,
                                        List<OrganizationUserRoleMapping> organizationUserRoleMappingsToUpdate,
                                        List<String> childOrganizationIdsToDeleteRecords, int tenantId)
            throws OrganizationUserRoleMgtServerException {
        JdbcTemplate jdbcTemplate = Utils.getNewJdbcTemplate();
        try {
            jdbcTemplate.withTransaction(template -> {
                /*
                 We are getting the organization-user-role mappings accordingly for all the scenarios mentioned in @{OrganizationUserRoleManagerImpl}
                 Therefore, we only need to add the user role mappings, delete the user role mappings and update the user role mappings accordingly.
                 */
                // add organization-user-role mappings
                if (CollectionUtils.isNotEmpty(organizationUserRoleMappingsToAdd)) {
                    template.executeInsert(queryForMultipleInserts(organizationUserRoleMappingsToAdd.size()),
                            preparedStatement -> {
                                int parameterIndex = 0;
                                for (OrganizationUserRoleMapping organizationUserRoleMapping
                                        : organizationUserRoleMappingsToAdd) {
                                    preparedStatement.setString(++parameterIndex, Utils.generateUniqueID());
                                    preparedStatement
                                            .setString(++parameterIndex, organizationUserRoleMapping.getUserId());
                                    preparedStatement
                                            .setString(++parameterIndex, organizationUserRoleMapping.getRoleId());
                                    preparedStatement
                                            .setInt(++parameterIndex, organizationUserRoleMapping.getHybridRoleId());
                                    preparedStatement.setInt(++parameterIndex, tenantId);
                                    preparedStatement
                                            .setString(++parameterIndex,
                                                    organizationUserRoleMapping.getOrganizationId());
                                    preparedStatement.setString(++parameterIndex,
                                            organizationUserRoleMapping.getAssignedLevelOrganizationId());
                                    preparedStatement
                                            .setInt(++parameterIndex,
                                                    organizationUserRoleMapping.isMandatory() ? 1 : 0);
                                }
                            }, organizationUserRoleMappingsToAdd, false);
                }
                if (CollectionUtils.isNotEmpty(childOrganizationIdsToDeleteRecords)) {
                    template.executeUpdate(
                            queryForMultipleRoleMappingDeletion(childOrganizationIdsToDeleteRecords.size()),
                            preparedStatement -> {
                                int parameterIndex = 0;
                                preparedStatement.setString(++parameterIndex, userId);
                                preparedStatement.setString(++parameterIndex, roleId);
                                preparedStatement.setInt(++parameterIndex, tenantId);
                                preparedStatement.setString(++parameterIndex, organizationId);
                                for (String childOrgId : childOrganizationIdsToDeleteRecords) {
                                    preparedStatement.setString(++parameterIndex, childOrgId);
                                }
                            });
                }
                if (CollectionUtils.isNotEmpty(organizationUserRoleMappingsToUpdate)) {
                    template.executeUpdate(DatabaseConstants.H2Constants.UPDATE_ORGANIZATION_USER_ROLE_MAPPING_INHERIT_PROPERTY,preparedStatement -> {

                        for (OrganizationUserRoleMapping organizationUserRoleMapping: organizationUserRoleMappingsToUpdate) {
                            int parameterIndex=0;
                            //TODO: Fix this
                            preparedStatement.setInt(++parameterIndex, 1);
                            preparedStatement.setString(++parameterIndex, userId);
                            preparedStatement.setString(++parameterIndex, roleId);
                            preparedStatement.setString(++parameterIndex, organizationId);
                            preparedStatement.setString(++parameterIndex, organizationId);
                            preparedStatement.setInt(++parameterIndex, tenantId);
                        }
                    });
                }
                /*template.executeUpdate(DatabaseConstants.H2Constants.UPDATE_ORGANIZATION_USER_ROLE_MAPPING_INHERIT_PROPERTY, preparedStatement -> {
                    int parameterIndex = 0;
                    preparedStatement.setInt(++parameterIndex, mandatory ? 1 : 0);
                    preparedStatement.setString(++parameterIndex, userId);
                    preparedStatement.setString(++parameterIndex, roleId);
                    preparedStatement.setString(++parameterIndex, organizationID);
                    preparedStatement.setString(++parameterIndex, organizationID);
                    preparedStatement.setInt(++parameterIndex, tenantId);
                });*/

                return null;
            });
        } catch (TransactionException e) {
            String message =
                    String.format(String.valueOf(OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_UPDATE_ERROR),
                            organizationId, userId, roleId);
            throw new OrganizationUserRoleMgtServerException(message,
                    OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_UPDATE_ERROR.getCode(), e);
        }
    }

    //TODO: Check this
    @Override
    public boolean isOrganizationUserRoleMappingExists(String organizationId, String userId, String roleId, String assignedLevel,
                                                       boolean mandatory, int tenantId) throws OrganizationUserRoleMgtException {
        JdbcTemplate jdbcTemplate = Utils.getNewJdbcTemplate();
        int mappingsCount = 0;
        try {
            mappingsCount = jdbcTemplate
                    .fetchSingleRecord(buildIsRoleMappingExistsQuery(assignedLevel, mandatory),
                            (resultSet, rowNumber) ->
                                    resultSet.getInt(DatabaseConstants.H2Constants.COUNT_COLUMN_NAME),
                            preparedStatement -> {
                                int parameterIndex = 0;
                                preparedStatement.setString(++parameterIndex, userId);
                                preparedStatement.setString(++parameterIndex, roleId);
                                preparedStatement.setInt(++parameterIndex, tenantId);
                                preparedStatement.setString(++parameterIndex, organizationId);
                                preparedStatement.setString(++parameterIndex, assignedLevel);
                                preparedStatement.setInt(++parameterIndex, mandatory ? 1 : 0);
                            });
        } catch (DataAccessException e) {
            String message =
                    String.format(String.valueOf(OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_RETRIEVING_ERROR), roleId,
                            userId, organizationId);
            throw new OrganizationUserRoleMgtServerException(message,
                    OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_RETRIEVING_ERROR.getCode(), e);
        }
        return mappingsCount > 0;
    }

    @Override
    public int getDirectlyAssignedOrganizationUserRoleMappingInheritance(String organizationId, String userId, String roleId, int tenantId) throws OrganizationUserRoleMgtException {
        // Since this method is to get directly assigned organization-user-role mapping, assignedLevel(an org. id) = @param{organizationId}
        JdbcTemplate jdbcTemplate = Utils.getNewJdbcTemplate();
        int directlyAssignedRoleMappingInheritance = -1;
        try {
            boolean mappingExists = jdbcTemplate
                    .fetchSingleRecord(buildIsRoleMappingExistsQuery(organizationId, false),
                            // We are not checking whether the role is mandatory or not. We want to get a user role mapping on
                            // params organizationId, userId, roleId, tenantId and assignedLevel
                            (resultSet, rowNumber) ->
                                    resultSet.getInt(DatabaseConstants.H2Constants.COUNT_COLUMN_NAME) == 1,
                            preparedStatement -> {
                                int parameterIndex = 0;
                                preparedStatement.setString(++parameterIndex, userId);
                                preparedStatement.setString(++parameterIndex, roleId);
                                preparedStatement.setInt(++parameterIndex, tenantId);
                                preparedStatement.setString(++parameterIndex, organizationId);
                                preparedStatement.setString(++parameterIndex, organizationId);
                            });
            if (!mappingExists) {
                return directlyAssignedRoleMappingInheritance;
            }
            directlyAssignedRoleMappingInheritance =
                    jdbcTemplate.fetchSingleRecord(DatabaseConstants.H2Constants.GET_DIRECTLY_ASSIGNED_ORGANIZATION_USER_ROLE_MAPPING_LINK,
                            (resultSet, rowNumber) -> resultSet.getInt(DatabaseConstants.H2Constants.VIEW_MANDATORY_COLUMN),
                            preparedStatement -> {
                                int parameterIndex = 0;
                                preparedStatement.setString(++parameterIndex, userId);
                                preparedStatement.setString(++parameterIndex, roleId);
                                preparedStatement.setInt(++parameterIndex, tenantId);
                                preparedStatement.setString(++parameterIndex, organizationId);
                                preparedStatement.setString(++parameterIndex, organizationId);
                            });
        } catch (DataAccessException e) {
            String message =
                    String.format(String.valueOf(OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_RETRIEVING_ERROR), roleId,
                            userId, organizationId);
            throw new OrganizationUserRoleMgtServerException(message,
                    OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_RETRIEVING_ERROR.getCode(), e);
        }
        return directlyAssignedRoleMappingInheritance;
    }

    @Override
    public Integer getRoleIdBySCIMGroupName(String roleName, int tenantId) throws OrganizationUserRoleMgtServerException {
        JdbcTemplate jdbcTemplate = Utils.getNewJdbcTemplate();
        try {
            return jdbcTemplate.fetchSingleRecord(DatabaseConstants.H2Constants.GET_ROLE_ID_BY_SCIM_GROUP_NAME,
                    (resultSet, rowNumber) ->
                            resultSet.getInt(DatabaseConstants.H2Constants.VIEW_ID_COLUMN),
                    preparedStatement -> {
                        int parameterIndex = 0;
                        preparedStatement.setString(++parameterIndex, roleName);
                        preparedStatement.setInt(++parameterIndex, tenantId);
                    });
        } catch (DataAccessException e) {
            throw handleServerException(OrganizationUserRoleMgtConstants.ErrorMessages.ERROR_CODE_HYBRID_ROLE_ID_RETRIEVING_ERROR, roleName);
        }
    }

    @Override
    public List<ChildParentAssociation> getAllSubOrganizations(String organizationId) throws OrganizationUserRoleMgtException {
        JdbcTemplate jdbcTemplate = Utils.getNewJdbcTemplate();

        try {
            List<ChildParentAssociation> childParentAssociations = jdbcTemplate.executeQuery(DatabaseConstants.H2Constants.FIND_ALL_CHILD_ORG_IDS,
                    (resultSet, rowNumber) ->
                            new ChildParentAssociation(resultSet.getString(DatabaseConstants.H2Constants.VIEW_ID_COLUMN),
                                    resultSet.getString(DatabaseConstants.H2Constants.VIEW_PARENT_ID_COLUMN)),
                    preparedStatement -> preparedStatement.setString(1, organizationId));
            return childParentAssociations;
        } catch (DataAccessException e) {
            throw handleServerException(ERROR_CODE_ORGANIZATION_GET_CHILDREN_ERROR, "Organization Id " + organizationId,
                    e);
        }
    }

    private String queryForMultipleInserts(Integer numberOfMapings) {
        StringBuilder sb = new StringBuilder();
        sb.append(DatabaseConstants.H2Constants.INSERT_ALL);

        for (int i = 0; i < numberOfMapings; i++) {
            sb.append(DatabaseConstants.H2Constants.INSERT_INTO_ORGANIZATION_USER_ROLE_MAPPING);
        }
        sb.append(DatabaseConstants.H2Constants.SELECT_DUMMY_RECORD);
        return sb.toString();
    }

    private String queryForMultipleRoleMappingDeletion(int numberOfOrganizations) {
        StringBuilder sb = new StringBuilder();
        sb.append(DatabaseConstants.H2Constants.DELETE_ORGANIZATION_USER_ROLE_MAPPINGS_ASSIGNED_AT_ORG_LEVEL);
        sb.append(DatabaseConstants.H2Constants.AND).append("(");
        for (int i = 0; i < numberOfOrganizations; i++) {
            sb.append(DatabaseConstants.H2Constants.ORG_ID_ADDING);
            if (i != numberOfOrganizations - 1) {
                sb.append(DatabaseConstants.H2Constants.OR);
            }
        }
        sb.append(")");
        return sb.toString();
    }

    private String buildIsRoleMappingExistsQuery(String assignedLevel, boolean checkMandatory) {

        StringBuilder sb = new StringBuilder();
        sb.append(DatabaseConstants.H2Constants.GET_ORGANIZATION_USER_ROLE_MAPPING);
        if (StringUtils.isNotEmpty(assignedLevel)) {
            sb.append(DatabaseConstants.H2Constants.AND).append(DatabaseConstants.H2Constants.ASSIGNED_AT_ADDING);
        }
        if (checkMandatory) {
            sb.append(DatabaseConstants.H2Constants.AND).append(DatabaseConstants.H2Constants.MANDATORY_ADDING);
        }
        return sb.toString();
    }
}
