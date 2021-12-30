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

package org.wso2.carbon.identity.organization.role.mgt.core.constants;

public class DatabaseConstants {

    public class H2Constants {
        //TODO: static finals
        public static final String COUNT_COLUMN_NAME = "COUNT(1)";
        public static final String INSERT_ALL = "INSERT ALL";
        public static final String VIEW_ID_COLUMN = "UM_ID";
        public static final String VIEW_PARENT_ID_COLUMN = "UM_PARENT_ID";
        public static final String VIEW_USER_ID_COLUMN = "UM_USER_ID";
        public static final String VIEW_ROLE_ID_COLUMN = "UM_ROLE_ID";
        public static final String VIEW_ROLE_NAME_COLUMN = "UM_ROLE_NAME";
        public static final String VIEW_MANDATORY_COLUMN = "MANDATORY";
        public static final String VIEW_ASSIGNED_AT_COLUMN = "ASSIGNED_AT";
        public static final String VIEW_ASSIGNED_AT_NAME_COLUMN = "NAME";
        public static final String ORG_ID_ADDING = "ORG_ID = ?";
        public static final String ASSIGNED_AT_ADDING = "ASSIGNED_AT = ?";
        public static final String MANDATORY_ADDING = "MANDATORY = ?";
        public static final String AND = " AND ";
        public static final String OR = " OR ";
        public static final String INSERT_INTO_ORGANIZATION_USER_ROLE_MAPPING = " INTO UM_USER_ROLE_ORG (UM_ID, UM_USER_ID, UM_ROLE_ID," +
                "UM_HYBRID_ROLE_ID, UM_TENANT_ID, ORG_ID, ASSIGNED_AT, MANDATORY) VALUES ( ?, ?, ?, ?, ?, ?, ?, ?) ";
        public static final String INSERT_INTO_ORGANIZATION_USER_ROLE_MAPPING_USING_SP = "{call add_org_user_role_mapping(?,?,?,?,?,?)}";
        public static final String SELECT_DUMMY_RECORD = "SELECT 1 FROM DUAL";
        public static final String GET_USERS_BY_ORG_AND_ROLE = "SELECT URO.UM_USER_ID, URO.MANDATORY,  URO.ASSIGNED_AT," +
                "UO.UM_ORG_NAME FROM UM_USER_ROLE_ORG URO LEFT JOIN UM_ORG UO ON URO.ASSIGNED_AT = UO.UM_ID WHERE URO.ORG_ID = ?" +
                "AND URO.UM_ROLE_ID = ? AND URO.UM_TENANT_ID = ?";
        public static final String DELETE_ORGANIZATION_USER_ROLE_MAPPINGS_ASSIGNED_AT_ORG_LEVEL = "DELETE FROM UM_USER_ROLE_ORG " +
                "WHERE UM_USER_ID = ? AND UM_ROLE_ID = ? AND UM_TENANT_ID = ? AND ASSIGNED_AT = ? ";
        public static final String DELETE_ORGANIZATION_USER_ROLE_MAPPINGS_ASSIGNED_AT_ORG_LEVEL_NON_MANDATORY = "DELETE FROM UM_USER_ROLE_ORG " +
                "WHERE UM_USER_ID = ? AND UM_ROLE_ID = ? AND UM_TENANT_ID = ? ";
        public static final String DELETE_ALL_ORGANIZATION_USER_ROLE_MAPPINGS_BY_USERID = "DELETE FROM UM_USER_ROLE_ORG " +
                "WHERE UM_USER_ID = ? AND UM_TENANT_ID = ?";
        //TODO: ORG_AUTHZ_VIEW TABLE CREATION AND TESTING
        //TODO: Writing Unit Tests
        public static final String GET_ROLES_BY_ORG_AND_USER = "SELECT DISTINCT UM_ROLE_ID, UM_ROLE_NAME FROM ORG_AUTHZ_VIEW " +
                "WHERE ORG_ID = ? AND UM_USER_ID = ? AND UM_TENANT_ID = ?";
        public static final String UPDATE_ORGANIZATION_USER_ROLE_MAPPING_INHERIT_PROPERTY = "UPDATE UM_USER_ROLE_ORG SET " +
                "MANDATORY = ? WHERE UM_USER_ID = ? AND UM_ROLE_ID = ? AND ORG_ID = ? AND ASSIGNED_AT = ? AND UM_TENANT_ID = ?";
        public static final String GET_ROLE_ID_BY_SCIM_GROUP_NAME =
                "SELECT UM_ID FROM UM_HYBRID_ROLE WHERE UM_ROLE_NAME = ? AND UM_TENANT_ID = ?";
        public static final String GET_ORGANIZATION_USER_ROLE_MAPPING =
                "SELECT COUNT(1) FROM UM_USER_ROLE_ORG WHERE UM_USER_ID = ? AND UM_ROLE_ID = ? AND UM_TENANT_ID = ? AND ORG_ID = ?";
        public static final String GET_DIRECTLY_ASSIGNED_ORGANIZATION_USER_ROLE_MAPPING_LINK =
                "SELECT MANDATORY FROM UM_USER_ROLE_ORG WHERE UM_USER_ID = ? AND UM_ROLE_ID = ? AND UM_TENANT_ID = ? AND " +
                        "ORG_ID = ? AND ASSIGNED_AT = ?";
        public static final String GET_MANDATORY_VALUE_OF_ORGANIZATION_USER_ROLE_MAPPING_LINK =
                "SELECT MANDATORY FROM UM_USER_ROLE_ORG WHERE UM_USER_ID = ? AND UM_ROLE_ID = ? AND UM_TENANT_ID = ? AND " +
                "ORG_ID = ?";
        public static final String GET_ASSIGNED_AT_VALUE_OF_ORGANIZATION_USER_ROLE_MAPPING_LINK =
                "SELECT ASSIGNED_AT FROM UM_USER_ROLE_ORG WHERE UM_USER_ID = ? AND UM_ROLE_ID = ? AND UM_TENANT_ID = ? AND " +
                        "ORG_ID = ?";
        public static final String FIND_ALL_CHILD_ORG_IDS =
                "WITH childOrgs(UM_ID, UM_PARENT_ID) AS ( SELECT UM_ID , UM_PARENT_ID FROM UM_ORG WHERE UM_PARENT_ID = ?" +
                "UNION ALL SELECT UO.UM_ID, UO.UM_PARENT_ID FROM UM_ORG UO JOIN childOrgs CO ON CO.UM_ID = UO.UM_PARENT_ID)"+
                        "SELECT UM_ID, UM_PARENT_ID FROM childOrgs ORDER BY UM_ID";
        public static final String VIEW_ORG_ID_COLUMN = "ORG_ID";
    }


}
