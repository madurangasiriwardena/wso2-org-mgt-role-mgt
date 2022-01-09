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

public class OrganizationUserRoleMgtConstants {

    public static final String PATCH_OP_REPLACE = "replace";
    /**
     * Error messages.
     */
    public enum ErrorMessages {
        // Role Mgt Client Errors (ORG-60200 - ORG-60999)
        INVALID_ROLE_NON_INTERNAL_ROLE("ORG-60200", "Invalid role", "%s"),
        INVALID_ROLE_ID("ORG-60201", "Invalid role", "%s"),
        INVALID_ORGANIZATION_ROLE_USERS_GET_REQUEST("ORG-60202",
                "Invalid users search/get request for an organization's role",
                "Invalid pagination arguments. 'limit' should be greater than 0 and 'offset' should be greater than -1"),
        DELETE_ORG_ROLE_USER_REQUEST_INVALID_MAPPING("ORG-60203", "Role mapping does not exist", "%s"),
        ADD_ORG_ROLE_USER_REQUEST_INVALID_USER("ORG-60204", "Invalid user", "%s"),
        DELETE_ORG_ROLE_USER_REQUEST_INVALID_DIRECT_MAPPING("ORG-60205", "Invalid direct role mapping", "%s"),
        PATCH_ORG_ROLE_USER_REQUEST_TOO_MANY_OPERATIONS("ORG-60206", "Too many operations",
                "Only one patch operation is valid because only the includeSubOrg attribute can be changed."),
        PATCH_ORG_ROLE_USER_REQUEST_INVALID_MAPPING("ORG-60207", "Invalid mapping",
                "No matching role mapping to be updated."),
        PATCH_ORG_ROLE_USER_REQUEST_OPERATION_UNDEFINED("ORG-60208", "Operation undefined",
                "Patch operation is not defined"),
        PATCH_ORG_ROLE_USER_REQUEST_INVALID_OPERATION("ORG-60209", "Invalid operation",
                "Patch op must be 'replace'"),
        PATCH_ORG_ROLE_USER_REQUEST_PATH_UNDEFINED("ORG-60210", "Path undefined",
                "Patch operation path is not defined"),
        PATCH_ORG_ROLE_USER_REQUEST_INVALID_PATH("ORG-60211", "Invalid path",
                "Patch path must be '/includeSubOrgs'"),
        PATCH_ORG_ROLE_USER_REQUEST_INVALID_VALUE("ORG-60212", "Invalid value",
                "Patch operation value must be a boolean"),
        PATCH_ORG_ROLE_USER_REQUEST_INVALID_BOOLEAN_VALUE("ORG-60213", "Invalid value",
                "Patch operation boolean value error"),
        ADD_ORG_ROLE_USER_REQUEST_MAPPING_EXISTS("ORG-60214", "Mapping already exists", "%s"),
        INVALID_REQUEST("ORG-60215", "Invalid request", "Error while processing the request."),
        ADD_ORG_ROLE_USER_REQUEST_INVALID_ORGANIZATION_PARAM("ORG-60215", "subOrganization value must be true if mandatory value is true.", "Error while processing the request."),
        DELETE_ORG_ROLE_USER_REQUEST_INVALID_BOOLEAN_VALUE("ORG-60216", "Invalid value",
                "Delete operation boolean value error"),

        // Role Mgt Server Errors (ORG-65200 - ORG-65999)
        ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_ADD_ERROR("ORG-65200",
                "Error while creating the role mappings", ""),
        ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_DELETE_ERROR("ORG-65201",
                "Error while deleting the organization user role mapping.", ""),
        ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_RETRIEVING_ERROR("ORG-65202",
                "Error while retrieving the role : %s, for user : %s for organization : %s", ""),
        ERROR_CODE_HYBRID_ROLE_ID_RETRIEVING_ERROR("ORG-65203",
                "Error while retrieving the hybrid role id for role : %s", ""),
        ERROR_CODE_USERS_PER_ORG_ROLE_RETRIEVING_ERROR("ORG-65204",
                "Error while retrieving users for role: %s , organization : %s", ""),
        ERROR_CODE_ROLES_PER_ORG_USER_RETRIEVING_ERROR("ORG-65205",
                "Error while retrieving roles for user: %s , organization : %s", ""),
        ERROR_CODE_EVENTING_ERROR("ORG-65206", "Error while handling the event : %s", ""),
        ERROR_CODE_USER_STORE_OPERATIONS_ERROR("ORG-65207", "Error accessing user store : %s", ""),
        ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_DELETE_PER_USER_ERROR("ORG-65208",
                "Error while deleting organization user role mappings for user : %s", ""),
        ERROR_CODE_ORGANIZATION_USER_ROLE_MAPPINGS_UPDATE_ERROR("ORG-65209",
                "Error while updating mandatory property of organization mapping", ""),
        ERROR_CODE_UNEXPECTED("ORG-65210", "Unexpected Error", ""),
        ERROR_CODE_ORGANIZATION_GET_CHILDREN_ERROR("ORG-65211",
                "Error while retrieving the child organizations : %s", "");

        private final String code;
        private final String message;
        private final String description;

        ErrorMessages(String code, String message, String description) {

            this.code = code;
            this.message = message;
            this.description = description;
        }

        public String getCode() {

            return code;
        }

        public String getMessage() {

            return message;
        }

        public String getDescription() {

            return description;
        }
    }

    /**
     * Forbidden Error Messages.
     */
    public enum ForbiddenErrorMessages {

    }

    /**
     * Not Found Error Messages.
     */
    public enum NotFoundErrorMessages {

        ORG_60203, ORG_60204, ORG_60205
    }

    /**
     * Conflict Error Messages.
     */
    public enum ConflictErrorMessages {

        ORG_60213
    }
}
