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

package org.wso2.carbon.identity.organization.role.mgt.endpoint.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonCreator;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.util.ArrayList;
import java.util.List;
import org.wso2.carbon.identity.organization.role.mgt.endpoint.dto.UserRoleMappingDTOUsers;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;
import javax.validation.Valid;
import javax.xml.bind.annotation.*;

public class UserRoleMappingDTO  {
  
    private String roleId;
    private List<UserRoleMappingDTOUsers> users = null;


    /**
    **/
    public UserRoleMappingDTO roleId(String roleId) {

        this.roleId = roleId;
        return this;
    }
    
    @ApiModelProperty(example = "7d4e3ac9-da93-4b7a-a2d0-84bb6c01dc25", required = true, value = "")
    @JsonProperty("roleId")
    @Valid
    @NotNull(message = "Property roleId cannot be null.")

    public String getRoleId() {
        return roleId;
    }
    public void setRoleId(String roleId) {
        this.roleId = roleId;
    }

    /**
    **/
    public UserRoleMappingDTO users(List<UserRoleMappingDTOUsers> users) {

        this.users = users;
        return this;
    }
    
    @ApiModelProperty(value = "")
    @JsonProperty("users")
    @Valid
    public List<UserRoleMappingDTOUsers> getUsers() {
        return users;
    }
    public void setUsers(List<UserRoleMappingDTOUsers> users) {
        this.users = users;
    }

    public UserRoleMappingDTO addUsersItem(UserRoleMappingDTOUsers usersItem) {
        if (this.users == null) {
            this.users = new ArrayList<>();
        }
        this.users.add(usersItem);
        return this;
    }

    

    @Override
    public boolean equals(java.lang.Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        UserRoleMappingDTO userRoleMappingDTO = (UserRoleMappingDTO) o;
        return Objects.equals(this.roleId, userRoleMappingDTO.roleId) &&
            Objects.equals(this.users, userRoleMappingDTO.users);
    }

    @Override
    public int hashCode() {
        return Objects.hash(roleId, users);
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append("class UserRoleMappingDTO {\n");
        
        sb.append("    roleId: ").append(toIndentedString(roleId)).append("\n");
        sb.append("    users: ").append(toIndentedString(users)).append("\n");
        sb.append("}");
        return sb.toString();
    }

    /**
    * Convert the given object to string with each line indented by 4 spaces
    * (except the first line).
    */
    private String toIndentedString(java.lang.Object o) {

        if (o == null) {
            return "null";
        }
        return o.toString().replace("\n", "\n");
    }
}

