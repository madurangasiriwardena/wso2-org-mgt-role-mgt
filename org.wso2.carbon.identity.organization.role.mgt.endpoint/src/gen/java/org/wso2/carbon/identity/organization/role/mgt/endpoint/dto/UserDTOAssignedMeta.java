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
import org.wso2.carbon.identity.organization.role.mgt.endpoint.dto.UserDTOAssignedAt;
import javax.validation.constraints.*;


import io.swagger.annotations.*;
import java.util.Objects;
import javax.validation.Valid;
import javax.xml.bind.annotation.*;

public class UserDTOAssignedMeta  {
  
    private Boolean mandatory;
    private UserDTOAssignedAt assignedAt;

    /**
    **/
    public UserDTOAssignedMeta mandatory(Boolean mandatory) {

        this.mandatory = mandatory;
        return this;
    }
    
    @ApiModelProperty(value = "")
    @JsonProperty("mandatory")
    @Valid
    public Boolean getMandatory() {
        return mandatory;
    }
    public void setMandatory(Boolean mandatory) {
        this.mandatory = mandatory;
    }

    /**
    **/
    public UserDTOAssignedMeta assignedAt(UserDTOAssignedAt assignedAt) {

        this.assignedAt = assignedAt;
        return this;
    }
    
    @ApiModelProperty(value = "")
    @JsonProperty("assignedAt")
    @Valid
    public UserDTOAssignedAt getAssignedAt() {
        return assignedAt;
    }
    public void setAssignedAt(UserDTOAssignedAt assignedAt) {
        this.assignedAt = assignedAt;
    }



    @Override
    public boolean equals(java.lang.Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        UserDTOAssignedMeta userDTOAssignedMeta = (UserDTOAssignedMeta) o;
        return Objects.equals(this.mandatory, userDTOAssignedMeta.mandatory) &&
            Objects.equals(this.assignedAt, userDTOAssignedMeta.assignedAt);
    }

    @Override
    public int hashCode() {
        return Objects.hash(mandatory, assignedAt);
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append("class UserDTOAssignedMeta {\n");
        
        sb.append("    mandatory: ").append(toIndentedString(mandatory)).append("\n");
        sb.append("    assignedAt: ").append(toIndentedString(assignedAt)).append("\n");
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

