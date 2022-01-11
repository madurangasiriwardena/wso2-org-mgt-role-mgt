# wso2-org-mgt-role-mgt

This is the **role-management** implementation of **WSO2 - Organization Management Implementation for Identity Server**.
For now, the implementation is done as an **OSGI** bundle and uses **H2** database and **WSO2 IS 5.11.0**


# Configurations

- Do the following configurations in **deployment.toml** file in`{IS-HOME}/repository/conf/deployment.toml`

    - Add the following configurations to use inbuilt H2 database.
      ```
      [database.identity_db]
      type = "h2"
      url = "jdbc:h2:./repository/database/WSO2IDENTITY_DB;DB_CLOSE_ON_EXIT=FALSE;LOCK_TIMEOUT=60000"
      username = "wso2carbon"
      password = "wso2carbon"
      ```
      ```
      [database.shared_db]
      type = "h2"
      url = "jdbc:h2:./repository/database/WSO2SHARED_DB;DB_CLOSE_ON_EXIT=FALSE;LOCK_TIMEOUT=60000"
      username = "wso2carbon"
      password = "wso2carbon"
      ```
      ```
      [database_configuration]
      enable_h2_console = "true"
      ```
    - Set H2 database as the primary user store.
      ```
      [user_store]
      type = "database_unique_id"
      ```
    - Set `resource-access-control` to use the API.
      ```
      [[resource.access_control]]
      context="(.*)/api/identity/organization-mgt/v1.0/(.*)"
      secure = "true"
      http_method = "ALL
      ```
    - Next start the IS and go to the H2 console using, `http://localhost:8082` and provide the JDBC URL, username and password given above.
      `JDBC URL = jdbc:h2:{IS-HOME}/repository/database/WSO2SHARED_DB`
      `username = wso2carbon`
      `password = wso2carbon`

    - Then use the following queries to add tables.
      ```
      CREATE TABLE IF NOT EXISTS UM_ORG (
      UM_ID VARCHAR(255) NOT NULL,
      UM_ORG_NAME VARCHAR(255) NOT NULL,
      UM_ORG_DESCRIPTION VARCHAR(1024),
      UM_CREATED_TIME TIMESTAMP NOT NULL,
      UM_LAST_MODIFIED TIMESTAMP NOT NULL,
      UM_STATUS VARCHAR(255) DEFAULT 'ACTIVE' NOT NULL, UM_TENANT_ID INTEGER DEFAULT 0,
      UM_PARENT_ID VARCHAR(255), PRIMARY KEY (UM_ID), UNIQUE(UM_ORG_NAME, UM_TENANT_ID), FOREIGN KEY (UM_PARENT_ID) REFERENCES UM_ORG(UM_ID) ON DELETE CASCADE );
       ```
          
      |  UM_ID|UM_ORG_NAME|UM_ORG_DESCRIPTION|UM_CREATED_TIME|UM_LAST_MODIFIED|UM_STATUS|UM_TENANT_ID|UM_PARENT_ID
      |---------|--------------------|------------------------------|-------------------------|-----------|--------------|--------------|-----
          
      ```
      CREATE TABLE UM_USER_ROLE_ORG (
      UM_ID VARCHAR2(255) NOT NULL,
      UM_USER_ID VARCHAR2(255) NOT NULL,
      UM_ROLE_ID VARCHAR2(1024) NOT NULL,
      UM_HYBRID_ROLE_ID INTEGER NOT NULL,
      UM_TENANT_ID INTEGER DEFAULT 0,
      ORG_ID VARCHAR2(255) NOT NULL,
      ASSIGNED_AT VARCHAR2(255) NOT NULL,
      MANDATORY INTEGER DEFAULT 0,
      PRIMARY KEY (UM_ID),
      CONSTRAINT FK_UM_USER_ROLE_ORG_UM_HYBRID_ROLE FOREIGN KEY (UM_HYBRID_ROLE_ID, UM_TENANT_ID) REFERENCES UM_HYBRID_ROLE(UM_ID, UM_TENANT_ID) ON DELETE CASCADE,
      CONSTRAINT FK_UM_USER_ROLE_ORG_UM_ORG FOREIGN KEY (ORG_ID) REFERENCES UM_ORG(UM_ID) ON DELETE CASCADE,
      CONSTRAINT FK_UM_USER_ROLE_ORG_ASSIGNED_AT FOREIGN KEY (ASSIGNED_AT) REFERENCES UM_ORG(UM_ID) ON DELETE CASCADE);
       ```
            
      | UM_ID|UM_USER_ID|UM_ROLE_ID|UM_HYBRID_ROLE_ID|UM_TENANT_ID|ORG_ID|ASSIGNED_AT|MANDATORY
      |--------|---------|---------------|--------------------|---------------|-------------|---------|-----------|
    - Add the following `VIEW` to database.
      ```
      CREATE VIEW ORG_AUTHZ_VIEW AS
      SELECT
      URP.UM_PERMISSION_ID,
      URO.UM_ROLE_ID,
      URO.UM_HYBRID_ROLE_ID,
      URP.UM_ROLE_NAME,
      URP.UM_IS_ALLOWED,
      URP.UM_TENANT_ID,
      URP.UM_DOMAIN_ID,
      UP.UM_RESOURCE_ID,
      UP.UM_ACTION,
      UHR.UM_ID,
      URO.UM_USER_ID,
      URO.ORG_ID,
      UO.UM_ORG_NAME
      FROM
      UM_USER_ROLE_ORG URO
      LEFT JOIN
      UM_HYBRID_ROLE UHR
      ON
      (UHR.UM_ID = URO.UM_HYBRID_ROLE_ID)
      LEFT JOIN
      UM_ROLE_PERMISSION URP
      ON
      (UHR.UM_ROLE_NAME = URP.UM_ROLE_NAME)
      LEFT JOIN
      UM_PERMISSION UP
      ON
      URP.UM_PERMISSION_ID = UP.UM_ID
      LEFT JOIN
      UM_ORG UO
      ON
      URO.ORG_ID = UO.UM_ID
      ```

## Build

This is a multi-module project containing two modules,
- `org.wso2.carbon.identity.organization.role,mgt.core`
- `org.wso2.carbon.identity.organization.role.mgt.endpoint`

Type,
`mvn clean install` to generate the `jar` file in `core` module and `war` file in `endpoint` module.
Alternatively can use `mvn clean install -DskipTests` or `mvn clean install Dmaven.skip.test=true` to skip tests.

- Copy the `api#identitiy#organization-mgt#v1.0.war` file to `{IS-HOME}/repository/deployment/server/webapps`
- Copy the `org.wso2.carbon.identity.organization.role.mgt.core-<version>.jar` file to `{IS-HOME}/repository/components/dropins`

## Check the OSGI Service is working

Run **WSO2 IS** using the following command to check the **OSGI** service.
`sh wso2server.sh -dosgiConsole`
After deploying the **WSO2 IS** check the service is working or not by,
`ss <jar filename>` and selecting the `jar` file.

## Debugging

To debug, open the **WSO2 IS** in remote debugging.
`sh wso2server.sh -debug <port-name>`

## Features
For the following features assume the following organization structure.
There are five organizations, A, B, C, D, E. Organization A is the immediate parent of B, 
Organization B is the immediate parent of C and Organization C is the immediate parent of D and E.

[![](https://mermaid.ink/img/eyJjb2RlIjoiZ3JhcGggVERcbiAgICBBKEEpIC0tPiBCKEIpXG4gICAgQihCKSAtLT4gQyhDKVxuICAgIEMgLS0-IEQoRClcbiAgICBDIC0tPiBFKEUpXG4gICIsIm1lcm1haWQiOnsidGhlbWUiOiJkZWZhdWx0In0sInVwZGF0ZUVkaXRvciI6dHJ1ZSwiYXV0b1N5bmMiOnRydWUsInVwZGF0ZURpYWdyYW0iOnRydWV9)](https://mermaid.live/edit#eyJjb2RlIjoiZ3JhcGggVERcbiAgICBBKEEpIC0tPiBCKEIpXG4gICAgQihCKSAtLT4gQyhDKVxuICAgIEMgLS0-IEQoRClcbiAgICBDIC0tPiBFKEUpXG4gICIsIm1lcm1haWQiOiJ7XG4gIFwidGhlbWVcIjogXCJkZWZhdWx0XCJcbn0iLCJ1cGRhdGVFZGl0b3IiOnRydWUsImF1dG9TeW5jIjp0cnVlLCJ1cGRhdGVEaWFncmFtIjp0cnVlfQ)

### Add organization-user-role mappings
**API**  
```
https://localhost:9443/t/{tenant}/api/identity/organization-mgt/v1.0/organizations/{organization-id}/roles
```

**Sample Request Body**  
```
{
    "roleId": "bd4a44b9-deb4-4981-82bf-b10226531767",
    "users": [
        {
            "userId": "f88a990b-a08d-4078-85f4-f615ce03a980",
            "mandatory": false,
            "includeSubOrgs": true
        }
    ]
}
```
**Notes**

- Assigning a **mandatory** role it will be applied to the organization tree.
- For example, if user `U1` assign role `R1` to organization `A` it will be assigned to all the sub-organizations (B, C, D, E).
- After that, the database table `UM_USER_ROLE_ORG` will look like this.

    |UM_ID|UM_USER_ID|UM_ROLE_ID|UM_HYBRID_ROLE_ID|UM_TENANT_ID|ORG_ID|ASSIGNED_AT|MANDATORY
    |-----|------|-----|----|-----|----|-----|-----
    |URO1|U1|R1|1|-1234|A|A|1
    |URO2|U1|R1|1|-1234|B|A|1
    |URO3|U1|R1|1|-1234|C|A|1
    |URO4|U1|R1|1|-1234|D|A|1
    |URO5|U1|R1|1|-1234|E|A|1
  

- Removing or editing that **mandatory** role can **only** be done at the assigned level.
  

- When assigning a non-mandatory role to this hierarchy the user can assign it to that organization only or the all the organizations.
- For example, if user `U1` assigns role `R1` to organization `A` only, that role will only be at organization A.
- After that, the database table `UM_USER_ROLE_ORG` will look like this.

    |UM_ID|UM_USER_ID|UM_ROLE_ID|UM_HYBRID_ROLE_ID|UM_TENANT_ID|ORG_ID|ASSIGNED_AT|MANDATORY
    |-----|------|-----|----|-----|----|-----|-----
    |URO1|U1|R1|1|-1234|A|A|0

- If the user `U1` assigns role `R1` to organization `A` with `includeSubOrgs` it will be propagated to all the sub organizations as a new copy.
- After that, the database table `UM_USER_ROLE_ORG` will look like this.

    |UM_ID|UM_USER_ID|UM_ROLE_ID|UM_HYBRID_ROLE_ID|UM_TENANT_ID|ORG_ID|ASSIGNED_AT|MANDATORY
    |-----|------|-----|----|-----|----|-----|-----
    |URO1|U1|R1|1|-1234|A|A|0
    |URO2|U1|R1|1|-1234|B|B|0
    |URO3|U1|R1|1|-1234|C|C|0
    |URO4|U1|R1|1|-1234|D|D|0
    |URO5|U1|R1|1|-1234|E|E|0
- Note the changes in `ASSIGNED_AT` column in these three scenarios.
  

- Even if there exists a **mandatory** organization-user-role mapping, the same user can assign the same role as a non-mandatory role and vice-versa.
- For example, the user `U1` can assign role `R1` to organization `A` as a mandatory role and assign `R1` as non-mandatory without including sub-organizations.
- After that, the database table `UM_USER_ROLE_ORG` will look like this.

    |UM_ID|UM_USER_ID|UM_ROLE_ID|UM_HYBRID_ROLE_ID|UM_TENANT_ID|ORG_ID|ASSIGNED_AT|MANDATORY
    |-----|------|-----|----|-----|----|-----|-----
    |URO1|U1|R1|1|-1234|A|A|1
    |URO2|U1|R1|1|-1234|B|A|1
    |URO3|U1|R1|1|-1234|C|A|1
    |URO4|U1|R1|1|-1234|D|A|1
    |URO5|U1|R1|1|-1234|E|A|1
    |URO6|U1|R1|1|-1234|A|A|0

### Patch organization-user-role mappings
**API**
```
https://localhost:9443/t/{tenant}/api/identity/organization-mgt/v1.0/organizations/{organization-id}/roles/{role-id}/users/{user-id}
```

**Sample Request Body**
```
[
    {
        "op": "replace",
        "path": "/includeSubOrgs",
        "value": false
    },
    {
        "op": "replace",
        "path": "/isMandatory",
        "value": false
    }
]
```
**Notes**
- This API only updates the **mandatory** field and then makes adjustments accordingly.
- And it always passes two operations `/includeSubOrgs` and `/isMandatory`.
- If there are two organization-user-role mappings like following, it will always take precedent one. Meaning it will always select the **mandatory** user role mapping and adjust it accordingly.

  |UM_ID|UM_USER_ID|UM_ROLE_ID|UM_HYBRID_ROLE_ID|UM_TENANT_ID|ORG_ID|ASSIGNED_AT|MANDATORY
  |-----|------|-----|----|-----|----|-----|-----
  |URO1|U1|R1|1|-1234|A|A|1
  |URO2|U1|R1|1|-1234|A|A|0
- If there are two user role mappings like this, and we pass `/isMandatory` **true** and `/includeSubOrgs` **false** it will throw an error, since **mandatory roles should be propagated**.
- If there are two user role mappings like this, and we pass `/isMandatory` **true** and `/includeSubOrgs` **true** it will remove the `URO2` mapping since it does not follow the **mandatory** property. Then only `URO1` will exist.
- If there are two user role mappings like this, and we pass `/isMandatory` **false** and `/includeSubOrgs` **false** it will remove both the mappings and add a new mapping `URO3` with **mandatory** **false**.
- If there are two user role mappings like this, and we pass `isMandatory` **false** and `includeSubOrgs` **false** it will remove all the user-role mappings and add new user-role mappings for sub organizations as well.
- This is due to the precedence behavior of the algorithm selecting a user-role mapping based on `um_user_id` , `um_role_id`, `org_id` and `tenant_id`.
  

- If there are non-mandatory organization-user-role mappings as following, they will make adjustments according to the `/isMandatory` and `/includeSubOrgs` values.

    |UM_ID|UM_USER_ID|UM_ROLE_ID|UM_HYBRID_ROLE_ID|UM_TENANT_ID|ORG_ID|ASSIGNED_AT|MANDATORY
    |-----|------|-----|----|-----|----|-----|-----
    |URO1|U1|R1|1|-1234|A|A|0
    |URO2|U1|R1|1|-1234|B|B|0
    |URO3|U1|R1|1|-1234|C|C|0

- If `/isMandatory` **false** and `/includeSubOrgs` **true** it will add new user-role mappings for the sub-organizations if they don't exist.
- If `/isMandatory` **false** and `/includeSubOrgs` **false** nothing will happen.
- If `/isMandatory` **true** and `/includeSubOrgs` **false** it will give an error since **mandatory roles should be propagated to sub-organizations**.
- If `/isMandatory` **true** and `/includeSubOrgs` **true** it will add new user-role mappings for sub-organizations and the given organization with mandatory property, while removing the non-mandatory roles in those with same `um_user_name`, `um_role_id` and `org_id`.
  
- If there are mandatory organization-user-role mappings as following, they will make adjustments according to the `/isMandatory` and `/includeSubOrgs` values.

    |UM_ID|UM_USER_ID|UM_ROLE_ID|UM_HYBRID_ROLE_ID|UM_TENANT_ID|ORG_ID|ASSIGNED_AT|MANDATORY
    |-----|------|-----|----|-----|----|-----|-----
    |URO1|U1|R1|1|-1234|A|A|1
    |URO2|U1|R1|1|-1234|B|A|1
    |URO3|U1|R1|1|-1234|C|A|1

- If `/isMandatory` **false** and `/includeSubOrgs` **true** it will remove all the mandatory and non-mandatory user-role mappings and add them anew.
- If `/isMandatory` **false** and `/includeSubOrgs` **false** it will remove all the mandatory and non-mandatory role mappings and make one user-role mapping in the mentioned organization.
- If `/isMandatory` **true** and `/includeSubOrgs` **false** it will give an error since **mandatory roles should be propagated to sub-organizations**.
- If `/isMandatory` **true** and `/includeSubOrgs` **true** it will remove all the non-mandatory user-role mappings in the sub-organizations and the mentioned organization.

### Delete organization-user-role mappings
**API**
```
https://localhost:9443/t/{tenant}/api/identity/organization-mgt/v1.0/organizations/{organization-id}/roles/{role-id}/users/{user-id}
```

**Request Parameters**
```
includeSubOrgs
```
**Notes**
- This API deletes organization-user-role mappings.
- As mentioned in `patch operation` for **role-management** this will always take the precedent one.
- If there are two organization-user-role mappings as given below, it will select the one with mandatory 1.
  
  |UM_ID|UM_USER_ID|UM_ROLE_ID|UM_HYBRID_ROLE_ID|UM_TENANT_ID|ORG_ID|ASSIGNED_AT|MANDATORY
  |-----|------|-----|----|-----|----|-----|-----
  |URO1|U1|R1|1|-1234|A|A|1
  |URO2|U1|R1|1|-1234|A|A|0

- If `includeSubOrgs=true` it will remove all the user-role mappings including mandatory and non-mandatory.
- If `includeSubOrgs=false` it will give an error since, the priority is given to mandatory user-role mapping.
  
- If there are only non-mandatory user-role mappings, then if `includeSubOrgs=true` it will remove all the non-mandatory user-role mappings in sub-organizations and the mentioned organization, else if `includeSubOrgs=false` it will only remove the user-role mapping in that mentioned organization.

### Get users from a certain organization having certain roles
**API**
```
https://localhost:9443/t/{tenant}/api/identity/organization-mgt/v1.0/organizations/{organization-id}/roles/{role-id}/
```

**Notes**
- This gives the user list of an organization with specific role.

### Get roles from a certain user in a organization
**API**
```
https://localhost:9443/t/{tenant}/api/identity/organization-mgt/v1.0/organizations/{organization-id}/users/{user-id}/
```

**Notes**
- This gives the user list of an organization with specific role.
