package org.georchestra.console.ws.backoffice.roles;

import java.util.stream.StreamSupport;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.georchestra.console.ds.DataServiceException;
import org.georchestra.console.ds.RoleDao;
import org.georchestra.console.dto.Role;
import org.georchestra.console.ws.backoffice.roles.RolesController;
import org.json.JSONArray;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.ldap.NameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;

import lombok.NonNull;

@Controller
public class RolesExport {
    @Autowired
    private RoleDao roleDao;

    private static final Log LOG = LogFactory.getLog(RolesController.class.getName());

    private static final String CSV_DELIMITER = ",";
    private final String CSV_HEADER = "roleName, roleUsers, description\r\n";

    @PostMapping(value = "/private/export/roles.csv", consumes = MediaType.APPLICATION_JSON_VALUE, produces = "text/csv; charset=utf-8")
    @ResponseBody
    public String getRolesAsCsv(@RequestBody String roles) throws Exception {
        // get user from json
        String[] parsedRoles = parseRolesNamesFromJSONArray(roles);
        // @NonNull
        String csvRoles = exportRolesAsCsv(parsedRoles);
        return csvRoles;
    }

    /**
     * Parses and returns the roles names given as a JSON array (e.g.
     * {@code ["CKAn_ADMIN", "ADMINISTRATOR"]})
     */
    private String[] parseRolesNamesFromJSONArray(String rawRoles) {
        JSONArray jsonRoles = new JSONArray(rawRoles);
        String[] roles = StreamSupport.stream(jsonRoles.spliterator(), false).toArray(String[]::new);
        return roles;
    }

    /**
     * exportRoleAsCsv
     * 
     * @param orgNames
     * @return
     * @throws DataServiceException
     */
    public @NonNull String exportRolesAsCsv(@NonNull String... roleNames) throws DataServiceException {
        StringBuilder res = new StringBuilder();
        // insert CSV header as column names
        res.append(CSV_HEADER);
        // get each org infos as CSV lines
        for (String roleName : roleNames) {
            try {
                // get org infos
                Role role = this.roleDao.findByCommonName(roleName);

                res.append(toCsv(role));
            } catch (NameNotFoundException e) {
                LOG.error(String.format("Role [%s] not found, skipping", roleName), e);
            }
        }

        return res.toString();
    }

    /**
     * toCsv
     * 
     * @param role
     * @return role as string according to the csv header
     */
    private String toCsv(Role role) {

        StringBuilder csv = new StringBuilder();

        // create csv as string according to header
        csv.append(toFormatedString(role.getName()));
        csv.append(CSV_DELIMITER);
        csv.append(toFormatedString(role.getUserList().toString()));
        csv.append(CSV_DELIMITER);
        csv.append(toFormatedString(role.getDescription()));
        csv.append("\r\n"); // CRLF

        return csv.toString();
    }

    /**
     * toFromatedString
     * 
     * @param data
     * @return formated string
     */
    private String toFormatedString(String data) {
        String ret = "";
        if (data != null) {
            ret = data.replace(",", ".");
        }
        return ret;
    }

}
