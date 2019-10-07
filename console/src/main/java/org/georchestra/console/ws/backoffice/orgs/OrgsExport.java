package org.georchestra.console.ws.backoffice.orgs;

import java.util.stream.StreamSupport;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.georchestra.console.ds.DataServiceException;
import org.georchestra.console.ds.OrgsDao;
import org.georchestra.console.dto.orgs.Org;
import org.georchestra.console.dto.orgs.OrgExt;
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
public class OrgsExport {
    @Autowired
    private OrgsDao orgDao;

    @Autowired
    public void OrgsController(OrgsDao dao) {
        this.orgDao = dao;
    }

    private static final Log LOG = LogFactory.getLog(OrgsController.class.getName());

    private static final String CSV_DELIMITER = ",";
    private final String CSV_HEADER = "id, organizationName, shortName, members, postalAddress, description, businessCategory, webSite\r\n";

    @PostMapping(value = "/private/export/orgs.csv", consumes = MediaType.APPLICATION_JSON_VALUE, produces = "text/csv; charset=utf-8")
    @ResponseBody
    public String getOrgsAsCsv(@RequestBody String orgs) throws Exception {
        // get user from json
        String[] parsedOrgs = parseOrgsNamesFromJSONArray(orgs);
        // @NonNull
        String csvOrgs = exportOrgsAsCsv(parsedOrgs);
        return csvOrgs;
    }

    /**
     * Parses and returns the orgs names given as a JSON array (e.g.
     * {@code ["craig", "c2c"]})
     */
    private String[] parseOrgsNamesFromJSONArray(String rawOrgs) {
        JSONArray jsonOrgs = new JSONArray(rawOrgs);
        String[] orgs = StreamSupport.stream(jsonOrgs.spliterator(), false).toArray(String[]::new);
        return orgs;
    }

    /**
     * exportOrgsAsCsv
     * 
     * @param orgNames
     * @return
     * @throws DataServiceException
     */
    public @NonNull String exportOrgsAsCsv(@NonNull String... orgNames) throws DataServiceException {
        StringBuilder res = new StringBuilder();
        // insert CSV header as column names
        res.append(CSV_HEADER);
        // get each org infos as CSV lines
        for (String orgName : orgNames) {
            try {
                // get org infos
                Org org = this.orgDao.findByCommonName(orgName);
                OrgExt orgExt = this.orgDao.findExtById(orgName);
                org.setOrgExt(orgExt);

                res.append(toCsv(org, orgExt));
            } catch (NameNotFoundException e) {
                LOG.error(String.format("Org [%s] not found, skipping", orgName), e);
            }
        }

        return res.toString();
    }

    /**
     * toCsv
     * 
     * @param org
     * @return org as string according to the csv header
     */
    private String toCsv(Org org, OrgExt orgExt) {

        StringBuilder csv = new StringBuilder();

        // create csv as string according to header
        csv.append(toFormatedString(org.getId()));
        csv.append(CSV_DELIMITER);
        csv.append(toFormatedString(org.getName()));
        csv.append(CSV_DELIMITER);
        csv.append(toFormatedString(org.getShortName()));
        csv.append(CSV_DELIMITER);
        csv.append(toFormatedString(org.getMembers().toString()));
        csv.append(CSV_DELIMITER);
        csv.append(toFormatedString(orgExt.getAddress()));
        csv.append(CSV_DELIMITER);
        csv.append(toFormatedString(orgExt.getDescription()));
        csv.append(CSV_DELIMITER);
        csv.append(toFormatedString(orgExt.getOrgType()));
        csv.append(CSV_DELIMITER);
        csv.append(toFormatedString(orgExt.getUrl()));
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
