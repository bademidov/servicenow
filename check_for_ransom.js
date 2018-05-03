// Get JSON formatted Malwarebytes Cloud credentials from ServiceNow integration configuration
function GetCredentials() {
  var configs = new GlideRecord("sn_sec_core_integration_item_config");
  configs.addQuery("integration", "dae4cbfb0f941b401ea08f8ce1050e17"); // Sys Id of Integration
  configs.query();
  var configObj = {};
  var credentials = {};
  while (configs.next()) {
  configObj[configs.getValue("name")] = configs.getValue("value");
  if (configs.getValue("elem_type").toLowerCase() == "password" && !gs.nil(configs.password_value))
    configObj[configs.getValue("name")] = configs.password_value.getDecryptedValue();
  if (configs.getValue("elem_type") == "boolean")
    configObj[configs.getValue("name")] = configs.getValue("value") == "true";
  }
  credentials = JSON.stringify(configObj);
  return credentials;
}

// Authentication
function GetAuthToken(credentials) {
  var sm = new sn_ws.RESTMessageV2('x_malwa_mb_threat.Login', 'POST');
  sm.setRequestBody(credentials);
  var response = sm.execute();
  var responseBody = response.getBody();
  var httpStatus = response.getStatusCode();
  if (httpStatus != 200)  {
    gs.info('HTTP Error (Authentication):' + httpStatus);
  }
  var parser = new global.JSON();
  var parsedData = parser.decode(responseBody);
  var auth_token = parsedData.tokens.auth_token.token;
  return auth_token;
}

// Get Real-Time detections records from Malwarebytes Cloud
function GetLastRansom(category, auth_token)  {
  var sm = new sn_ws.RESTMessageV2('x_malwa_mb_threat.Detections', 'Default GET');
  sm.setQueryParameter("page_size", "1");
  sm.setQueryParameter("category", category);
  sm.setRequestHeader("Authorization", auth_token);
  var response = sm.execute();
  var responseBody = response.getBody();
  var httpStatus = response.getStatusCode();
  if (httpStatus != 200)  {
    gs.info('HTTP Error (GetDetections):' + httpStatus);
  }
  var parser = new global.JSON();
  var parsedData = parser.decode(responseBody);
  gs.info(parsedData.threats[0].id);
  gs.info(parsedData.threats[0].reported_at);
  gs.info(parsedData.threats[0].threat_name);
  gs.info(parsedData.threats[0].status);
  gs.info(parsedData.threats[0].machine_name);
  gs.info(parsedData.threats[0].group_name);
  gs.info(parsedData.threats[0].policy_name);
//  var ransom_threats = [];
//  for (var i = 0; i < threats.length; i++) {

//    if (threats[i].scan_id == "00000000-0000-0000-0000-000000000000") {
//    if (threats[i].category == "arw") {
//      gs.info(threats[i].scan_id);
//      gs.info(threats[i].category);
//      ransom_threats.push(threats[i]);
//    }
  return parsedData.threats[0];
}

//
function CheckRansomTable(last) {
  var gr = new GlideRecord('x_malwa_mb_threat_ransom');
  gr.setLimit(1);
  gr.orderByDesc('sys_created_on');
  gr.query();
  while(gr.next())  {
    if (gr.detection_id != last.id)  {
       gs.info("last.id: " + last.id);
       gs.info("gr.detection_id:" + gr.detection_id);
        //
        // Create a new security incident
        //
        gs.info("Creating a new Security Incident!");

        // Update the table with new values
        gs.info("Updating Ransom table");
        return true;
      }
      else {
        gs.info("Same ID. Ignoring...");
        return false;
      }
  }
}

function CreateIncident(last) {
  var gr = new GlideRecord('sn_si_incident_import');
  gr.initialize();
  gr.cmdb_ci = last.machine_name;
  gr.risk_score = 95;
  gr.short_description = last.threat_name + " has been detected on the endpoint " + last.machine_name;
  //gr.sys_import_set = '06e201430f155b001ea08f8ce1050e66';
  gr.sys_import_set = 'aebe83d20f3d57001ea08f8ce1050eca';
  gr.insert();
}
//
function UpdateRansomTable(last) {
  var gr = new GlideRecord('x_malwa_mb_threat_ransom');
  var empty = IsEmpty();
  gs.info(empty);
  if (empty)  {
    gr.initialize();
    while(gr.next())  {
      gr.detection_id = last.id;
      gr.reported_at = last.reported_at;
      gr.threat_name = last.threat_name;
      gr.action_taken = last.status;
      gr.computer_name = last.machine_name;
      gr.group_name = last.group_name;
      gr.policy_name = last.policy_name;
      gr.insert();
    }
  }
  else if (empty == false) {
    gr.query();
    while(gr.next())  {
      gr.detection_id = last.id;
      gr.reported_at = last.reported_at;
      gr.threat_name = last.threat_name;
      gr.action_taken = last.status;
      gr.computer_name = last.machine_name;
      gr.group_name = last.group_name;
      gr.policy_name = last.policy_name;
      gs.info("NOT EMPTY1");
      gr.update();
    }
  }
}

// Check if Ransom table is empty
function IsEmpty()  {
  var count = new GlideAggregate('x_malwa_mb_threat_ransom');
  count.addAggregate('COUNT');
  count.query();
  var rowcount = 0;
  if (count.next())
     rowcount = count.getAggregate('COUNT');
  if (rowcount == 0)  {
    return true;
  }
  else if (rowcount == 1) {
    return false;
  }
  else {
    gs.info("IsEmpty function error" + "rowcount = " + rowcount);
  }
}



function main() {
  var credentials = GetCredentials();
  var auth_token = "Bearer " + GetAuthToken(credentials);
  var last_ransom = GetLastRansom("arw", auth_token);

  if (CheckRansomTable(last_ransom))  {
    UpdateRansomTable(last_ransom);
    CreateIncident(last_ransom);
  }

}

main();
