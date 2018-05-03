// Get JSON formatted credentials
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

// Get endpoint ID by its name
function GetEndpointId(name, auth_token) {
  var sm = new sn_ws.RESTMessageV2('x_malwa_mb_threat.Get Endpoints', 'Default GET');
  sm.setRequestHeader("Authorization", auth_token);
  var response = sm.execute();
  var responseBody = response.getBody();
  var httpStatus = response.getStatusCode();
  if (httpStatus != 200)  {
    gs.info('HTTP Error (GetEndpointId):' + httpStatus);
  }
  var parser = new global.JSON();
  var parsedData = parser.decode(responseBody);
  for (var i = 0; i < parsedData.machines.length; i++) {
    if (name == parsedData.machines[i].name)  {
      gs.info("ID of the endpoint " + name + " is " + parsedData.machines[i].id);
      return parsedData.machines[i].id;
    }
  }
}

// Run threat scan for selected endpointId
function RunThreatScan(endpointId, auth_token)  {
  var sm = new sn_ws.RESTMessageV2('x_malwa_mb_threat.Run Threat Scan', 'Default POST');
  var remove = true;
  var body = '{"command":"command.threat.scan","data":"{\\"scan_settings\\":{\\"type\\":\\"ThreatScan\\",\\"remove\\":' + remove +'}}","machine_ids":[\"' + endpointId + '\"]}';
  sm.setRequestHeader("Authorization", auth_token);
  sm.setRequestBody(body);
  var response = sm.execute();
  var responseBody = response.getBody();
  var httpStatus = response.getStatusCode();
  if (httpStatus != 200)  {
    gs.info('HTTP Error (RunThreatScan):' + httpStatus);
  }
}

// Get Malwarebytes scan ID
function GetScanId(endpointId, auth_token)  {
  var sm = new sn_ws.RESTMessageV2('x_malwa_mb_threat.Get Scan ID', 'Default GET');
  sm.setRequestHeader("Authorization", auth_token);
  sm.setQueryParameter("machine_id", endpointId);
  sm.setQueryParameter("page_size", "1");
  var response = sm.execute();
  var responseBody = response.getBody();
  var httpStatus = response.getStatusCode();
  if (httpStatus != 200)  {
    gs.info('HTTP Error (GetScanId):' + httpStatus);
  }
  var parser = new global.JSON();
  var parsedData = parser.decode(responseBody);
  var id = parsedData.jobs[0].id;
  gs.info("Malwarebytes Threat Scan Id: " + id);
  return id;
}

// Return computer name by sys_id
function SysIdToName(sys_id)  {
  var gr = new GlideRecord('x_malwa_mb_threat_scans_history');
  gr.addQuery("sys_id", sys_id);
  gr.query();
  while (gr.next()) {
    return gr.affected_ci.name;
  }
}

// Add scan ID to Scan History table and update scan status to "Initiated"
function UpdateScanStatus(sys_id, scan_id, endpointId) {
  var gr = new GlideRecord('x_malwa_mb_threat_scans_history');
  gr.addQuery("sys_id", sys_id);
  gr.query();
//  gs.info("Sys_id:" + sys_id);
  while (gr.next()) {
//    gs.info("Sys_id:" + sys_id);
    if (gr.sys_id == sys_id) {
      gr.scan_id = scan_id;
      gr.scan_status = "Initiated";
      gr.machine_id = endpointId;
      gr.update();
    }
  }
}

// Get sys_id for records where the status is "New"
function GetSysIDs() {
  var sys_ids = [];
  var gr = new GlideRecord('x_malwa_mb_threat_scans_history');
  gr.addQuery("scan_status","New");
  gr.query();
  while (gr.next()) {
    sys_ids.unshift(gr.sys_id.toString());
  }
  if (sys_ids.length === 0) {
    gs.info("There are no new Malwarebytes scans to be initiated ");
  }
  return sys_ids;
}

function main() {
  var scan_id = "";
  var credentials = GetCredentials();
  var auth_token = "Bearer " + GetAuthToken(credentials);
  var sys_ids = GetSysIDs();
  for (var i = 0; i < sys_ids.length; i++) {
    var name = SysIdToName(sys_ids[i]);
    var endpointId = GetEndpointId(name, auth_token);
    gs.info("Endpoints ID: " + endpointId);
    gs.info("Initiating Malwarebytes Threat Scan for " + name + " (" + endpointId + ")");
    RunThreatScan(endpointId, auth_token);
    scan_id = GetScanId(endpointId, auth_token);
    if (scan_id != undefined) {
      UpdateScanStatus(sys_ids[i], scan_id, endpointId);
    }
    else if (scan_id == undefined)  {
      gs.info("Scan ID is undefined!");
    }
  }
}

main();
