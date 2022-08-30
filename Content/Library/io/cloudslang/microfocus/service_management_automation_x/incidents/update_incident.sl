########################################################################################################################
#!!
#! @description: Updates an existing incident in Micro Focus Service Management Automation X, using the REST API call.
#!
#! @input saw_url: The Service Management Automation X URL to make the request to.
#!                 Examples: scheme://{serverAddress}.
#! @input sso_token: The SSO token for the session. Use the "Get SSO Token" utility to retrieve it.
#! @input tenant_id: The Micro Focus SMAX tenant Id.
#! @input entity_id: The Micro Focus SMAX entity to be updated.
#! @input incident_properties: A comma separated list of <key>:<value> pairs representing the properties to be updated for the
#!                    given incident.
#!                    Examples: "Status":"Pending","DisplayLabel":"UpdatedLabel"
#! @input incident_title: Value to be added to the incident "title" field in the form of a text having maximum length up
#!                        to 500 characters.
#! @input incident_description: Value to be added to the incident "description" field in the form of a text having maximum
#!                              length up to 1,000,000.
#! @input incident_impact: Value to be added to the incident "impact" field.
#!                         Example: SingleUser
#! @input incident_urgency: Value to be added to the incident "urgency" field.
#!                          Example: SlightDisruption
#! @input incident_reported_by: Value to be added to the incident "reported by" field in the form of an id.
#!                              Example: 10015
#! @input incident_current_assignment: Value to be added to the incident "current assignment" field.
#!                                     Example: ServiceDesk
#! @input incident_service_desk_group: Value to be added to the incident "service desk group" field in the form of an id.
#!                                     Example: 10004
#! @input incident_expert_group: Value to be added to the incident "expert group" field in the form of an id.
#!                               Example: 10004
#! @input incident_contact: Value to be added to the incident "contact" field in the form of an id.
#!                          Example: 10015
#! @input incident_service: Value to be added to the incident "service" field in the form of an id.
#!                          Example: 10088
#! @input incident_category: Value to be added to the incident "category" field in the form of an id.
#!                           Example: 10075
#! @input incident_model: Value to be added to the incident "model" field in the form of an id.
#!                        Example: 10076
#! @input incident_owner: Value to be added to the incident "owner" field in the form of an id.
#!                        Example: 10015
#! @input incident_expert_assignee: Value to be added to the incident "expert assignee" field in the form of an id.
#!                                  Example: 10015
#! @input incident_preferred_contact_method: Value to be added to the incident "preferred contact method" field.
#! @input incident_solution: Value to be added to the incident "solution" field in the form of a text having maximum
#!                           length up to 1,000,000.
#! @input incident_completion_code: Value to be added to the incident "completion code" field.
#! @input incident_closure_category: Value to be added to the incident "closure category" field.
#! @input incident_solved_time: Value to be added to the incident "solved time" field.
#! @input incident_status: Value to be added to the incident "status" field.
#! @input proxy_host: The proxy server used to access the web site.
#! @input proxy_port: The proxy server port.
#!                    Default value: 8080.
#!                    Valid values: -1, and positive integer values. When the value is '-1' the default port of the scheme,
#!                    specified in the 'proxy_host', will be used.
#! @input proxy_username: The user name used when connecting to the proxy. The 'auth_type' input will be used to choose
#!                        authentication type. The 'Basic' and 'Digest' proxy authentication type are supported.
#! @input proxy_password: The proxy server password associated with the proxyUsername input value.
#! @input trust_all_roots: Specifies whether to enable weak security over SSL/TSL. A certificate is trusted even if no
#!                         trusted certification authority issued it. Default value: false Valid values: true, false
#! @input x509_hostname_verifier: Specifies the way the server hostname must match a domain name in the subject's
#!                                Common Name (CN) or subjectAltName field of the X.509 certificate. The hostname verification
#!                                system prevents communication with other hosts other than the ones you intended.
#!                                This is done by checking that the hostname is in the subject alternative name extension
#!                                of the certificate. This system is designed to ensure that, if an attacker(Man In The Middle)
#!                                redirects traffic to his machine, the client will not accept the connection. If you
#!                                set this input to "allow_all", this verification is ignored and you become vulnerable
#!                                to security attacks. For the value "browser_compatible" the hostname verifier works
#!                                the same way as Curl and Firefox. The hostname must match either the first CN, or any
#!                                of the subject-alts. A wildcard can occur in the CN, and in any of the subject-alts.
#!                                The only difference between "browser_compatible" and "strict" is that a wildcard
#!                                (such as "*.foo.com") with "browser_compatible" matches all subdomains, including "a.b.foo.com".
#!                                From the security perspective, to provide protection against possible Man-In-The-Middle
#!                                attacks, we strongly recommend to use "strict" option.
#!                                Default value: strict
#!                                Valid values: strict, browser_compatible, allow_all
#! @input trust_keystore: The pathname of the Java TrustStore file. This contains certificates from other parties that
#!                        you expect to communicate with, or from Certificate Authorities that you trust to identify other
#!                        parties. If the protocol (specified by the 'url') is not 'https' or if trust_all_roots is 'true'
#!                        this input is ignored.
#!                        Default value: <OO_Home>/java/lib/security/cacerts
#!                        Format: Java KeyStore (JKS)
#! @input trust_password: The password associated with the TrustStore file. If trust_all_roots is false and trust_keystore
#!                        is empty, trust_password default will be supplied.
#!                        Default value: changeit
#! @input connect_timeout: The time to wait for a connection to be established, in seconds. A timeout value of '0'
#!                         represents an infinite timeout.
#!                         Default value: 0
#!                         Format: an integer representing seconds
#!                         Examples: 10, 20
#!
#! @output return_result: The entire result as JSON. It gets populated even when HTTP status is not 200.
#! @output error_json: The retrieved error as JSON.
#! @output op_status: The meta completion_status retrieved from Service Management Automation X.
#!!#
########################################################################################################################
namespace: io.cloudslang.microfocus.service_management_automation_x.incidents
flow:
  name: update_incident
  inputs:
    - saw_url
    - sso_token
    - tenant_id
    - entity_id
    - incident_properties:
        required: false
    - incident_title:
        required: false
    - incident_descripion:
        required: false
    - incident_impact:
        required: false
    - incident_urgency:
        required: false
    - incident_reported_by:
        required: false
    - incident_current_assignment:
        required: false
    - incident_service_desk_group:
        required: false
    - incident_expert_group:
        required: false
    - incident_contact:
        required: false
    - incident_service:
        required: false
    - incident_category:
        required: false
    - incident_model:
        required: false
    - incident_owner:
        required: false
    - incident_expert_assignee:
        required: false
    - incident_preferred_contact_method:
        required: false
    - incident_solution:
        required: false
    - incident_completion_code:
        required: false
    - incident_closure_category:
        required: false
    - incident_solved_time:
        required: false
    - incident_status:
        required: false
    - proxy_host:
        required: false
    - proxy_port:
        default: '8080'
        required: false
    - proxy_username:
        required: false
    - proxy_password:
        required: false
        sensitive: true
    - trust_all_roots:
        default: 'false'
        required: false
    - x509_hostname_verifier:
        default: strict
        required: false
    - trust_keystore:
        required: false
    - trust_password:
        required: false
        sensitive: true
    - connect_timeout:
        default: '0'
        required: false
  workflow:
    - is_null:
        do:
          io.cloudslang.base.utils.is_null:
            - variable: '${incident_properties}'
        navigate:
          - IS_NULL: entity_param_vaidator
          - IS_NOT_NULL: update_entities_1
    - update_entities:
        do:
          io.cloudslang.microfocus.service_management_automation_x.commons.update_entities:
            - saw_url: '${saw_url}'
            - sso_token: '${sso_token}'
            - tenant_id: '${tenant_id}'
            - json_body: "${'{\"entity_type\":\"Incident\",\"properties\":{\"Id\":' + entity_id + ',' + parameters + '}}'}"
            - proxy_host: '${proxy_host}'
            - proxy_port: '${proxy_port}'
            - proxy_username: '${proxy_username}'
            - proxy_password:
                value: '${proxy_password}'
                sensitive: true
            - trust_all_roots: '${trust_all_roots}'
            - x509_hostname_verifier: '${x509_hostname_verifier}'
            - trust_keystore: '${trust_keystore}'
            - trust_password:
                value: '${trust_password}'
                sensitive: true
            - connect_timeout: '${connect_timeout}'
        publish:
          - return_result
          - error_json
          - op_status
        navigate:
          - FAILURE: on_failure
          - SUCCESS: SUCCESS
    - entity_param_vaidator:
        do:
          io.cloudslang.microfocus.service_management_automation_x.utils.entity_param_vaidator:
            - incident_title: '${incident_title}'
            - incident_descripion: '${incident_descripion}'
            - incident_impact: '${incident_impact}'
            - incident_urgency: '${incident_urgency}'
            - incident_reported_by: '${incident_reported_by}'
            - incident_current_assignment: '${incident_current_assignment}'
            - incident_service_desk_group: '${incident_service_desk_group}'
            - incident_expert_group: '${incident_expert_group}'
            - incident_contact: '${incident_contact}'
            - incident_service: '${incident_service}'
            - incident_category: '${incident_category}'
            - incident_model: '${incident_model}'
            - incident_owner: '${incident_owner}'
            - incident_expert_assignee: '${incident_expert_assignee}'
            - incident_preferred_contact_method: '${incident_preferred_contact_method}'
            - incident_solution: '${incident_solution}'
            - incident_completion_code: '${incident_completion_code}'
            - incident_closure_category: '${incident_closure_category}'
            - incident_solved_time: '${incident_solved_time}'
            - incident_status: '${incident_status}'
        publish:
          - parameters
          - return_code
          - error_message
        navigate:
          - SUCCESS: update_entities
          - FAILURE: on_failure
    - update_entities_1:
        do:
          io.cloudslang.microfocus.service_management_automation_x.commons.update_entities:
            - saw_url: '${saw_url}'
            - sso_token: '${sso_token}'
            - tenant_id: '${tenant_id}'
            - json_body: "${'{\"entity_type\":\"Incident\",\"properties\":{\"Id\":' + entity_id + ',' + incident_properties + '}}'}"
            - proxy_host: '${proxy_host}'
            - proxy_port: '${proxy_port}'
            - proxy_username: '${proxy_username}'
            - proxy_password:
                value: '${proxy_password}'
                sensitive: true
            - trust_all_roots: '${trust_all_roots}'
            - x509_hostname_verifier: '${x509_hostname_verifier}'
            - trust_keystore: '${trust_keystore}'
            - trust_password:
                value: '${trust_password}'
                sensitive: true
            - connect_timeout: '${connect_timeout}'
        publish:
          - return_result
          - error_json
          - op_status
        navigate:
          - FAILURE: on_failure
          - SUCCESS: SUCCESS
  outputs:
    - return_result: '${return_result}'
    - error_json: '${error_json}'
    - op_status: '${op_status}'
  results:
    - FAILURE
    - SUCCESS
extensions:
  graph:
    steps:
      is_null:
        x: 100
        'y': 250
      update_entities:
        x: 700
        'y': 125
        navigate:
          f9366420-f39a-a622-9c26-9a92fae889f1:
            targetId: 90f50f32-18f5-aded-c71f-d9e3a0bc8501
            port: SUCCESS
      entity_param_vaidator:
        x: 400
        'y': 125
      update_entities_1:
        x: 400
        'y': 375
        navigate:
          35608f0d-0089-f3e5-f605-71313d547541:
            targetId: 90f50f32-18f5-aded-c71f-d9e3a0bc8501
            port: SUCCESS
    results:
      SUCCESS:
        90f50f32-18f5-aded-c71f-d9e3a0bc8501:
          x: 700
          'y': 375
