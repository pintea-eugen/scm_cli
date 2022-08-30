########################################################################################################################
#!!
#! @description: Creates a new request in Micro Focus Service Management Automation X, using the REST API call.
#!
#! @input saw_url: The Service Management Automation X URL to make the request to.
#!                 Examples: scheme://{serverAddress}.
#! @input sso_token: The SSO token for the session. Use the "Get SSO Token" utility to retrieve it.
#! @input tenant_id: The Micro Focus SMAX tenant Id.
#! @input request_properties: The properties in JSON format for the entity to be created.
#!                    Examples: {"Urgency":"NoDisruption","RegisteredForActualService":"11453","Category":"10937",
#!                    "OwnedByPerson":"10069","ContactPerson":"10069","PreferredContactMethod":"PreferredContactMethodEmail",
#!                    "ClosureCategory":"10937","DisplayLabel":"Incident 01","Description":"<p>Test Incident</p>",
#!                    "DataDomains":["Public"],"KnowledgeCandidate":true}
#! @input request_title: Value to be added to the request "title" field in the form of a text having maximum length up to
#!                       500 characters.
#! @input request_description: Value to be added to the request "description" field in the form of a text having maximum
#!                             length up to 1,000,000.
#! @input request_requested_by: Value to be added to the request "requested by" field in the form of an id.
#!                              Example: 10015
#! @input request_requested_for: Value to be added to the request "requested for" field.
#! @input request_impact: Value to be added to the request "impact" field.
#!                        Example: SingleUser
#! @input request_urgency: Value to be added to the request "urgency" field.
#!                         Example: SlightDisruption
#! @input request_offering: Value to be added to the request "offering" field.
#! @input request_service: Value to be added to the request "service" field in the form of an id.
#!                         Example: 10088
#! @input request_preferred_contact_method: Value to be added to the request "preferred contact method" field.
#! @input request_device: Value to be added to the request "device" field.
#! @input request_infrastructure_and_peripheral: Value to be added to the request "infrastructure and peripheral" field.
#! @input request_subscription: Value to be added to the request "subscription" field.
#! @input proxy_host: The proxy server used to access the web site.
#! @input proxy_port: The proxy server port.
#!                    Default value: 8080.
#!                    Valid values: -1, and positive integer values. When the value is '-1' the default port of the scheme,
#!                    specified in the 'proxy_host', will be used.
#! @input proxy_username: The user name used when connecting to the proxy. The 'auth_type' input will be used to choose
#!                        authentication type. The 'Basic' and 'Digest' proxy authentication type are supported.
#! @input proxy_password: The proxy server password associated with the proxy_username input value.
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
#! @input connect_timeout: The time to wait for a connection to be established, in seconds. A timeout value of '0' represents
#!                         an infinite timeout.
#!                         Default value: 0
#!                         Format: an integer representing seconds
#!                         Examples: 10, 20
#!
#! @output created_id: The ID of the created incident.
#! @output entity_json: The retrieved entity as JSON.
#! @output error_json: The retrieved entity error as JSON.
#! @output return_result: The entire HTTP result as JSON. This is the only output that gets populated if HTTP status is not 200.
#! @output op_status: The meta completion_status retrieved from Service Management Automation X.
#!!#
########################################################################################################################
namespace: io.cloudslang.microfocus.service_management_automation_x.requests
flow:
  name: create_request
  inputs:
    - saw_url
    - sso_token
    - tenant_id
    - request_properties:
        required: false
    - request_title:
        required: false
    - request_description:
        required: false
    - request_requested_by:
        required: false
    - request_requested_for:
        required: false
    - request_impact:
        required: false
    - request_urgency:
        required: false
    - request_offering:
        required: false
    - request_service:
        required: false
    - request_preferred_contact_method:
        required: false
    - request_device:
        required: false
    - request_infrastructure_and_peripheral:
        required: false
    - request_subscription:
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
            - variable: '${request_properties}'
        navigate:
          - IS_NULL: entity_param_vaidator
          - IS_NOT_NULL: create_entity_1
    - create_entity:
        do:
          io.cloudslang.microfocus.service_management_automation_x.commons.create_entity:
            - saw_url: '${saw_url}'
            - sso_token: '${sso_token}'
            - tenant_id: '${tenant_id}'
            - json_body: "${'{\"entity_type\":\"Request\",\"properties\":{' + parameters + '}}'}"
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
          - created_id
          - entity_json
          - error_json
          - return_result
          - op_status
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: on_failure
    - entity_param_vaidator:
        do:
          io.cloudslang.microfocus.service_management_automation_x.utils.entity_param_vaidator:
            - request_title: '${request_title}'
            - request_description: '${request_description}'
            - request_requested_by: '${request_requested_by}'
            - request_requested_for: '${request_requested_for}'
            - request_impact: '${request_impact}'
            - request_urgency: '${request_urgency}'
            - request_preferred_contact_method: '${request_preferred_contact_method}'
            - request_offering: '${request_offering}'
            - request_service: '${request_service}'
            - request_device: '${request_device}'
            - request_infrastructure_and_peripheral: '${request_infrastructure_and_peripheral}'
            - request_subscription: '${request_subscription}'
        publish:
          - parameters
          - error_message
          - return_code
        navigate:
          - SUCCESS: create_entity
          - FAILURE: on_failure
    - create_entity_1:
        do:
          io.cloudslang.microfocus.service_management_automation_x.commons.create_entity:
            - saw_url: '${saw_url}'
            - sso_token: '${sso_token}'
            - tenant_id: '${tenant_id}'
            - json_body: "${'{\"entity_type\":\"Request\",\"properties\":' + request_properties + '}'}"
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
          - created_id
          - entity_json
          - error_json
          - return_result
          - op_status
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: on_failure
  outputs:
    - created_id: '${created_id}'
    - entity_json: '${entity_json}'
    - error_json: '${error_json}'
    - return_result: '${return_result}'
    - op_status: '${op_status}'
  results:
    - SUCCESS
    - FAILURE
extensions:
  graph:
    steps:
      is_null:
        x: 100
        'y': 250
      create_entity:
        x: 700
        'y': 125
        navigate:
          f4989278-32a2-9352-9beb-08b0ce4860bb:
            targetId: 13b831e1-4988-6c8c-7860-1904569b983a
            port: SUCCESS
      entity_param_vaidator:
        x: 400
        'y': 125
      create_entity_1:
        x: 400
        'y': 375
        navigate:
          935fe4c0-ad95-6000-861b-c25e970ce739:
            targetId: 13b831e1-4988-6c8c-7860-1904569b983a
            port: SUCCESS
    results:
      SUCCESS:
        13b831e1-4988-6c8c-7860-1904569b983a:
          x: 700
          'y': 375
