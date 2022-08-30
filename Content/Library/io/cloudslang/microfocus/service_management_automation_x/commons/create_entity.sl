########################################################################################################################
#!!
#! @description: Creates a new entity in Micro Focus Service Management Automation X, using the REST API call.
#!               Notes: 
#!               1. The inputJSON is part of the body of the rest call. It contains the entity type and properties. 
#!               Example for inputJSON:
#!               {
#!               "entity_type": "Incident",
#!               "properties": {
#!               "RegisteredForActualService": "10088",
#!               "DisplayLabel": "test",
#!               "Description": "<p>test</p>",
#!               "UserOptions": "{\"complexTypeProperties\":[{\"properties\":{}}]}"
#!               }
#!               } 
#!               use this format. 
#!               You can add more properties, or remove unnecessary properties as long as you include the required properties.
#!               Each Entity has different required properties.
#!
#! @input saw_url: The Service Management Automation X URL to make the request to.
#!                 Examples: scheme://{serverAddress}.
#! @input sso_token: The SSO token for the session. Use the "Get SSO Token" utility to retrieve it.
#! @input tenant_id: The Micro Focus SMAX tenant Id.
#! @input json_body: The JSON format for the entity to be created.
#! @input proxy_host: The proxy server used to access the web site.
#! @input proxy_port: The proxy server port.
#!                    Default value: 8080.
#!                    Valid values: -1, and positive integer values. When the value is '-1' the default port of the
#!                    scheme, specified in the 'proxy_host', will be used.
#! @input proxy_username: The user name used when connecting to the proxy. The 'auth_type' input will be used to choose
#!                        authentication type. The 'Basic' and 'Digest' proxy authentication type are supported.
#! @input proxy_password: The proxy server password associated with the proxy_username input value.
#! @input trust_all_roots: Specifies whether to enable weak security over SSL/TSL. A certificate is trusted even if no
#!                         trusted certification authority issued it.
#!                         Default value: false
#!                         Valid values: true, false
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
#! @input trust_keystore: The pathname of the Java TrustStore file. This contains certificates from other parties that you
#!                        expect to communicate with, or from Certificate Authorities that you trust to identify other parties.
#!                        If the protocol (specified by the 'url') is not 'https' or if trust_all_roots is 'true' this input is ignored.
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
#! @output created_id: The ID of the created entity.
#! @output entity_json: The retrieved entity as JSON.
#! @output error_json: The retrieved entity error as JSON.
#! @output return_result: The entire HTTP result as JSON. This is the only output that gets populated if HTTP status is not 200.
#! @output op_status: The meta completion_status retrieved from Service Management Automation X.
#!!#
########################################################################################################################
namespace: io.cloudslang.microfocus.service_management_automation_x.commons
flow:
  name: create_entity
  inputs:
    - saw_url
    - sso_token
    - tenant_id
    - json_body
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
    - http_client_post:
        do:
          io.cloudslang.base.http.http_client_post:
            - url: "${saw_url + '/rest/' + tenant_id + '/ems/bulk'}"
            - auth_type: Basic
            - proxy_host: '${proxy_host}'
            - proxy_port: '${proxy_port}'
            - proxy_username: '${proxy_username}'
            - proxy_password:
                value: '${proxy_password}'
                sensitive: true
            - tls_version: TLSv1.2
            - allowed_cyphers: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_DHE_RSA_WITH_AES_256_CBC_SHA256,TLS_DHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_CBC_SHA256,TLS_RSA_WITH_AES_128_CBC_SHA256'
            - trust_all_roots: '${trust_all_roots}'
            - x_509_hostname_verifier: '${x509_hostname_verifier}'
            - trust_keystore: '${trust_keystore}'
            - trust_password:
                value: '${trust_password}'
                sensitive: true
            - keystore_password:
                value: null
                sensitive: true
            - request_character_set: ISO-8859-1
            - headers: "${'Cookie:LWSSO_COOKIE_KEY=' + sso_token + '; TENANTID=' + tenant_id}"
            - body: "${'{\"entities\": [' + json_body +  '],  \"operation\": \"CREATE\"}'}"
            - content_type: application/json
        publish:
          - status_code
          - result_json: '${return_result}'
          - return_result
          - status: FAILED
        navigate:
          - SUCCESS: get_meta_completion_status
          - FAILURE: on_failure
    - is_status_ok:
        do:
          io.cloudslang.base.strings.string_equals:
            - first_string: '${status}'
            - second_string: OK
            - ignore_case: 'true'
        navigate:
          - SUCCESS: get_entity_id
          - FAILURE: get_error_details
    - get_meta_completion_status:
        do:
          io.cloudslang.microfocus.service_management_automation_x.utils.get_value:
            - json_obj: '${result_json}'
            - path: meta.completion_status
        publish:
          - status: '${value}'
        navigate:
          - SUCCESS: is_status_ok
          - FAILURE: on_failure
    - get_entity_id:
        do:
          io.cloudslang.microfocus.service_management_automation_x.utils.get_value:
            - json_obj: '${result_json}'
            - path: 'entity_result_list[0].entity.properties.Id'
        publish:
          - created_id: '${value}'
        navigate:
          - SUCCESS: get_entity
          - FAILURE: on_failure
    - get_entity:
        do:
          io.cloudslang.microfocus.service_management_automation_x.utils.get_value:
            - json_obj: '${result_json}'
            - path: 'entity_result_list[0].entity'
        publish:
          - entity_json: '${value}'
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: on_failure
    - get_error_details:
        do:
          io.cloudslang.microfocus.service_management_automation_x.utils.get_value:
            - json_obj: '${result_json}'
            - path: 'entity_result_list[0].errorDetails'
        publish:
          - error_json: '${value}'
        navigate:
          - SUCCESS: FAILURE
          - FAILURE: on_failure
  outputs:
    - created_id: '${created_id}'
    - entity_json: '${entity_json}'
    - error_json: '${error_json}'
    - return_result: '${return_result}'
    - op_status: '${status}'
  results:
    - SUCCESS
    - FAILURE
extensions:
  graph:
    steps:
      http_client_post:
        x: 41
        'y': 76
      is_status_ok:
        x: 376
        'y': 78
      get_meta_completion_status:
        x: 195
        'y': 76
      get_entity_id:
        x: 553
        'y': 75
      get_entity:
        x: 740
        'y': 80
        navigate:
          7a6132a3-b0e6-d3a2-ad7c-30bbbc0e05fd:
            targetId: 65dd5717-27ee-1107-56d5-b9f77193fc14
            port: SUCCESS
      get_error_details:
        x: 377
        'y': 285
        navigate:
          02057364-9714-0e1f-30ff-0aca3f86d7d4:
            targetId: ab248a48-7a1e-ebea-e8dd-d8095e1118c1
            port: SUCCESS
    results:
      SUCCESS:
        65dd5717-27ee-1107-56d5-b9f77193fc14:
          x: 890
          'y': 78
      FAILURE:
        ab248a48-7a1e-ebea-e8dd-d8095e1118c1:
          x: 550
          'y': 288
