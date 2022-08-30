########################################################################################################################
#!!
#! @description: Fetch the details of a single entity from Micro Focus Service Management Automation X, by using the specified fields.
#!
#! @input saw_url: The Service Management Automation X URL to make the request to.
#!                 Examples: scheme://{serverAddress}.
#! @input sso_token: The Micro Focus SMAX SSO token for the session. Use the "Get SSO Token" utility to retrieve it.
#! @input tenant_id: The Micro Focus SMAX tenant Id.
#! @input entity_type: The Micro Focus SMAX entity type.
#! @input entity_id: The Micro Focus SMAX entity Id.
#! @input fields: The entity fields to get, separated by ",".
#!                Examples: Id,Status,OwnedByPerson,OwnedByPerson.Name,OwnedByPerson.Email
#! @input proxy_host: The proxy server used to access the web site.
#! @input proxy_port: The proxy server port.
#!                    Default value: 8080.
#!                    Valid values: -1, and positive integer values. When the value is '-1' the default port of the
#!                    scheme, specified in the 'proxy_host', will be used.
#! @input proxy_username: The user name used when connecting to the proxy. The 'auth_type' input will be used to
#!                        choose authentication type. The 'Basic' and 'Digest' proxy authentication type are supported.
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
#! @output entity_json: The retrieved entity as JSON.
#! @output error_json: The retrieved entity error as JSON.
#! @output return_result: The entire HTTP response.
#! @output op_status: The meta completion_status retrieved from Service Management Automation X or NO_RESULTS in case no entity is found.
#!!#
########################################################################################################################
namespace: io.cloudslang.microfocus.service_management_automation_x.commons
flow:
  name: get_entity
  inputs:
    - saw_url
    - sso_token
    - tenant_id
    - entity_type
    - entity_id
    - fields
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
    - get_ems_entity:
        do:
          io.cloudslang.base.http.http_client_get:
            - url: "${saw_url + '/rest/' + tenant_id + '/ems/' + entity_type + '/' + entity_id + '?layout=' + fields}"
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
            - connect_timeout: '${connect_timeout}'
            - headers: "${'Cookie:LWSSO_COOKIE_KEY=' + sso_token + '; TENANTID=' + tenant_id}"
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
          - SUCCESS: get_all_entities
          - FAILURE: get_meta_error_details
    - set_status_to_no_results:
        do:
          io.cloudslang.base.utils.do_nothing: []
        publish:
          - status: NO_RESULTS
        navigate:
          - SUCCESS: NO_RESULTS
          - FAILURE: on_failure
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
    - get_meta_error_details:
        do:
          io.cloudslang.microfocus.service_management_automation_x.utils.get_value:
            - json_obj: '${result_json}'
            - path: meta.errorDetails
        publish:
          - error_json: '${value}'
        navigate:
          - SUCCESS: FAILURE
          - FAILURE: on_failure
    - get_entity_0:
        do:
          io.cloudslang.microfocus.service_management_automation_x.utils.get_value:
            - json_obj: '${result_json}'
            - path: 'entities[0]'
        publish:
          - entity_json: '${value}'
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: on_failure
    - no_entities:
        do:
          io.cloudslang.base.math.compare_numbers:
            - value1: '${array_size}'
            - value2: '0'
        navigate:
          - GREATER_THAN: get_entity_0
          - EQUALS: set_status_to_no_results
          - LESS_THAN: set_status_to_no_results
    - get_array_size:
        do:
          io.cloudslang.microfocus.service_management_automation_x.utils.get_array_size:
            - array: '${entity_json}'
        publish:
          - array_size: '${size}'
        navigate:
          - SUCCESS: no_entities
          - FAILURE: on_failure
    - get_all_entities:
        do:
          io.cloudslang.microfocus.service_management_automation_x.utils.get_value:
            - json_obj: '${result_json}'
            - path: entities
        publish:
          - entity_json: '${value}'
        navigate:
          - SUCCESS: get_array_size
          - FAILURE: on_failure
  outputs:
    - entity_json: '${entity_json}'
    - error_json: '${error_json}'
    - return_result: '${return_result}'
    - op_status: '${status}'
  results:
    - FAILURE
    - SUCCESS
    - NO_RESULTS
extensions:
  graph:
    steps:
      get_ems_entity:
        x: 41
        'y': 75
      get_meta_completion_status:
        x: 216
        'y': 76
      get_all_entities:
        x: 402
        'y': 279
      set_status_to_no_results:
        x: 739
        'y': 495
        navigate:
          66cd1181-2ef7-da55-68c2-0f158f14d75f:
            targetId: afdd107b-0838-4008-10d8-544a409378f6
            port: SUCCESS
      get_array_size:
        x: 568
        'y': 282
      is_status_ok:
        x: 398
        'y': 80
      get_meta_error_details:
        x: 602
        'y': 78
        navigate:
          b916b41f-3014-c111-b3dc-28b02801ee24:
            targetId: 862ea345-f75f-89eb-6c18-efef20b95742
            port: SUCCESS
      get_entity_0:
        x: 914
        'y': 284
        navigate:
          eb77ba77-8ea0-dd09-ff36-6b5471f1cb1d:
            targetId: 0a5b2ed3-c73f-d76c-6dfd-879d8f11f742
            port: SUCCESS
      no_entities:
        x: 731
        'y': 288
    results:
      FAILURE:
        862ea345-f75f-89eb-6c18-efef20b95742:
          x: 807
          'y': 81
      SUCCESS:
        0a5b2ed3-c73f-d76c-6dfd-879d8f11f742:
          x: 1050
          'y': 282
      NO_RESULTS:
        afdd107b-0838-4008-10d8-544a409378f6:
          x: 953
          'y': 498
