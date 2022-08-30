########################################################################################################################
#!!
#! @description: Fetch the details of multiple entities from Micro Focus Service Management Automation X, with the fields
#!               & the filter specified as inputs.
#!
#! @input saw_url: The Service Management Automation X URL to make the request to.
#!                 Examples: scheme://{serverAddress}.
#! @input sso_token: The SSO token for the session.
#! @input tenant_id: The Micro Focus SMAX tenant Id.
#! @input entity_type: The entity type to be queried.
#! @input query: The query filter Examples: IdentityCard > 100 or FirstName = 'EmployeeFirst11'
#! @input fields: The properties or sub-structure of a data resource should be returned by a service.
#! @input size: The maximum number of resources requested to be returned.
#! @input skip: How many resources should be skipped by specifying the starting index of the returned result. When not
#!              specified, its default value is zero, such that the first resource returned from the data-store is the
#!              first resource returned by the queried service.
#! @input proxy_host: The proxy server used to access the web site.
#! @input proxy_port: The proxy server port.
#!                    Default value: 8080.
#!                    Valid values: -1, and positive integer values. When the value is '-1' the default port of the scheme,
#!                    specified in the 'proxyHost', will be used.
#! @input proxy_username: The user name used when connecting to the proxy. The 'authType' input will be used to choose
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
#!                        you expect to communicate with, or from Certificate Authorities that you trust to identify
#!                        other parties.  If the protocol (specified by the 'url') is not 'https' or if trustAllRoots is
#!                        'true' this input is ignored.
#!                        Default value: <OO_Home>/java/lib/security/cacerts
#!                        Format: Java KeyStore (JKS)
#! @input trust_password: The password associated with the TrustStore file. If trustAllRoots is false and trustKeystore
#!                        is empty, trustPassword default will be supplied.
#!                        Default value: changeit
#! @input connect_timeout: The time to wait for a connection to be established, in seconds. A timeout value of '0'
#!                         represents an infinite timeout. Default value: 0 Format: an integer representing seconds
#!                         Examples: 10, 20
#!
#! @output entity_json: The retrieved entities as JSON.
#! @output error_json: The retrieved entity error as JSON.
#! @output return_result: The entire HTTP result as JSON. This is the only output that gets populated if HTTP status is not 200.
#! @output op_status: The meta completion_status retrieved from Service Management Automation X.
#! @output result_count: The number of the results.
#!!#
########################################################################################################################
namespace: io.cloudslang.microfocus.service_management_automation_x.commons
flow:
  name: query_entities
  inputs:
    - saw_url
    - sso_token
    - tenant_id
    - entity_type
    - query:
        required: false
    - fields
    - size:
        required: false
    - skip:
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
    - query_param_validator:
        do:
          io.cloudslang.microfocus.service_management_automation_x.utils.query_param_validator:
            - query: '${query}'
            - skip: '${skip}'
            - size: '${size}'
        publish:
          - query_params
          - return_code
          - error_message
        navigate:
          - SUCCESS: query_entities
    - query_entities:
        do:
          io.cloudslang.base.http.http_client_get:
            - url: "${saw_url + '/rest/' + tenant_id + '/ems/' + entity_type + '?layout=' + fields + query_params}"
            - auth_type: null
            - proxy_host: '${proxy_host}'
            - proxy_port: '${proxy_port}'
            - proxy_username: '${proxy_username}'
            - proxy_password:
                value: '${proxy_password}'
                sensitive: true
            - trust_all_roots: '${trust_all_roots}'
            - x_509_hostname_verifier: '${x509_hostname_verifier}'
            - trust_keystore: '${trust_keystore}'
            - trust_password:
                value: '${trust_password}'
                sensitive: true
            - connect_timeout: '${connect_timeout}'
            - socket_timeout: '0'
            - headers: "${'Cookie:LWSSO_COOKIE_KEY=' + sso_token + '; TENANTID=' + tenant_id}"
            - content_type: application/json
        publish:
          - status_code
          - result_json: '${return_result}'
          - return_result
          - status: FAILED
          - array_size: '0'
        navigate:
          - SUCCESS: get_meta_completion_status
          - FAILURE: on_failure
    - get_array_of_entities:
        do:
          io.cloudslang.microfocus.service_management_automation_x.utils.get_value:
            - json_obj: '${result_json}'
            - path: entities
        publish:
          - entity_json: '${value}'
        navigate:
          - SUCCESS: get_array_size
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
    - is_status_ok:
        do:
          io.cloudslang.base.strings.string_equals:
            - first_string: '${status}'
            - second_string: OK
            - ignore_case: 'true'
        navigate:
          - SUCCESS: get_array_of_entities
          - FAILURE: get_meta_error_details
    - get_meta_error_details:
        do:
          io.cloudslang.microfocus.service_management_automation_x.utils.get_value:
            - json_obj: '${result_json}'
            - path: meta.errorDetails
        publish:
          - error_json: '${value}'
          - return_code
          - array_size: '0'
        navigate:
          - SUCCESS: FAILURE
          - FAILURE: on_failure
    - is_array_size_greater_than_0:
        do:
          io.cloudslang.base.math.compare_numbers:
            - value1: '${array_size}'
            - value2: '0'
        navigate:
          - GREATER_THAN: SUCCESS
          - EQUALS: set_status_to_no_results
          - LESS_THAN: set_status_to_no_results
    - set_status_to_no_results:
        do:
          io.cloudslang.base.utils.do_nothing: []
        publish:
          - status: NO_RESULTS
        navigate:
          - SUCCESS: NO_RESULTS
          - FAILURE: on_failure
    - get_array_size:
        do:
          io.cloudslang.microfocus.service_management_automation_x.utils.get_array_size:
            - array: '${entity_json}'
        publish:
          - array_size: '${size}'
        navigate:
          - SUCCESS: is_array_size_greater_than_0
          - FAILURE: on_failure
  outputs:
    - entity_json: '${entity_json}'
    - error_json: '${error_json}'
    - return_result: '${return_result}'
    - op_status: '${status}'
    - result_count: '${array_size}'
  results:
    - FAILURE
    - SUCCESS
    - NO_RESULTS
extensions:
  graph:
    steps:
      get_meta_completion_status:
        x: 700
        'y': 250
      query_param_validator:
        x: 100
        'y': 250
      set_status_to_no_results:
        x: 2200
        'y': 375
        navigate:
          ef54ac6f-f626-e918-7001-3c09df170f21:
            targetId: 5badf563-8535-0a56-6bba-3da9c3b3ac72
            port: SUCCESS
      get_array_size:
        x: 1600
        'y': 125
      is_status_ok:
        x: 1000
        'y': 250
      query_entities:
        x: 400
        'y': 250
      get_meta_error_details:
        x: 1300
        'y': 375
        navigate:
          5b7540cd-a5a9-0946-940d-cb44b0675e70:
            targetId: e5046bc7-542c-5711-d270-60409311125e
            port: SUCCESS
      is_array_size_greater_than_0:
        x: 1900
        'y': 250
        navigate:
          5cebcc2b-4566-76fc-2f08-45cf34786953:
            targetId: 640917c4-aa05-e6c5-f1d0-92b3ef15f64f
            port: GREATER_THAN
      get_array_of_entities:
        x: 1300
        'y': 125
    results:
      FAILURE:
        e5046bc7-542c-5711-d270-60409311125e:
          x: 1600
          'y': 375
      SUCCESS:
        640917c4-aa05-e6c5-f1d0-92b3ef15f64f:
          x: 2200
          'y': 125
      NO_RESULTS:
        5badf563-8535-0a56-6bba-3da9c3b3ac72:
          x: 2500
          'y': 250
