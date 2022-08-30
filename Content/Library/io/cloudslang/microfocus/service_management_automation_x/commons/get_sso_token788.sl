########################################################################################################################
#!!
#! @description: Gets an SSO Token from Micro Focus Service Management Automation X.
#!                
#!               Notes:
#!               1. Currently, Service Management Automation X does not support 2-way SSL certificate authentication.
#!
#! @input saw_url: The Service Management Automation X URL to make the request to.
#!                 Examples: scheme://{serverAddress}.
#! @input tenant_id: The Micro Focus SMAX tenant Id.
#! @input username: The user name used for authentication.
#! @input password: The password used for authentication.
#! @input token_type: Token generator endpoint to be used.
#!                    Valid values: "token" - SMAX version 2020.11 and later. "login" - SMAX versions older than 2020.11.
#!                    Default value: token
#! @input proxy_host: The proxy server used to access the web site.
#! @input proxy_port: The proxy server port.
#!                    Default value: 8080.
#!                    Valid values: -1, and positive integer values. When the value is '-1' the default port of the
#!                    scheme, specified in the 'proxyHost', will be used.
#! @input proxy_username: The user name used when connecting to the proxy. The 'authType' input will be used to choose
#!                        authentication type. The 'Basic' and 'Digest' proxy authentication type are supported.
#! @input proxy_password: The proxy server password associated with the proxyUsername input value.
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
#! @output sso_token: The ssoToken retrieved by the request.
#! @output status_code: The HTTP status code. Format: 1xx (Informational - Request received, continuing process),
#!                      2xx (Success - The action was successfully received, understood, and accepted),
#!                      3xx (Redirection - Further action must be taken in order to complete the request),
#!                      4xx (Client Error - The request contains bad syntax or cannot be fulfilled),
#!                      5xx Server Error - The server failed to fulfil an apparently valid request)
#!                      Examples: 200, 404
#! @output exception: In case of success response, this result is empty. In case of failure response, this result
#!                    contains the java stack trace of the runtime exception.
#! @output response_headers: The list containing the headers of the response message, separated by newline.
#!                           Format: This is conforming with HTTP standard for headers (RFC 2616).
#! @output return_code: '0' if success, '-1' otherwise.
#!
#! @result FAILURE: the operation completed successfully.
#! @result SUCCESS: an error occurred.
#!!#
########################################################################################################################
namespace: io.cloudslang.microfocus.service_management_automation_x.commons
flow:
  name: get_sso_token
  inputs:
    - saw_url
    - tenant_id:
        required: false
    - username
    - password:
        sensitive: true
    - token_type:
        default: token
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
    - check_empty_tenant_id:
        do:
          io.cloudslang.base.utils.is_null:
            - variable: '${tenant_id}'
        navigate:
          - IS_NULL: check_token_type
          - IS_NOT_NULL: check_token_type_1
    - check_token_type:
        do:
          io.cloudslang.base.strings.string_equals:
            - first_string: '${token_type}'
            - second_string: token
            - ignore_case: 'true'
        navigate:
          - SUCCESS: get_access_token
          - FAILURE: get_access_token_1
    - get_access_token:
        do:
          io.cloudslang.base.http.http_client_post:
            - url: "${saw_url + '/auth/authentication-endpoint/authenticate/token'}"
            - auth_type: Basic
            - username: '${username}'
            - password:
                value: '${password}'
                sensitive: true
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
            - request_character_set: ISO-8859-1
            - connect_timeout: '${connect_timeout}'
            - headers: null
            - body: "${'{ \"Login\":\"' + username + '\", \"Password\": \"' + password + '\" }'}"
            - content_type: application/json
        publish:
          - return_result
          - error_message
          - return_code
          - status_code
          - response_headers
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: on_failure
    - get_access_token_1:
        do:
          io.cloudslang.base.http.http_client_post:
            - url: "${saw_url + '/auth/authentication-endpoint/authenticate/login'}"
            - auth_type: Basic
            - username: '${username}'
            - password:
                value: '${password}'
                sensitive: true
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
            - request_character_set: ISO-8859-1
            - connect_timeout: '${connect_timeout}'
            - headers: null
            - body: "${'{ \"Login\":\"' + username + '\", \"Password\": \"' + password + '\" }'}"
            - content_type: application/json
        publish:
          - return_result
          - error_message
          - return_code
          - status_code
          - response_headers
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: on_failure
    - check_token_type_1:
        do:
          io.cloudslang.base.strings.string_equals:
            - first_string: '${token_type}'
            - second_string: token
            - ignore_case: 'true'
        navigate:
          - SUCCESS: get_access_token_2
          - FAILURE: get_access_token_3
    - get_access_token_2:
        do:
          io.cloudslang.base.http.http_client_post:
            - url: "${saw_url + '/auth/authentication-endpoint/authenticate/token?TENANTID=' + tenant_id}"
            - auth_type: Basic
            - username: '${username}'
            - password:
                value: '${password}'
                sensitive: true
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
            - request_character_set: ISO-8859-1
            - connect_timeout: '${connect_timeout}'
            - headers: null
            - body: "${'{ \"Login\":\"' + username + '\", \"Password\": \"' + password + '\" }'}"
            - content_type: application/json
        publish:
          - return_result
          - error_message
          - return_code
          - status_code
          - response_headers
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: on_failure
    - get_access_token_3:
        do:
          io.cloudslang.base.http.http_client_post:
            - url: "${saw_url + '/auth/authentication-endpoint/authenticate/login?TENANTID=' + tenant_id}"
            - auth_type: Basic
            - username: '${username}'
            - password:
                value: '${password}'
                sensitive: true
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
            - request_character_set: ISO-8859-1
            - connect_timeout: '${connect_timeout}'
            - headers: null
            - body: "${'{ \"Login\":\"' + username + '\", \"Password\": \"' + password + '\" }'}"
            - content_type: application/json
        publish:
          - return_result
          - error_message
          - return_code
          - status_code
          - response_headers
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: on_failure
  outputs:
    - sso_token: '${return_result}'
    - status_code: '${status_code}'
    - exception: '${error_message}'
    - response_headers: '${response_headers}'
    - return_code: '${return_code}'
  results:
    - FAILURE
    - SUCCESS
extensions:
  graph:
    steps:
      check_empty_tenant_id:
        x: 100
        'y': 450
      check_token_type:
        x: 400
        'y': 225
      get_access_token:
        x: 700
        'y': 112.5
        navigate:
          75c2d360-6851-a03e-e376-923ca35a00c1:
            targetId: 94394906-e188-639f-4584-da68d3817e3f
            port: SUCCESS
      get_access_token_1:
        x: 700
        'y': 337.5
        navigate:
          ae4ee928-511b-b414-88d0-b3c87fd8dcdc:
            targetId: 94394906-e188-639f-4584-da68d3817e3f
            port: SUCCESS
      check_token_type_1:
        x: 400
        'y': 675
      get_access_token_2:
        x: 700
        'y': 562.5
        navigate:
          e35d003d-411f-e5bf-800d-35cd79c9b1b2:
            targetId: 94394906-e188-639f-4584-da68d3817e3f
            port: SUCCESS
      get_access_token_3:
        x: 700
        'y': 787.5
        navigate:
          bb36d9ff-4d5a-0151-c6c4-49dd7ae3d548:
            targetId: 94394906-e188-639f-4584-da68d3817e3f
            port: SUCCESS
    results:
      SUCCESS:
        94394906-e188-639f-4584-da68d3817e3f:
          x: 1000
          'y': 450
