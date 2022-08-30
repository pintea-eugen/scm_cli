########################################################################################################################
#!!
#! @description: Fetch Incident properties from Micro Focus Service Management Automation X, using the REST API call.
#!
#! @input saw_url: The Service Management Automation X URL to make the request to.
#!                 Examples: scheme://{serverAddress}.
#! @input sso_token: The Micro Focus SMAX SSO token for the session. Use the "Get SSO Token" utility to retrieve it.
#! @input tenant_id: The Micro Focus SMAX tenant Id.
#! @input entity_id: The Micro Focus SMAX entity Id.
#! @input fields: The entity fields to get, separated by ",".
#!                Examples: Id,Status,OwnedByPerson,OwnedByPerson.Name,OwnedByPerson.Email
#! @input proxy_host: The proxy server used to access the web site.
#! @input proxy_port: The proxy server port.
#!                    Default value: 8080.
#!                    Valid values: -1, and positive integer values. When the value is '-1' the default port of the scheme,
#!                    specified in the 'proxyHost', will be used.
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
#! @input trust_keystore: The pathname of the Java TrustStore file. This contains certificates from other parties that
#!                        you expect to communicate with, or from Certificate Authorities that you trust to identify other parties.
#!                        If the protocol (specified by the 'url') is not 'https' or if trustAllRoots is 'true' this input is ignored.
#!                        Default value: <OO_Home>/java/lib/security/cacerts
#!                        Format: Java KeyStore (JKS)
#! @input trust_password: The password associated with the TrustStore file. If trustAllRoots is false and trustKeystore
#!                        is empty, trustPassword default will be supplied.
#!                        Default value: changeit
#! @input connect_timeout: The time to wait for a connection to be established, in seconds. A timeout value of '0' represents
#!                         an infinite timeout.
#!                         Default value: 0
#!                         Format: an integer representing seconds
#!                         Examples: 10, 20
#!
#! @output entity_json: This incident as JSON retrieved by the request.
#! @output error_json: The error as JSON retrieved by the request.
#! @output return_result: The entire HTTP response.
#! @output op_status: The meta completion_status retrieved by the request or NO_RESULTS in case entity is not found.
#!!#
########################################################################################################################
namespace: io.cloudslang.microfocus.service_management_automation_x.incidents
flow:
  name: get_incident
  inputs:
    - saw_url
    - sso_token
    - tenant_id
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
    - get_entity:
        do:
          io.cloudslang.microfocus.service_management_automation_x.commons.get_entity:
            - saw_url: '${saw_url}'
            - sso_token: '${sso_token}'
            - tenant_id: '${tenant_id}'
            - entity_type: Incident
            - entity_id: '${entity_id}'
            - fields: '${fields}'
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
          - entity_json
          - error_json
          - return_result
          - op_status
        navigate:
          - FAILURE: on_failure
          - SUCCESS: SUCCESS
          - NO_RESULTS: NO_RESULTS
  outputs:
    - entity_json: '${entity_json}'
    - error_json: '${error_json}'
    - return_result: '${return_result}'
    - op_status: '${op_status}'
  results:
    - FAILURE
    - SUCCESS
    - NO_RESULTS
extensions:
  graph:
    steps:
      get_entity:
        x: 100
        'y': 250
        navigate:
          0b4aeb45-a7d3-bd6b-55e0-6b18684e1dc9:
            targetId: e932ac56-638d-7f3a-6974-3324b66c40c4
            port: SUCCESS
          d588c246-b269-66a2-5ab9-856d1fcab341:
            targetId: a2f851c6-cb9d-af56-09c5-55a474d4e29c
            port: NO_RESULTS
    results:
      NO_RESULTS:
        a2f851c6-cb9d-af56-09c5-55a474d4e29c:
          x: 400
          'y': 375
      SUCCESS:
        e932ac56-638d-7f3a-6974-3324b66c40c4:
          x: 400
          'y': 125
