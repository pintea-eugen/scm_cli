########################################################################################################################
#!!
#! @description: Queries Micro Focus Service Management Automation X incident, using the REST API call.
#!
#! @input saw_url: The Service Management Automation X URL to make the request to.
#!                 Examples: scheme://{serverAddress}.
#! @input sso_token: The SSO token for the session.
#! @input tenant_id: The Micro Focus SMAX tenant Id.
#! @input query: The query filter.
#!               Examples: IdentityCard > 100 or FirstName = 'EmployeeFirst11'
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
#!                        you expect to communicate with, or from Certificate Authorities that you trust to identify other
#!                        parties.  If the protocol (specified by the 'url') is not 'https' or if trustAllRoots is 'true'
#!                        this input is ignored.
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
#! @output entity_json: The retrieved entities as JSON.
#! @output error_json: The retrieved entity error as JSON.
#! @output return_result: The entire HTTP result as JSON. This is the only output that gets populated if HTTP status is not 200.
#! @output op_status: The meta completion_status retrieved from Service Management Automation X.
#! @output result_count: The number of the results.
#!!#
########################################################################################################################
namespace: io.cloudslang.microfocus.service_management_automation_x.incidents
flow:
  name: query_incidents
  inputs:
    - saw_url
    - sso_token
    - tenant_id
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
    - query_entities:
        do:
          io.cloudslang.microfocus.service_management_automation_x.commons.query_entities:
            - saw_url: '${saw_url}'
            - sso_token: '${sso_token}'
            - tenant_id: '${tenant_id}'
            - entity_type: Incident
            - query: '${query}'
            - fields: '${fields}'
            - size: '${size}'
            - skip: '${skip}'
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
          - result_count
        navigate:
          - FAILURE: on_failure
          - SUCCESS: SUCCESS
          - NO_RESULTS: NO_RESULTS
  outputs:
    - entity_json: '${entity_json}'
    - error_json: '${error_json}'
    - return_result: '${return_result}'
    - op_status: '${op_status}'
    - result_count: '${result_count}'
  results:
    - SUCCESS
    - FAILURE
    - NO_RESULTS
extensions:
  graph:
    steps:
      query_entities:
        x: 100
        'y': 250
        navigate:
          701c0878-fb48-589b-02a8-717413eeb274:
            targetId: d2f304cf-bc0e-1c6b-df09-7b063bc828aa
            port: SUCCESS
          bc4902e4-51d4-bf32-be18-c163d1240ec2:
            targetId: 5c9bb863-3455-8cf8-9e95-1929b86c9ad3
            port: NO_RESULTS
    results:
      SUCCESS:
        d2f304cf-bc0e-1c6b-df09-7b063bc828aa:
          x: 400
          'y': 125
      NO_RESULTS:
        5c9bb863-3455-8cf8-9e95-1929b86c9ad3:
          x: 400
          'y': 375
