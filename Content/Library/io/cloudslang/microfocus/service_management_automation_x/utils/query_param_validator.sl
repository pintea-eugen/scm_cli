namespace: io.cloudslang.microfocus.service_management_automation_x.utils
operation:
  name: query_param_validator
  inputs:
    - query:
        required: false
    - skip:
        required: false
    - size:
        required: false
  python_action:
    use_jython: false
    script: "from urllib.parse import quote\ndef execute(query, skip, size):\n    query_params = \"\"\n    return_code = 0\n    error_message = \"\"\n    \n    try:\n        if query:\n            query_params = \"&filter=\" + quote(query, safe='')\n        else:\n            query_params = \"&filter=\"\n        \n        if size:\n            query_params = query_params + \"&size=\" + size\n        elif not size:\n            query_params = query_params + \"&size=\"\n            \n        if skip:\n            query_params = query_params + \"&skip=\" + skip\n        elif not skip:\n            query_params = query_params + \"&skip=\"\n    \n    except Exception as e:\n        return_code = 1\n        error_message = str(e)\n        \n    return {\"query_params\": query_params, \"return_code\":return_code, \"error_message\":error_message}"
  outputs:
    - query_params
    - return_code
    - error_message
  results:
    - SUCCESS
