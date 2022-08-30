namespace: io.cloudslang.microfocus.service_management_automation_x.utils
operation:
  name: get_array_size
  inputs:
    - array
  python_action:
    use_jython: false
    script: "import json\n\ndef execute(array): \n    size = 0\n    return_code = 0\n    error_message = ''\n    \n    try:\n        json_array = json.loads(array)\n        for element in json_array:\n            size = size + 1\n    except Exception as e:\n        return_code = 1\n        error_message = str(e)\n        \n    return{\"size\":size, \"return_code\": return_code, \"error_message\": error_message}"
  outputs:
    - size
    - return_code
    - error_message
  results:
    - SUCCESS: "${return_code == '0'}"
    - FAILURE
