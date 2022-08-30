namespace: io.cloudslang.microfocus.service_management_automation_x.utils
operation:
  name: get_value
  inputs:
    - json_obj
    - path
  python_action:
    use_jython: false
    script: "import json\r\nimport re\r\n\r\ndef execute(path, json_obj):\r\n    error_message = ''\r\n    return_code = 0\r\n    data = json.loads(json_obj)\r\n    paths = path.split('.')\r\n    try:\r\n        for i in range(0, len(paths)):\r\n            if ''.join([i for i in paths[i] if not i.isdigit()]).replace(\"[\", \"\").replace(\"]\", \"\") in data:\r\n                if \"[\" in paths[i] and \"]\" in paths[i]:\r\n                    data = data[''.join([i for i in paths[i] if not i.isdigit()]).replace(\"[\", \"\").replace(\"]\", \"\")][int(re.sub('\\D', '', paths[i]))]\r\n                else:\r\n                    data = data[paths[i]]\r\n            else:\r\n                error_message = 'Path not found.'\r\n                return_code = 1\r\n                data = \"\"\r\n    except Exception as e:\r\n        return_code = 1\r\n        error_message = str(e)\r\n    return{\"value\":str(data).replace(\"\\\"\", \"\\\\\\\"\").replace(\"\\'\", \"\\\"\").replace(\"True\", \"true\").replace(\"False\", \"false\"), \"error_message\":error_message, \"return_code\":return_code}"
  outputs:
    - value
    - error_message
    - return_code
  results:
    - SUCCESS: "${return_code == '0'}"
    - FAILURE
