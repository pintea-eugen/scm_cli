namespace: test1
flow:
  name: test1
  workflow:
    - random_number_generator:
        do:
          io.cloudslang.base.math.random_number_generator:
            - min: '1'
            - max: '11'
        navigate:
          - SUCCESS: SUCCESS
          - FAILURE: on_failure
  results:
    - FAILURE
    - SUCCESS
extensions:
  graph:
    steps:
      random_number_generator:
        x: 160
        'y': 160
        navigate:
          01f783a4-4fa7-830b-e9a0-7f973bf058c9:
            targetId: 81350d56-2fd5-00d5-3fb1-3fcba79e2b21
            port: SUCCESS
    results:
      SUCCESS:
        81350d56-2fd5-00d5-3fb1-3fcba79e2b21:
          x: 360
          'y': 160
