{
  "vpcs": [
    {
      "id": "vpc-xxxx",
      "internetGateway": { "id": "igw-xxxx" },
      "subnets": {
        "public": [
          {
            "id": "subnet-aaa",
            "resources": {
              "ec2Instances": [{ "id": "i-123" }],
              "rdsInstances": []
            }
          }
        ],
        "private": [
          {
            "id": "subnet-bbb",
            "resources": {
              "ec2Instances": [],
              "rdsInstances": [{ "id": "eni-xyz" }]
            }
          }
        ]
      }
    }
  ]
}
