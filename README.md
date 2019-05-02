# Notice 
By default these stacks will create resources in your eu-west-1 region. You can change this in sample/region/config/config.yaml

# Required
* AWS account 
* AWS IAM role with admin permissions 
* Sceptre
```
pip3 install virtualenv  # you need pip 3 for this command
python3 -m virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
```

* Kubectl
  - https://docs.aws.amazon.com/eks/latest/userguide/install-kubectl.html

* aws-iam-authenticator
  - https://docs.aws.amazon.com/eks/latest/userguide/install-aws-iam-authenticator.html

# Commands
To create launch stacks run the following command in sample/region -directory:
```
sceptre launch-env test 
```

Get access to EKS cluster:
```
aws eks --region <region> update-kubeconfig --name <cluster_name>

example:
aws eks --region eu-west-1 update-kubeconfig --name thesis-eks-cluster
```

Connect EC2 instances to EKS cluster. Before this to work you will need to replace ``<node instance role arn>`` placeholder in this file with instance role arn:
```
kubectl apply -f sample/kubernetes_template/aws-auth-cm.yaml
```

Launch deployment:
```
kubectl apply -f sample/kubernetes_template/deployment.yaml
```

Create loadbalancer:
```
kubectl apply -f sample/kubernetes_template/service.yaml
```

Create cluster autoscaler. Before this to work you will need to replace ``<Node Autoscaling group name>`` placeholder in this file with Autoscaling group name:
```
kubectl apply -f sample/kubernetes_template/CA.yaml
```
