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


# Setup



aws eks --region <region> update-kubeconfig --name <cluster_name>
