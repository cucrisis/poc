provider "tfe" {
  hostname = "app.terraform.io"
  token    = var.tfe_token
}

variable "tfe_token" {
  description = "Terraform Enterprise token"
  type        = string
  sensitive   = true
}

variable "organization" {
  description = "Terraform Enterprise organization name"
  type        = string
}

variable "workspace" {
  description = "Terraform Enterprise workspace name"
  type        = string
}

variable "repo_consumer_task_path" {
  description = "The local path for the consumer task."
  type        = string
  default     = "./consumer_task"
}

variable "repo_consumer_crypto_agent_path" {
  description = "The local path for the consumer crypto agent."
  type        = string
  default     = "./consumer_crypto_agent"
}

variable "repo_producer_crypto_agent_path" {
  description = "The local path for the producer crypto agent."
  type        = string
  default     = "./producer_crypto_agent"
}

provider "aws" {
  region = "us-west-2"
}

resource "aws_kms_key" "s3_key" {
  description             = "KMS key for S3 data encryption"
  deletion_window_in_days = 10
}

resource "aws_kms_alias" "s3_key_alias" {
  name          = "alias/s3EncryptionKey"
  target_key_id = aws_kms_key.s3_key.id
}

resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_subnet" "main" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-west-2a"
}

resource "aws_internet_gateway" "gw" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table" "r" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.gw.id
  }
}

resource "aws_route_table_association" "a" {
  subnet_id      = aws_subnet.main.id
  route_table_id = aws_route_table.r.id
}

resource "aws_security_group" "sg" {
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "main_sg"
  }
}

resource "aws_instance" "producer_instance" {
  ami                         = "ami-0abcdef1234567890"
  instance_type               = "t2.micro"
  subnet_id                   = aws_subnet.main.id
  security_groups             = [aws_security_group.sg.name]
  associate_public_ip_address = true

  provisioner "file" {
    source      = var.repo_producer_crypto_agent_path
    destination = "/home/ec2-user/producer_crypto_agent"
  }

  user_data = <<-EOF
                #!/bin/bash

                # Function to log messages
                log_message() {
                    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
                }

                log_message "Starting producer crypto agent user data script"

                # Update system and install necessary packages
                log_message "Updating system and installing packages"
                sudo yum update -y
                sudo yum install -y aws-cli nodejs

                # Navigate to the producer crypto agent directory
                cd /home/ec2-user/producer_crypto_agent

                # Install npm dependencies if not already installed
                if [ ! -d "node_modules" ]; then
                    log_message "Installing npm dependencies"
                    npm install
                else
                    log_message "npm dependencies already installed"
                fi

                # Run the producer crypto agent if not already running
                if ! pgrep -f "node app.js"; then
                    log_message "Starting producer crypto agent"
                    node app.js &
                else
                    log_message "Producer crypto agent already running"
                fi

                log_message "Producer crypto agent user data script completed"
              EOF
              
  connection {
    type        = "ssh"
    user        = "ec2-user"
    private_key = file("~/.ssh/id_rsa")
    host        = self.public_ip
  }

  tags = {
    Name = "ProducerInstance"
  }
}

resource "aws_s3_bucket" "data_bucket" {
  bucket = "ctc-enclave-bucket"
}

resource "aws_iam_role" "nitro_enclave_role" {
  name = "nitro_enclave_role"

  assume_role_policy = <<-EOF
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": {
            "Service": "ec2.amazonaws.com"
          },
          "Action": "sts:AssumeRole"
        }
      ]
    }
  EOF
}

resource "aws_iam_role_policy_attachment" "attach_policy" {
  role       = aws_iam_role.nitro_enclave_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonS3FullAccess"
}

resource "aws_iam_instance_profile" "nitro_instance_profile" {
  name = "nitro_instance_profile"
  role = aws_iam_role.nitro_enclave_role.name
}

resource "aws_sqs_queue" "jobs_queue" {
  name = "jobs-queue"
}

resource "aws_instance" "consumer_instance" {
  ami                         = "ami-0abcdef1234567890"
  instance_type               = "m5.large"
  subnet_id                   = aws_subnet.main.id
  security_groups             = [aws_security_group.sg.name]
  iam_instance_profile        = aws_iam_instance_profile.nitro_instance_profile.name
  associate_public_ip_address = true

  provisioner "file" {
    source      = var.repo_consumer_task_path
    destination = "/home/ec2-user/consumer_task"
  }

  provisioner "file" {
    source      = var.repo_consumer_crypto_agent_path
    destination = "/home/ec2-user/consumer_crypto_agent"
  }

  user_data = <<-EOF
                #!/bin/bash

                # Function to log messages
                log_message() {
                    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1"
                }

                log_message "Starting user data script"

                # Update system and install necessary packages
                log_message "Updating system and installing packages"
                sudo yum update -y
                sudo amazon-linux-extras install aws-nitro-enclaves-cli -y
                sudo yum install -y aws-nitro-enclaves-cli-devel git docker

                # Add ec2-user to necessary groups if not already a member
                if ! groups ec2-user | grep -q "\bne\b"; then
                    log_message "Adding ec2-user to ne group"
                    sudo usermod -aG ne ec2-user
                fi

                if ! groups ec2-user | grep -q "\bdocker\b"; then
                    log_message "Adding ec2-user to docker group"
                    sudo usermod -aG docker ec2-user
                fi

                # Enable and start Docker service if not already running
                if ! sudo systemctl is-enabled docker; then
                    log_message "Enabling Docker service"
                    sudo systemctl enable docker
                fi

                if ! sudo systemctl is-active docker; then
                    log_message "Starting Docker service"
                    sudo systemctl start docker
                fi

                # Build Docker images if they don't already exist
                if ! sudo docker images | grep -q "enclave_base"; then
                    log_message "Building enclave_base Docker image"
                    cd /home/ec2-user/consumer_task
                    sudo docker build -t enclave_base .
                fi

                if ! sudo docker images | grep -q "nitro-enclave-container-ai-ml"; then
                    log_message "Building nitro-enclave-container-ai-ml Docker image"
                    cd /home/ec2-user/consumer_task
                    sudo docker build -t nitro-enclave-container-ai-ml:latest .
                fi

                # Build and run Nitro Enclave if not already running
                if [ ! -f /home/ec2-user/nitro-enclave-container-ai-ml.eif ]; then
                    log_message "Building Nitro Enclave image"
                    sudo nitro-cli build-enclave --docker-uri nitro-enclave-container-ai-ml:latest --output-file /home/ec2-user/nitro-enclave-container-ai-ml.eif
                fi

                if ! sudo nitro-cli describe-enclaves | grep -q "nitro-enclave-container-ai-ml"; then
                    log_message "Running Nitro Enclave"
                    sudo nitro-cli run-enclave --cpu-count 2 --memory 14336 --eif-path /home/ec2-user/nitro-enclave-container-ai-ml.eif
                fi

                # Create allowlist for Nitro Enclave if it doesn't already exist
                if [ ! -f /etc/nitro-enclaves/allowlist.json ]; then
                    log_message "Creating Nitro Enclave allowlist"
                    sudo mkdir -p /etc/nitro-enclaves/
                    sudo tee /etc/nitro-enclaves/allowlist.json > /dev/null <<EOL
                {
                  "allowlist": [
                    {
                      "service": "kms",
                      "actions": [
                        "Decrypt",
                        "Encrypt",
                        "GenerateDataKey",
                        "GenerateDataKeyWithoutPlaintext"
                      ]
                    }
                  ]
                }
                EOL
                    sudo chmod 755 /etc/nitro-enclaves/allowlist.json
                fi

                # Install and run the consumer crypto agent if not already running
                log_message "Installing and running consumer crypto agent"
                cd /home/ec2-user/consumer_crypto_agent
                npm install

                if ! pgrep -f "node app.js"; then
                    log_message "Starting consumer crypto agent"
                    node app.js &
                fi

                log_message "User data script completed"
              EOF

  connection {
    type        = "ssh"
    user        = "ec2-user"
    private_key = file("~/.ssh/id_rsa")
    host        = self.public_ip
  }

  tags = {
    Name = "ConsumerInstance"
  }
}

resource "aws_iam_policy" "kms_policy" {
  name = "nitro_kms_policy"

  policy = <<-EOF
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": [
            "kms:Decrypt",
            "kms:Encrypt",
            "kms:GenerateDataKey*"
          ],
          "Resource": "*"
        }
      ]
    }
  EOF
}

resource "aws_iam_role_policy_attachment" "attach_kms_policy" {
  role       = aws_iam_role.nitro_enclave_role.name
  policy_arn = aws_iam_policy.kms_policy.arn
}
