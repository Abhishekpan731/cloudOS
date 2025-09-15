# CloudOS AWS Infrastructure
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.0"
}

provider "aws" {
  region = var.aws_region
}

# Variables
variable "aws_region" {
  description = "AWS region for CloudOS deployment"
  type        = string
  default     = "us-west-2"
}

variable "cluster_name" {
  description = "Name of the CloudOS cluster"
  type        = string
  default     = "cloudos-cluster"
}

variable "master_instance_type" {
  description = "EC2 instance type for master node"
  type        = string
  default     = "t3.large"
}

variable "node_instance_type" {
  description = "EC2 instance type for compute nodes"
  type        = string
  default     = "t3.medium"
}

variable "node_count" {
  description = "Number of compute nodes"
  type        = number
  default     = 3
}

variable "ssh_key_name" {
  description = "AWS SSH key pair name"
  type        = string
}

# Data sources
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# VPC and Networking
resource "aws_vpc" "cloudos_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name    = "${var.cluster_name}-vpc"
    Project = "CloudOS"
  }
}

resource "aws_internet_gateway" "cloudos_igw" {
  vpc_id = aws_vpc.cloudos_vpc.id

  tags = {
    Name    = "${var.cluster_name}-igw"
    Project = "CloudOS"
  }
}

resource "aws_route_table" "cloudos_public_rt" {
  vpc_id = aws_vpc.cloudos_vpc.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.cloudos_igw.id
  }

  tags = {
    Name    = "${var.cluster_name}-public-rt"
    Project = "CloudOS"
  }
}

resource "aws_subnet" "cloudos_public_subnet" {
  count             = min(length(data.aws_availability_zones.available.names), 3)
  vpc_id            = aws_vpc.cloudos_vpc.id
  cidr_block        = "10.0.${count.index + 1}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  map_public_ip_on_launch = true

  tags = {
    Name    = "${var.cluster_name}-public-subnet-${count.index + 1}"
    Project = "CloudOS"
  }
}

resource "aws_route_table_association" "cloudos_public_rta" {
  count          = length(aws_subnet.cloudos_public_subnet)
  subnet_id      = aws_subnet.cloudos_public_subnet[count.index].id
  route_table_id = aws_route_table.cloudos_public_rt.id
}

# Security Groups
resource "aws_security_group" "cloudos_master_sg" {
  name_prefix = "${var.cluster_name}-master-"
  vpc_id      = aws_vpc.cloudos_vpc.id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTPS (Web UI)
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # HTTP (API)
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # gRPC (Node communication)
  ingress {
    from_port   = 50051
    to_port     = 50051
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.cluster_name}-master-sg"
    Project = "CloudOS"
  }
}

resource "aws_security_group" "cloudos_node_sg" {
  name_prefix = "${var.cluster_name}-node-"
  vpc_id      = aws_vpc.cloudos_vpc.id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Node communication
  ingress {
    from_port   = 50052
    to_port     = 50052
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Container traffic
  ingress {
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name    = "${var.cluster_name}-node-sg"
    Project = "CloudOS"
  }
}

# Master Node
resource "aws_instance" "cloudos_master" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.master_instance_type
  key_name              = var.ssh_key_name
  subnet_id             = aws_subnet.cloudos_public_subnet[0].id
  vpc_security_group_ids = [aws_security_group.cloudos_master_sg.id]

  root_block_device {
    volume_type = "gp3"
    volume_size = 50
    encrypted   = true
  }

  user_data = base64encode(templatefile("${path.module}/scripts/master-init.sh", {
    cluster_name = var.cluster_name
  }))

  tags = {
    Name    = "${var.cluster_name}-master"
    Project = "CloudOS"
    Role    = "master"
  }
}

# Compute Nodes
resource "aws_instance" "cloudos_nodes" {
  count                  = var.node_count
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.node_instance_type
  key_name              = var.ssh_key_name
  subnet_id             = aws_subnet.cloudos_public_subnet[count.index % length(aws_subnet.cloudos_public_subnet)].id
  vpc_security_group_ids = [aws_security_group.cloudos_node_sg.id]

  root_block_device {
    volume_type = "gp3"
    volume_size = 30
    encrypted   = true
  }

  user_data = base64encode(templatefile("${path.module}/scripts/node-init.sh", {
    cluster_name  = var.cluster_name
    master_ip     = aws_instance.cloudos_master.private_ip
    node_index    = count.index
  }))

  depends_on = [aws_instance.cloudos_master]

  tags = {
    Name    = "${var.cluster_name}-node-${count.index + 1}"
    Project = "CloudOS"
    Role    = "compute"
  }
}

# Outputs
output "master_public_ip" {
  description = "Public IP address of the CloudOS master node"
  value       = aws_instance.cloudos_master.public_ip
}

output "master_private_ip" {
  description = "Private IP address of the CloudOS master node"
  value       = aws_instance.cloudos_master.private_ip
}

output "node_public_ips" {
  description = "Public IP addresses of the CloudOS compute nodes"
  value       = aws_instance.cloudos_nodes[*].public_ip
}

output "node_private_ips" {
  description = "Private IP addresses of the CloudOS compute nodes"
  value       = aws_instance.cloudos_nodes[*].private_ip
}

output "cluster_endpoint" {
  description = "CloudOS cluster endpoint"
  value       = "https://${aws_instance.cloudos_master.public_ip}"
}

output "ssh_connection" {
  description = "SSH connection command for master node"
  value       = "ssh -i ~/.ssh/${var.ssh_key_name}.pem ubuntu@${aws_instance.cloudos_master.public_ip}"
}