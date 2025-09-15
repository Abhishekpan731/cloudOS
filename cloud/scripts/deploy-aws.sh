#!/bin/bash

# CloudOS AWS Deployment Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="$SCRIPT_DIR/../terraform/aws"

# Default values
CLUSTER_NAME="cloudos-cluster"
AWS_REGION="us-west-2"
MASTER_INSTANCE_TYPE="t3.large"
NODE_INSTANCE_TYPE="t3.medium"
NODE_COUNT=3
SSH_KEY_NAME=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}"
    echo "=================================="
    echo "  CloudOS AWS Deployment Script"
    echo "=================================="
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy CloudOS cluster to AWS

Options:
    -n, --cluster-name NAME     Cluster name (default: cloudos-cluster)
    -r, --region REGION         AWS region (default: us-west-2)
    -m, --master-type TYPE      Master instance type (default: t3.large)
    -t, --node-type TYPE        Node instance type (default: t3.medium)
    -c, --node-count COUNT      Number of compute nodes (default: 3)
    -k, --ssh-key KEY_NAME      AWS SSH key pair name (required)
    -h, --help                  Show this help message

Examples:
    $0 --ssh-key my-keypair
    $0 --cluster-name production --region us-east-1 --node-count 5 --ssh-key my-keypair
EOF
}

check_dependencies() {
    print_info "Checking dependencies..."

    # Check for AWS CLI
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI not found. Please install it first."
        echo "Install: https://aws.amazon.com/cli/"
        exit 1
    fi

    # Check for Terraform
    if ! command -v terraform &> /dev/null; then
        print_error "Terraform not found. Please install it first."
        echo "Install: https://terraform.io/downloads"
        exit 1
    fi

    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS credentials not configured. Run 'aws configure' first."
        exit 1
    fi

    print_success "All dependencies found"
}

validate_ssh_key() {
    print_info "Validating SSH key..."

    if [ -z "$SSH_KEY_NAME" ]; then
        print_error "SSH key name is required. Use --ssh-key option."
        exit 1
    fi

    # Check if key exists in AWS
    if ! aws ec2 describe-key-pairs --key-names "$SSH_KEY_NAME" --region "$AWS_REGION" &> /dev/null; then
        print_error "SSH key '$SSH_KEY_NAME' not found in region '$AWS_REGION'"
        echo ""
        print_info "Available keys in region:"
        aws ec2 describe-key-pairs --region "$AWS_REGION" --query 'KeyPairs[].KeyName' --output text
        exit 1
    fi

    print_success "SSH key validated"
}

deploy_infrastructure() {
    print_info "Deploying CloudOS infrastructure..."

    cd "$TERRAFORM_DIR"

    # Initialize Terraform
    print_info "Initializing Terraform..."
    terraform init

    # Plan deployment
    print_info "Creating deployment plan..."
    terraform plan \
        -var "cluster_name=$CLUSTER_NAME" \
        -var "aws_region=$AWS_REGION" \
        -var "master_instance_type=$MASTER_INSTANCE_TYPE" \
        -var "node_instance_type=$NODE_INSTANCE_TYPE" \
        -var "node_count=$NODE_COUNT" \
        -var "ssh_key_name=$SSH_KEY_NAME" \
        -out=cloudos.plan

    # Confirm deployment
    echo ""
    print_warning "About to deploy CloudOS cluster with the following configuration:"
    echo "  Cluster Name: $CLUSTER_NAME"
    echo "  AWS Region: $AWS_REGION"
    echo "  Master Instance: $MASTER_INSTANCE_TYPE"
    echo "  Node Instance: $NODE_INSTANCE_TYPE"
    echo "  Node Count: $NODE_COUNT"
    echo "  SSH Key: $SSH_KEY_NAME"
    echo ""
    read -p "Continue with deployment? (y/N): " -n 1 -r
    echo

    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Deployment cancelled."
        exit 0
    fi

    # Apply deployment
    print_info "Applying Terraform configuration..."
    terraform apply cloudos.plan

    if [ $? -eq 0 ]; then
        print_success "Infrastructure deployed successfully!"
    else
        print_error "Infrastructure deployment failed!"
        exit 1
    fi
}

show_outputs() {
    print_info "Getting deployment information..."

    cd "$TERRAFORM_DIR"

    MASTER_IP=$(terraform output -raw master_public_ip)
    CLUSTER_ENDPOINT=$(terraform output -raw cluster_endpoint)
    SSH_COMMAND=$(terraform output -raw ssh_connection)

    echo ""
    print_success "CloudOS cluster deployed successfully!"
    echo ""
    echo "Cluster Information:"
    echo "==================="
    echo "Cluster Name: $CLUSTER_NAME"
    echo "Master IP: $MASTER_IP"
    echo "Web UI: $CLUSTER_ENDPOINT"
    echo "SSH Command: $SSH_COMMAND"
    echo ""
    echo "Node IPs:"
    terraform output -json node_public_ips | jq -r '.[]' | while read ip; do
        echo "  - $ip"
    done
    echo ""
    print_info "The cluster is initializing. It may take 5-10 minutes for all services to be ready."
    print_info "Check the web UI at: $CLUSTER_ENDPOINT"
}

wait_for_cluster() {
    print_info "Waiting for cluster to become ready..."

    cd "$TERRAFORM_DIR"
    MASTER_IP=$(terraform output -raw master_public_ip)

    # Wait for master to be ready
    for i in {1..30}; do
        if curl -s -k "https://$MASTER_IP/api/v1/status" > /dev/null; then
            print_success "Master node is ready!"
            break
        fi

        if [ $i -eq 30 ]; then
            print_warning "Master node is taking longer than expected to start."
            print_info "You can check the status manually at: https://$MASTER_IP"
            break
        fi

        echo -n "."
        sleep 10
    done
}

cleanup() {
    print_warning "Cleaning up deployment..."

    cd "$TERRAFORM_DIR"

    terraform destroy \
        -var "cluster_name=$CLUSTER_NAME" \
        -var "aws_region=$AWS_REGION" \
        -var "master_instance_type=$MASTER_INSTANCE_TYPE" \
        -var "node_instance_type=$NODE_INSTANCE_TYPE" \
        -var "node_count=$NODE_COUNT" \
        -var "ssh_key_name=$SSH_KEY_NAME" \
        -auto-approve

    print_success "Cleanup completed!"
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -n|--cluster-name)
            CLUSTER_NAME="$2"
            shift 2
            ;;
        -r|--region)
            AWS_REGION="$2"
            shift 2
            ;;
        -m|--master-type)
            MASTER_INSTANCE_TYPE="$2"
            shift 2
            ;;
        -t|--node-type)
            NODE_INSTANCE_TYPE="$2"
            shift 2
            ;;
        -c|--node-count)
            NODE_COUNT="$2"
            shift 2
            ;;
        -k|--ssh-key)
            SSH_KEY_NAME="$2"
            shift 2
            ;;
        --cleanup)
            CLEANUP_MODE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Main execution
print_header

if [ "$CLEANUP_MODE" = true ]; then
    cleanup
    exit 0
fi

check_dependencies
validate_ssh_key
deploy_infrastructure
show_outputs
wait_for_cluster

echo ""
print_success "CloudOS deployment completed!"
print_info "Visit the web UI to manage your cluster and add more nodes."