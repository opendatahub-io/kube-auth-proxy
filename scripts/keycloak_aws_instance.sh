#!/bin/bash
set -euo pipefail

KEYCLOAK_VERSION="26.0"
INFO_FILE="keycloak-instance-info.txt"
MANAGED_BY_TAG="Key=ManagedBy,Value=odh-keycloak-script"

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

CREATED_RESOURCES=()
SETUP_IN_PROGRESS=false

cleanup_on_failure() {
    local exit_code=$?
    if [ "$SETUP_IN_PROGRESS" != "true" ]; then
        return
    fi
    SETUP_IN_PROGRESS=false

    if [ ${#CREATED_RESOURCES[@]} -eq 0 ]; then
        return
    fi

    echo ""
    echo -e "${RED}Setup failed (exit code: $exit_code). Cleaning up created resources...${NC}"

    for resource in "${CREATED_RESOURCES[@]}"; do
        local type="${resource%%:*}"
        local id="${resource#*:}"
        case "$type" in
            instance)
                echo -e "   Terminating instance $id..."
                aws ec2 terminate-instances --instance-ids "$id" &>/dev/null || true
                aws ec2 wait instance-terminated --instance-ids "$id" 2>/dev/null || true
                ;;
            sg)
                echo -e "   Deleting security group $id..."
                sleep 3
                aws ec2 delete-security-group --group-id "$id" &>/dev/null || true
                ;;
            subnet)
                echo -e "   Deleting subnet $id..."
                aws ec2 delete-subnet --subnet-id "$id" &>/dev/null || true
                ;;
            igw)
                local vpc="${resource##*,}"
                local gw_id="${id%%,*}"
                echo -e "   Detaching and deleting internet gateway $gw_id..."
                aws ec2 detach-internet-gateway --vpc-id "$vpc" --internet-gateway-id "$gw_id" &>/dev/null || true
                aws ec2 delete-internet-gateway --internet-gateway-id "$gw_id" &>/dev/null || true
                ;;
            rt)
                echo -e "   Deleting route table $id..."
                aws ec2 delete-route-table --route-table-id "$id" &>/dev/null || true
                ;;
            vpc)
                echo -e "   Deleting VPC $id..."
                sleep 2
                aws ec2 delete-vpc --vpc-id "$id" &>/dev/null || true
                ;;
            keypair)
                echo -e "   Deleting key pair $id..."
                aws ec2 delete-key-pair --key-name "$id" &>/dev/null || true
                rm -f "${id}.pem" 2>/dev/null || true
                ;;
        esac
    done
    CREATED_RESOURCES=()
    echo -e "${YELLOW}Cleanup done. Some resources may need manual removal.${NC}"
}

trap 'cleanup_on_failure' EXIT

show_menu() {
    clear
    echo ""
    echo -e "${CYAN}Keycloak AWS EC2 Management Script${NC}"
    echo -e "${CYAN}====================================${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} Create Keycloak instance"
    echo -e "  ${RED}2)${NC} Destroy Keycloak instance"
    echo -e "  ${BLUE}3)${NC} Show instance status"
    echo -e "  ${YELLOW}4)${NC} Exit"
    echo ""
    read -p "Enter your choice [1-4]: " CHOICE
}

check_aws() {
    if ! command -v aws &>/dev/null; then
        echo -e "${RED}Error: AWS CLI is not installed.${NC}"
        exit 1
    fi

    if ! aws sts get-caller-identity &>/dev/null; then
        echo -e "${RED}Error: AWS credentials not configured. Run 'aws configure' first.${NC}"
        exit 1
    fi
}

detect_or_prompt_region() {
    AWS_REGION=$(aws configure get region 2>/dev/null || true)
    if [ -z "$AWS_REGION" ]; then
        echo -e "${YELLOW}No default AWS region configured.${NC}"
        read -p "Enter AWS region (e.g., us-east-1): " AWS_REGION
        if [ -z "$AWS_REGION" ]; then
            echo -e "${RED}Error: AWS region is required.${NC}"
            exit 1
        fi
    fi
    export AWS_DEFAULT_REGION="$AWS_REGION"
    echo -e "   ${GREEN}OK${NC} Using region: $AWS_REGION"
}

add_sg_rule() {
    local sg_id="$1"
    local port="$2"
    local cidr="$3"
    local desc="$4"

    local result
    set +e
    result=$(aws ec2 authorize-security-group-ingress \
        --group-id "$sg_id" \
        --protocol tcp \
        --port "$port" \
        --cidr "$cidr" 2>&1)
    local rc=$?
    set -e

    if [ $rc -eq 0 ]; then
        echo -e "   ${GREEN}OK${NC} Added $desc (port $port from $cidr)"
    elif echo "$result" | grep -q "InvalidPermission.Duplicate"; then
        echo -e "   ${GREEN}OK${NC} $desc (port $port) already exists"
    else
        echo -e "   ${YELLOW}Warning: Could not add $desc: $result${NC}"
    fi
}

collect_user_input() {
    echo -e "${YELLOW}Configuration:${NC}"
    echo ""

    read -p "Instance type [t3.medium]: " INSTANCE_TYPE
    INSTANCE_TYPE=${INSTANCE_TYPE:-t3.medium}
    echo -e "   ${GREEN}OK${NC} Instance type: $INSTANCE_TYPE"

    read -p "Key pair name [keycloak-keypair]: " KEY_NAME
    KEY_NAME=${KEY_NAME:-keycloak-keypair}
    echo -e "   ${GREEN}OK${NC} Key pair: $KEY_NAME"

    while true; do
        read -sp "Keycloak admin password (required, min 8 chars): " ADMIN_PASSWORD
        echo ""
        if [ -z "$ADMIN_PASSWORD" ]; then
            echo -e "   ${RED}Password cannot be empty.${NC}"
            continue
        fi
        if [ ${#ADMIN_PASSWORD} -lt 8 ]; then
            echo -e "   ${RED}Password must be at least 8 characters.${NC}"
            continue
        fi
        read -sp "Confirm password: " ADMIN_PASSWORD_CONFIRM
        echo ""
        if [ "$ADMIN_PASSWORD" != "$ADMIN_PASSWORD_CONFIRM" ]; then
            echo -e "   ${RED}Passwords do not match. Try again.${NC}"
            continue
        fi
        break
    done
    echo -e "   ${GREEN}OK${NC} Admin password set"

    read -p "Instance name tag [keycloak]: " INSTANCE_NAME
    INSTANCE_NAME=${INSTANCE_NAME:-keycloak}
    echo -e "   ${GREEN}OK${NC} Instance name: $INSTANCE_NAME"
}

setup_key_pair() {
    echo -e "${YELLOW}Setting up key pair...${NC}"
    if ! aws ec2 describe-key-pairs --key-names "$KEY_NAME" &>/dev/null; then
        aws ec2 create-key-pair --key-name "$KEY_NAME" --query 'KeyMaterial' --output text >"${KEY_NAME}.pem"
        chmod 400 "${KEY_NAME}.pem"
        CREATED_RESOURCES+=("keypair:$KEY_NAME")
        echo -e "   ${GREEN}OK${NC} Key pair created: ${KEY_NAME}.pem"
    else
        echo -e "   ${GREEN}OK${NC} Using existing key pair: $KEY_NAME"
    fi
}

get_user_ip() {
    echo -e "${YELLOW}Getting your IP address...${NC}"
    MY_IP=$(curl -s --connect-timeout 5 https://checkip.amazonaws.com || true)
    if [ -z "$MY_IP" ]; then
        echo -e "   ${RED}Warning: Could not detect your public IP.${NC}"
        echo -e "   ${YELLOW}Opening SSH to 0.0.0.0/0 is insecure. Please provide your IP or CIDR.${NC}"
        read -rp "Enter your IP or CIDR for SSH access (e.g., 1.2.3.4/32): " SSH_CIDR
        if [ -z "$SSH_CIDR" ]; then
            echo -e "   ${RED}Error: SSH CIDR is required.${NC}"
            exit 1
        fi
        echo -e "   ${GREEN}OK${NC} Using SSH CIDR: $SSH_CIDR"
    else
        SSH_CIDR="${MY_IP}/32"
        echo -e "   ${GREEN}OK${NC} Your IP: $MY_IP"
    fi
}

setup_vpc_and_subnet() {
    echo -e "${YELLOW}Creating VPC and subnet...${NC}"

    local az1
    az1=$(aws ec2 describe-availability-zones --query 'AvailabilityZones[0].ZoneName' --output text)

    local vpc_cidr="10.1.0.0/16"
    local vpc_name="keycloak-vpc"

    VPC_ID=$(aws ec2 create-vpc \
        --cidr-block "$vpc_cidr" \
        --tag-specifications "ResourceType=vpc,Tags=[{Key=Name,Value=$vpc_name},{$MANAGED_BY_TAG}]" \
        --query 'Vpc.VpcId' --output text)

    if [ -z "$VPC_ID" ] || [ "$VPC_ID" == "None" ]; then
        echo -e "   ${RED}Error: Failed to create VPC${NC}"
        exit 1
    fi
    CREATED_RESOURCES+=("vpc:$VPC_ID")
    echo -e "   ${GREEN}OK${NC} Created VPC: $VPC_ID"

    aws ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-hostnames
    aws ec2 modify-vpc-attribute --vpc-id "$VPC_ID" --enable-dns-support

    local igw_id
    igw_id=$(aws ec2 create-internet-gateway \
        --tag-specifications "ResourceType=internet-gateway,Tags=[{Key=Name,Value=${vpc_name}-igw},{$MANAGED_BY_TAG}]" \
        --query 'InternetGateway.InternetGatewayId' --output text)
    aws ec2 attach-internet-gateway --vpc-id "$VPC_ID" --internet-gateway-id "$igw_id"
    CREATED_RESOURCES+=("igw:${igw_id},${VPC_ID}")
    echo -e "   ${GREEN}OK${NC} Created and attached Internet Gateway: $igw_id"

    local subnet_cidr="10.1.1.0/24"
    SUBNET_ID=$(aws ec2 create-subnet \
        --vpc-id "$VPC_ID" \
        --cidr-block "$subnet_cidr" \
        --availability-zone "$az1" \
        --tag-specifications "ResourceType=subnet,Tags=[{Key=Name,Value=${vpc_name}-public},{$MANAGED_BY_TAG}]" \
        --query 'Subnet.SubnetId' --output text)
    CREATED_RESOURCES+=("subnet:$SUBNET_ID")
    echo -e "   ${GREEN}OK${NC} Created subnet: $SUBNET_ID"

    aws ec2 modify-subnet-attribute --subnet-id "$SUBNET_ID" --map-public-ip-on-launch

    local rt_id
    rt_id=$(aws ec2 create-route-table \
        --vpc-id "$VPC_ID" \
        --tag-specifications "ResourceType=route-table,Tags=[{Key=Name,Value=${vpc_name}-public-rt},{$MANAGED_BY_TAG}]" \
        --query 'RouteTable.RouteTableId' --output text)
    CREATED_RESOURCES+=("rt:$rt_id")

    aws ec2 create-route --route-table-id "$rt_id" --destination-cidr-block 0.0.0.0/0 --gateway-id "$igw_id" >/dev/null
    aws ec2 associate-route-table --subnet-id "$SUBNET_ID" --route-table-id "$rt_id" >/dev/null

    echo -e "   ${GREEN}OK${NC} Configured routing"
}

setup_security_group() {
    echo -e "${YELLOW}Creating security group...${NC}"

    local sg_name="keycloak-sg"
    SG_ID=$(aws ec2 create-security-group \
        --group-name "$sg_name" \
        --description "Keycloak security group" \
        --vpc-id "$VPC_ID" \
        --query 'GroupId' --output text)

    if [ -z "$SG_ID" ] || [ "$SG_ID" == "None" ]; then
        echo -e "   ${RED}Error: Failed to create security group${NC}"
        exit 1
    fi
    CREATED_RESOURCES+=("sg:$SG_ID")
    echo -e "   ${GREEN}OK${NC} Created security group: $SG_ID"

    echo -e "   Adding security group rules..."
    add_sg_rule "$SG_ID" 22 "$SSH_CIDR" "SSH"
    add_sg_rule "$SG_ID" 443 "0.0.0.0/0" "HTTPS"

    echo ""
    echo -e "   ${YELLOW}Note: Only HTTPS (443) and SSH (22) are exposed. No HTTP.${NC}"
}

generate_user_data_script() {
    local password_escaped
    password_escaped=$(printf '%s' "$ADMIN_PASSWORD" | sed "s/'/'\\\\''/g")

    cat <<EOF
#!/bin/bash
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1

echo "=== Starting Keycloak installation ==="
date

echo "Updating system..."
yum update -y || true

echo "Installing Docker..."
yum install docker -y || { echo "yum install docker failed"; exit 1; }

echo "Starting Docker..."
systemctl start docker
systemctl enable docker

echo "Waiting for Docker to be ready..."
for i in \$(seq 1 40); do
    docker info >/dev/null 2>&1 && break
    sleep 3
done
docker info >/dev/null 2>&1 || { echo "Docker did not become ready"; exit 1; }

usermod -a -G docker ec2-user

echo "Cleaning up disk space..."
yum clean all
rm -rf /var/cache/yum/*
docker system prune -af --volumes 2>/dev/null || true

echo "Pulling Keycloak ${KEYCLOAK_VERSION} image..."
docker pull quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} || {
    echo "Retrying image pull..."
    docker system prune -af 2>/dev/null || true
    sleep 5
    docker pull quay.io/keycloak/keycloak:${KEYCLOAK_VERSION}
}

docker rm -f keycloak 2>/dev/null || true

echo "Generating self-signed certificate..."
mkdir -p /opt/keycloak-certs
cd /opt/keycloak-certs

PUBLIC_IP=""
for i in \$(seq 1 10); do
    IMDS_TOKEN=\$(curl -s -X PUT --connect-timeout 2 \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 60" \
        "http://169.254.169.254/latest/api/token" 2>/dev/null)
    if [ -n "\${IMDS_TOKEN}" ]; then
        PUBLIC_IP=\$(curl -s -H "X-aws-ec2-metadata-token: \${IMDS_TOKEN}" \
            --connect-timeout 2 "http://169.254.169.254/latest/meta-data/public-ipv4" 2>/dev/null)
        [ -n "\${PUBLIC_IP}" ] && break
    fi
    sleep 3
done
[ -z "\${PUBLIC_IP}" ] && PUBLIC_IP=127.0.0.1

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout tls.key \
    -out tls.crt \
    -subj "/CN=keycloak" \
    -addext "subjectAltName=DNS:keycloak,DNS:localhost,IP:127.0.0.1,IP:\${PUBLIC_IP}"

chmod 644 tls.crt
chmod 600 tls.key
chown 1000:1000 tls.crt tls.key

echo "Starting Keycloak container..."
docker run -d --name keycloak --restart unless-stopped \
    -p 443:8443 \
    -v /opt/keycloak-certs:/etc/x509/https:ro \
    -e KEYCLOAK_ADMIN=admin \
    -e KEYCLOAK_ADMIN_PASSWORD='${password_escaped}' \
    -e KC_HTTPS_CERTIFICATE_FILE=/etc/x509/https/tls.crt \
    -e KC_HTTPS_CERTIFICATE_KEY_FILE=/etc/x509/https/tls.key \
    quay.io/keycloak/keycloak:${KEYCLOAK_VERSION} \
    start \
        --https-port=8443 \
        --hostname-strict=false \
        --http-enabled=false || {
    echo "Failed to start container"
    docker logs keycloak 2>&1 || true
    exit 1
}

sleep 5
if docker ps | grep -q keycloak; then
    echo "Keycloak container is running"
    docker ps | grep keycloak
else
    echo "ERROR: Keycloak container failed to start"
    docker logs keycloak 2>&1 || true
    exit 1
fi

echo "=== Keycloak installation complete ==="
date
EOF
}

launch_ec2_instance() {
    echo -e "${YELLOW}Finding latest Amazon Linux AMI...${NC}"
    local ami_id
    ami_id=$(aws ec2 describe-images --owners amazon \
        --filters "Name=name,Values=al2023-ami-*-x86_64" "Name=state,Values=available" \
        --query 'Images | sort_by(@, &CreationDate) | [-1].ImageId' --output text)
    echo -e "   ${GREEN}OK${NC} Found AMI: $ami_id"

    local user_data
    user_data=$(generate_user_data_script)

    echo -e "${YELLOW}Launching EC2 instance...${NC}"
    INSTANCE_ID=$(aws ec2 run-instances \
        --image-id "$ami_id" \
        --instance-type "$INSTANCE_TYPE" \
        --key-name "$KEY_NAME" \
        --security-group-ids "$SG_ID" \
        --subnet-id "$SUBNET_ID" \
        --associate-public-ip-address \
        --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":30,"DeleteOnTermination":true,"VolumeType":"gp3"}}]' \
        --user-data "$user_data" \
        --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$INSTANCE_NAME},{$MANAGED_BY_TAG}]" \
        --query 'Instances[0].InstanceId' --output text)

    if [ -z "$INSTANCE_ID" ] || [ "$INSTANCE_ID" == "None" ]; then
        echo -e "   ${RED}Error: Failed to launch instance${NC}"
        exit 1
    fi
    CREATED_RESOURCES+=("instance:$INSTANCE_ID")

    echo -e "   ${GREEN}OK${NC} Instance launched: $INSTANCE_ID"
    echo -e "${YELLOW}Waiting for instance to start...${NC}"
    aws ec2 wait instance-running --instance-ids "$INSTANCE_ID"

    PUBLIC_IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
        --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
}

save_instance_info() {
    cat >"$INFO_FILE" <<EOF
INSTANCE_ID=$INSTANCE_ID
PUBLIC_IP=$PUBLIC_IP
SECURITY_GROUP_ID=$SG_ID
KEY_NAME=$KEY_NAME
INSTANCE_NAME=$INSTANCE_NAME
VPC_ID=$VPC_ID
SUBNET_ID=$SUBNET_ID
KEYCLOAK_VERSION=$KEYCLOAK_VERSION
EOF
    chmod 600 "$INFO_FILE"
}

display_success_message() {
    echo ""
    echo -e "${GREEN}Setup Complete${NC}"
    echo -e "${GREEN}==============${NC}"
    echo ""
    echo -e "${BLUE}Instance Details:${NC}"
    echo -e "   Instance ID:      ${GREEN}$INSTANCE_ID${NC}"
    echo -e "   Public IP:        ${GREEN}$PUBLIC_IP${NC}"
    echo -e "   Security Group:   ${GREEN}$SG_ID${NC}"
    echo -e "   Keycloak Version: ${GREEN}$KEYCLOAK_VERSION${NC}"
    echo -e "   Region:           ${GREEN}$AWS_REGION${NC}"
    echo ""
    echo -e "${BLUE}SSH Access:${NC}"
    echo -e "   ${CYAN}ssh -i ${KEY_NAME}.pem ec2-user@${PUBLIC_IP}${NC}"
    echo ""
    echo -e "${BLUE}Keycloak Access:${NC}"
    echo -e "   Wait 2-3 minutes for Keycloak to start, then:"
    echo -e "   HTTPS: ${CYAN}https://${PUBLIC_IP}:443${NC}"
    echo -e "   Admin: ${GREEN}admin${NC} / <your-password>"
    echo ""
    echo -e "   ${YELLOW}Note: HTTPS uses a self-signed certificate (browser will show a warning).${NC}"
    echo ""
    echo -e "${BLUE}Download CA certificate (for ROSA external auth):${NC}"
    echo -e "   ${CYAN}echo | openssl s_client -servername ${PUBLIC_IP} -connect ${PUBLIC_IP}:443 2>/dev/null | openssl x509 -outform PEM > keycloak-ca.crt${NC}"
    echo ""
    echo -e "${BLUE}Check Keycloak logs:${NC}"
    echo -e "   ${CYAN}ssh -i ${KEY_NAME}.pem ec2-user@${PUBLIC_IP} 'sudo docker logs keycloak --tail 50'${NC}"
    echo ""
    echo -e "${BLUE}Instance info saved to:${NC} ${GREEN}${INFO_FILE}${NC} (password NOT stored)"
    echo ""
}

create_instance() {
    echo ""
    echo -e "${BLUE}Creating Keycloak Instance${NC}"
    echo -e "${BLUE}==========================${NC}"
    echo ""

    detect_or_prompt_region
    collect_user_input

    echo ""
    echo -e "${BLUE}Starting setup...${NC}"
    echo ""

    SETUP_IN_PROGRESS=true
    CREATED_RESOURCES=()

    get_user_ip
    setup_key_pair
    setup_vpc_and_subnet
    setup_security_group
    launch_ec2_instance
    save_instance_info

    SETUP_IN_PROGRESS=false
    CREATED_RESOURCES=()

    display_success_message
}

delete_vpc_resources() {
    local vpc_id="$1"
    echo -e "   Cleaning up VPC resources..."

    local remaining_sgs
    remaining_sgs=$(aws ec2 describe-security-groups --filters "Name=vpc-id,Values=$vpc_id" \
        --query 'SecurityGroups[?GroupName!=`default`].GroupId' --output text 2>/dev/null)
    for sg in $remaining_sgs; do
        aws ec2 delete-security-group --group-id "$sg" 2>/dev/null &&
            echo -e "   ${GREEN}OK${NC} Deleted security group: $sg" || true
    done

    local igw_id
    igw_id=$(aws ec2 describe-internet-gateways \
        --filters "Name=attachment.vpc-id,Values=$vpc_id" \
        --query 'InternetGateways[0].InternetGatewayId' --output text 2>/dev/null)
    if [ -n "$igw_id" ] && [ "$igw_id" != "None" ]; then
        aws ec2 detach-internet-gateway --vpc-id "$vpc_id" --internet-gateway-id "$igw_id" 2>/dev/null
        aws ec2 delete-internet-gateway --internet-gateway-id "$igw_id" 2>/dev/null &&
            echo -e "   ${GREEN}OK${NC} Internet Gateway deleted" || true
    fi

    local subnet_ids
    subnet_ids=$(aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc_id" \
        --query 'Subnets[*].SubnetId' --output text 2>/dev/null)
    for sub in $subnet_ids; do
        aws ec2 delete-subnet --subnet-id "$sub" 2>/dev/null &&
            echo -e "   ${GREEN}OK${NC} Subnet deleted: $sub" || true
    done

    local rt_ids
    rt_ids=$(aws ec2 describe-route-tables --filters "Name=vpc-id,Values=$vpc_id" \
        --query 'RouteTables[*].RouteTableId' --output text 2>/dev/null)
    for rt in $rt_ids; do
        local is_main
        is_main=$(aws ec2 describe-route-tables --route-table-ids "$rt" \
            --query 'RouteTables[0].Associations[?Main==`true`].RouteTableId' --output text 2>/dev/null)
        if [ -z "$is_main" ] || [ "$is_main" == "None" ]; then
            aws ec2 delete-route-table --route-table-id "$rt" 2>/dev/null &&
                echo -e "   ${GREEN}OK${NC} Route table deleted: $rt" || true
        fi
    done

    sleep 3
    aws ec2 delete-vpc --vpc-id "$vpc_id" 2>/dev/null &&
        echo -e "   ${GREEN}OK${NC} VPC deleted" ||
        echo -e "   ${YELLOW}Warning: Could not delete VPC (may have remaining dependencies)${NC}"
}

destroy_instance() {
    echo ""
    echo -e "${RED}Destroying Keycloak Instance${NC}"
    echo -e "${RED}============================${NC}"
    echo ""

    if [ -f "$INFO_FILE" ]; then
        source "$INFO_FILE"
        SG_ID=$SECURITY_GROUP_ID

        echo -e "${BLUE}Loaded instance info from: $INFO_FILE${NC}"
        echo ""
        echo -e "   Instance ID:    $INSTANCE_ID"
        echo -e "   Public IP:      $PUBLIC_IP"
        echo -e "   VPC:            $VPC_ID"
        echo -e "   Security Group: $SG_ID"
        echo -e "   Key Pair:       $KEY_NAME"
        echo ""
        read -p "This will destroy ALL resources (instance, VPC, SG, key pair). Continue? (yes/no): " CONFIRM
        if [ "$CONFIRM" != "yes" ]; then
            echo "Cancelled."
            return
        fi
    else
        echo -e "${YELLOW}No instance info file found. Searching for ALL keycloak resources...${NC}"
        echo ""

        local all_instances
        all_instances=$(aws ec2 describe-instances \
            --filters "Name=tag:ManagedBy,Values=odh-keycloak-script" "Name=instance-state-name,Values=running,stopped,stopping,pending" \
            --query 'Reservations[*].Instances[*].InstanceId' --output text 2>/dev/null)

        local all_vpcs
        all_vpcs=$(aws ec2 describe-vpcs \
            --filters "Name=tag:ManagedBy,Values=odh-keycloak-script" \
            --query 'Vpcs[*].VpcId' --output text 2>/dev/null)

        KEY_NAME="keycloak-keypair"

        local found_anything=false

        if [ -n "$all_instances" ] && [ "$all_instances" != "None" ]; then
            echo -e "   Found instance(s): $all_instances"
            found_anything=true
        else
            all_instances=""
        fi

        if [ -n "$all_vpcs" ] && [ "$all_vpcs" != "None" ]; then
            echo -e "   Found VPC(s): $all_vpcs"
            found_anything=true
        else
            all_vpcs=""
        fi

        if aws ec2 describe-key-pairs --key-names "$KEY_NAME" &>/dev/null; then
            echo -e "   Found key pair: $KEY_NAME"
            found_anything=true
        else
            KEY_NAME=""
        fi

        if [ "$found_anything" != "true" ]; then
            echo -e "${RED}No Keycloak resources found.${NC}"
            return
        fi

        echo ""
        read -p "This will destroy ALL listed resources. Continue? (yes/no): " CONFIRM
        if [ "$CONFIRM" != "yes" ]; then
            echo "Cancelled."
            return
        fi

        echo ""
        echo -e "${YELLOW}Starting cleanup...${NC}"

        # Terminate all keycloak instances
        for inst in $all_instances; do
            if [ -n "$inst" ] && [ "$inst" != "None" ]; then
                echo -e "   Terminating instance $inst..."
                aws ec2 terminate-instances --instance-ids "$inst" &>/dev/null || true
                aws ec2 wait instance-terminated --instance-ids "$inst" 2>/dev/null || true
                echo -e "   ${GREEN}OK${NC} Instance $inst terminated"
            fi
        done

        # Delete all keycloak VPCs
        for vpc in $all_vpcs; do
            if [ -n "$vpc" ] && [ "$vpc" != "None" ]; then
                echo -e "   Deleting VPC $vpc and all associated resources..."
                delete_vpc_resources "$vpc"
            fi
        done

        # Delete key pair
        if [ -n "$KEY_NAME" ]; then
            echo -e "   Deleting key pair $KEY_NAME..."
            aws ec2 delete-key-pair --key-name "$KEY_NAME" 2>/dev/null &&
                echo -e "   ${GREEN}OK${NC} Key pair deleted" ||
                echo -e "   ${YELLOW}Warning: Could not delete key pair${NC}"
            rm -f "${KEY_NAME}.pem" 2>/dev/null && echo -e "   ${GREEN}OK${NC} Local key file deleted" || true
        fi

        echo ""
        echo -e "${GREEN}Cleanup complete. All resources removed.${NC}"
        echo ""
        return
    fi

    echo ""
    echo -e "${YELLOW}Starting cleanup...${NC}"

    # 1. Terminate instance
    if [ -n "$INSTANCE_ID" ] && [ "$INSTANCE_ID" != "None" ]; then
        local state
        state=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
            --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null)
        if [ "$state" == "terminated" ]; then
            echo -e "   ${GREEN}OK${NC} Instance already terminated"
        else
            echo -e "   Terminating instance..."
            aws ec2 terminate-instances --instance-ids "$INSTANCE_ID" &>/dev/null
            aws ec2 wait instance-terminated --instance-ids "$INSTANCE_ID"
            echo -e "   ${GREEN}OK${NC} Instance terminated"
        fi
    fi

    # 2. Delete VPC (includes SGs, subnets, IGW, route tables)
    if [ -n "${VPC_ID:-}" ] && [ "$VPC_ID" != "None" ]; then
        echo -e "   Deleting VPC and all associated resources..."
        delete_vpc_resources "$VPC_ID"
    fi

    # 3. Delete key pair
    if [ -n "${KEY_NAME:-}" ]; then
        echo -e "   Deleting key pair..."
        aws ec2 delete-key-pair --key-name "$KEY_NAME" 2>/dev/null &&
            echo -e "   ${GREEN}OK${NC} Key pair deleted" ||
            echo -e "   ${YELLOW}Warning: Could not delete key pair${NC}"
        rm -f "${KEY_NAME}.pem" 2>/dev/null && echo -e "   ${GREEN}OK${NC} Local key file deleted" || true
    fi

    # 4. Delete info file
    if [ -f "$INFO_FILE" ]; then
        rm -f "$INFO_FILE"
        echo -e "   ${GREEN}OK${NC} Info file deleted"
    fi

    echo ""
    echo -e "${GREEN}Cleanup complete. All resources removed.${NC}"
    echo ""
}

show_status() {
    echo ""
    echo -e "${BLUE}Instance Status${NC}"
    echo -e "${BLUE}===============${NC}"
    echo ""

    if [ -f "$INFO_FILE" ]; then
        source "$INFO_FILE"
        local state
        state=$(aws ec2 describe-instances --instance-ids "$INSTANCE_ID" \
            --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null)

        echo -e "   Instance ID:      ${GREEN}$INSTANCE_ID${NC}"
        echo -e "   Public IP:        ${GREEN}$PUBLIC_IP${NC}"
        echo -e "   State:            ${GREEN}$state${NC}"
        echo -e "   Keycloak Version: ${GREEN}${KEYCLOAK_VERSION:-unknown}${NC}"
        echo ""
        echo -e "${BLUE}Access:${NC}"
        echo -e "   SSH:   ${CYAN}ssh -i ${KEY_NAME}.pem ec2-user@${PUBLIC_IP}${NC}"
        echo -e "   HTTPS: ${CYAN}https://${PUBLIC_IP}:443${NC}"
    else
        echo -e "${YELLOW}No instance info file found. Searching...${NC}"
        local iid
        iid=$(aws ec2 describe-instances \
            --filters "Name=tag:Name,Values=keycloak" "Name=instance-state-name,Values=running,stopped" \
            --query 'Reservations[0].Instances[0].InstanceId' --output text 2>/dev/null)

        if [ -z "$iid" ] || [ "$iid" == "None" ]; then
            echo -e "${RED}No Keycloak instance found.${NC}"
        else
            local ip state
            ip=$(aws ec2 describe-instances --instance-ids "$iid" \
                --query 'Reservations[0].Instances[0].PublicIpAddress' --output text 2>/dev/null)
            state=$(aws ec2 describe-instances --instance-ids "$iid" \
                --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null)
            echo -e "   Instance: ${GREEN}$iid${NC}"
            echo -e "   IP:       ${GREEN}$ip${NC}"
            echo -e "   State:    ${GREEN}$state${NC}"
        fi
    fi
    echo ""
}

# --- Main ---
check_aws

while true; do
    show_menu
    case $CHOICE in
        1) create_instance ;;
        2) destroy_instance ;;
        3) show_status ;;
        4)
            echo -e "${BLUE}Goodbye.${NC}"
            SETUP_IN_PROGRESS=false
            exit 0
            ;;
        *) echo -e "${RED}Invalid option. Choose 1-4.${NC}" ;;
    esac
    read -p "Press Enter to continue..."
done