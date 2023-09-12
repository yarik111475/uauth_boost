#!/bin/bash
set -e
REALM_ID=$(openssl x509 -noout -subject -in /opt/certs/users/Realm-manager.pem |
  grep -o "\w\{8\}-\w\{4\}-\w\{4\}-\w\{4\}-\w\{12\}")
SERVICE_ADMIN_ID=$(openssl x509 -noout -subject -in /opt/certs/users/u_auth_service_admin.pem |
  grep -o "\w\{8\}-\w\{4\}-\w\{4\}-\w\{4\}-\w\{12\}")

echo "Init tables"
./uatables

echo "Creating SuperUsers"
./uashell create-super-user \
  --user_id $REALM_ID \
  --email realm_manager \
  --location_id $REALM_ID \
  --ou_id $REALM_ID
./uashell create-super-user \
  --user_id $SERVICE_ADMIN_ID \
  --email service_admin \
  --location_id $SERVICE_ADMIN_ID \
  --ou_id $SERVICE_ADMIN_ID

echo "Run UAuth"
./uaserver