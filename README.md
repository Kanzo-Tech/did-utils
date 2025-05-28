# did-utils

## Prerequisites

Before running the services, make sure you have the following installed:

- Docker

## Running the services

1. Clone the repository
   ```
   git clone https://github.com/Kanzo-Tech/ssi-utils.git
   ```
2. Modify the `etc/hosts` file to add the following line:
   ```
   127.0.0.1 solid
   ```
3. Run the `run.sh` script
   ```sh
   ./run.sh
   ```
4. Run the following `curl` command to generate a DID:
   ```sh
   curl -X POST http://localhost:3001/generate-did \
     -H "Content-Type: application/json" \
     -d '{"domain": "example.com","path": "user/alice", "name": "Alice", "email": "alice@example.com", "dni": "123456789"}'
   ```
5. Access the services at the following URLs:
   - Generated DID location: http://solid:3000/my-pod/VerifiableCredentials/did-web-user-alice
   - Generated PDF file location: http://solid:3000/my-pod/VerifiableCredentials/signed-dummy-user-alice.pdf
