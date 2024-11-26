from python_aes import (
    generate_aes_key,
    encrypt_object,
    decrypt_object
)
from infrastructure import (
    AuthenticationServer,
    TicketGrantingServer,
    ServiceServer,
    create_infrastructure
)
from communication import (
    ResponseToBadRequest,
    RequestToAuthenticationServer,
    TicketGrantingTicket,
    ResponseOfAuthenticationServer,
    RequestToTicketGrantingServer,
    ServiceTicket,
    ResponseOfTicketGrantingServer,
    RequestToServiceServer,
    ResponseOfServiceServer
)
import time
from operator import attrgetter
from uuid import uuid4

def main():
    # This creates the different parts of the infrastructure.
    """TODO Step 1: Take a look at the infrastructure to see how pre-shared keys work, along with the permissions.
    Your job in this lab will be to have client1 get access to Minecraft from the Service server"""
    possible_services, possible_clients, authentication_server, ticket_granting_server, service_server = create_infrastructure()

    # Client Selection
    sorted_clients = sorted(possible_clients, key=attrgetter('client_id'))
    print("\n".join(f"{i}: {item.client_id}" for i, item in enumerate(sorted_clients[:4])))
    while True:
        selection = input("Select a client by entering a number (0-3): ")
        if selection.isdigit() and int(selection) in range(4):
            break
    client = sorted_clients[int(selection)]

    # Desired Service Selection
    sorted_services = sorted(possible_services)
    print("\n".join(f"{i}: {item}" for i, item in enumerate(sorted_services)))
    while True:
        selection = input("Select a service to request by entering a number (0-3): ")
        if selection.isdigit() and int(selection) in range(4):
            break
    desired_service = sorted_services[int(selection)]

    # Communicate with the authentication server
    """TODO Step 2: Take a look at how authentication_server_logic works and compare it to the diagram. This 
    will help you understand how the authentication server communicates, and could help when writing the TGT server"""
    request = RequestToAuthenticationServer(client.client_id, client.ip_address)
    response = authentication_server_logic(request, authentication_server)
    if isinstance(response, ResponseToBadRequest):
        print(response.reasoning)
        return
    ticket_granting_server_session_key = decrypt_object(response.encrypted_key_for_next_communication, client.client_key)
    client_id_and_timestamp = (client.client_id, time.time())
    encrypted_client_id_and_timestamp = encrypt_object(client_id_and_timestamp, ticket_granting_server_session_key)
    encrypted_ticket_granting_ticket = response.encrypted_ticket_granting_ticket

    # Communicate with the ticket granting server
    """TODO Step 3: Now that you are starting to understand kerberos, it's time you wrote the next part of the
    kerberos communication process. Write the code for creating the client request to tgt, then write the tgt server
    logic to get the tgt response. Also get the next communication key"""
    request_ticket_granting_server = RequestToTicketGrantingServer(desired_service, encrypted_ticket_granting_ticket, encrypted_client_id_and_timestamp)
    response_ticket_granting_server = ticket_granting_server_logic(request_ticket_granting_server, ticket_granting_server)
    if isinstance(response_ticket_granting_server, ResponseToBadRequest):
        print(response_ticket_granting_server.reasoning)
        return
    service_session_key = decrypt_object(response_ticket_granting_server.encrypted_key_for_next_communication, ticket_granting_server_session_key)
    client_id_and_timestamp = (client.client_id, time.time())
    encrypted_client_id_and_timestamp = encrypt_object(client_id_and_timestamp, service_session_key)
    encrypted_service_ticket = response_ticket_granting_server.encrypted_service_ticket

    # Communicate with the service server
    """TODO Step 4: Now construct the request to the service server. Write the code for the service_server_logic, which
    returns the appropriate response. Decrypt the one time code, and print it to the console"""
    request_service_server = RequestToServiceServer(encrypted_service_ticket, encrypted_client_id_and_timestamp)
    response_service_server = service_server_logic(request_service_server, service_server)
    if isinstance(response_service_server, ResponseToBadRequest):
        print(response_service_server.reasoning)
        return
    time_stamp = decrypt_object(response_service_server.encrypted_timestamp, service_session_key)
    one_time_code = decrypt_object(response_service_server.encrypted_one_time_access_to_service, service_session_key)
    print(one_time_code)

def authentication_server_logic(request:RequestToAuthenticationServer, server:AuthenticationServer) -> ResponseOfAuthenticationServer | ResponseToBadRequest:
    # Checks that the client's id is one of the ids that maps to a key on the Authentication Server.
    # If not there, create a random key for the imposter
    client_key = server.client_id_to_key_C.get(request.client_id)
    valid = client_key is not None
    if not valid:
        return ResponseToBadRequest('Client id is not mapped to a key in the Authentication Server')
    
    # Generate the key for the next communication and encrypt it so that only the client can read it
    next_communication_key = generate_aes_key()
    encrypted_key_for_next_communication = encrypt_object(next_communication_key, client_key)

    # Create and encrypt the ticket granting ticket
    ticket_granting_ticket = TicketGrantingTicket(next_communication_key, request.client_id, request.ip_address, valid)
    encrypted_ticket_granting_ticket = encrypt_object(ticket_granting_ticket, server.key_TGS)

    # Return the response of the authentication server
    return ResponseOfAuthenticationServer(encrypted_ticket_granting_ticket, encrypted_key_for_next_communication)

def ticket_granting_server_logic(request:RequestToTicketGrantingServer, server:TicketGrantingServer) -> ResponseOfTicketGrantingServer | ResponseToBadRequest:
    # Decrypts TGT with TGS secret key and gets the TGS session key from the TGT
    ticket_granting_ticket:TicketGrantingTicket = decrypt_object(request.encrypted_ticket_granting_ticket, server.key_TGS)
    ticket_granting_server_session_key = ticket_granting_ticket.next_communication_key

    # Decrypts the client ID and timestamp with the TGS session key
    client_id_and_timestamp = decrypt_object(request.encrypted_client_id_and_timestamp, ticket_granting_server_session_key)
    client_id = client_id_and_timestamp[0]

    # Verifies the TGT with the client ID and timestamp
    valid = True if client_id == ticket_granting_ticket.client and ticket_granting_ticket.validity else False
    
    if not valid:
        return ResponseToBadRequest('Client id did not match the client id of the TGT')

    # Checks that the requested service is one of the services that the client is allowed to access.
    authorized_services = server.clients_id_to_authorized_services.get(ticket_granting_ticket.client)
    if request.requested_service not in authorized_services:
        valid = False
        return ResponseToBadRequest('Client id is not allowed access to this service')
    
    # Generate the key for the next communication and encrypt it so that only the client can read it with the TGS session key
    next_communication_key = generate_aes_key()
    encrypted_key_for_next_communication = encrypt_object(next_communication_key, ticket_granting_server_session_key)

    # Create and encrypt the service ticket
    service_ticket = ServiceTicket(next_communication_key, client_id, ticket_granting_ticket.address, valid, request.requested_service)
    encrypted_service_ticket = encrypt_object(service_ticket, server.key_S)

    # Return the response of the ticket granting server
    return ResponseOfTicketGrantingServer(encrypted_service_ticket, encrypted_key_for_next_communication)
    
def service_server_logic(request:RequestToServiceServer, server:ServiceServer) -> ResponseOfServiceServer | ResponseToBadRequest:
    # Decrypts service ticket with services secret key and gets the service session key from the service ticket
    service_ticket:ServiceTicket = decrypt_object(request.encrypted_service_ticket, server.key_S)
    service_session_key = service_ticket.next_communication_key

    # Decrypts the client ID and timestamp with the TGS session key
    client_id_and_timestamp = decrypt_object(request.encrypted_client_id_and_timestamp, service_session_key)
    client_id = client_id_and_timestamp[0]

    # Verifies the service ticket with the client ID and timestamp
    valid = True if client_id == service_ticket.client and service_ticket.validity else False
    
    if not valid:
        return ResponseToBadRequest('Client id did not match the client id of the service ticket')
    
    # Create and encrypt the timestamp
    timestamp = time.time()
    encrypted_timestamp = encrypt_object(timestamp, service_session_key)
    
    # Create and encrypt the one time code
    one_time_code = uuid4()
    encrypted_one_time_code = encrypt_object(one_time_code, service_session_key)
    
    # Return the response of the service server
    return ResponseOfServiceServer(encrypted_one_time_code, encrypted_timestamp)

if __name__ == '__main__':
    main()