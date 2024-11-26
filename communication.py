from typing import NamedTuple

class ResponseToBadRequest(NamedTuple):
    reasoning: str

class RequestToAuthenticationServer(NamedTuple):
    client_id: str
    ip_address: str

class TicketGrantingTicket(NamedTuple):
    next_communication_key: bytes
    client: str
    address: str
    validity: bool

class ResponseOfAuthenticationServer(NamedTuple):
    encrypted_ticket_granting_ticket: bytes
    encrypted_key_for_next_communication: bytes

class RequestToTicketGrantingServer(NamedTuple):
    requested_service: str
    encrypted_ticket_granting_ticket: bytes
    encrypted_client_id_and_timestamp: bytes

class ServiceTicket(NamedTuple):
    next_communication_key: bytes
    client: str
    address: str
    validity: bool
    service: str

class ResponseOfTicketGrantingServer(NamedTuple):
    encrypted_service_ticket: bytes
    encrypted_key_for_next_communication: bytes

class RequestToServiceServer(NamedTuple):
    encrypted_service_ticket: bytes
    encrypted_client_id_and_timestamp: bytes

class ResponseOfServiceServer(NamedTuple):
    encrypted_one_time_access_to_service: bytes
    encrypted_timestamp: bytes