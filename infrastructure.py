import os
from typing import NamedTuple

class Client(NamedTuple):
    client_id: str
    ip_address: str
    client_key: str

class AuthenticationServer(NamedTuple):
    client_id_to_key_C: dict[str, bytes]
    key_TGS: bytes

class TicketGrantingServer(NamedTuple):
    clients_id_to_authorized_services: dict[str, set[str]]
    key_TGS: bytes
    key_S: bytes

class ServiceServer(NamedTuple):
    key_S: str
    provideable_services: set[str]

class Infrastructure(NamedTuple):
    possible_services: set[str]
    possible_clients: set[Client]
    authentication_server: AuthenticationServer
    ticket_granting_server: TicketGrantingServer
    service_server: ServiceServer

def create_infrastructure() -> Infrastructure:
    # Create possible services the user could possibly request (even if not provideable)
    minecraft = 'Minecraft'
    wholesome_memes = 'Wholesome Memes'
    clone_wars = 'Star Wars: The Clone Wars'
    ms_paint = 'MS Paint'
    provideable_services = {minecraft, wholesome_memes, clone_wars}
    possible_services = {minecraft, wholesome_memes, clone_wars, ms_paint}

    # Create the good clients and a bad one for the user to possibly role play as
    client0 = Client('Advanced_Networking_Student0', '10.10.10.10', os.urandom(32))
    client1 = Client('Advanced_Networking_Student1', '10.10.10.11', os.urandom(32))
    client2 = Client('Advanced_Networking_Student2', '10.10.10.12', os.urandom(32))
    bad_client = Client('Uninvited_Guest', '10.10.10.13', os.urandom(32))
    possible_clients = {client0, client1, client2, bad_client}

    # Create the Authentication Server
    client_id_to_key_C = {
        client0.client_id: client0.client_key,
        client1.client_id: client1.client_key,
        client2.client_id: client2.client_key,
    }
    key_TGS = os.urandom(32)
    authentication_server = AuthenticationServer(client_id_to_key_C, key_TGS)
    
    # Create the Ticket Granting Server
    clients_id_to_authorized_services = {
        client0.client_id: {minecraft, wholesome_memes},
        client1.client_id: {minecraft, clone_wars},
        client2.client_id: {minecraft},
    }
    key_S = os.urandom(32)
    ticket_granting_server = TicketGrantingServer(clients_id_to_authorized_services, key_TGS, key_S)

    # Create the Service Server
    service_server = ServiceServer(key_S, provideable_services)

    # Return the completed infrastructure
    return Infrastructure(
        possible_services,
        possible_clients,
        authentication_server,
        ticket_granting_server,
        service_server
    )