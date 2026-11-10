import socket
import select
import sys
import time

routing_table={}

filename = sys.argv[1]

def read_config(filename):
    input_ports = []
    outputs = [] #[port, metric, router_id]
    try:
        with open (filename, 'r') as file:
            for line in file:
                line = line.strip()

                if not line or line.startswith('#'): #remove lines that have comements
                    continue

                elif line.startswith("router-id"):
                    router_id = int(line.split()[1])
                elif line.startswith("input-ports"):
                    parts = line.split(None, 1)
                    if len(parts) > 1:
                        inputs = [p.strip() for p in parts[1].split(",")]
                        for port in inputs:
                            if port:
                                if int(port) >= 1024 and int(port) <=64000:
                                    input_ports.append(int(port))
                                elif port:
                                    print(f"Error: Port {int(port)} out of range")
                                    sys.exit(1)
                elif line.startswith("outputs"):
                    output = line.replace('outputs ', '').split(', ')
                    for i in output:
                        i = i.strip()
                        if not i:
                            continue
                        parts = i.split('-')
                        outputs.append([int(parts[0]), int(parts[1]), int(parts[2])])
    except FileNotFoundError:
        print("FileNotFoundError")
        sys.exit(1)
    
    if router_id is None:
        print("No router id")
        sys.exit(1)
    if not input_ports:
        print("No Input Ports")
        sys.exit(1)
    if not outputs:
        print("No Outputs= Ports")
        sys.exit(1)

    return router_id, input_ports, outputs

def create_socket(input_ports):
    sockets = []
    for address in input_ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", address))
        sockets.append(sock)
    return sockets

def main(sockets, outputs, routing_table, router_id):
    timer = time.time()

    while True:
        readable, _, _ = select.select(sockets, [], [], 1)
        if readable:
            for sock in readable:
                data, address = sock.recvfrom(1024)
                try:
                    sender_id, decoded = decode_packet(data)
                except ValueError as e:
                    print(f"Incorrect packet {e}")
                    continue

                changed = update_routes(sender_id, decoded, outputs, routing_table)

                if changed:
                    print_routing_table(routing_table)
                    send_update(sockets, outputs, routing_table, router_id)
                
        timer1 = time.time()
        if timer1 - timer > 10:
            print_routing_table(routing_table)
            send_update(sockets, outputs, routing_table, router_id)
            timer = timer1

        timeout_changed = timeout(routing_table, router_id)

        if timeout_changed:
            print_routing_table(routing_table)
            send_update(sockets, outputs, routing_table, router_id)

def update_routes(sender_id, routes, outputs, routing_table):

    changed = False
    neighbour_cost = None
    neighbour = None

    for i in outputs:
        if i[2] == sender_id:
            neighbour_cost = i[1]
            neighbour = i[2]
    
    if neighbour_cost is None:
        return False

    if neighbour in routing_table:
        routing_table[neighbour][2] = time.time()
            
    for dest, cost in routes:
        if cost == 16:
            if dest in routing_table and routing_table[dest][1] == neighbour:
                if routing_table[dest][0] != 16:
                    routing_table[dest][0] = 16
                    routing_table[dest][2] = time.time()
                    changed = True
        else:
            new_cost = min(neighbour_cost + cost, 16)

            if dest not in routing_table:
                routing_table[dest] = [new_cost, neighbour, time.time()]
            elif routing_table[dest][1] == neighbour:
                routing_table[dest][2] = time.time()
                if routing_table[dest][0] != new_cost:
                    routing_table[dest][0] = new_cost
                    routing_table[dest][2] = time.time()
            elif new_cost < routing_table[dest][0]:
                routing_table[dest] = [new_cost, neighbour, time.time()]

    return changed


def packet_entry(neighbour_id, routing_table, router_id):
    packet = bytearray()
    packet += (2).to_bytes(1, 'big')  #command
    packet += (2).to_bytes(1, 'big')  #version
    packet += router_id.to_bytes(2, 'big')

    for i in routing_table:
        cost, next_hop, _ = routing_table[i]

        if next_hop == neighbour_id:
            cost = 16

        packet += (2).to_bytes(2, 'big') #afi
        packet += (0).to_bytes(2, 'big')
        packet += i.to_bytes(4, 'big') #dest
        packet += (0).to_bytes(4, 'big')
        packet += (0).to_bytes(4, 'big')
        packet += cost.to_bytes(4, 'big')

    return packet

def decode_packet(data):
    if len(data) < 4:
        raise ValueError("No header")

    command = data[0]
    version = data[1]
    sender_id = int.from_bytes(data[2:4], 'big')

    if command != 2:
        raise ValueError(f"Invalid command: {command}")
    if version != 2:
        raise ValueError(f"Invalid version: {version}")
    if not (1 <= sender_id <= 64000):
        raise ValueError(f"Invalid Sender ID: {sender_id}")

    decoded = []
    for i in range(4, len(data), 20):
        chunk = data[i:i+20]
            
        afi = int.from_bytes(chunk[0:2], 'big')
        zero1 = int.from_bytes(chunk[2:4], 'big')
        dest_id = int.from_bytes(chunk[4:8], 'big')
        zero2 = int.from_bytes(chunk[8:12], 'big')
        zero3 = int.from_bytes(chunk[12:16], 'big')
        cost = int.from_bytes(chunk[16:20], 'big')

        if afi != 2:
            raise ValueError(f"Invalid AFI: {afi}")
        if not (0 <= cost <= 16):
            raise ValueError(f"Metric out of range: {cost}")
        if zero1 != 0 or zero2 != 0 or zero3 != 0:
             raise ValueError("Reserved fields must be zero")

        decoded.append((dest_id, cost))

    return sender_id, decoded

def timeout(routing_table, router_id):
    now = time.time()
    timeout_changed = False
    garbage_bag = []

    for dest in routing_table:
        if dest == router_id:
            continue

        cost, next_hop, previous_time = routing_table[dest]
        if cost < 16 and (now - previous_time) > 60: #initial timeout
            routing_table[dest][0] = 16
            routing_table[dest][2] = now
            timeout_changed = True

        elif cost == 16 and (now - previous_time) > 40: #garbage collection
            garbage_bag.append(dest)
            timeout_changed = True

    for dest in garbage_bag:
        del routing_table[dest]

    return timeout_changed

def send_update(sockets, outputs, routing_table, router_id):
    for output in outputs:
        port = output[0]
        neighbour_id = output[2]

        packet = packet_entry(neighbour_id, routing_table, router_id)
        sockets[0].sendto(packet, ("127.0.0.1", port))

def print_routing_table(routing_table):
    for i in routing_table:
        print(f"router-id: {i}, metric: {routing_table[i][0]}, next_hop: {routing_table[i][1]}")
    print()

router_id, input_ports, outputs = read_config(filename)

current_time = time.time() #initialisation of the routing table
routing_table[router_id] = [0, None, current_time]
for i in outputs:
    routing_table[i[2]] = [i[1], i[2], current_time]


print_routing_table(routing_table)
sockets = create_socket(input_ports)
main(sockets, outputs, routing_table, router_id)