import random
import struct
import socket

# Корневой DNS-сервер
ROOT_DNS_SERVER = '198.41.0.4'

# Функция для кодирования имени хоста
def encode_hostname(hostname):
    parts = hostname.split('.')
    encoded_parts = [struct.pack('!B', len(part)) + part.encode() for part in parts]
    return b''.join(encoded_parts) + b'\0'

# Функция для создания DNS-запроса
def create_dns_query(hostname):
    transaction_id = random.randint(0, 65535)
    flags = 0x0000  # Рекурсивный запрос выключен
    qdcount = 1
    ancount = 0
    nscount = 0
    arcount = 0

    header = struct.pack('>HHHHHH', transaction_id, flags, qdcount, ancount, nscount, arcount)

    if isinstance(hostname, bytes):
        qname = hostname
    else:
        qname = encode_hostname(hostname)

    qtype = 1  # Тип A
    qclass = 1  # Класс IN

    question = qname + struct.pack('>HH', qtype, qclass)

    dns_query = header + question
    return dns_query


# Функция для отправки DNS-запроса и получения ответа
def send_dns_query(query, server='8.8.8.8', port=53):
    # Создаем UDP сокет
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    try:
        # Отправляем запрос на DNS-сервер
        sock.sendto(query, (server, port))

        # Получаем ответ
        response, _ = sock.recvfrom(512)

        return response
    except socket.timeout:
        print("Request timed out")
        return None
    finally:
        sock.close()

# Функция для декодирования имени домена
def decode_name(response, offset):
    labels = []
    jumped = False
    original_offset = offset
    while True:
        length, = struct.unpack('>B', response[offset:offset + 1])
        if length & 0xC0 == 0xC0:  # Это указатель
            if not jumped:
                original_offset = offset + 2
            pointer, = struct.unpack('>H', response[offset:offset + 2])
            offset = pointer & 0x3FFF
            jumped = True
        elif length == 0:
            offset += 1
            break
        else:
            offset += 1
            labels.append(response[offset:offset + length].decode())
            offset += length
    if not jumped:
        original_offset = offset
    return '.'.join(labels), original_offset

# Функция для разбора записи ресурса
def parse_resource_record(response, offset):
    name, offset = decode_name(response, offset)
    rtype, rclass, ttl, rdlength = struct.unpack('>HHIH', response[offset:offset + 10])
    offset += 10
    rdata = response[offset:offset + rdlength]
    offset += rdlength

    if rtype == 1:  # Тип A (адрес)
        rdata = socket.inet_ntoa(rdata)

    return {
        'name': name,
        'type': rtype,
        'class': rclass,
        'ttl': ttl,
        'rdata': rdata
    }, offset

# Функция для разбора ответа DNS
def parse_dns_response(response, transaction_id):
    header = struct.unpack('>HHHHHH', response[:12])
    response_id, flags, qdcount, ancount, nscount, arcount = header

    print(f"Transaction ID: {response_id}")
    print(f"Flags: {flags}")
    print(f"Questions: {qdcount}, Answers: {ancount}, Authorities: {nscount}, Additional: {arcount}")

    if response_id != transaction_id:
        print("Warning: Transaction ID does not match.")
    else:
        print("Transaction ID matches.")

    offset = 12
    for _ in range(qdcount):
        name, offset = decode_name(response, offset)
        qtype, qclass = struct.unpack('>HH', response[offset:offset + 4])
        offset += 4
        print(f"Question: {name}, Type: {qtype}, Class: {qclass}")

    for _ in range(ancount):
        rr, offset = parse_resource_record(response, offset)
        print(f"Answer: {rr}")

    for _ in range(nscount):
        rr, offset = parse_resource_record(response, offset)
        print(f"Authority: {rr}")

    for _ in range(arcount):
        rr, offset = parse_resource_record(response, offset)
        print(f"Additional: {rr}")

# Реализация рекурсивного следования
def resolve(hostname, server=ROOT_DNS_SERVER):
    print(f"Querying {server} for {hostname}")
    query = create_dns_query(hostname)
    transaction_id = struct.unpack('>H', query[:2])[0]

    response = send_dns_query(query, server=server)
    if not response:
        print(f"Failed to get response from {server}")
        return None

    header = struct.unpack('>HHHHHH', response[:12])
    response_id, flags, qdcount, ancount, nscount, arcount = header

    if response_id != transaction_id:
        print("Warning: Transaction ID does not match.")
        return None

    offset = 12
    for _ in range(qdcount):
        name, offset = decode_name(response, offset)
        qtype, qclass = struct.unpack('>HH', response[offset:offset + 4])
        offset += 4

    answers = []
    for _ in range(ancount):
        rr, offset = parse_resource_record(response, offset)
        answers.append(rr)

    authorities = []
    for _ in range(nscount):
        rr, offset = parse_resource_record(response, offset)
        authorities.append(rr)

    additionals = []
    for _ in range(arcount):
        rr, offset = parse_resource_record(response, offset)
        additionals.append(rr)

    # Проверка ответов на наличие записи A
    for answer in answers:
        if answer['type'] == 1:  # Запись A
            return answer['rdata']

    # Если записей A нет, следуем по записям NS
    for authority in authorities:
        if authority['type'] == 2:  # Запись NS
            ns_name = authority['rdata']
            # Ищем дополнительную запись с IP-адресом этого NS
            for additional in additionals:
                if additional['type'] == 1 and additional['name'] == ns_name:
                    return resolve(hostname, server=additional['rdata'])

            # Если IP-адреса нет в дополнительных записях, запрашиваем его
            ns_ip = resolve(ns_name)
            if ns_ip:
                return resolve(hostname, server=ns_ip)

    return None

# Главный блок для отправки запроса и получения ответа
if __name__ == "__main__":
    hostname = "dns.google.com"
    query = create_dns_query(hostname)
    transaction_id = struct.unpack('>H', query[:2])[0]  # Извлекаем идентификатор транзакции из запроса
    print(f"Query (hex): {query.hex()}")

    response = send_dns_query(query)
    if response:
        print(f"Response (hex): {response.hex()}")
        parse_dns_response(response, transaction_id)
    else:
        print("No response received.")

    ip_address = resolve(hostname)
    if ip_address:
        print(f"Resolved {hostname} to {ip_address}")
    else:
        print(f"Failed to resolve {hostname}")
