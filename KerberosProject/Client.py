import sys
import time
import requests
import json
import pprint
import socket
import Constants
import CryptoOperations
import kerberos
import requests
class KerberosTicket:
    def __init__(self, service):
        __, krb_context = kerberos.authGSSClientInit(service)
        kerberos.authGSSClientStep(krb_context, "")
        self._krb_context = krb_context
        self.auth_header = ("Negotiate " +
                            kerberos.authGSSClientResponse(krb_context))


if len(sys.argv) > 2:
    username = sys.argv[1]
    device_id = sys.argv[2]
    krb = KerberosTicket("HTTP@monarch.example.com")
    headers = {'Content-type': 'application/json', 'Accept': 'application/json', "Authorization": krb.auth_header}
    print('\nRequesting a IoT Device ticket from IoT Service for the smart bulb\n')
    user_request = {}
    user_request["username"] = username
    user_request["device_id"] = device_id
    # put the actual address where IS is hosted
    url = "http://monarch.example.com:8080/device_ticket"
    r = requests.post(url, data=json.dumps(user_request), headers=headers)
    response_is = r.json()
    print('Received response from IoT Service')
    pprint.pprint(response_is)
    print('\n')
    ticket_device = response_is["ticket"]
    session_key = response_is["session_key"]
    nonce = response_is["nonce"]
    actual_device_id = Constants.device_id_dict[device_id]
    device_type = Constants.iot_device_type_dict[actual_device_id]
    while True:
        if device_type == Constants.device_type_normal:
            command = input('Input command(attest/turn_on/turn_off) for device or q to exit\n')
        else:
            command = input('Input command(turn_on/turn_off) for device or q to exit\n')
        match command:
            case "q":
                break
            case "turn_on":
                print('\nTurning on the smart bulb\n')
            case "turn_off":
                print('\nTurning off the smart bulb\n')
            case "attest":
                print('\nAttesting the smart bulb\n')
        print('Sending service request to device')
        print('Calculating hmac to create request authenticator')
        if device_type == Constants.device_type_normal:
            time_stamp = format(int(time.time()), '032d')
            time_hmac = CryptoOperations.hmac_sha256(session_key, str(time_stamp))
            message = Constants.normal_device_request_format.format(Constants.command_dict[command],
                                                                    Constants.client_id_dict[username],
                                                                    Constants.client_interface_dict[username], nonce,
                                                                    ticket_device, time_stamp, time_hmac)
        else:
            message = Constants.nordic_device_request_format.format(Constants.command_dict[command],
                                                                    Constants.client_id_dict[username],
                                                                    Constants.client_interface_dict[username], nonce,
                                                                    ticket_device)

        # put the actual ip address of the device
        device_ip = '192.168.158.191'
        device_port = 9000
        udp_client_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        udp_client_socket.settimeout(50)
        # Send to server using created UDP socket
        bytes_to_send = str.encode(message)
        device_address_port = (device_ip, device_port)
        udp_client_socket.sendto(bytes_to_send, device_address_port)

        try:
            result_from_device_bytes, client_address = udp_client_socket.recvfrom(1024)
            result_from_device = result_from_device_bytes.decode()
            print('Received response from device:\n', result_from_device)
            if command == 'attest':
                local_hmac = CryptoOperations.hmac_sha256(session_key, Constants.iot_device_memory_dict[actual_device_id])
                print("local hmac:", local_hmac)
                if result_from_device == local_hmac:
                    print("\ndevice healthy")
            else:
                print(result_from_device)
            print('\n')
        except Exception:
            print(Exception)
            pass
else:
    print("All required arguments not provided")
