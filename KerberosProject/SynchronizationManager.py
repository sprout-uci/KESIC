import random
import threading
import socket
import time
import Constants
import CryptoOperations
class SynchronizationManager(threading.Thread):
    def __init__(self, counter_manager, port = 12345, id=1):
        threading.Thread.__init__(self)
        self.bufferSize = 1024
        self.port = port
        self.counter_manager = counter_manager
        self.id = id

    def run(self):
        udp_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        udp_socket.bind(('', self.port))
        while True:
            if self.id==1:
                print('\n\n\nWaiting for synchronization request from devices\n')
            try:
                message_address = udp_socket.recvfrom(self.bufferSize)
                message = message_address[0]
                address = message_address[1]
                message_str = message.decode('utf-8')
                if self.id==1:
                    iot_id = message_str[0:8]
                    request_reset_counter = message_str[8:40]
                    request_reset_counter_int = int(request_reset_counter)
                    device_reset_counter = self.counter_manager.device_reset_counter_dict.get(iot_id)
                    if device_reset_counter is None:
                        device_reset_counter = 0
                    reset_counter_diff = request_reset_counter_int - device_reset_counter
                    if reset_counter_diff==0 or reset_counter_diff==1:
                        self.counter_manager.device_reset_counter_dict[iot_id]=request_reset_counter_int
                        request_hmac = message_str[40:]
                        sync_request_plaintext = iot_id + request_reset_counter
                        calc_hmac = CryptoOperations.hmac_sha256(Constants.iot_device_key3_dict.get(iot_id), sync_request_plaintext)
                        if request_hmac == calc_hmac:
                            device_type = Constants.iot_device_type_dict[iot_id]
                            if device_type==Constants.device_type_normal:
                                sync_val =  format(int(time.time()), '032d')
                                sync_response_plaintext = Constants.service_id_dict[
                                                              'iot_service'] + request_reset_counter + sync_val
                                auth_is = CryptoOperations.hmac_sha256(Constants.iot_device_key3_dict.get(iot_id),
                                                                       sync_response_plaintext)
                                sync_response = sync_response_plaintext + auth_is
                                sync_response_bytes = sync_response.encode()
                                udp_socket.sendto(sync_response_bytes, address)
                            else:
                                # call for attestation
                                challange = format(random.randint(0,4294967295),'032d')
                                self.counter_manager.device_challange_dict[iot_id] = challange
                                auth_is_plaintext = Constants.service_id_dict['iot_service'] + challange
                                auth_is = CryptoOperations.hmac_sha256(Constants.iot_device_key3_dict.get(iot_id), auth_is_plaintext)
                                attest_request=auth_is_plaintext+auth_is
                                attest_request_bytes = attest_request.encode()
                                udp_socket.sendto(attest_request_bytes, address)
                        else:
                            error_message = "invalid authenticator"
                            error_message_bytes = error_message.encode()
                            udp_socket.sendto(error_message_bytes, address)
                    else:
                        error_message = "invalid counter\n"
                        error_message_bytes = error_message.encode()
                        udp_socket.sendto(error_message_bytes, address)
                else:
                    iot_id = message_str[0:8]
                    reply_hmac = message_str[8:]
                    challange = self.counter_manager.device_challange_dict[iot_id]
                    session_key = CryptoOperations.hmac_sha256(Constants.iot_device_key2_dict.get(iot_id),
                                                               challange)
                    local_hmac = CryptoOperations.hmac_sha256(session_key, Constants.iot_device_memory_dict[iot_id])
                    if reply_hmac == local_hmac:
                        self.counter_manager.device_attestation_time_dict[iot_id]=time.time()
                        sync_val = format(int(time.time()), '032d')
                        self.counter_manager.device_ticket_counter_dict[iot_id]=int(sync_val)
                        reset_counter_val = format(self.counter_manager.device_reset_counter_dict[iot_id], '032d')
                        sync_response_plaintext = Constants.service_id_dict['iot_service'] + reset_counter_val + sync_val
                        auth_is = CryptoOperations.hmac_sha256(Constants.iot_device_key3_dict.get(iot_id), sync_response_plaintext)
                        sync_response = sync_response_plaintext + auth_is
                        sync_response_bytes = sync_response.encode()
                        udp_socket.sendto(sync_response_bytes, address)
                    else:
                        error_message = "invalid attestation result\n"
                        error_message_bytes = error_message.encode()
                        udp_socket.sendto(error_message_bytes, address)
            except Exception as e:
                print(e)
                pass
