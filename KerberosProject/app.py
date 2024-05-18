import json
from flask import Flask, jsonify, request
import time
import CryptoOperations
import Constants
import SynchronizationManager
from CounterManager import CounterManager

counter_manager = CounterManager()
device_last_ticket_time_dict = dict()

thread1 = SynchronizationManager.SynchronizationManager(counter_manager)
thread2 = SynchronizationManager.SynchronizationManager(counter_manager, 12346, 2)
thread1.start()
thread2.start()
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello World!'

@app.route('/device_ticket', methods=['POST'])
def get_device_ticket():
    request_json = request.get_json()
    request_username = request_json['username']
    print('Received device ticket request from: ', request_username, '\n')
    response = {}

    if request_username not in Constants.usernames:
        print("invalid username\n\n\n")
        response["error_message"] = "invalid username"
        return jsonify(response), 401
    request_device_id = request_json['device_id']
    current_time = time.time()
    client_id = Constants.client_id_dict[request_username]
    client_interface = Constants.client_interface_dict[request_username]
    if request_device_id in Constants.device_ids:
        actual_device_id = Constants.device_id_dict[request_device_id]
        device_type = Constants.iot_device_type_dict[actual_device_id]
        if device_type == Constants.device_type_normal:
            life_time = format(int(current_time + Constants.device_ticket_validity_in_seconds), '032d')
            nonce = life_time
        else:
            device_last_attestation_time = counter_manager.device_attestation_time_dict.get(actual_device_id)
            if device_last_attestation_time is None or (time.time()-device_last_attestation_time)>Constants.iot_device_awake_time_dict[actual_device_id]:
                response["error_message"] = "The device is not awake. Please try again later."
                return jsonify(response), 404
            device_counter = counter_manager.device_ticket_counter_dict.get(actual_device_id)
            device_counter += 1
            counter_manager.device_ticket_counter_dict[actual_device_id] = device_counter
            nonce = format(device_counter, '032d')
        ticket_info = Constants.device_ticket_info_format.format(client_id, client_interface, nonce,
                                                                 actual_device_id)
        ticket_iot = CryptoOperations.hmac_sha256(Constants.iot_device_key1_dict[actual_device_id], ticket_info)
        session_key = CryptoOperations.hmac_sha256(Constants.iot_device_key2_dict[actual_device_id], ticket_info)
        response["device_id"] = request_device_id
        response["timestamp"] = current_time
        response["session_key"] = session_key
        response["ticket"] = ticket_iot
        response["nonce"] = nonce
        print('Sending response\n\n\n')
        if device_type == Constants.device_type_nordic:
            device_last_ticket_time_dict[actual_device_id]=time.time()
        return jsonify(response), 200
    else:
        print('Invalid device id\n\n\n')
        response["error_message"] = "invalid device id"
        return jsonify(response), 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
